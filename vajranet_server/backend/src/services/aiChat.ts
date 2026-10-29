/**
 * AI chat service — multi-provider streaming tool-use loop.
 *
 * Provider, API key, model, and connection options are configured from the UI
 * (Admin → AI Assistant → Settings) and stored encrypted in the
 * `ai_provider_configs` table — see AiProviderConfig / aiProviderConfigController.
 * There is no .env fallback: if nothing is configured, chat requests return a
 * clear "not configured" error.
 */

import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import type { DataSource } from 'typeorm';
import { AI_TOOLS } from '../mcp/tools';
import { SYSTEM_PROMPT } from '../mcp/schema/definitions';
import { executeTool } from '../mcp/executor';
import type { ToolCallInput, ExecutorContext } from '../mcp/executor';
import { getUserNodeScope } from '../utils/nodeScope';
import { decrypt } from '../utils/encryption';
import type { AiProvider } from '../orm/entities/ai/AiProviderConfig';
import { getLogger } from '../utils/logger';
import { EXTERNAL_API_TIMEOUT_MS } from '../consts/timeout';

const logger = getLogger('services.aiChat');

const MAX_TOOL_ITERATIONS = 8;
const REQUEST_TIMEOUT_MS  = EXTERNAL_API_TIMEOUT_MS;
const DEFAULT_MAX_OUTPUT_TOKENS = 4096;
/** Model used per AI provider when the caller/config doesn't specify one. */
export const DEFAULT_AI_MODEL_BY_PROVIDER: Record<AiProvider, string> = {
  anthropic: 'claude-sonnet-5',
  openai: 'gpt-5.6-terra',
};

// Types

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export type StreamEvent =
  | { type: 'text_delta'; text: string }
  | { type: 'tool_call'; tool_name: string; tool_input: Record<string, unknown> }
  | { type: 'tool_result'; tool_name: string; result: string; is_error: boolean }
  | { type: 'done' }
  | { type: 'error'; message: string };

export interface AiChatContext {
  primaryDb: DataSource;
  secondaryDb: DataSource;
  /**
   * Group-scoped historical-hunting connection (vajra_hunt), the same one
   * run_query.ts uses. Undefined if the deployment has not provisioned the role;
   * only consulted for callers whose scope is restricted.
   */
  huntDb?: DataSource;
  /** id of the authenticated user driving this chat session — threaded through to tool execution */
  userId: number;
}

interface ActiveProviderConfig {
  provider: AiProvider;
  apiKey: string;
  model: string | null;
  baseUrl: string | null;
  organization: string | null;
  maxOutputTokens: number | null;
}

async function loadActiveProviderConfig(primaryDb: DataSource): Promise<ActiveProviderConfig | null> {
  const { AiProviderConfig } = await import('../orm/entities/ai/AiProviderConfig');
  const repo = primaryDb.getRepository(AiProviderConfig);
  const config = await repo.findOne({ where: { isActive: true } });
  if (!config) return null;

  return {
    provider: config.provider,
    apiKey: decrypt(config.apiKeyEncrypted, config.apiKeyIv, config.apiKeyAuthTag),
    model: config.model,
    baseUrl: config.baseUrl,
    organization: config.organization,
    maxOutputTokens: config.maxOutputTokens,
  };
}

// Input validation

function validateMessages(messages: ChatMessage[]): string | null {
  if (!Array.isArray(messages) || messages.length === 0) return 'No messages provided';
  if (messages.length > 100) return 'Conversation too long (max 100 messages)';
  for (const m of messages) {
    if (m.role !== 'user' && m.role !== 'assistant') return `Invalid role: ${m.role}`;
    if (typeof m.content !== 'string') return 'Message content must be a string';
    if (m.content.length > 32_000) return 'Message too long';
  }
  if (messages[messages.length - 1].role !== 'user') return 'Last message must be from user';
  return null;
}

// Tool schema converter (Anthropic to OpenAI format)

function toOpenAiTools(): OpenAI.ChatCompletionTool[] {
  return AI_TOOLS.map((t) => ({
    type: 'function' as const,
    function: {
      name: t.name,
      description: t.description,
      parameters: t.input_schema as OpenAI.FunctionParameters,
    },
  }));
}

// Main entry point

export async function* streamAiResponse(
  messages: ChatMessage[],
  ctx: AiChatContext,
): AsyncGenerator<StreamEvent> {
  const validationError = validateMessages(messages);
  if (validationError) {
    logger.warn({ userId: ctx.userId, reason: validationError }, 'Chat request rejected by message validation');
    yield { type: 'error', message: validationError };
    return;
  }

  // Resolved once per chat turn rather than per tool call: a turn can invoke
  // several tools via MAX_TOOL_ITERATIONS, and they all share the same caller
  // and access scope.
  let scope: Awaited<ReturnType<typeof getUserNodeScope>>;
  try {
    scope = await getUserNodeScope(ctx.userId);
  } catch (err) {
    logger.error({ err, userId: ctx.userId }, 'Failed to resolve node scope for chat user');
    throw err;
  }
  const executorCtx: ExecutorContext = {
    primaryDb: ctx.primaryDb,
    secondaryDb: ctx.secondaryDb,
    huntDb: ctx.huntDb,
    userId: ctx.userId,
    scope,
  };

  let activeConfig: ActiveProviderConfig | null;
  try {
    activeConfig = await loadActiveProviderConfig(ctx.primaryDb);
  } catch (err: any) {
    logger.error({ err, userId: ctx.userId }, 'Failed to load AI provider configuration');
    yield {
      type: 'error',
      message: err?.message || 'Failed to load AI provider configuration.',
    };
    return;
  }
  if (!activeConfig) {
    logger.warn({ userId: ctx.userId }, 'Chat request received but no AI provider is configured');
    yield {
      type: 'error',
      message: 'AI provider is not configured. A Super Administrator can set it up from AI Assistant → Settings.',
    };
    return;
  }

  logger.debug(
    { userId: ctx.userId, provider: activeConfig.provider, model: activeConfig.model || DEFAULT_AI_MODEL_BY_PROVIDER[activeConfig.provider], messageCount: messages.length },
    'Starting AI chat turn',
  );

  const gen = activeConfig.provider === 'openai'
    ? streamOpenAi(messages, executorCtx, activeConfig)
    : streamAnthropic(messages, executorCtx, activeConfig);

  yield* gen;
}

// Anthropic provider

async function* streamAnthropic(
  messages: ChatMessage[],
  ctx: ExecutorContext,
  config: ActiveProviderConfig,
): AsyncGenerator<StreamEvent> {
  const client = new Anthropic({ apiKey: config.apiKey, baseURL: config.baseUrl || undefined, timeout: REQUEST_TIMEOUT_MS });
  const model  = config.model || DEFAULT_AI_MODEL_BY_PROVIDER.anthropic;
  const maxOutputTokens = config.maxOutputTokens || DEFAULT_MAX_OUTPUT_TOKENS;

  const apiMessages: Anthropic.MessageParam[] = messages.map((m) => ({
    role: m.role,
    content: m.content,
  }));

  let iterations = 0;
  const startTime = Date.now();

  while (iterations < MAX_TOOL_ITERATIONS) {
    if (Date.now() - startTime > REQUEST_TIMEOUT_MS) {
      logger.warn({ userId: ctx.userId, iterations, elapsedMs: Date.now() - startTime }, 'Anthropic chat request hit the request timeout');
      yield { type: 'error', message: 'Request timeout.' };
      return;
    }
    iterations++;

    try {
      const stream = client.messages.stream({
        model,
        max_tokens: maxOutputTokens,
        system: SYSTEM_PROMPT,
        tools: AI_TOOLS,
        messages: apiMessages,
      });

      let streamTruncatedByTimeout = false;
      for await (const event of stream) {
        if (Date.now() - startTime > REQUEST_TIMEOUT_MS) { streamTruncatedByTimeout = true; break; }
        if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
          yield { type: 'text_delta', text: event.delta.text };
        }
      }
      if (streamTruncatedByTimeout) {
        // Forwarding of text_delta stops here, but stream.finalMessage() below
        // still awaits the request to completion, so without this the "chat turn
        // completed" log would look like a normal finish.
        logger.warn({ userId: ctx.userId, iterations, elapsedMs: Date.now() - startTime }, 'Anthropic stream stopped forwarding text to caller after exceeding request timeout mid-stream');
      }

      const finalMessage = await stream.finalMessage();
      const toolBlocks = finalMessage.content.filter(
        (b): b is Anthropic.ToolUseBlock => b.type === 'tool_use',
      );

      if (toolBlocks.length === 0) {
        logger.info({ userId: ctx.userId, iterations, elapsedMs: Date.now() - startTime }, 'Anthropic chat turn completed');
        break;
      }

      apiMessages.push({ role: 'assistant', content: finalMessage.content });
      const toolResults: Anthropic.ToolResultBlockParam[] = [];

      for (const tb of toolBlocks) {
        const input = tb.input as Record<string, unknown>;
        yield { type: 'tool_call', tool_name: tb.name, tool_input: input };

        let result;
        try {
          result = await executeTool({ name: tb.name, input }, ctx);
        } catch (err: any) {
          logger.error({ err, userId: ctx.userId, toolName: tb.name }, 'Tool execution threw during Anthropic chat turn');
          // Tagged so the outer catch, which frames everything as an "Anthropic
          // API call failed" with API status fields, does not re-log this under a
          // misleading label: it is a tool-execution error, not an API error.
          if (err && typeof err === 'object') err.__loggedByToolExecution = true;
          throw err;
        }
        if (result.is_error) {
          logger.warn({ userId: ctx.userId, toolName: tb.name, iterations }, 'Tool call returned an error result during Anthropic chat turn');
        }
        yield { type: 'tool_result', tool_name: tb.name, result: result.content, is_error: result.is_error ?? false };
        toolResults.push({ type: 'tool_result', tool_use_id: tb.id, content: result.content, is_error: result.is_error });
      }

      apiMessages.push({ role: 'user', content: toolResults });

    } catch (err: any) {
      // Anthropic's APIError carries status/type as own properties, not under
      // .response, and pino's default err serializer keeps only message/stack, so
      // without pulling these out an invalid key, a rate limit and a transient
      // 5xx are indistinguishable. Skipped when the tool-execution catch above
      // already logged this error; see __loggedByToolExecution.
      if (!err?.__loggedByToolExecution) {
        logger.error({ err, userId: ctx.userId, model, iterations, status: err?.status, errorType: err?.type }, 'Anthropic API call failed');
      }
      yield { type: 'error', message: `Anthropic API error: ${err instanceof Error ? err.message : String(err)}` };
      return;
    }
  }

  if (iterations >= MAX_TOOL_ITERATIONS) {
    logger.warn({ userId: ctx.userId, iterations }, 'Anthropic chat request reached max tool iterations');
    yield { type: 'text_delta', text: '\n\n⚠️ Reached maximum tool iterations. Some info may be incomplete.' };
  }
  yield { type: 'done' };
}

// OpenAI provider

async function* streamOpenAi(
  messages: ChatMessage[],
  ctx: ExecutorContext,
  config: ActiveProviderConfig,
): AsyncGenerator<StreamEvent> {
  const client = new OpenAI({
    apiKey: config.apiKey,
    baseURL: config.baseUrl || undefined,
    organization: config.organization || undefined,
    timeout: REQUEST_TIMEOUT_MS,
  });
  const model  = config.model || DEFAULT_AI_MODEL_BY_PROVIDER.openai;
  const maxOutputTokens = config.maxOutputTokens || DEFAULT_MAX_OUTPUT_TOKENS;
  const tools  = toOpenAiTools();

  const apiMessages: OpenAI.ChatCompletionMessageParam[] = [
    { role: 'system', content: SYSTEM_PROMPT },
    ...messages.map((m) => ({ role: m.role as 'user' | 'assistant', content: m.content })),
  ];

  let iterations = 0;
  const startTime = Date.now();

  while (iterations < MAX_TOOL_ITERATIONS) {
    if (Date.now() - startTime > REQUEST_TIMEOUT_MS) {
      logger.warn({ userId: ctx.userId, iterations, elapsedMs: Date.now() - startTime }, 'OpenAI chat request hit the request timeout');
      yield { type: 'error', message: 'Request timeout.' };
      return;
    }
    iterations++;

    try {
      // Streaming call
      const stream = await client.chat.completions.create({
        model,
        max_completion_tokens: maxOutputTokens,
        tools,
        tool_choice: 'auto',
        messages: apiMessages,
        stream: true,
      });

      // Accumulate text + tool calls from stream
      let textBuffer = '';
      // tool_call accumulator: index → {id, name, argsBuffer}
      const toolCallMap: Record<number, { id: string; name: string; argsBuffer: string }> = {};

      let streamTruncatedByTimeout = false;
      for await (const chunk of stream) {
        if (Date.now() - startTime > REQUEST_TIMEOUT_MS) { streamTruncatedByTimeout = true; break; }

        const delta = chunk.choices[0]?.delta;
        if (!delta) continue;

        if (delta.content) {
          textBuffer += delta.content;
          yield { type: 'text_delta', text: delta.content };
        }

        if (delta.tool_calls) {
          for (const tc of delta.tool_calls) {
            const idx = tc.index;
            if (!toolCallMap[idx]) {
              toolCallMap[idx] = { id: tc.id ?? '', name: tc.function?.name ?? '', argsBuffer: '' };
            }
            if (tc.id) toolCallMap[idx].id = tc.id;
            if (tc.function?.name) toolCallMap[idx].name = tc.function.name;
            if (tc.function?.arguments) toolCallMap[idx].argsBuffer += tc.function.arguments;
          }
        }
      }

      if (streamTruncatedByTimeout) {
        // Distinguishes the model finishing from the stream being abandoned
        // mid-response on timeout; both otherwise log as a normal turn
        // completion, leaving cut-off text or missing tool calls unexplained.
        logger.warn({ userId: ctx.userId, iterations, elapsedMs: Date.now() - startTime }, 'OpenAI stream stopped forwarding text to caller after exceeding request timeout mid-stream');
      }

      const toolCalls = Object.values(toolCallMap);
      if (toolCalls.length === 0) {
        logger.info({ userId: ctx.userId, iterations, elapsedMs: Date.now() - startTime }, 'OpenAI chat turn completed');
        break;
      }

      // Append assistant message with tool_calls
      const assistantMsg: OpenAI.ChatCompletionAssistantMessageParam = {
        role: 'assistant',
        content: textBuffer || null,
        tool_calls: toolCalls.map((tc) => ({
          id: tc.id,
          type: 'function' as const,
          function: { name: tc.name, arguments: tc.argsBuffer },
        })),
      };
      apiMessages.push(assistantMsg);

      // Execute each tool and feed results back
      for (const tc of toolCalls) {
        let input: Record<string, unknown> = {};
        try { input = JSON.parse(tc.argsBuffer); } catch (err) {
          logger.warn({ err, userId: ctx.userId, toolName: tc.name }, 'Failed to parse tool call arguments as JSON; using empty input');
        }

        const toolCall: ToolCallInput = { name: tc.name, input };
        yield { type: 'tool_call', tool_name: tc.name, tool_input: input };

        let result;
        try {
          result = await executeTool(toolCall, ctx);
        } catch (err: any) {
          logger.error({ err, userId: ctx.userId, toolName: tc.name }, 'Tool execution threw during OpenAI chat turn');
          // Same reasoning as the Anthropic branch: tag so the outer catch does
          // not re-log this as a misleading "OpenAI API call failed".
          if (err && typeof err === 'object') err.__loggedByToolExecution = true;
          throw err;
        }
        if (result.is_error) {
          logger.warn({ userId: ctx.userId, toolName: tc.name, iterations }, 'Tool call returned an error result during OpenAI chat turn');
        }
        yield { type: 'tool_result', tool_name: tc.name, result: result.content, is_error: result.is_error ?? false };

        const toolResultMsg: OpenAI.ChatCompletionToolMessageParam = {
          role: 'tool',
          tool_call_id: tc.id,
          content: result.content,
        };
        apiMessages.push(toolResultMsg);
      }

    } catch (err: any) {
      // Same reasoning as the Anthropic branch: OpenAI's APIError also carries
      // status as an own property, so pull it out explicitly rather than letting
      // an invalid key, a rate limit and a transient 5xx collapse into one log
      // line. Skipped when the tool-execution catch above already logged it.
      if (!err?.__loggedByToolExecution) {
        logger.error({ err, userId: ctx.userId, model, iterations, status: err?.status, code: err?.code }, 'OpenAI API call failed');
      }
      yield { type: 'error', message: `OpenAI API error: ${err instanceof Error ? err.message : String(err)}` };
      return;
    }
  }

  if (iterations >= MAX_TOOL_ITERATIONS) {
    logger.warn({ userId: ctx.userId, iterations }, 'OpenAI chat request reached max tool iterations');
    yield { type: 'text_delta', text: '\n\n⚠️ Reached maximum tool iterations. Some info may be incomplete.' };
  }
  yield { type: 'done' };
}
