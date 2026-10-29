/**
 * NodesView Send Message tab: Send notification/message to node agent.
 * API/WS: Backend or WebSocket to deliver message to agent.
 */

import { useState } from 'react';
import type { NodeData } from './types';
import { ERROR_MESSAGES, SUCCESS_MESSAGES } from './constants';
import { sanitizeAsciiMultiLine } from '../../../services/inputSanitizers';

interface NodesViewSendMessageProps {
  node: NodeData;
  /** WebSocket connected state (shared from parent NodesView) */
  wsConnected: boolean;
  /** Send a message over the shared WebSocket */
  wsSendMessage: (message: unknown) => Promise<{ status?: string; message?: string; response?: unknown }>;
}

const NodesViewSendMessage = ({ node, wsConnected, wsSendMessage }: NodesViewSendMessageProps) => {
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const hostId = node.host_identifier || String(node.id);
  // Use shared WebSocket from parent NodesView
  const connected = wsConnected;
  const sendWebSocketMessage = wsSendMessage;

  const handleSend = async () => {
    const trimmed = message.trim();
    if (!trimmed) {
      setFeedback({ type: 'error', text: ERROR_MESSAGES.EMPTY_MESSAGE });
      return;
    }

    if (!connected) {
      setFeedback({ type: 'error', text: 'WebSocket not connected. Please wait or refresh the page.' });
      return;
    }

    setFeedback(null);
    setLoading(true);
    try {
      // Send message to node agent via WebSocket
      const response = await sendWebSocketMessage({
        type: 'agent',
        params: {
          agent: 'message',
          action: 'message',
          arg1: trimmed,
        },
        host_identifier: hostId,
      });

      // Handle response
      if (response.status === 'error') {
        throw new Error(response.message || 'Failed to send message to agent');
      }

      setMessage('');
      setFeedback({ type: 'success', text: SUCCESS_MESSAGES.MESSAGE_SENT });
    } catch (error: unknown) {
      console.error('Send message error:', error);
      setFeedback({
        type: 'error',
        text: (error instanceof Error && error.message) || 'Failed to send message to agent.',
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-4 flex items-center justify-center min-h-[200px]">
      <div className="bg-white rounded-xl border border-blue-100 overflow-hidden w-full max-w-md">
        <div className="px-4 py-3 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100">
          <h6 className="font-semibold text-gray-800 flex items-center gap-2">
            <i className="fa fa-paper-plane text-blue-600" /> Send Message
          </h6>
          <span className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${connected ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
            {connected ? 'Agent Connected' : 'Agent Disconnected'}
          </span>
        </div>
        <div className="p-4 space-y-4">
          <label className="block text-sm font-medium text-gray-700">Message</label>
          <textarea
            value={message}
            onChange={(e) => setMessage(sanitizeAsciiMultiLine(e.target.value, 500, false))}
            placeholder="Enter your message..."
            rows={4}
            disabled={!connected}
            className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          />
          {feedback && (
            <p className={`text-sm ${feedback.type === 'success' ? 'text-green-600' : 'text-red-600'}`}>{feedback.text}</p>
          )}
          <div className="flex gap-2 justify-end">
            <button
              type="button"
              onClick={() => { setMessage(''); setFeedback(null); }}
              className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 font-medium hover:bg-gray-50"
            >
              Clear
            </button>
            <button
              type="button"
              onClick={handleSend}
              disabled={loading || !message.trim() || !connected}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? 'Sending...' : 'Send message'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NodesViewSendMessage;
