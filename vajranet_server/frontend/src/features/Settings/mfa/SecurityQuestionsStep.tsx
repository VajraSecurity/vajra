import { PREDEFINED_QUESTIONS } from "./constants";

interface QuestionFieldProps {
  index: 1 | 2;
  question: string;
  answer: string;
  otherQuestion: string;
  onQuestionChange: (value: string) => void;
  onAnswerChange: (value: string) => void;
}

function QuestionField({ index, question, answer, otherQuestion, onQuestionChange, onAnswerChange }: QuestionFieldProps) {
  return (
    <fieldset className="space-y-2 rounded-xl border border-gray-200 p-3.5">
      <legend className="px-1 text-xs font-semibold text-gray-500">Question {index}</legend>
      <div>
        <label htmlFor={`mfa-security-question-${index}`} className="sr-only">
          Security question {index}
        </label>
        <select
          id={`mfa-security-question-${index}`}
          value={question}
          onChange={(e) => onQuestionChange(e.target.value)}
          required
          className="w-full rounded-lg border border-gray-300 bg-white px-2.5 py-2 text-sm text-gray-900 outline-none transition-colors focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
        >
          <option value="" disabled>
            Select a question…
          </option>
          {PREDEFINED_QUESTIONS.map((q) => (
            <option key={q} value={q} disabled={q === otherQuestion}>
              {q}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label htmlFor={`mfa-security-answer-${index}`} className="sr-only">
          Answer {index}
        </label>
        <input
          id={`mfa-security-answer-${index}`}
          type="text"
          value={answer}
          onChange={(e) => onAnswerChange(e.target.value)}
          placeholder="Your answer"
          required
          className="w-full rounded-lg border border-gray-300 bg-white px-2.5 py-2 text-sm text-gray-900 outline-none transition-colors focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
        />
      </div>
    </fieldset>
  );
}

interface SecurityQuestionsStepProps {
  question1: string;
  answer1: string;
  question2: string;
  answer2: string;
  onQuestion1Change: (value: string) => void;
  onAnswer1Change: (value: string) => void;
  onQuestion2Change: (value: string) => void;
  onAnswer2Change: (value: string) => void;
}

export function SecurityQuestionsStep({
  question1,
  answer1,
  question2,
  answer2,
  onQuestion1Change,
  onAnswer1Change,
  onQuestion2Change,
  onAnswer2Change,
}: SecurityQuestionsStepProps) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-gray-500">
        Choose two different security questions and answers to store with your account. Your recovery codes in the next
        step are what let you back in if you ever lose access to your authenticator &mdash; keep those safe.
      </p>
      <QuestionField
        index={1}
        question={question1}
        answer={answer1}
        otherQuestion={question2}
        onQuestionChange={onQuestion1Change}
        onAnswerChange={onAnswer1Change}
      />
      <QuestionField
        index={2}
        question={question2}
        answer={answer2}
        otherQuestion={question1}
        onQuestionChange={onQuestion2Change}
        onAnswerChange={onAnswer2Change}
      />
    </div>
  );
}
