import React from "react";

interface ErrorBoundaryProps {
  children: React.ReactNode;
  /**
   * When this value changes, the boundary will reset and attempt to re-render.
   * Useful for route changes after a route-level crash.
   */
  resetKey?: string;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = {
    hasError: false,
    error: null,
  };

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("[ErrorBoundary] Render crashed:", error, info);
  }

  componentDidUpdate(prevProps: ErrorBoundaryProps) {
    if (this.props.resetKey !== prevProps.resetKey && this.state.hasError) {
      this.setState({ hasError: false, error: null });
    }
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 p-6">
        <div className="w-full max-w-xl bg-white rounded-2xl shadow border border-gray-200 p-6">
          <div className="text-red-700 font-semibold text-lg mb-2">Something went wrong.</div>
          <div className="text-sm text-gray-600 mb-4">
            The page crashed while rendering. You can reload, or navigate to another page.
          </div>

          {this.state.error?.message && (
            <pre className="text-xs text-gray-800 bg-gray-50 border border-gray-200 rounded p-3 whitespace-pre-wrap mb-4">
              {this.state.error.message}
            </pre>
          )}

          <div className="flex flex-col sm:flex-row gap-3">
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="px-4 py-2 rounded-lg bg-blue-600 text-white font-medium hover:bg-blue-700"
            >
              Reload page
            </button>
            <button
              type="button"
              onClick={() => (window.location.href = "/login")}
              className="px-4 py-2 rounded-lg border border-gray-300 bg-white text-gray-800 font-medium hover:bg-gray-50"
            >
              Go to login
            </button>
          </div>
        </div>
      </div>
    );
  }
}

export default ErrorBoundary;

