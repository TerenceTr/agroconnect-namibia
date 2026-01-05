// ============================================================================
// ErrorBoundary.jsx — Temporary Safety Net (Dev + Demo)
// ----------------------------------------------------------------------------
// ROLE:
// • Prevents white-screen crashes
// • Logs errors cleanly
// • Can be removed after stabilization
// ============================================================================

import React from 'react';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error('🔥 UI Crash:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center text-white">
          <div className="glass-card p-8 max-w-md text-center">
            <h2 className="text-xl font-semibold mb-2">Something went wrong</h2>
            <p className="text-white/70 text-sm">
              This is a temporary safeguard while we stabilize the UI.
            </p>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
