import React from 'react';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    if (this.props.onError) {
      this.props.onError(error, info);
    }
  }

  handleReload = () => {
    if (typeof window !== 'undefined') window.location.reload();
  };

  handleCopy = () => {
    const { diagnostics } = this.props;
    const payload = JSON.stringify(diagnostics || {}, null, 2);
    navigator.clipboard?.writeText(payload).catch(() => {});
  };

  render() {
    const { hasError } = this.state;
    if (!hasError) return this.props.children;
    const { diagnostics } = this.props;
    return (
      <div className="app-shell">
        <div className="topbar surface">
          <div className="topbar__brand">
            <div className="wordmark">mustard</div>
            <div className="topbar__subtitle">Bulk Find &amp; Replace</div>
          </div>
        </div>
        <main className="content">
          <section className="card surface">
            <div className="section-header">
              <h2>Something went wrong.</h2>
              <span className="pill pill-red">Crash</span>
            </div>
            <div className="muted">Reload the app to continue. If it persists, share diagnostics.</div>
            <div className="modal-actions">
              <button className="btn btn-primary" type="button" onClick={this.handleReload}>
                Reload
              </button>
              <button className="btn btn-secondary" type="button" onClick={this.handleCopy}>
                Copy diagnostics
              </button>
            </div>
            {diagnostics && (
              <pre className="crash-diagnostics">{JSON.stringify(diagnostics, null, 2)}</pre>
            )}
          </section>
        </main>
      </div>
    );
  }
}

export default ErrorBoundary;
