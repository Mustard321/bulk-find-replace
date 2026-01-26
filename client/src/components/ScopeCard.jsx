import React from 'react';

const ScopeCard = ({ boardId, ctxLoaded }) => (
  <section className="card surface">
    <div className="section-header">
      <h2>Step 1 · Choose scope</h2>
      <span className="pill">Safe</span>
    </div>
    <div className="scope-grid">
      <div className="scope-item surface-2">
        <div className="scope-label">Board</div>
        <div className="scope-value">{ctxLoaded ? (boardId || 'Waiting for board') : 'Loading context…'}</div>
        <div className="muted">Runs on the active board in Monday.</div>
      </div>
      <div className="scope-item surface-2">
        <div className="scope-label">Columns</div>
        <div className="scope-value">Text + long text</div>
        <div className="muted">Auto-selected to keep results consistent.</div>
      </div>
      <div className="scope-item surface-2">
        <div className="scope-label">Filters</div>
        <div className="scope-value">Optional</div>
        <div className="muted">Filtering can be added later.</div>
      </div>
    </div>
  </section>
);

export default ScopeCard;
