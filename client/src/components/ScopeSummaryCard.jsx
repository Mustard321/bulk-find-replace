import React from 'react';

const ScopeSummaryCard = ({ boardId, ctxLoaded, targetsLabel, columnRule, filtersActive }) => (
  <section className="card surface">
    <div className="section-header">
      <h2>Scope summary</h2>
      {filtersActive && <span className="pill pill-gold">Exclusions active</span>}
    </div>
    <div className="scope-summary">
      <div className="scope-summary__row">
        <div className="scope-summary__label">Board ID</div>
        <div className="scope-summary__value">{ctxLoaded ? (boardId || 'Waiting for board') : 'Loading context…'}</div>
      </div>
      <div className="scope-summary__row">
        <div className="scope-summary__label">Targets</div>
        <div className="scope-summary__value">{targetsLabel}</div>
      </div>
      <div className="scope-summary__row">
        <div className="scope-summary__label">Columns</div>
        <div className="scope-summary__value">{columnRule}</div>
      </div>
    </div>
  </section>
);

export default ScopeSummaryCard;
