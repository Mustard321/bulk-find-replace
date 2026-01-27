import React from 'react';

const SafetyCard = ({ limit, setLimit, dryRun, setDryRunPreference }) => (
  <section className="card surface">
    <div className="section-header">
      <h2>Step 3 · Safety</h2>
      <span className="pill pill-gold">Recommended</span>
    </div>
    <div className="grid-2">
      <label className="field">
        <span className="field__label">Maximum changes this run</span>
        <input
          className="input"
          type="number"
          min="1"
          placeholder="250"
          value={limit.maxChanges}
          onChange={(e) => setLimit({ maxChanges: e.target.value ? Number(e.target.value) : '' })}
        />
        <span className="muted">Keeps large updates manageable. Default is 250.</span>
      </label>
      <div className="field">
        <span className="field__label">Dry run</span>
        <label className="toggle">
          <input
            type="checkbox"
            checked={dryRun}
            onChange={(e) => setDryRunPreference(e.target.checked)}
          />
          <span>Run a safe preview instead of applying</span>
        </label>
        <span className="muted">Turn this off only when you are ready to apply changes.</span>
      </div>
    </div>
  </section>
);

export default SafetyCard;
