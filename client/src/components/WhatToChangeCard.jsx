import React from 'react';

const WhatToChangeCard = ({
  find,
  replace,
  setFind,
  setReplace,
  rules,
  setRules,
  onPreview,
  previewDisabled,
  previewLoading,
  canPreview
}) => (
  <section className="card surface">
    <div className="section-header">
      <h2>Step 2 · What to change</h2>
      <span className="pill">Safe</span>
    </div>
    <div className="form-grid">
      <label className="field">
        <span className="field__label">Find</span>
        <input
          className="input"
          value={find}
          onChange={(e) => setFind(e.target.value)}
          placeholder="Text to find"
          onKeyDown={(event) => {
            if (event.key !== 'Enter' || !canPreview) return;
            event.preventDefault();
            onPreview();
          }}
        />
      </label>
      <label className="field">
        <span className="field__label">Replace with</span>
        <input
          className="input"
          value={replace}
          onChange={(e) => setReplace(e.target.value)}
          placeholder="Leave blank to remove text"
          onKeyDown={(event) => {
            if (event.key !== 'Enter' || !canPreview) return;
            event.preventDefault();
            onPreview();
          }}
        />
      </label>
      <div className="toggle-row">
        <label className="toggle">
          <input
            type="checkbox"
            checked={rules.caseSensitive}
            onChange={(e) => setRules({ ...rules, caseSensitive: e.target.checked })}
          />
          <span>Match case</span>
        </label>
        <label className="toggle">
          <input
            type="checkbox"
            checked={rules.wholeWord}
            onChange={(e) => setRules({ ...rules, wholeWord: e.target.checked })}
          />
          <span>Whole word only</span>
        </label>
      </div>
      <div className="form-actions">
        <button className="btn btn-primary" type="button" onClick={onPreview} disabled={previewDisabled}>
          {previewLoading ? 'Previewing…' : 'Preview changes'}
        </button>
        <div className="muted">Preview is a safe dry run. No data changes yet.</div>
      </div>
    </div>
  </section>
);

export default WhatToChangeCard;
