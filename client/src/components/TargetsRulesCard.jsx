import React from 'react';

const TargetsRulesCard = ({
  targets,
  setTargets,
  rules,
  setRules,
  filters,
  setFilters,
  limit,
  setLimit
}) => (
  <section className="card surface">
    <div className="section-header">
      <h2>Step 2 · Targets &amp; rules</h2>
      <span className="pill">Safe</span>
    </div>
    <div className="grid-2">
      <div className="field">
        <span className="field__label">Targets</span>
        <label className="toggle">
          <input
            type="checkbox"
            checked={targets.items}
            onChange={(e) => setTargets({ ...targets, items: e.target.checked })}
          />
          <span>Items</span>
        </label>
        <label className="toggle">
          <input
            type="checkbox"
            checked={targets.subitems}
            onChange={(e) => setTargets({ ...targets, subitems: e.target.checked })}
          />
          <span>Subitems</span>
        </label>
        <label className="toggle">
          <input
            type="checkbox"
            checked={targets.docs}
            onChange={(e) => setTargets({ ...targets, docs: e.target.checked })}
          />
          <span>Docs (WorkDocs)</span>
        </label>
      </div>
      <div className="field">
        <span className="field__label">Rules</span>
        <label className="toggle">
          <input
            type="checkbox"
            checked={rules.caseSensitive}
            onChange={(e) => setRules({ ...rules, caseSensitive: e.target.checked })}
          />
          <span>Case sensitive</span>
        </label>
        <label className="toggle">
          <input
            type="checkbox"
            checked={rules.wholeWord}
            onChange={(e) => setRules({ ...rules, wholeWord: e.target.checked })}
          />
          <span>Whole word</span>
        </label>
        <label className="field">
          <span className="field__label">Max changes</span>
          <input
            className="input"
            type="number"
            min="1"
            placeholder="No limit"
            value={limit.maxChanges}
            onChange={(e) => setLimit({ maxChanges: e.target.value ? Number(e.target.value) : '' })}
          />
        </label>
      </div>
    </div>

    <div className="grid-2">
      <label className="field">
        <span className="field__label">Include column IDs</span>
        <input
          className="input"
          value={filters.includeColumnIds}
          onChange={(e) => setFilters({ ...filters, includeColumnIds: e.target.value })}
          placeholder="col_1, col_2"
        />
        <span className="muted">Leave blank for all text + long text columns.</span>
      </label>
      <label className="field">
        <span className="field__label">Exclude column IDs</span>
        <input
          className="input"
          value={filters.excludeColumnIds}
          onChange={(e) => setFilters({ ...filters, excludeColumnIds: e.target.value })}
          placeholder="col_3"
        />
      </label>
      <label className="field">
        <span className="field__label">Include group IDs</span>
        <input
          className="input"
          value={filters.includeGroupIds}
          onChange={(e) => setFilters({ ...filters, includeGroupIds: e.target.value })}
          placeholder="topics, backlog"
        />
      </label>
      <label className="field">
        <span className="field__label">Exclude group IDs</span>
        <input
          className="input"
          value={filters.excludeGroupIds}
          onChange={(e) => setFilters({ ...filters, excludeGroupIds: e.target.value })}
          placeholder="done"
        />
      </label>
      <label className="field">
        <span className="field__label">Include name contains</span>
        <input
          className="input"
          value={filters.includeNameContains}
          onChange={(e) => setFilters({ ...filters, includeNameContains: e.target.value })}
          placeholder="alpha, beta"
        />
      </label>
      <label className="field">
        <span className="field__label">Exclude name contains</span>
        <input
          className="input"
          value={filters.excludeNameContains}
          onChange={(e) => setFilters({ ...filters, excludeNameContains: e.target.value })}
          placeholder="draft"
        />
      </label>
      <label className="field">
        <span className="field__label">Doc IDs (optional)</span>
        <input
          className="input"
          value={filters.docIds}
          onChange={(e) => setFilters({ ...filters, docIds: e.target.value })}
          placeholder="12345, 67890"
        />
        <span className="muted">Use if doc discovery misses items.</span>
      </label>
    </div>
  </section>
);

export default TargetsRulesCard;
