import React from 'react';
import MultiSelectList from './MultiSelectList';

const WhereToLookCard = ({
  targets,
  setTargets,
  columnScope,
  setColumnScope,
  textColumns,
  groupOptions,
  includeColumnIds,
  setIncludeColumnIds,
  includeGroupIds,
  setIncludeGroupIds,
  includeNameContains,
  setIncludeNameContains,
  excludeNameContains,
  setExcludeNameContains,
  excludeColumnIds,
  setExcludeColumnIds,
  docIdsText,
  setDocIdsText,
  metaLoading,
  metaError
}) => (
  <section className="card surface">
    <div className="section-header">
      <h2>Step 1 · Where to look</h2>
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
      <label className="field">
        <span className="field__label">Look in</span>
        <select
          className="input"
          value={columnScope}
          onChange={(e) => setColumnScope(e.target.value)}
        >
          <option value="all">All text fields</option>
          <option value="custom">Choose fields…</option>
        </select>
        <span className="muted">Only text and long text fields are scanned.</span>
      </label>
    </div>

    {columnScope === 'custom' && (
      <MultiSelectList
        label="Choose fields"
        options={textColumns}
        selectedIds={includeColumnIds}
        onChange={setIncludeColumnIds}
        searchPlaceholder="Search fields"
        emptyLabel={metaLoading ? 'Loading fields…' : 'No matching fields.'}
      />
    )}

    <MultiSelectList
      label="Only in groups (optional)"
      options={groupOptions}
      selectedIds={includeGroupIds}
      onChange={setIncludeGroupIds}
      searchPlaceholder="Search groups"
      emptyLabel={metaLoading ? 'Loading groups…' : 'No matching groups.'}
    />

    <div className="grid-2">
      <label className="field">
        <span className="field__label">Only names containing</span>
        <input
          className="input"
          value={includeNameContains}
          onChange={(e) => setIncludeNameContains(e.target.value)}
          placeholder="Optional"
        />
      </label>
      <label className="field">
        <span className="field__label">Exclude names containing</span>
        <input
          className="input"
          value={excludeNameContains}
          onChange={(e) => setExcludeNameContains(e.target.value)}
          placeholder="Optional"
        />
      </label>
    </div>

    <details className="advanced">
      <summary className="advanced__summary">Advanced options</summary>
      <div className="advanced__body">
        <MultiSelectList
          label="Exclude fields"
          options={textColumns}
          selectedIds={excludeColumnIds}
          onChange={setExcludeColumnIds}
          searchPlaceholder="Search fields"
          emptyLabel={metaLoading ? 'Loading fields…' : 'No matching fields.'}
        />
        <label className="field">
          <span className="field__label">Docs: manually specify doc IDs</span>
          <textarea
            className="input textarea"
            value={docIdsText}
            onChange={(e) => setDocIdsText(e.target.value)}
            placeholder="Add doc IDs separated by commas or new lines"
            rows={3}
          />
          <span className="muted">Use only if doc discovery misses documents.</span>
        </label>
      </div>
    </details>

    {metaError && (
      <div className="notice notice--error surface-2">
        We couldn’t load fields or groups. You can still run previews on all text fields.
      </div>
    )}
  </section>
);

export default WhereToLookCard;
