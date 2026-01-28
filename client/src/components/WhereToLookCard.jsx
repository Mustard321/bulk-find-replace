import React from 'react';
import MultiSelectList from './MultiSelectList';

const SelectedChips = ({ label, items }) => {
  return (
    <div className="selected-chips">
      <div className="selected-chips__label">{label}</div>
      <div className="chip-list">
        {items.length > 0 ? (
          items.map((item) => (
            <span className="chip" key={item}>{item}</span>
          ))
        ) : (
          <span className="muted">None selected yet.</span>
        )}
      </div>
    </div>
  );
};

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
  metaError,
  onRetryMeta,
  metaWaiting
}) => {
  const selectedFieldNames = textColumns
    .filter((col) => includeColumnIds.includes(col.id))
    .map((col) => col.label);
  const selectedGroupNames = groupOptions
    .filter((group) => includeGroupIds.includes(group.id))
    .map((group) => group.label);

  return (
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
            <option value="all">All text fields ({textColumns.length})</option>
            <option value="custom">Choose fields…</option>
          </select>
          <span className="muted">Only text and long text fields are scanned.</span>
        </label>
      </div>

      {textColumns.length === 0 && !metaLoading && (
        <div className="empty-state">
          <div className="empty-title">No text fields available.</div>
          <div className="muted">Add a text or long text field to use Bulk Find &amp; Replace.</div>
        </div>
      )}

      {columnScope === 'custom' && (
        <>
          <MultiSelectList
            label="Choose fields"
            options={textColumns}
            selectedIds={includeColumnIds}
            onChange={setIncludeColumnIds}
            searchPlaceholder="Search fields"
            emptyLabel={metaLoading ? 'Loading fields…' : 'No matching fields.'}
          />
          <SelectedChips label={`Selected: ${selectedFieldNames.length}`} items={selectedFieldNames} />
        </>
      )}

      <MultiSelectList
        label={`Only in groups (optional) · All groups (${groupOptions.length})`}
        options={groupOptions}
        selectedIds={includeGroupIds}
        onChange={setIncludeGroupIds}
        searchPlaceholder="Search groups"
        emptyLabel={metaLoading ? 'Loading groups…' : 'No matching groups.'}
      />
      <SelectedChips label={`Selected: ${selectedGroupNames.length}`} items={selectedGroupNames} />

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
        <div className={`notice ${metaWaiting ? 'notice--neutral' : 'notice--error'} surface-2`}>
          <div>{metaError}</div>
          {!metaWaiting && (
            <button className="btn btn-secondary" type="button" onClick={onRetryMeta}>
              Retry loading fields
            </button>
          )}
        </div>
      )}
    </section>
  );
};

export default WhereToLookCard;
