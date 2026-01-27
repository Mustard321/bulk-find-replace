import React, { useEffect, useMemo, useState } from 'react';
import DiffRow from './DiffRow';
import { formatNumber } from '../utils/formatters.jsx';

const PreviewPanel = ({
  preview,
  summary,
  previewLoading,
  searchInput,
  setSearchInput,
  showOnlyChanged,
  setShowOnlyChanged,
  compactView,
  setCompactView,
  filteredRows,
  find,
  hasNext,
  hasPrev,
  onNextPage,
  onPrevPage,
  pageIndex,
  warnings
}) => {
  const [expandedRows, setExpandedRows] = useState(new Set());
  const truncateLimit = compactView ? 140 : 240;

  useEffect(() => {
    setExpandedRows(new Set());
  }, [preview]);

  const summaryCards = useMemo(
    () => [
      { label: 'Items matched', value: formatNumber(summary.totalItems) },
      { label: 'Fields affected', value: formatNumber(preview.length) },
      { label: 'Estimated changes', value: formatNumber(summary.totalMatches) }
    ],
    [summary, preview]
  );

  const handleExpandToggle = (key) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  return (
    <section className="card surface">
      <div className="section-header">
        <h2>Step 4 · Preview</h2>
        <span className="pill pill-gold">Preview only</span>
      </div>
      <div className="summary-grid">
        {summaryCards.map((card) => (
          <div key={card.label} className="summary-card surface-2">
            <div className="summary-card__label">{card.label}</div>
            <div className="summary-card__value">{card.value}</div>
          </div>
        ))}
      </div>

      <div className="preview-toolbar">
        <label className="search-field">
          <span className="sr-only">Search preview</span>
          <input
            className="input"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search in preview"
          />
        </label>
        <label className="toggle">
          <input
            type="checkbox"
            checked={showOnlyChanged}
            onChange={(e) => setShowOnlyChanged(e.target.checked)}
          />
          <span>Show only changed</span>
        </label>
        <label className="toggle">
          <input
            type="checkbox"
            checked={compactView}
            onChange={(e) => setCompactView(e.target.checked)}
          />
          <span>Compact view</span>
        </label>
      </div>

      {warnings?.length > 0 && (
        <div className="notice notice--neutral surface-2">
          {warnings.map((warning) => (
            <div key={warning}>{warning}</div>
          ))}
        </div>
      )}

      {previewLoading && (
        <div className="skeleton-stack">
          {Array.from({ length: 4 }).map((_, idx) => (
            <div className="skeleton" key={`skeleton-${idx}`} />
          ))}
        </div>
      )}

      {!previewLoading && preview.length === 0 && (
        <div className="empty-state">
          <div className="empty-title">Run a preview to see changes.</div>
          <div className="muted">We only scan text and long text columns on the current board.</div>
        </div>
      )}

      {!previewLoading && preview.length > 0 && summary.totalMatches === 0 && (
        <div className="empty-state">
          <div className="empty-title">No matches found.</div>
          <div className="muted">Try case-insensitive matching or check your column scope.</div>
        </div>
      )}

      {!previewLoading && preview.length > 0 && filteredRows.length === 0 && summary.totalMatches > 0 && (
        <div className="empty-state">
          <div className="empty-title">No rows match these filters.</div>
          <div className="muted">Clear search or turn off “show only changed”.</div>
        </div>
      )}

      {!previewLoading && filteredRows.length > 0 && (
        <div className="diff-list nice-scroll">
          {filteredRows.map((row, index) => {
            const key = `${row.itemId}-${row.columnId}-${index}`;
            return (
              <DiffRow
                key={key}
                row={row}
                find={find}
                compact={compactView}
                expanded={expandedRows.has(key)}
                onToggleExpand={() => handleExpandToggle(key)}
                truncateLimit={truncateLimit}
              />
            );
          })}
        </div>
      )}

      {!previewLoading && (hasNext || hasPrev) && (
        <div className="pagination">
          <button className="btn btn-secondary" type="button" onClick={onPrevPage} disabled={!hasPrev}>
            Previous page
          </button>
          <div className="muted">Page {pageIndex}</div>
          <button className="btn btn-secondary" type="button" onClick={onNextPage} disabled={!hasNext}>
            Next page
          </button>
        </div>
      )}
    </section>
  );
};

export default PreviewPanel;
