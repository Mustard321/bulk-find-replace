import React from 'react';
import { highlightText } from '../utils/formatters.jsx';

const DiffRow = ({ row, find, compact, expanded, onToggleExpand, truncateLimit }) => {
  const beforeText = row.before || '—';
  const afterText = row.after || '—';
  const shouldTruncate = beforeText.length > truncateLimit || afterText.length > truncateLimit;
  const displayBefore = expanded || !shouldTruncate ? beforeText : `${beforeText.slice(0, truncateLimit)}…`;
  const displayAfter = expanded || !shouldTruncate ? afterText : `${afterText.slice(0, truncateLimit)}…`;

  return (
    <div className={`diff-row surface-2 ${compact ? 'is-compact' : ''}`}>
      <div className="diff-meta">
        <div className="diff-title">{row.itemName}</div>
        <div className="muted">{row.columnTitle}</div>
      </div>
      <div className="diff-values">
        <div className="diff-cell">
          <div className="diff-label">Before</div>
          <div className="diff-text">{highlightText(displayBefore, find)}</div>
        </div>
        <div className="diff-cell">
          <div className="diff-label">After</div>
          <div className="diff-text">{highlightText(displayAfter, find)}</div>
        </div>
      </div>
      {shouldTruncate && (
        <button className="btn btn-secondary diff-toggle" type="button" onClick={onToggleExpand}>
          {expanded ? 'Show less' : 'Show more'}
        </button>
      )}
    </div>
  );
};

export default DiffRow;
