import React from 'react';

export const formatNumber = (value) => {
  if (value === null || value === undefined) return '0';
  const safe = Number(value);
  if (Number.isNaN(safe)) return '0';
  return safe.toLocaleString();
};

export const highlightText = (text, term) => {
  const safeText = String(text || '');
  const safeTerm = String(term || '').trim();
  if (!safeTerm) return safeText;
  const parts = safeText.split(safeTerm);
  return parts.flatMap((part, index) => {
    if (index === parts.length - 1) return [part];
    return [
      part,
      <mark key={`${part}-${index}`} className="diff-highlight">
        {safeTerm}
      </mark>
    ];
  });
};
