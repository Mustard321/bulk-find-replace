import React, { useMemo, useState } from 'react';

const MultiSelectList = ({ label, options, selectedIds, onChange, searchPlaceholder, emptyLabel }) => {
  const [search, setSearch] = useState('');
  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return options;
    return options.filter((option) => option.label.toLowerCase().includes(term));
  }, [options, search]);

  const toggle = (id) => {
    if (selectedIds.includes(id)) {
      onChange(selectedIds.filter((entry) => entry !== id));
    } else {
      onChange([...selectedIds, id]);
    }
  };

  return (
    <div className="multi-select">
      <label className="field">
        <span className="field__label">{label}</span>
        <input
          className="input"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={searchPlaceholder}
        />
      </label>
      <div className="multi-select__list nice-scroll">
        {filtered.map((option) => (
          <label className="toggle" key={option.id}>
            <input
              type="checkbox"
              checked={selectedIds.includes(option.id)}
              onChange={() => toggle(option.id)}
            />
            <span>{option.label}</span>
          </label>
        ))}
        {filtered.length === 0 && <div className="muted">{emptyLabel}</div>}
      </div>
    </div>
  );
};

export default MultiSelectList;
