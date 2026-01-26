import React from 'react';

const TopBar = ({ onHelp }) => (
  <header className="topbar surface">
    <div className="topbar__brand">
      <div className="wordmark">mustard</div>
      <div className="topbar__subtitle">Bulk Find &amp; Replace</div>
    </div>
    <button className="btn btn-secondary" type="button" onClick={onHelp}>
      What this does
    </button>
  </header>
);

export default TopBar;
