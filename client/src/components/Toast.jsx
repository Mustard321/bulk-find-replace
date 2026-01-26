import React from 'react';

const Toast = ({ message, onClose }) => (
  <div className="toast surface-2" role="status">
    <span>{message}</span>
    <button className="btn btn-secondary" type="button" onClick={onClose}>
      Dismiss
    </button>
  </div>
);

export default Toast;
