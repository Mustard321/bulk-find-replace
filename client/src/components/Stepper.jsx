import React from 'react';

const Stepper = ({ currentStep, connected }) => {
  const steps = [
    { id: 1, label: 'Scope', status: connected ? 'Connected' : 'Waiting' },
    { id: 2, label: 'Find & replace' },
    { id: 3, label: 'Preview' },
    { id: 4, label: 'Apply' }
  ];

  return (
    <div className="stepper" role="list">
      {steps.map((step) => {
        const isActive = step.id === currentStep;
        const isComplete = step.id < currentStep;
        return (
          <div
            key={step.id}
            className={`stepper__step surface-2 ${isActive ? 'is-active' : ''} ${isComplete ? 'is-complete' : ''}`}
            role="listitem"
          >
            <div className="stepper__badge">{step.id}</div>
            <div className="stepper__meta">
              <div className="stepper__label">{step.label}</div>
              {step.id === 1 && (
                <span className={`pill ${connected ? 'pill-green' : ''}`}>
                  {step.status}
                </span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default Stepper;
