import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import BackgroundSystem from './BackgroundAnimation';

// Mount App normally
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);

// Mount background animation in a separate DOM node
// completely independent of App — zero risk of breaking anything
const bgContainer = document.createElement('div');
bgContainer.id = 'aipet-bg';
document.body.appendChild(bgContainer);
const bgRoot = ReactDOM.createRoot(bgContainer);
bgRoot.render(<BackgroundSystem />);
