import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import App from './App';
import Landing from './Landing';
import BackgroundSystem from './BackgroundAnimation';

function Root() {
  return (
    <BrowserRouter>
      <Routes>
        {/* World-class marketing landing page */}
        <Route path="/" element={<Landing />} />
        {/* Full dashboard app — handles its own auth, login, and sub-routes */}
        <Route path="/app/*" element={<App />} />
        {/* Any unknown path falls through to the app */}
        <Route path="/*" element={<App />} />
      </Routes>
    </BrowserRouter>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<Root />);

// Background animation — completely independent of routing
const bgContainer = document.createElement('div');
bgContainer.id = 'aipet-bg';
document.body.appendChild(bgContainer);
const bgRoot = ReactDOM.createRoot(bgContainer);
bgRoot.render(<BackgroundSystem />);
