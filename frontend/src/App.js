// frontend/src/App.js
//
// Top-level layout: a dark glassmorphism shell around the four dashboard
// views. The frontend never talks to MongoDB, FastAPI, or the LLM service
// directly — every component below routes through services/api.js and,
// through it, the authenticated Express gateway only.

import React, { useState, useEffect } from 'react';
import Dashboard from './components/Dashboard';
import CBOMGraph from './components/CBOMGraph';
import ScannerInput from './components/ScannerInput';
import MigrationPlanner from './components/MigrationPlanner';
import Login from './components/Login';
import { getProjectToken, clearProjectToken } from './services/api';
import './App.css';

const TABS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'graph', label: 'Asset Graph' },
  { id: 'scanner', label: 'Scanner' },
  { id: 'planner', label: 'Migration Planner' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    setIsAuthenticated(!!getProjectToken());
  }, []);

  const handleLogin = () => setIsAuthenticated(true);
  const handleLogout = () => {
    clearProjectToken();
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return (
      <div className="app-shell" style={{ display: 'flex', flexDirection: 'column', height: '100vh', justifyContent: 'center' }}>
        <header className="app-header glass-panel" style={{ position: 'absolute', top: 0, width: '100%' }}>
          <div className="brand">
            <span className="brand-mark">E</span>
            <div>
              <h1>ECDAT</h1>
              <p className="muted">Enterprise Cryptographic Discovery &amp; Analysis Tool</p>
            </div>
          </div>
        </header>
        <Login onLogin={handleLogin} />
      </div>
    );
  }

  return (
    <div className="app-shell">
      <header className="app-header glass-panel">
        <div className="brand">
          <span className="brand-mark">E</span>
          <div>
            <h1>ECDAT</h1>
            <p className="muted">Enterprise Cryptographic Discovery &amp; Analysis Tool</p>
          </div>
        </div>

        <nav className="tab-nav">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
          <button type="button" className="tab-btn" style={{ marginLeft: '1rem', borderLeft: '1px solid rgba(255,255,255,0.1)' }} onClick={handleLogout}>
            Change Project
          </button>
        </nav>
      </header>

      <main className="app-main">
        {activeTab === 'dashboard' && <Dashboard />}
        {activeTab === 'graph' && <CBOMGraph />}
        {activeTab === 'scanner' && <ScannerInput />}
        {activeTab === 'planner' && <MigrationPlanner />}
      </main>
    </div>
  );
}
