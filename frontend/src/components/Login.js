import React, { useState } from 'react';
import { createProject, setProjectToken } from '../services/api';

export default function Login({ onLogin }) {
  const [tokenInput, setTokenInput] = useState('');
  const [projectName, setProjectName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [mode, setMode] = useState('token'); // 'token' or 'create'
  
  const handleTokenSubmit = (e) => {
    e.preventDefault();
    if (!tokenInput.trim()) return;
    setProjectToken(tokenInput.trim());
    onLogin();
  };

  const handleCreateProject = async (e) => {
    e.preventDefault();
    if (!projectName.trim()) return;
    setLoading(true);
    setError('');
    try {
      const data = await createProject(projectName.trim(), 'Created via Dashboard');
      if (data.token) {
        setProjectToken(data.token);
        onLogin();
      } else {
        setError('Project created but no token received.');
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to create project');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-panel" style={{ maxWidth: '400px', margin: '100px auto', padding: '2rem' }}>
      <h2>{mode === 'token' ? 'Enter Project Token' : 'Create New Project'}</h2>
      
      {error && <div className="error-text" style={{ marginBottom: '1rem' }}>{error}</div>}
      
      {mode === 'token' ? (
        <form onSubmit={handleTokenSubmit}>
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem' }}>X-ECDAT-Token</label>
            <input 
              type="text" 
              value={tokenInput} 
              onChange={(e) => setTokenInput(e.target.value)}
              placeholder="ecdat_..."
              style={{ width: '100%', padding: '0.5rem', boxSizing: 'border-box' }}
              autoFocus
            />
          </div>
          <button type="submit" className="tab-btn active" style={{ width: '100%' }}>
            Access Dashboard
          </button>
          <div style={{ marginTop: '1rem', textAlign: 'center' }}>
            <button type="button" className="tab-btn" onClick={() => setMode('create')}>
              Or create a new project
            </button>
          </div>
        </form>
      ) : (
        <form onSubmit={handleCreateProject}>
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem' }}>Project Name</label>
            <input 
              type="text" 
              value={projectName} 
              onChange={(e) => setProjectName(e.target.value)}
              placeholder="My Project"
              style={{ width: '100%', padding: '0.5rem', boxSizing: 'border-box' }}
              autoFocus
            />
          </div>
          <button type="submit" className="tab-btn active" style={{ width: '100%' }} disabled={loading}>
            {loading ? 'Creating...' : 'Create Project'}
          </button>
          <div style={{ marginTop: '1rem', textAlign: 'center' }}>
            <button type="button" className="tab-btn" onClick={() => setMode('token')}>
              Or enter an existing token
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
