// frontend/src/components/ScannerInput.js
//
// Manual network-scan trigger (Path B) plus the project's live token, so a
// user can wire up the GitHub Actions side (Path A) without leaving the
// dashboard. The token is never re-derivable from stored data once issued —
// this view only ever displays what's already in local storage.

import React, { useState } from 'react';
import { triggerNetworkScan, getProjectToken } from '../services/api';

export default function ScannerInput() {
  const [url, setUrl] = useState('');
  const [status, setStatus] = useState('idle'); // idle | loading | success | error
  const [message, setMessage] = useState('');
  const [copied, setCopied] = useState(false);
  const token = getProjectToken();

  async function handleSubmit(e) {
    e.preventDefault();
    if (!url.trim()) return;
    setStatus('loading');
    setMessage('');
    try {
      await triggerNetworkScan(url.trim());
      setStatus('success');
      setMessage('Scan queued — results will appear in the Asset Graph shortly.');
      setUrl('');
    } catch (err) {
      setStatus('error');
      setMessage(err.response?.data?.error || 'Could not start the scan. Check the URL and try again.');
    }
  }

  async function copyToken() {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  const tokenPreview = token
    ? `${token.slice(0, 14)}${'•'.repeat(10)}${token.slice(-4)}`
    : 'No token issued yet — create a project to receive one.';

  return (
    <div className="glass-panel scanner-input">
      <h3>Network Scanner</h3>
      <p className="muted">
        Submit a live endpoint to inspect its TLS/SSL certificate for weak or aging cryptography.
      </p>

      <form onSubmit={handleSubmit} className="scanner-form">
        <input
          type="url"
          required
          placeholder="https://example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          disabled={status === 'loading'}
        />
        <button type="submit" disabled={status === 'loading'}>
          {status === 'loading' ? 'Scanning…' : 'Scan Endpoint'}
        </button>
      </form>

      {message && <p className={status === 'error' ? 'error-text' : 'success-text'}>{message}</p>}

      <div className="token-block">
        <span className="token-label">Project token</span>
        <code className="token-value">{tokenPreview}</code>
        <button type="button" className="btn-ghost" onClick={copyToken} disabled={!token}>
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <p className="muted small">Add this as a GitHub Actions secret to enable the automated code-scan path.</p>
    </div>
  );
}
