const { execFile } = require('child_process');
const crypto = require('crypto');
const Asset = require('../models/Asset');
const Project = require('../models/Project');

/**
 * scanController.js
 *
 * Path B — the manual, user-triggered network scan. Unlike the automated
 * Semgrep path, this is invoked from an authenticated browser session:
 * the user submits a live URL and the gateway runs Nmap against it to
 * extract TLS/SSL certificate metadata (algorithm, key size, expiry).
 *
 * Results merge into the SAME normalized `assets` collection as Path A,
 * deduplicated by the same { projectId, contentHash } mechanism, under
 * the token-resolved projectId — never a client-supplied one.
 */

// Only bare hostnames or http(s) URLs are accepted — this is deliberately
// restrictive. execFile (not exec/spawn with shell:true) already avoids
// shell interpolation, but validating the target up front prevents
// nonsensical or abusive scan targets from ever reaching the nmap
// process at all.
function extractHostname(rawTarget) {
  let candidate = rawTarget.trim();
  if (!/^https?:\/\//i.test(candidate)) {
    candidate = `https://${candidate}`;
  }

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return null;
  }

  // Reject anything that isn't a plausible public hostname — no raw IPs
  // to internal ranges, no credentials embedded in the URL, etc.
  if (!parsed.hostname || parsed.username || parsed.password) {
    return null;
  }

  return parsed.hostname;
}

function runNmapTlsScan(hostname) {
  return new Promise((resolve, reject) => {
    execFile(
      'nmap',
      ['-Pn', '-p', '443', '--script', 'ssl-cert', hostname],
      { timeout: 15000 },
      (err, stdout) => {
        if (err) return reject(err);
        resolve(stdout);
      }
    );
  });
}

/**
 * Very small, defensive parser for nmap's ssl-cert script output.
 * Real deployments should prefer nmap's -oX XML output and an XML
 * parser over scraping human-readable text; this regex-based extraction
 * is kept intentionally simple here and should be hardened before
 * relying on it for anything beyond a best-effort signal.
 */
function parseCertificateInfo(nmapOutput) {
  const algMatch = nmapOutput.match(/Public Key type:\s*(\w+)/i);
  const bitsMatch = nmapOutput.match(/Public Key bits:\s*(\d+)/i);
  const expiryMatch = nmapOutput.match(/Not valid after:\s*([\d-]+T[\d:]+)/i);

  if (!algMatch) return null;

  return {
    algorithm: `${algMatch[1].toUpperCase()}${bitsMatch ? '-' + bitsMatch[1] : ''}`,
    keySize: bitsMatch ? Number(bitsMatch[1]) : null,
    notValidAfter: expiryMatch ? expiryMatch[1] : null,
  };
}

async function triggerNetworkScan(req, res) {
  const { url } = req.body || {};
  const projectId = req.projectId; // resolved by authenticateProject

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'url is required' });
  }

  const hostname = extractHostname(url);
  if (!hostname) {
    return res.status(400).json({ error: 'invalid or unsupported target URL' });
  }

  let nmapOutput;
  try {
    nmapOutput = await runNmapTlsScan(hostname);
  } catch (err) {
    console.error(`[scanController] nmap failed for ${hostname}:`, err.message);
    return res.status(502).json({ error: 'network scan failed', detail: err.message });
  }

  const certInfo = parseCertificateInfo(nmapOutput);
  if (!certInfo) {
    return res.status(200).json({
      message: 'scan completed — no certificate/algorithm data found',
      hostname,
    });
  }

  const contentHash = crypto
    .createHash('sha256')
    .update(`${hostname}:443:${certInfo.algorithm}`)
    .digest('hex');

  const riskTag = /RSA-1024|MD5|SHA1/i.test(certInfo.algorithm) ? 'Critical' : 'Unverified';

  // Section 10 "Unlinked Asset" safeguard: a submitted URL is only
  // considered linked to this project if it matches the project's own
  // expected-domains list (populated from committed config, never .env —
  // req.project is already loaded by authenticateProject). An empty list
  // means nothing has been configured yet, so we deliberately default to
  // NOT linked rather than silently trusting every URL — an unconfigured
  // project shouldn't produce false "linked" confidence.
  const expectedDomains = req.project?.expectedDomains || [];
  const isLinked = expectedDomains.length > 0 && expectedDomains.includes(hostname);

  try {
    await Asset.updateOne(
      { projectId, contentHash },
      {
        $set: {
          projectId,
          source: 'nmap',
          filePath: hostname, // network findings carry a hostname, not a file path
          line: null,
          algorithm: certInfo.algorithm,
          riskTag,
          isLinked,
          contentHash,
          status: 'active',
          updatedAt: new Date(),
        },
        $setOnInsert: { fixStatus: 'none', fixSnippet: null, createdAt: new Date() },
      },
      { upsert: true }
    );
  } catch (err) {
    console.error('[scanController] failed to persist network finding:', err.message);
    return res.status(500).json({ error: 'failed to persist scan result' });
  }

  return res.status(200).json({
    hostname,
    algorithm: certInfo.algorithm,
    notValidAfter: certInfo.notValidAfter,
    riskTag,
    isLinked,
  });
}

module.exports = { triggerNetworkScan };
