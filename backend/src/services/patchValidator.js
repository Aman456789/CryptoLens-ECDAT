'use strict';

/**
 * patchValidator.js — The Double-Validation Gate (TRD v2.2 §3.6,
 * REQ-FUNC-14/15/16; Backend Schema v1.2 §4).
 *
 * An LLM is a fallible, non-deterministic dependency (REQ-AI-03). Nothing
 * this module produces may reach `fixStatus: 'generated'` on an Asset
 * document without independently re-verifying the candidate is both:
 *
 *   Step 1 (runSastOnPatch) — actually free of the original weak pattern
 *           (and free of anything else the same rule set flags — a
 *           hallucinated hardcoded IV or ECB-mode call is just as
 *           disqualifying as the original vulnerability surviving).
 *   Step 2 (runKatValidation) — cryptographically CORRECT, i.e. the
 *           candidate's output matches published NIST Known-Answer-Test
 *           vectors exactly. This is a correctness check, not a security-
 *           policy check: code can pass Step 1 (no bad patterns) while
 *           still being a broken, non-functional implementation.
 *
 * Design contract this file enforces (TRD, verbatim):
 *   - validateCandidate() must NEVER throw for an ordinary validation
 *     failure. A rejected candidate is a handled outcome (-> the caller
 *     writes fixStatus:'fix_pending'), not an error. It may only throw —
 *     or more precisely, reject its returned Promise — for a genuine
 *     infrastructure fault (e.g. the KAT fixture file failing to load,
 *     which is caught below and re-thrown loudly at *module load time*,
 *     not per-candidate, so it fails fast at process start rather than
 *     silently failing every candidate at request time).
 *   - Step 2 is only attempted if Step 1 passes (sequenced, not
 *     parallel) — a candidate already known to be unfit shouldn't spend a
 *     KAT execution cycle before being rejected either way.
 *
 * SECURITY NOTE: Step 2 executes LLM-generated code. This module never
 * `eval()`s or `vm.runInThisContext()`s a candidate inside this process —
 * it is written to a throwaway temp file and run as a short-lived `node`
 * child process with a hard wall-clock timeout, the same isolation
 * boundary Step 1 already uses for Semgrep. That bounds "infinite loop in
 * a bad candidate" and keeps a candidate's own crash inside its own
 * process, but it is NOT a full security sandbox (no seccomp/network-
 * namespace/filesystem isolation). Running this inside a locked-down,
 * network-disabled container (or a serverless sandbox with no egress) is
 * a deployment-hardening requirement this file assumes, not one it can
 * enforce from inside Node — flagging this explicitly rather than
 * implying execFile + a timeout is a complete answer to "run untrusted
 * code safely."
 *
 * INTEGRATION CONTRACT (cross-file — not enforced by this file alone):
 * runKatValidation() calls a candidate as `module.exports(vectorInput)`.
 * For this gate to ever pass, the prompt template in nvidiaLlmService.js
 * must instruct the model to emit its primary operation as a single
 * `module.exports` function taking one object argument and returning
 * `{ ciphertext, tag }` (AEAD standards) or `{ ciphertext, sharedSecret }`
 * (KEM standards) as hex strings. That prompt change is outside this
 * file's scope — documented here so it isn't silently assumed away.
 */

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');

const execFileAsync = promisify(execFile);

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------

const SEMGREP_RULES_PATH = process.env.SEMGREP_RULES_PATH || '/app/rules/custom-crypto-rules.yaml';
const SEMGREP_TIMEOUT_MS = Number(process.env.SEMGREP_TIMEOUT_MS) || 10_000;
const KAT_EXEC_TIMEOUT_MS = Number(process.env.KAT_EXEC_TIMEOUT_MS) || 5_000;

const KAT_VECTORS_PATH = process.env.KAT_VECTORS_PATH
  ? path.resolve(process.env.KAT_VECTORS_PATH)
  : path.join(__dirname, 'fixtures', 'nist-kat-vectors.json');

// KAT fixtures are loaded once at process start from a bundled, offline
// fixture file — never fetched at runtime, consistent with this project's
// air-gap posture (REQ-AI-02, REQ-AI-04). A missing/corrupt fixture file is
// a deployment configuration error, not a per-candidate failure, so it is
// intentionally allowed to throw here and crash the process at startup —
// loud and immediate, rather than every single candidate silently and
// mysteriously failing katPassed at request time with no obvious cause.
let KAT_VECTORS;
try {
  // eslint-disable-next-line import/no-dynamic-require, global-require
  KAT_VECTORS = require(KAT_VECTORS_PATH);
} catch (err) {
  throw new Error(
    `[patchValidator] FATAL: could not load NIST KAT vector fixture from ` +
      `"${KAT_VECTORS_PATH}" (set KAT_VECTORS_PATH to override). The ` +
      `Double-Validation Gate cannot run Step 2 without it. Original error: ${err.message}`
  );
}

// Standards this gate knows how to execute a KAT check for, grouped by the
// I/O shape of their vectors — see the module doc-comment's INTEGRATION
// CONTRACT for the exact candidate calling convention each shape implies.
const AEAD_STANDARDS = new Set(['AES-256-GCM', 'ChaCha20-Poly1305']);
const KEM_STANDARDS = new Set(['ML-KEM-768', 'ML-KEM-1024']);

// --------------------------------------------------------------------------
// Step 1 — SAST-on-Patch (re-run the exact same discovery rule set against
// the LLM's own candidate output)
// --------------------------------------------------------------------------

// Semgrep's own file-extension-based language detection means the temp
// file's extension has to actually match the candidate's language, or none
// of custom-crypto-rules.yaml's `languages:`-scoped rules will ever fire —
// producing a vacuous "0 findings" pass that verified nothing.
const LANGUAGE_EXTENSIONS = { javascript: 'js', typescript: 'ts', python: 'py', java: 'java' };

/**
 * validateCandidate() is not given an explicit `language` argument (see
 * its signature below) — this heuristic exists to fill that gap from the
 * candidate's own syntax. It is a best-effort fallback, not a substitute
 * for passing the original finding's known language through explicitly;
 * if the calling job ever has that value on hand, wiring it straight into
 * runSastOnPatch() instead of through this function is strictly more
 * reliable and should be preferred.
 *
 * @param {string} candidateCode
 * @returns {'javascript'|'python'|'java'|null} null when no language could
 *   be inferred with reasonable confidence.
 */
function detectLanguageFromCode(candidateCode) {
  if (typeof candidateCode !== 'string' || candidateCode.trim() === '') return null;

  if (/^\s*(import\s+\w+|from\s+\w+\s+import|def\s+\w+\s*\(|class\s+\w+\s*:)/m.test(candidateCode)) {
    return 'python';
  }
  if (/^\s*(public|private)\s+(static\s+)?(final\s+)?class\b/m.test(candidateCode)) {
    return 'java';
  }
  if (/\b(const|let|var|function|module\.exports|require\()\b/.test(candidateCode)) {
    return 'javascript';
  }
  return null;
}

/**
 * Step 1 of the gate. Writes the candidate to a throwaway temp file (Semgrep
 * operates on files, not in-memory strings), re-runs the exact same
 * cryptographic rule set used for original discovery against it, and
 * requires zero findings of any kind — which catches both the original
 * weak pattern surviving the "fix" and any new anti-pattern the model
 * introduced while generating it (hardcoded IV, static nonce, ECB mode).
 *
 * @param {string} candidateCode
 * @param {'javascript'|'typescript'|'python'|'java'|null} language
 * @returns {Promise<{ sastPassed: boolean, findings: Array<object>, reason?: string }>}
 *   Never rejects — an infrastructure fault (Semgrep missing, malformed
 *   output) is reported as `sastPassed: false` with a `reason`, not thrown,
 *   because losing the ability to run Step 1 is itself a reason to refuse
 *   to trust the candidate, not a reason to crash the job.
 */
async function runSastOnPatch(candidateCode, language) {
  const ext = LANGUAGE_EXTENSIONS[language] || 'txt';
  if (ext === 'txt') {
    // No rule in custom-crypto-rules.yaml is scoped to a `.txt` file, so
    // Semgrep will report zero findings no matter what the candidate
    // contains — an unearned pass, not a real one. Fail closed instead of
    // silently green-lighting an unscannable candidate.
    return { sastPassed: false, findings: [], reason: 'undetected_candidate_language' };
  }

  const tmpFile = path.join(os.tmpdir(), `ecdat-candidate-${Date.now()}-${process.pid}.${ext}`);

  try {
    await fs.writeFile(tmpFile, candidateCode, 'utf8');

    let stdout;
    try {
      ({ stdout } = await execFileAsync(
        'semgrep',
        ['--config', SEMGREP_RULES_PATH, '--json', '--quiet', tmpFile],
        { timeout: SEMGREP_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
      ));
    } catch (execErr) {
      // Semgrep's own CLI convention is to exit non-zero when it HAS
      // findings — that is the single most common outcome of this exact
      // check (a candidate that still contains the flagged pattern), not
      // an infrastructure failure. Node's execFile rejects on any non-zero
      // exit, but still attaches stdout/stderr to the error object, so a
      // "findings present" exit and a genuine crash are distinguished by
      // whether usable JSON came back at all — not by exit code alone.
      if (typeof execErr.stdout === 'string' && execErr.stdout.trim().length > 0) {
        stdout = execErr.stdout;
      } else {
        return {
          sastPassed: false,
          findings: [],
          reason: `semgrep_execution_failed: ${execErr.message}`,
        };
      }
    }

    let parsed;
    try {
      parsed = JSON.parse(stdout);
    } catch (parseErr) {
      return { sastPassed: false, findings: [], reason: `semgrep_output_unparseable: ${parseErr.message}` };
    }

    // Semgrep can exit non-zero AND still emit well-formed, parseable JSON
    // for a reason that has nothing to do with the candidate's content —
    // most importantly, an invalid/missing --config path produces exactly
    // this shape: `results: []` (nothing was ever actually scanned) plus a
    // populated `errors` array explaining why. Trusting `results.length
    // === 0` alone here would silently treat "the scan never ran" as "the
    // candidate is clean" — the single most dangerous possible failure
    // mode for a validation gate. Both `errors` being non-empty and
    // `paths.scanned` being empty are checked, since either alone is
    // already sufficient evidence that no real scan happened.
    const hadErrors = Array.isArray(parsed.errors) && parsed.errors.length > 0;
    const scannedNothing = Array.isArray(parsed.paths?.scanned) && parsed.paths.scanned.length === 0;
    if (hadErrors || scannedNothing) {
      const errorSummary = hadErrors
        ? parsed.errors.map((e) => e.message || e.type).join('; ')
        : 'no files were scanned';
      return { sastPassed: false, findings: [], reason: `semgrep_reported_errors: ${errorSummary}` };
    }

    const findings = Array.isArray(parsed.results) ? parsed.results : [];
    return { sastPassed: findings.length === 0, findings };
  } catch (err) {
    // Anything else unexpected (e.g. tmp file write failure) — same
    // fail-closed contract as above.
    return { sastPassed: false, findings: [], reason: `unexpected_error: ${err.message}` };
  } finally {
    // Best-effort cleanup — never let a cleanup failure mask the real
    // pass/fail result computed above, or throw out of this function.
    await fs.unlink(tmpFile).catch(() => {});
  }
}

// --------------------------------------------------------------------------
// Step 2 — NIST KAT vector validation
// --------------------------------------------------------------------------

/**
 * Normalizes a hex-ish string for comparison: strips an optional "0x"
 * prefix, strips whitespace, lowercases. KAT vector fixtures and candidate
 * output are both expected to be hex-encoded, but "which case / which
 * prefix convention" is exactly the kind of incidental formatting
 * difference that should never cause a cryptographically-correct
 * candidate to fail this gate.
 *
 * This is a correctness comparison against already-published, non-secret
 * known-answer values — not an authentication check against a live
 * secret — so `crypto.timingSafeEqual` buys nothing here; there is no
 * attacker on the other end of this comparison to time.
 */
function normalizeHex(value) {
  return String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/^0x/, '');
}

function katOutputsMatch(actual, vector, targetStandard) {
  if (!actual) return false;

  if (KEM_STANDARDS.has(targetStandard)) {
    return (
      normalizeHex(actual.ciphertext) === normalizeHex(vector.expectedCiphertext) &&
      normalizeHex(actual.sharedSecret) === normalizeHex(vector.expectedSharedSecret)
    );
  }

  // AEAD standards (AES-256-GCM / ChaCha20-Poly1305)
  return (
    normalizeHex(actual.ciphertext) === normalizeHex(vector.expectedCiphertext) &&
    normalizeHex(actual.tag) === normalizeHex(vector.expectedTag)
  );
}

/**
 * Executes a candidate's `module.exports` function against one KAT vector,
 * isolated in a short-lived `node` child process (see the module-level
 * SECURITY NOTE) rather than in this process. Only JavaScript candidates
 * are executable today — this is a documented scope limit, not a silent
 * gap: an unsupported language fails closed with a clear reason instead of
 * pretending to validate code it cannot actually run.
 *
 * @returns {Promise<object|null>} the candidate's returned object, or null
 *   if it could not be executed for any reason (timeout, crash, wrong
 *   language, malformed output). Never rejects.
 */
async function executeCandidateAgainstVector(candidateCode, vector, language) {
  if (language !== 'javascript') {
    return null;
  }

  const harnessFile = path.join(os.tmpdir(), `ecdat-kat-harness-${Date.now()}-${process.pid}.js`);

  // The harness wraps the candidate rather than requiring it as a separate
  // module, so the candidate never needs to be a resolvable/importable
  // package — it only needs to assign to `module.exports` once, which is
  // exactly what nvidiaLlmService.js's prompt must instruct the model to do.
  const harnessSource = [
    '"use strict";',
    candidateCode,
    '',
    '(async () => {',
    '  try {',
    '    const vectorInput = JSON.parse(process.argv[2]);',
    '    if (typeof module.exports !== "function") {',
    '      throw new Error("candidate does not export a callable function");',
    '    }',
    '    const result = await module.exports(vectorInput);',
    '    process.stdout.write(JSON.stringify(result ?? {}));',
    '    process.exit(0);',
    '  } catch (err) {',
    '    process.stderr.write(String((err && err.stack) || err));',
    '    process.exit(1);',
    '  }',
    '})();',
  ].join('\n');

  try {
    await fs.writeFile(harnessFile, harnessSource, 'utf8');

    const { stdout } = await execFileAsync('node', [harnessFile, JSON.stringify(vector)], {
      timeout: KAT_EXEC_TIMEOUT_MS,
      maxBuffer: 1024 * 1024,
    });

    try {
      return JSON.parse(stdout);
    } catch {
      return null; // candidate ran but didn't emit valid JSON — treat as a failed vector, not a crash
    }
  } catch {
    // Covers: candidate threw, candidate hung past KAT_EXEC_TIMEOUT_MS
    // (execFile kills the process and rejects), or any other execution
    // fault. All of these mean "this vector did not pass" — never thrown
    // further up.
    return null;
  } finally {
    await fs.unlink(harnessFile).catch(() => {});
  }
}

/**
 * Step 2 of the gate. Runs the candidate against every published KAT
 * vector for its target standard and requires an exact match on all of
 * them — a single mismatch fails the whole gate for this candidate.
 *
 * @param {string} candidateCode
 * @param {string} targetStandard  One of Asset.targetStandard's enum values.
 * @param {'javascript'|'python'|'java'|null} language
 * @returns {Promise<{ katPassed: boolean, reason?: string }>} Never rejects.
 */
async function runKatValidation(candidateCode, targetStandard, language) {
  const vectors = KAT_VECTORS[targetStandard];

  if (!Array.isArray(vectors) || vectors.length === 0) {
    // No fixture for this standard is a configuration gap, not a candidate
    // failure — fail closed rather than silently skipping validation and
    // letting an un-validated candidate through as "generated".
    return { katPassed: false, reason: 'no_kat_fixture_for_standard' };
  }

  for (const vector of vectors) {
    const actual = await executeCandidateAgainstVector(candidateCode, vector, language);

    if (actual === null) {
      return { katPassed: false, reason: 'candidate_execution_failed_or_unsupported_language' };
    }
    if (!katOutputsMatch(actual, vector, targetStandard)) {
      return { katPassed: false, reason: 'kat_output_mismatch' };
    }
  }

  return { katPassed: true };
}

// --------------------------------------------------------------------------
// The combined gate
// --------------------------------------------------------------------------

/**
 * @param {string} candidateCode   The LLM's generated replacement code.
 * @param {string} algorithm       The original finding's algorithm string
 *                                  (e.g. "RSA-1024") — used only for logging
 *                                  context here; it does not influence the
 *                                  pass/fail outcome of either step.
 * @param {string} targetStandard  Asset.targetStandard — selects which KAT
 *                                  vector set Step 2 validates against.
 * @returns {Promise<{ sastPassed: boolean, katPassed: boolean }>}
 *   Guaranteed to resolve, never reject, under any input — including a
 *   missing/empty candidateCode, an unrecognized targetStandard, or an
 *   internal error in either step. The caller (verificationQueue.js) is
 *   contractually free to treat any non-`{true,true}` result identically
 *   (-> fixStatus:'fix_pending') without needing a try/catch of its own
 *   around this call.
 */
async function validateCandidate(candidateCode, algorithm, targetStandard) {
  try {
    if (typeof candidateCode !== 'string' || candidateCode.trim() === '') {
      return { sastPassed: false, katPassed: false };
    }

    const language = detectLanguageFromCode(candidateCode);

    const step1 = await runSastOnPatch(candidateCode, language);
    if (!step1.sastPassed) {
      console.warn(
        `[patchValidator] Step 1 (SAST) rejected candidate for algorithm=${algorithm} ` +
          `targetStandard=${targetStandard}: ${step1.reason || `${step1.findings.length} finding(s)`}`
      );
      // Step 2 is intentionally never reached here — a candidate already
      // known to be unfit shouldn't spend a KAT execution cycle on top of
      // the SAST cycle it already failed.
      return { sastPassed: false, katPassed: false };
    }

    if (!KEM_STANDARDS.has(targetStandard) && !AEAD_STANDARDS.has(targetStandard)) {
      console.warn(`[patchValidator] unrecognized targetStandard "${targetStandard}" — failing closed`);
      return { sastPassed: true, katPassed: false };
    }

    const step2 = await runKatValidation(candidateCode, targetStandard, language);
    if (!step2.katPassed) {
      console.warn(
        `[patchValidator] Step 2 (KAT) rejected candidate for algorithm=${algorithm} ` +
          `targetStandard=${targetStandard}: ${step2.reason}`
      );
    }

    return { sastPassed: true, katPassed: step2.katPassed };
  } catch (err) {
    // Final safety net. Every code path above already catches its own
    // failures and returns a result object rather than throwing — this
    // only fires on a truly unanticipated bug in this file itself, and
    // even then resolves to a fail-closed result instead of propagating a
    // rejection into the BullMQ job (which would trigger a full job retry
    // for what is, from the gate's perspective, still just "this candidate
    // did not pass").
    console.error(`[patchValidator] validateCandidate() unexpected internal error:`, err);
    return { sastPassed: false, katPassed: false };
  }
}

module.exports = {
  validateCandidate,
  // exported for unit testing (TRD v2.2 REQ-FUNC-15's four required test
  // cases exercise these individually) — not intended as a public API for
  // other services to call directly instead of validateCandidate().
  runSastOnPatch,
  runKatValidation,
  detectLanguageFromCode,
};
