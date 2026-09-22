'use strict';

const mongoose = require('mongoose');

/**
 * backend/src/models/Asset.js
 *
 * One document per finding — never an embedded array. MongoDB caps any
 * single document at 16MB; a per-project array of findings (code_assets,
 * network_assets, etc.) hits that ceiling on any real monorepo scan and
 * fails outright rather than gracefully. Full normalization removes the
 * ceiling entirely instead of just deferring it to a larger number.
 *
 * The unique compound index on { projectId, contentHash } is what makes
 * ingestion idempotent: re-scanning an unchanged commit resolves to an
 * update, never a duplicate insert.
 *
 * v3.0 additions (Dual-Risk Engine + Double-Validation Gate):
 *   - targetStandard        which NIST PQC / symmetric standard a
 *                            generated fix targets. Consumed by
 *                            patchValidator.js to select the right KAT
 *                            vector set, and by exportController.js's
 *                            CycloneDX mapping.
 *   - classicalRiskFlags    output of services/classicalTriageEngine.js.
 *                            Deliberately independent of riskTag/
 *                            moscaScore — see that module's own header
 *                            comment for why the two risk models are
 *                            never blended.
 *   - fixValidation         output of services/patchValidator.js's
 *                            Double-Validation Gate. A fix only reaches
 *                            fixStatus:'generated' once both checks are
 *                            recorded here.
 */
const AssetSchema = new mongoose.Schema(
  {
    projectId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Project',
      required: true,
      index: true,
    },

    source: {
      type: String,
      enum: ['semgrep', 'nmap'],
      required: true,
    },

    // --- location -------------------------------------------------------
    filePath: {
      type: String,
      default: null, // null for network-scan (nmap) findings; hostname for nmap
    },
    line: {
      type: Number,
      default: null,
    },
    column: {
      type: Number,
      default: null, // Semgrep's exact match column — null for nmap findings
    },

    // --- source context (code-scan findings only) ------------------------
    // Persisted so a later "regenerate fix" request (see
    // dashboardController.js regenerateFix) can rebuild the same
    // verification job without needing the original scan payload again.
    code: {
      type: String,
      default: null,
    },
    language: {
      type: String,
      default: null,
    },
    keySize: {
      type: Number,
      default: null,
    },

    // --- finding ----------------------------------------------------------
    algorithm: {
      type: String,
      required: true,
      trim: true, // e.g. "RSA-1024", "MD5"
    },
    riskTag: {
      type: String,
      enum: ['Critical', 'Low', 'Unverified'],
      default: 'Unverified',
    },

    // --- Mosca's Algorithm output (D + T > Q) — see services/moscaAlgorithm.js
    moscaScore: {
      type: Number,
      default: null, // D + T, in years; compared against Q at scoring time
    },
    dataShelfLifeYears: {
      type: Number,
      default: null,
    },
    migrationTimeYears: {
      type: Number,
      default: null,
    },

    // --- v3.0: classical (non-quantum) risk triage -------------------------
    // Output of services/classicalTriageEngine.js. NEVER read or written
    // by moscaAlgorithm.js / verificationQueue.js's Mosca-scoring branch —
    // the two risk models are computed and stored independently on
    // purpose (see classicalTriageEngine.js's header comment). `null` is
    // not a valid element here; an asset with no classical risk simply
    // has an empty array, not an array containing null.
    classicalRiskFlags: {
      type: [{ type: String, enum: ['SWEET32', 'WEAK_HASH'] }],
      default: [],
    },

    // --- remediation ----------------------------------------------------------
    fixStatus: {
      type: String,
      enum: ['none', 'generated', 'fix_pending'],
      default: 'none',
    },
    fixSnippet: {
      type: String,
      default: null,
    },

    // --- v3.0: remediation target + validation -----------------------------
    // Which standard a generated (or in-flight) fix targets. `null` means
    // no fix has been requested yet, or the finding predates v3.0 and has
    // not been re-run — explicitly whitelisted in the enum below, since
    // Mongoose's built-in enum validator otherwise rejects `null` even
    // when it's the schema's own default.
    targetStandard: {
      type: String,
      enum: ['ML-KEM-768', 'ML-KEM-1024', 'AES-256-GCM', 'ChaCha20-Poly1305', null],
      default: null,
    },

    // Output of services/patchValidator.js's Double-Validation Gate.
    // sastPassed/katPassed are nullable booleans (not a boolean defaulting
    // to false) so "never validated yet" is distinguishable from "ran the
    // gate and it failed" — collapsing those two states to `false` would
    // make it impossible to tell a genuinely rejected candidate apart from
    // a finding that never had a fix attempt at all.
    fixValidation: {
      type: new mongoose.Schema(
        {
          sastPassed: { type: Boolean, default: null },
          katPassed: { type: Boolean, default: null },
          validatedAt: { type: Date, default: null },
        },
        { _id: false }
      ),
      default: () => ({ sastPassed: null, katPassed: null, validatedAt: null }),
    },

    // --- cross-linking (Section 10 "Unlinked Asset" safeguard) --------------
    // true for every code-scan (semgrep) finding. For network-scan (nmap)
    // findings, true only when the submitted hostname matched the project's
    // known expected-domains list — see scanController.js.
    isLinked: {
      type: Boolean,
      default: true,
    },

    // --- idempotency key ----------------------------------------------------
    contentHash: {
      type: String,
      required: [true, 'contentHash is required for idempotent upserts'],
    },

    // --- lifecycle ----------------------------------------------------------
    status: {
      type: String,
      enum: ['active', 'resolved'],
      default: 'active',
      index: true,
    },
    resolvedAt: {
      type: Date,
      default: null,
    },

    createdAt: {
      type: Date,
      default: Date.now,
      immutable: true,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    versionKey: false,
  }
);

// CRITICAL: this is the index that makes bulk upserts idempotent — one
// finding per (project, contentHash), enforced by MongoDB itself, not by
// application-level pre-checks. Unchanged from v2.0.
AssetSchema.index({ projectId: 1, contentHash: 1 }, { unique: true });

// secondary indexes for dashboard query patterns
AssetSchema.index({ projectId: 1, riskTag: 1 });
AssetSchema.index({ projectId: 1, status: 1 });

AssetSchema.pre('save', function setUpdatedAt(next) {
  this.updatedAt = new Date();
  next();
});

module.exports = mongoose.model('Asset', AssetSchema);