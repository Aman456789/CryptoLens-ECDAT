const mongoose = require('mongoose');

/**
 * Project.js
 *
 * Stores project identity/configuration only. The raw API secret issued to
 * a client at project creation is NEVER persisted — only its hash is. The
 * secret itself lives solely with the client and is re-sent, per request,
 * as part of the X-ECDAT-Token header, where it is verified against
 * `tokenHash` (see authenticateProject.js).
 */
const ProjectSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Project name is required'],
      trim: true,
      maxlength: 200,
    },

    // Hash of the issued secret (bcrypt). The raw secret is shown to the
    // user exactly once at creation time and is unrecoverable from this
    // field by design.
    tokenHash: {
      type: String,
      required: [true, 'tokenHash is required'],
      select: false, // excluded from default query results
    },

    status: {
      type: String,
      enum: ['active', 'archived'],
      default: 'active',
    },

    // Domains this project's committed configuration is expected to talk
    // to (e.g. parsed from config.js / CORS or route definitions during a
    // code scan — never from .env, which is git-ignored and never reaches
    // the scanner). Used by scanController.js to decide whether a
    // manually-submitted network-scan URL can be confidently linked to
    // this project's code findings, or must be rendered as a disconnected
    // "Unlinked Asset" (Section 10 safeguard). An empty list is a valid,
    // explicit "nothing configured yet" state — it deliberately does NOT
    // mean "trust every domain"; see scanController.js for how that's
    // interpreted.
    expectedDomains: {
      type: [String],
      default: [],
    },

    createdAt: {
      type: Date,
      default: Date.now,
      immutable: true,
    },
  },
  {
    // disable Mongoose's default __v version key noise on a simple config doc
    versionKey: false,
    toJSON: {
      transform(doc, ret) {
        delete ret.tokenHash; // defense-in-depth: never serialize the hash either
        return ret;
      },
    },
  }
);

ProjectSchema.index({ status: 1 });

module.exports = mongoose.model('Project', ProjectSchema);
