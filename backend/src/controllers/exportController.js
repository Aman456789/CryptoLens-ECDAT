'use strict';

const crypto = require('crypto');
const Asset = require('../models/Asset');

/**
 * backend/src/controllers/exportController.js
 *
 * GET /api/export/cyclonedx — maps this project's active Asset documents
 * into a schema-valid CycloneDX 1.6 Bill of Materials using the
 * `cryptographic-asset` component type (the OWASP CycloneDX CBOM
 * capability). Auth is identical authenticateProject middleware as every
 * other route — this endpoint carries no shortcut of its own.
 *
 * Mapping shape, per finding: TWO components, not one —
 *   1. An `algorithm` cryptographic-asset — the weak (or, for a validated
 *      fix, target) algorithm itself.
 *   2. A `related-crypto-material` cryptographic-asset — the actual key/
 *      digest/ciphertext material found at that location, linked back to
 *      (1) via cryptoProperties.relatedCryptoMaterialProperties.securedBy.
 *      algorithmRef.
 * This mirrors how CycloneDX's own CBOM examples model "an algorithm in
 * use" separately from "the key material secured by that algorithm" —
 * collapsing both into a single component would lose the securedBy
 * relationship entirely.
 *
 * ECDAT-specific fields that have no dedicated CycloneDX property
 * (riskTag, moscaScore, classicalRiskFlags, fixStatus, targetStandard,
 * contentHash) are carried in each component's standard `properties`
 * name/value array — the spec-compliant extension point for vendor data,
 * rather than inventing non-standard top-level fields.
 */

const CYCLONEDX_SPEC_VERSION = '1.6';
const ECDAT_PROPERTY_NAMESPACE = 'ecdat';

// --------------------------------------------------------------------
// Algorithm classification — free-text `algorithm` strings (e.g.
// "RSA-1024", "3DES", "ML-KEM-768") to CycloneDX's controlled
// cryptoProperties vocabulary. Not exhaustive; unrecognized algorithms
// fall back to a safe "unknown" shape rather than throwing, since this
// endpoint must never fail a whole export over one unclassifiable finding.
// --------------------------------------------------------------------

const ALGORITHM_FAMILIES = [
  { match: /RSA/i, primitive: 'pke', materialType: 'private-key', cryptoFunctions: ['keygen', 'encrypt', 'decrypt', 'sign', 'verify'] },
  { match: /ECC|ECDSA|ECDH/i, primitive: 'pke', materialType: 'private-key', cryptoFunctions: ['keygen', 'sign', 'verify', 'keyderive'] },
  { match: /ML-KEM|KYBER/i, primitive: 'kem', materialType: 'shared-secret', cryptoFunctions: ['keygen', 'encapsulate', 'decapsulate'] },
  { match: /ML-DSA|DILITHIUM/i, primitive: 'signature', materialType: 'private-key', cryptoFunctions: ['keygen', 'sign', 'verify'] },
  { match: /CHACHA20/i, primitive: 'ae', materialType: 'secret-key', cryptoFunctions: ['encrypt', 'decrypt'] },
  { match: /AES/i, primitive: 'block-cipher', materialType: 'secret-key', cryptoFunctions: ['encrypt', 'decrypt'] },
  { match: /BLOWFISH|3DES|DESEDE|\bDES\b|RC4/i, primitive: 'block-cipher', materialType: 'secret-key', cryptoFunctions: ['encrypt', 'decrypt'] },
  { match: /MD5|SHA-?1|SHA-?256|SHA-?384|SHA-?512|SHA-?3/i, primitive: 'hash', materialType: 'digest', cryptoFunctions: ['digest'] },
];

const UNKNOWN_FAMILY = { primitive: 'unknown', materialType: 'other', cryptoFunctions: [] };

function classifyAlgorithm(algorithmName) {
  const name = typeof algorithmName === 'string' ? algorithmName : '';
  return ALGORITHM_FAMILIES.find((family) => family.match.test(name)) || UNKNOWN_FAMILY;
}

/**
 * Best-effort numeric parameter size: prefer the asset's own `keySize`
 * field when present, otherwise fall back to any digit run embedded in
 * the algorithm string (e.g. "RSA-1024" -> 1024). Returns null rather
 * than a misleading 0 when nothing is found.
 */
function extractParameterSize(asset) {
  if (typeof asset.keySize === 'number' && Number.isFinite(asset.keySize)) {
    return asset.keySize;
  }
  const digitMatch = typeof asset.algorithm === 'string' ? asset.algorithm.match(/(\d{2,5})/) : null;
  return digitMatch ? Number(digitMatch[1]) : null;
}

function buildEcdatProperties(asset) {
  const props = [
    { name: `${ECDAT_PROPERTY_NAMESPACE}:contentHash`, value: asset.contentHash },
    { name: `${ECDAT_PROPERTY_NAMESPACE}:riskTag`, value: asset.riskTag || 'Unverified' },
    { name: `${ECDAT_PROPERTY_NAMESPACE}:fixStatus`, value: asset.fixStatus || 'none' },
  ];

  if (asset.moscaScore !== null && asset.moscaScore !== undefined) {
    props.push({ name: `${ECDAT_PROPERTY_NAMESPACE}:moscaScore`, value: String(asset.moscaScore) });
  }
  if (Array.isArray(asset.classicalRiskFlags) && asset.classicalRiskFlags.length > 0) {
    props.push({
      name: `${ECDAT_PROPERTY_NAMESPACE}:classicalRiskFlags`,
      value: asset.classicalRiskFlags.join(','),
    });
  }
  if (asset.targetStandard) {
    props.push({ name: `${ECDAT_PROPERTY_NAMESPACE}:targetStandard`, value: asset.targetStandard });
  }
  if (asset.fixValidation) {
    if (asset.fixValidation.sastPassed !== null && asset.fixValidation.sastPassed !== undefined) {
      props.push({ name: `${ECDAT_PROPERTY_NAMESPACE}:fixValidation.sastPassed`, value: String(asset.fixValidation.sastPassed) });
    }
    if (asset.fixValidation.katPassed !== null && asset.fixValidation.katPassed !== undefined) {
      props.push({ name: `${ECDAT_PROPERTY_NAMESPACE}:fixValidation.katPassed`, value: String(asset.fixValidation.katPassed) });
    }
  }

  return props;
}

/**
 * Maps one Asset document to its pair of CycloneDX cryptographic-asset
 * components: [algorithmComponent, relatedCryptoMaterialComponent].
 */
function assetToComponents(asset) {
  const family = classifyAlgorithm(asset.algorithm);
  const parameterSize = extractParameterSize(asset);

  const algoRef = `crypto-algo-${asset.contentHash}`;
  const materialRef = `crypto-material-${asset.contentHash}`;

  const occurrenceLocation = asset.filePath
    ? asset.line
      ? `${asset.filePath}:${asset.line}`
      : asset.filePath
    : undefined;

  const algorithmComponent = {
    type: 'cryptographic-asset',
    'bom-ref': algoRef,
    name: asset.algorithm || 'unknown',
    cryptoProperties: {
      assetType: 'algorithm',
      algorithmProperties: {
        primitive: family.primitive,
        ...(parameterSize ? { parameterSetIdentifier: String(parameterSize) } : {}),
        executionEnvironment: 'software-plain-ram',
        cryptoFunctions: family.cryptoFunctions,
      },
    },
    properties: buildEcdatProperties(asset),
    ...(occurrenceLocation
      ? { evidence: { occurrences: [{ location: occurrenceLocation }] } }
      : {}),
  };

  const relatedCryptoMaterialComponent = {
    type: 'cryptographic-asset',
    'bom-ref': materialRef,
    name: `${asset.algorithm || 'unknown'} material`,
    cryptoProperties: {
      assetType: 'related-crypto-material',
      relatedCryptoMaterialProperties: {
        type: family.materialType,
        id: asset.contentHash,
        state: asset.status === 'resolved' ? 'deactivated' : 'active',
        ...(parameterSize ? { size: parameterSize } : {}),
        securedBy: {
          mechanism: 'algorithm',
          algorithmRef: algoRef,
        },
      },
    },
    ...(occurrenceLocation
      ? { evidence: { occurrences: [{ location: occurrenceLocation }] } }
      : {}),
  };

  return [algorithmComponent, relatedCryptoMaterialComponent];
}

/**
 * GET /api/export/cyclonedx
 *
 * Zero active assets is a valid, successful export (an empty `components`
 * array), not an error condition — a clean project should still produce a
 * schema-valid, openable CBOM.
 */
async function toCycloneDx(req, res) {
  const projectId = req.projectId; // resolved by authenticateProject

  let assets;
  try {
    assets = await Asset.find({ projectId, status: 'active' }).lean();
  } catch (err) {
    console.error('[exportController] failed to load assets for CBOM export:', err.message);
    return res.status(500).json({ error: 'failed to build CycloneDX export' });
  }

  let components = [];
  try {
    components = assets.flatMap((asset) => assetToComponents(asset));
  } catch (err) {
    // A single malformed document should not break the whole export —
    // but if the mapping itself is broken, surface that clearly rather
    // than silently returning a partial/incorrect BOM.
    console.error('[exportController] failed to map assets to CycloneDX components:', err.message);
    return res.status(500).json({ error: 'failed to build CycloneDX export' });
  }

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: CYCLONEDX_SPEC_VERSION,
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      component: {
        type: 'application',
        'bom-ref': `project-${projectId}`,
        name: 'ECDAT-scanned-project',
      },
    },
    components,
  };

  return res.status(200).json(bom);
}

module.exports = { toCycloneDx };
