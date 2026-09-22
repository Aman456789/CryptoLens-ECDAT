'use strict';

// Q — industry Q-Day estimate, expressed as a calendar year so it's easy
// for someone to bump this constant as estimates shift, rather than a
// raw duration that quietly goes stale every year it isn't touched.
const QUANTUM_ARRIVAL_YEAR = Number(process.env.QUANTUM_ARRIVAL_YEAR) || 2030;

// D — data shelf life, in years, by data sensitivity context.
const DATA_SHELF_LIFE_YEARS = {
  session: 0.01,      // ~3-4 days
  transactional: 3,
  financial: 7,
  medical: 50,
  government: 75,
  default: 10,
};

// T — migration time model: a fixed baseline plus a per-instance
// remediation cost, since more occurrences of the same weak algorithm
// mean more call sites to touch, review, and redeploy.
const BASE_MIGRATION_MONTHS = 3;
const MONTHS_PER_VULNERABLE_INSTANCE = 0.05;

// Some algorithms are more entrenched (e.g. embedded in certs/hardware)
// than others (e.g. a config flag) and take proportionally longer to swap.
const ALGORITHM_COMPLEXITY_MULTIPLIER = {
  RSA: 1.2,
  ECC: 1.2,
  DH: 1.1,
  default: 1.0,
};

function estimateDataShelfLife(dataContext) {
  return DATA_SHELF_LIFE_YEARS[dataContext] ?? DATA_SHELF_LIFE_YEARS.default;
}

function estimateMigrationTime(algorithm, vulnerableInstanceCount = 1) {
  const family = Object.keys(ALGORITHM_COMPLEXITY_MULTIPLIER).find((key) =>
    algorithm?.toUpperCase().includes(key)
  );
  const multiplier = ALGORITHM_COMPLEXITY_MULTIPLIER[family] ?? ALGORITHM_COMPLEXITY_MULTIPLIER.default;

  const months = (BASE_MIGRATION_MONTHS + vulnerableInstanceCount * MONTHS_PER_VULNERABLE_INSTANCE) * multiplier;
  return months / 12;
}

/**
 * @param {{ algorithm: string, dataContext?: string, vulnerableInstanceCount?: number }} asset
 * @returns {{ riskTag: 'Critical'|'Low', moscaScore: number, dataShelfLifeYears: number, migrationTimeYears: number, quantumArrivalYear: number }}
 */
function calculateMoscaRisk({ algorithm, dataContext, vulnerableInstanceCount = 1 }) {
  const D = estimateDataShelfLife(dataContext);
  const T = estimateMigrationTime(algorithm, vulnerableInstanceCount);

  // Q as a duration remaining from today, so it's dimensionally
  // comparable to D and T (both already expressed in years).
  const Q = QUANTUM_ARRIVAL_YEAR - new Date().getFullYear();

  const riskTag = D + T > Q ? 'Critical' : 'Low';
  const round = (n) => Math.round(n * 100) / 100;

  return {
    riskTag,
    moscaScore: round(D + T),
    dataShelfLifeYears: round(D),
    migrationTimeYears: round(T),
    quantumArrivalYear: QUANTUM_ARRIVAL_YEAR,
  };
}

module.exports = { calculateMoscaRisk };
