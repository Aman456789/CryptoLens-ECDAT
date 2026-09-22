'use strict';

const CircuitBreaker = require('opossum');
const axios = require('axios');

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || 'http://ai-service:8000';
const NVIDIA_API_URL = process.env.NVIDIA_API_URL || 'https://integrate.api.nvidia.com/v1/chat/completions';
const NVIDIA_API_KEY = process.env.NVIDIA_API_KEY;

// timeout here matches breaker.timeout below so opossum's clock and the
// underlying HTTP request's clock trip at (roughly) the same instant
const REQUEST_TIMEOUT_MS = 3000;

async function callFastApi(snippet) {
  const { data } = await axios.post(
    `${AI_SERVICE_URL}/verify`,
    { snippet },
    { timeout: REQUEST_TIMEOUT_MS }
  );
  return data; // { verdict: 0|1, truncated: boolean }
}

async function callNvidiaApi(prompt) {
  const { data } = await axios.post(
    NVIDIA_API_URL,
    { model: 'nvidia/pqc-code-gen', messages: [{ role: 'user', content: prompt }] },
    { headers: { Authorization: `Bearer ${NVIDIA_API_KEY}` }, timeout: REQUEST_TIMEOUT_MS }
  );
  return data;
}

const BREAKER_OPTIONS = {
  timeout: REQUEST_TIMEOUT_MS,
  errorThresholdPercentage: 50,
  resetTimeout: 15000,
};

function makeBreaker(fn, name) {
  const breaker = new CircuitBreaker(fn, BREAKER_OPTIONS);

  // last line of defense — callers get a degraded object back, never a
  // rejected promise, however the underlying dependency is failing
  breaker.fallback(() => ({ status: 'degraded', reason: `${name}_unavailable` }));

  breaker.on('open', () => console.error(`[CIRCUIT OPEN] ${name} — failing fast`));
  breaker.on('halfOpen', () => console.warn(`[CIRCUIT HALF-OPEN] ${name} — trial call in flight`));
  breaker.on('close', () => console.info(`[CIRCUIT CLOSED] ${name} — recovered`));

  return breaker;
}

const fastApiBreaker = makeBreaker(callFastApi, 'distilroberta-filter');
const nvidiaBreaker = makeBreaker(callNvidiaApi, 'nvidia-llm');

module.exports = { fastApiBreaker, nvidiaBreaker };
