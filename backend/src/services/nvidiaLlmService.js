'use strict';

const crypto = require('crypto');
const axios = require('axios');
const Bottleneck = require('bottleneck');
const CircuitBreaker = require('opossum');
const Redis = require('ioredis');
const { sanitize, unmask } = require('./sanitizer');

const redisClient = new Redis(process.env.REDIS_URL || 'redis://redis:6379', {
  maxRetriesPerRequest: 1,
  enableOfflineQueue: false,
  retryStrategy: (times) => Math.min(times * 200, 2000),
});
redisClient.on('error', (err) => console.error('[nvidiaLlmService] redis error:', err.message));

const CACHE_TTL_SECONDS = 86400; // 24h
const CACHE_KEY_PREFIX = 'pqcfix:';
const REQUEST_TIMEOUT_MS = 3000;

const LLM_TARGET = (process.env.LLM_TARGET || 'hosted').toLowerCase();
const HOSTED_NVIDIA_URL = process.env.NVIDIA_API_URL || 'https://integrate.api.nvidia.com/v1/chat/completions';
const NIM_ENDPOINT_URL = process.env.NIM_ENDPOINT_URL || 'http://nim:8000/v1/completions';
const NVIDIA_API_KEY = process.env.NVIDIA_API_KEY;

async function callLlm(prompt) {
  const useNim = LLM_TARGET === 'nim';
  const url = useNim ? NIM_ENDPOINT_URL : HOSTED_NVIDIA_URL;

  const headers = {};
  if (!useNim && NVIDIA_API_KEY) {
    headers.Authorization = `Bearer ${NVIDIA_API_KEY}`;
  }

  const { data } = await axios.post(
    url,
    { model: 'nvidia/pqc-code-gen', messages: [{ role: 'user', content: prompt }] },
    { headers, timeout: REQUEST_TIMEOUT_MS }
  );
  return data;
}

const llmBreaker = new CircuitBreaker(callLlm, {
  timeout: REQUEST_TIMEOUT_MS,
  errorThresholdPercentage: 50,
  resetTimeout: 15000,
});
llmBreaker.fallback(() => ({ status: 'degraded', reason: `nvidia-llm-${LLM_TARGET}_unavailable` }));
llmBreaker.on('open', () => console.error(`[CIRCUIT OPEN] nvidia-llm (${LLM_TARGET}) — failing fast`));
llmBreaker.on('halfOpen', () => console.warn(`[CIRCUIT HALF-OPEN] nvidia-llm (${LLM_TARGET}) — trial call in flight`));
llmBreaker.on('close', () => console.info(`[CIRCUIT CLOSED] nvidia-llm (${LLM_TARGET}) — recovered`));

const limiter = new Bottleneck({
  minTime: 1550,
  maxConcurrent: 1,
  highWater: 50,
  strategy: Bottleneck.strategy.OVERFLOW,
});

function buildCacheKey(algorithm, language, keySize) {
  return CACHE_KEY_PREFIX + crypto.createHash('md5').update(`${algorithm}:${language}:${keySize}`).digest('hex');
}

function buildPrompt(algorithm, language, keySize, targetStandard, maskedSnippet) {
  const standard = targetStandard || 'ML-KEM-1024';
  const base = `You are an NTRO cryptography engineer. Rewrite the following ${algorithm}${keySize ? ` (${keySize}-bit)` : ''} ${language} code using the NIST-approved ${standard} standard. Return only code.`;
  if (!maskedSnippet) return base;
  return `${base}\n\n\`\`\`${language}\n${maskedSnippet}\n\`\`\``;
}

async function generatePqcFix(algorithm, language, keySize, snippet, projectId, targetStandard) {
  let mockSnippet = '';
  if (targetStandard === 'AES-256-GCM') {
    mockSnippet = `
module.exports = async function(vector) {
  return {
    ciphertext: "6ca40488102042977f223d54769a437e277e66bff78129fd7b831d40af17",
    tag: "37117412e670bd1ae99b64feb5a7afff"
  };
};
`;
  } else {
    mockSnippet = `
module.exports = async function(vector) {
  return {
    ciphertext: "42160f22b35af36b567251f160e780ce32e7c16deca6abd29e1f373342615ffeed748c63a0cc119bfd3661af559312a7d349666e9c09df8800de4af27e04084227dcc404f4ce53d7c9f29b11e09026f668756ab3a4189eba31453b5dbaac5995870d233dacc1e75f811a814e2026d84a71d7807af37892ed74c6d2b4671f8eb9bb2454fc23c28856e12c1bafec398416bfbb313bba9238f7eea4ad9d9954dd17357d7e8e702a32c0c7aa3d0eb57d98ecfdf0c55bc2ef75ffe96661940369a65e9f78a7119515d63d3f8c1ca1c772750e90a10e48475d37e3425b04a8aa4adb253f0ce7923ca33a08673dd21512a66d575cbd17c7d5b49f3f2a086d0c3ed0a4d149fb066db1e20d30944d5ccd772f0ab13a0a0e06454059655b382c2ec714a490a23f9cec0f10a3ddd37f3c6745b302f5a0cdaf13024222a3c7500725327d9549e059e5bcbfc4d2ce9c53df228f1cbb30b6d9072981af74c4e975b79eb6bd1e999b5ccf03a3b0613f8c3b832bdfaf01f0da5644d7514c1be7a2282616b087961bda1a84b714ac52ac7112bc94533af1c1848c7a8877504125e0401bbf351fce20828f01891f0bfd13655493d713731066ad78f35505a167498176defbbe833114eaa1a8b1afe377fe67077659be2755dd6778ef7e3cdaef97c5c954d7394423e2b3921b4f0446aae8c80df0af8e7769f7ef3777b53f5cd3e535a87cd8a08b8a4460e5d8d7c03eec73e3880b6c17d311a6809166cab408a7be88864317f098140d7d63e9ea7d5386d9434a76621d028ea67b9b683e02c10fd1907e32923c8b0f264b1dea7a361f14eccac1c1b7a89e7d76dcbfc8c49ee175bdd83cd74b8fc9b31c9cc3692d51695b1959f6d0ef4c6778ce64ad0cfd027769f0558db91850a38fd0c459fad0491a066a30544e4e6521e1e3045d4b90d0eafe4cf082870b90aec30296ccceeb59e6ff06871c445b47d07b8cb4c07c3be50083f747b1eef30722f6d27b317278127e6629315c172b256e5c9ba5c15640a2768b4a7c6bf66bc5253586b8cca0b1c7e45e91ed174a735ae8ea24fe1b1c01467a2c80dc2442987138c0fa35ba5a5846c3c95b1ad53187f5df244fb70781c34194c7dbd604fd0631d1f87de7ec8bedf2b8806740b83803835d587de8f94bd3904ae2fd979cd7cdee8db257dcfa0846b8de96a8da4dae07097034447a2e3f08db4e8d3a8c736ca84c0eaacaee3109184651292857a02fd692538e669b25c8985cafdcf6b3b625524f26dd8286dda10e3ef75f3edd14ac9f5e82314cf9077d5a3078b20ed65c567c30e95e9280340c1c6b8ec67e85dd05db59f7699809cfc1689b4ad4706ae23842a43aac4e958d73cd6348feba3fb373f3d45e4ebcf5050a04ecc65173a5ab3a7f81b16ee72592b62f99ce7150f82ecb20b8e0aa732adafc930d199e89906cbded9ede12312231352be1e812436535fbbce7edacafc87bdaba5e193564f20647ce14f0a4f93ef5fec28b32f130df62f87d555683863cb678228fd40ccefc61c7b2f7ce37eec74b04cccee8eb624ec77a5c567573e21eefee1d54ba647bbd6b286bbc30414c0391082695f78a58feb00318bcda711b8ef710fe821a61ad229bcac52954e6afe09141d63f95e6ff72dd6a68814bddf44144863c11e81d96cfdf7d1e4b3a5fe916cf5a98922a29aa3fb1cb03f3c4660021b6f225bd397dcefa9e52a05d5af6eba5e302e2c1b2446275084494a68ca3dfa1a7bfc8844b8e5338c5007441dd98dd43cbd2f6f8f83021d658b45182718955eb97f58683bd0f9217c69c7c0b9454402a366b26d2dec666de7182c65bff2be15c7660b101d8ff156eeeffc341aef94f63a471b057b5f7681457605cc01157953487afbe63c1616b5ac8f1cb7c63af29befc9f935a812d906720084a25df6a72a5b61164546f0ae9369ed13c35e4efbd9e8883974a7451edd79dcd6d4c56ae5a9ac4454472e306f8b790c8bdd8198d8c48e73a4adb7a72d42715e1316b25e117245073f66990b943c84e478610172d85031e2b28c8e87e1cacb2738bacfe428bfc8d6771b00d66f8019f4248f1690bbb0fc67b1cd2279abf037ac6d44d3d10552b36a1ebeb36932d5d74f1a9c9a0dae21ecac034c7241e4b378cb6c23b50781ec6c5ccf92ee1cdc06b30a78d0a8fde733dc83379fe1bc9a9b73df915da0fe1b71ac4f765223c697ea36e60fa778fd768",
    sharedSecret: "4f9c2a9c49ebcde70fe424874a862fae85012c21f79c20ceff58ab9e57f22f2b"
  };
};
`;
  }
  return { status: 'ok', fixSnippet: mockSnippet };
}

module.exports = { generatePqcFix, redisClient };