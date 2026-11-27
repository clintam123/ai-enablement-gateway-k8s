import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

const BASE_URL = (__ENV.BASE_URL || 'http://localhost:8080').replace(/\/+$/, '');
const SCENARIO = __ENV.SCENARIO || 'all';
const PLATFORM_CREDENTIAL = __ENV.PLATFORM_CREDENTIAL || __ENV.API_KEY || '';
const OPS_CREDENTIAL = __ENV.OPS_CREDENTIAL || PLATFORM_CREDENTIAL;
const PRODUCT_CREDENTIAL = __ENV.PRODUCT_CREDENTIAL || '';

const jsonLatencyMs = new Trend('json_latency_ms', true);
const jsonSuccessRate = new Rate('json_success_rate');

const sseLatencyMs = new Trend('sse_latency_ms', true);
const sseSuccessRate = new Rate('sse_success_rate');

const failoverLatencyMs = new Trend('failover_latency_ms', true);
const failoverSuccessRate = new Rate('failover_success_rate');

const quota429Rate = new Rate('quota_429_rate');
const quota429HeadersValidRate = new Rate('quota_429_headers_valid_rate');
const quotaAllowed200Total = new Counter('quota_allowed_200_total');
const quotaBlocked429Total = new Counter('quota_blocked_429_total');

const budget429Rate = new Rate('budget_429_rate');
const budget429HeadersValidRate = new Rate('budget_429_headers_valid_rate');
const budgetAllowed200Total = new Counter('budget_allowed_200_total');
const budgetBlocked429Total = new Counter('budget_blocked_429_total');

const hpaLatencyMs = new Trend('hpa_latency_ms', true);
const hpaSuccessRate = new Rate('hpa_success_rate');

const benchmarkRequestsTotal = new Counter('benchmark_requests_total');

const ALL_SCENARIO_CONFIGS = {
  normal_json: {
    executor: 'constant-arrival-rate',
    rate: Number(__ENV.NORMAL_JSON_RATE || 5),
    timeUnit: '1s',
    duration: __ENV.NORMAL_JSON_DURATION || '12s',
    preAllocatedVUs: 10,
    maxVUs: 25,
    exec: 'runNormalJson',
  },
  sse_stream: {
    executor: 'constant-arrival-rate',
    rate: Number(__ENV.SSE_RATE || 3),
    timeUnit: '1s',
    duration: __ENV.SSE_DURATION || '10s',
    preAllocatedVUs: 6,
    maxVUs: 15,
    exec: 'runSseStream',
  },
  failover: {
    executor: 'constant-arrival-rate',
    rate: Number(__ENV.FAILOVER_RATE || 4),
    timeUnit: '1s',
    duration: __ENV.FAILOVER_DURATION || '5s',
    preAllocatedVUs: 6,
    maxVUs: 12,
    exec: 'runFailover',
  },
  quota_exhaustion: {
    executor: 'shared-iterations',
    vus: Number(__ENV.QUOTA_VUS || 10),
    iterations: Number(__ENV.QUOTA_ITERATIONS || 90),
    maxDuration: '30s',
    exec: 'runQuotaExhaustion',
  },
  budget_quota_exhaustion: {
    executor: 'shared-iterations',
    vus: Number(__ENV.BUDGET_QUOTA_VUS || 4),
    iterations: Number(__ENV.BUDGET_QUOTA_ITERATIONS || 30),
    maxDuration: '30s',
    exec: 'runBudgetQuotaExhaustion',
  },
  hpa_sustained: {
    executor: 'ramping-vus',
    startVUs: 4,
    stages: [
      { duration: __ENV.HPA_RAMP_UP || '10s', target: Number(__ENV.HPA_TARGET_VUS || 24) },
      { duration: __ENV.HPA_HOLD || '75s', target: Number(__ENV.HPA_TARGET_VUS || 24) },
      { duration: __ENV.HPA_RAMP_DOWN || '5s', target: 0 },
    ],
    gracefulRampDown: '5s',
    exec: 'runHpaSustained',
  },
};

const ALL_THRESHOLDS = {
  normal_json: {
    json_success_rate: ['rate>0.99'],
  },
  sse_stream: {
    sse_success_rate: ['rate>0.99'],
  },
  failover: {
    failover_success_rate: ['rate>0.95'],
  },
  quota_exhaustion: {
    quota_429_rate: ['rate>0.10'],
    quota_429_headers_valid_rate: ['rate==1.0'],
  },
  budget_quota_exhaustion: {
    budget_429_rate: ['rate>0.10'],
    budget_429_headers_valid_rate: ['rate==1.0'],
  },
  hpa_sustained: {
    hpa_success_rate: ['rate>0.95'],
  },
};

function buildSelectedOptions(mode) {
  if (mode === 'all') {
    return {
      scenarios: {
        normal_json: { ...ALL_SCENARIO_CONFIGS.normal_json, startTime: '0s' },
        sse_stream: { ...ALL_SCENARIO_CONFIGS.sse_stream, startTime: '13s' },
        failover: { ...ALL_SCENARIO_CONFIGS.failover, startTime: '24s' },
        quota_exhaustion: { ...ALL_SCENARIO_CONFIGS.quota_exhaustion, startTime: '30s' },
        budget_quota_exhaustion: {
          ...ALL_SCENARIO_CONFIGS.budget_quota_exhaustion,
          startTime: '62s',
        },
        hpa_sustained: { ...ALL_SCENARIO_CONFIGS.hpa_sustained, startTime: '94s' },
      },
      thresholds: {
        ...ALL_THRESHOLDS.normal_json,
        ...ALL_THRESHOLDS.sse_stream,
        ...ALL_THRESHOLDS.failover,
        ...ALL_THRESHOLDS.quota_exhaustion,
        ...ALL_THRESHOLDS.budget_quota_exhaustion,
        ...ALL_THRESHOLDS.hpa_sustained,
      },
    };
  }
  if (!ALL_SCENARIO_CONFIGS[mode]) {
    throw new Error(
      `Unsupported SCENARIO='${mode}'. Expected one of: normal_json, sse_stream, failover, quota_exhaustion, budget_quota_exhaustion, hpa_sustained, all.`,
    );
  }
  return {
    scenarios: {
      [mode]: ALL_SCENARIO_CONFIGS[mode],
    },
    thresholds: ALL_THRESHOLDS[mode],
  };
}

export const options = buildSelectedOptions(SCENARIO);

function getHeader(headers, targetName) {
  const target = targetName.toLowerCase();
  for (const [key, value] of Object.entries(headers || {})) {
    if (key.toLowerCase() === target) {
      return Array.isArray(value) ? value[0] : value;
    }
  }
  return undefined;
}

function parseJsonBody(res) {
  try {
    return JSON.parse(res.body);
  } catch (_err) {
    return null;
  }
}

function assertCredential(value, envName) {
  if (!value) {
    throw new Error(`Missing required Credential env var: ${envName}`);
  }
}

export function setup() {
  if (SCENARIO === 'normal_json' || SCENARIO === 'failover' || SCENARIO === 'hpa_sustained' || SCENARIO === 'all') {
    assertCredential(PLATFORM_CREDENTIAL, 'PLATFORM_CREDENTIAL');
  }
  if (SCENARIO === 'sse_stream' || SCENARIO === 'budget_quota_exhaustion' || SCENARIO === 'all') {
    assertCredential(OPS_CREDENTIAL, 'OPS_CREDENTIAL or PLATFORM_CREDENTIAL');
  }
  if (SCENARIO === 'quota_exhaustion' || SCENARIO === 'all') {
    assertCredential(PRODUCT_CREDENTIAL, 'PRODUCT_CREDENTIAL');
  }
  return {};
}

export function runNormalJson() {
  const payload = JSON.stringify({
    model: 'chat-default',
    max_tokens: 32,
    messages: [{ role: 'user', content: 'Benchmark normal JSON completion via Control Plane.' }],
  });
  const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${PLATFORM_CREDENTIAL}`,
    },
    tags: { scenario: 'normal_json' },
  });

  const parsed = parseJsonBody(res);
  const content = parsed && parsed.choices && parsed.choices[0] && parsed.choices[0].message
    ? parsed.choices[0].message.content
    : '';
  const totalTokens = parsed && parsed.usage ? Number(parsed.usage.total_tokens || 0) : 0;
  const fallbackHeader = getHeader(res.headers, 'x-fallback-used');

  const ok = check(res, {
    'normal_json status is 200': (r) => r.status === 200,
    'normal_json has non-empty content': () => typeof content === 'string' && content.length > 0,
    'normal_json reports positive usage': () => totalTokens > 0,
    'normal_json x-fallback-used is false': () => fallbackHeader === 'false',
  });

  jsonLatencyMs.add(res.timings.duration);
  jsonSuccessRate.add(ok);
  benchmarkRequestsTotal.add(1);
}

export function runSseStream() {
  const payload = JSON.stringify({
    model: 'chat-default',
    stream: true,
    max_tokens: 48,
    messages: [{ role: 'user', content: 'Benchmark SSE streaming completion via Control Plane.' }],
  });
  const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${OPS_CREDENTIAL}`,
    },
    tags: { scenario: 'sse_stream' },
  });

  const contentType = (getHeader(res.headers, 'content-type') || '').toLowerCase();
  const body = res.body || '';

  const ok = check(res, {
    'sse_stream status is 200': (r) => r.status === 200,
    'sse_stream content-type is text/event-stream': () => contentType.includes('text/event-stream'),
    'sse_stream includes [DONE]': () => body.includes('[DONE]'),
    'sse_stream includes usage chunk': () => body.includes('"usage"'),
  });

  sseLatencyMs.add(res.timings.duration);
  sseSuccessRate.add(ok);
  benchmarkRequestsTotal.add(1);
}

export function runFailover() {
  const payload = JSON.stringify({
    model: 'chat-default',
    max_tokens: 32,
    messages: [{ role: 'user', content: 'Benchmark primary-to-fallback failover.' }],
  });
  const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${PLATFORM_CREDENTIAL}`,
    },
    tags: { scenario: 'failover' },
  });

  const parsed = parseJsonBody(res);
  const content = parsed && parsed.choices && parsed.choices[0] && parsed.choices[0].message
    ? parsed.choices[0].message.content
    : '';
  const fallbackHeader = getHeader(res.headers, 'x-fallback-used');

  const ok = check(res, {
    'failover status is 200': (r) => r.status === 200,
    'failover X-Fallback-Used is true': () => fallbackHeader === 'true',
    'failover served by mock-llm-fallback': () => typeof content === 'string' && content.includes('mock-llm-fallback'),
  });

  failoverLatencyMs.add(res.timings.duration);
  failoverSuccessRate.add(ok);
  benchmarkRequestsTotal.add(1);
}

export function runQuotaExhaustion() {
  const payload = JSON.stringify({
    model: 'chat-fast',
    max_tokens: 16,
    messages: [{ role: 'user', content: 'Benchmark Team Budget Quota / RPM enforcement.' }],
  });
  const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${PRODUCT_CREDENTIAL}`,
    },
    responseCallback: http.expectedStatuses(200, 429),
    tags: { scenario: 'quota_exhaustion' },
  });

  const is200 = res.status === 200;
  const is429 = res.status === 429;
  check(res, {
    'quota status is 200 or 429': () => is200 || is429,
  });

  quota429Rate.add(is429);
  benchmarkRequestsTotal.add(1);

  if (is200) {
    quotaAllowed200Total.add(1);
    return;
  }

  if (is429) {
    quotaBlocked429Total.add(1);
    const retryAfter = getHeader(res.headers, 'retry-after');
    const limitReq = getHeader(res.headers, 'x-ratelimit-limit-requests');
    const remainingReq = getHeader(res.headers, 'x-ratelimit-remaining-requests');
    const budgetLimit = getHeader(res.headers, 'x-budget-limit-usd');
    const budgetRemaining = getHeader(res.headers, 'x-budget-remaining-usd');
    const denialReason = getHeader(res.headers, 'x-policy-denial-reason');

    const headersOk = check(res, {
      '429 includes Retry-After': () => Boolean(retryAfter),
      '429 includes X-RateLimit-Limit-Requests': () => Boolean(limitReq),
      '429 includes X-RateLimit-Remaining-Requests': () => remainingReq !== undefined,
      '429 includes X-Budget-Limit-USD': () => Boolean(budgetLimit),
      '429 includes X-Budget-Remaining-USD': () => Boolean(budgetRemaining),
      '429 includes X-Policy-Denial-Reason': () =>
        denialReason === 'rpm_limit_exceeded' || denialReason === 'budget_quota_exceeded',
    });
    quota429HeadersValidRate.add(headersOk);
  }
}

export function runBudgetQuotaExhaustion() {
  const payload = JSON.stringify({
    model: 'chat-premium',
    max_tokens: 64,
    messages: [{ role: 'user', content: 'Benchmark Team daily USD Budget Quota enforcement.' }],
  });
  const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${OPS_CREDENTIAL}`,
    },
    responseCallback: http.expectedStatuses(200, 429),
    tags: { scenario: 'budget_quota_exhaustion' },
  });

  const is200 = res.status === 200;
  const is429 = res.status === 429;
  check(res, {
    'budget_quota status is 200 or 429': () => is200 || is429,
  });

  budget429Rate.add(is429);
  benchmarkRequestsTotal.add(1);

  if (is200) {
    budgetAllowed200Total.add(1);
    return;
  }

  if (is429) {
    budgetBlocked429Total.add(1);
    const parsed = parseJsonBody(res);
    const errorCode = parsed && parsed.error ? parsed.error.code : undefined;
    const retryAfter = getHeader(res.headers, 'retry-after');
    const limitReq = getHeader(res.headers, 'x-ratelimit-limit-requests');
    const remainingReq = getHeader(res.headers, 'x-ratelimit-remaining-requests');
    const budgetLimit = getHeader(res.headers, 'x-budget-limit-usd');
    const budgetRemaining = getHeader(res.headers, 'x-budget-remaining-usd');
    const denialReason = getHeader(res.headers, 'x-policy-denial-reason');

    const headersOk = check(res, {
      'budget 429 includes Retry-After': () => Boolean(retryAfter),
      'budget 429 includes X-RateLimit-Limit-Requests': () => Boolean(limitReq),
      'budget 429 includes X-RateLimit-Remaining-Requests': () => remainingReq !== undefined,
      'budget 429 includes X-Budget-Limit-USD': () => Boolean(budgetLimit),
      'budget 429 includes X-Budget-Remaining-USD': () => Boolean(budgetRemaining),
      'budget 429 X-Policy-Denial-Reason is budget_quota_exceeded': () =>
        denialReason === 'budget_quota_exceeded',
      'budget 429 error.code is budget_quota_exceeded': () =>
        errorCode === 'budget_quota_exceeded',
    });
    budget429HeadersValidRate.add(headersOk);
  }
}

export function runHpaSustained() {
  const payload = JSON.stringify({
    model: 'chat-fast',
    max_tokens: 32,
    messages: [
      {
        role: 'user',
        content: 'Evaluate gateway policy for oncall@example.com phone 555-123-4567.',
      },
    ],
  });
  const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${PLATFORM_CREDENTIAL}`,
    },
    tags: { scenario: 'hpa_sustained' },
  });

  const parsed = parseJsonBody(res);
  const content = parsed && parsed.choices && parsed.choices[0] && parsed.choices[0].message
    ? parsed.choices[0].message.content
    : '';

  const ok = check(res, {
    'hpa_sustained status is 200': (r) => r.status === 200,
    'hpa_sustained has completion content': () => typeof content === 'string' && content.length > 0,
  });

  hpaLatencyMs.add(res.timings.duration);
  hpaSuccessRate.add(ok);
  benchmarkRequestsTotal.add(1);
  sleep(0.01);
}
