import { spawn } from 'child_process';
import jwt from 'jsonwebtoken';

const port = process.env.TEST_PORT || '4010';
const baseUrl = `http://localhost:${port}`;

const request = async (path, options = {}) => {
  const res = await fetch(`${baseUrl}${path}`, options);
  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json, text };
};

const assert = (condition, message) => {
  if (!condition) {
    throw new Error(message);
  }
};

const waitForReady = async () => {
  const attempts = 25;
  for (let i = 0; i < attempts; i += 1) {
    try {
      const res = await request('/__debug/ping');
      if (res.status === 200) return;
    } catch {
      // retry
    }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error('server did not start');
};

const run = async () => {
  const child = spawn('node', ['index.js'], {
    env: {
      ...process.env,
      PORT: port,
      SERVER_BASE_URL: baseUrl,
      ALLOWED_ORIGINS: 'http://localhost:3000',
      MONDAY_CLIENT_ID: 'dummy',
      MONDAY_CLIENT_SECRET: 'dummy',
      MONDAY_SIGNING_SECRET: 'testsecret'
    },
    stdio: 'ignore'
  });

  try {
    await waitForReady();

    const noAuth = await request('/api/debug/echo-auth');
    assert(noAuth.status === 200, 'echo-auth without header should return 200');
    assert(noAuth.json?.debug?.hasDots === false, 'expected hasDots=false without header');

    const fakeAuth = await request('/api/debug/echo-auth', {
      headers: { Authorization: 'Bearer abc.def.ghi' }
    });
    assert(fakeAuth.json?.debug?.hasDots === true, 'expected hasDots=true for abc.def.ghi');

    const token = jwt.sign({ dat: { user_id: 1, account_id: 2, app_id: 3 } }, 'testsecret', {
      algorithm: 'HS256'
    });
    const whoami = await request('/api/debug/whoami', {
      headers: { Authorization: `Bearer ${token}` }
    });
    assert(whoami.status === 200, 'whoami should return 200');
    assert(whoami.json?.ok === true, 'whoami ok should be true');
    assert(whoami.json?.accountId === 2, 'accountId should be 2');
    assert(whoami.json?.userId === 1, 'userId should be 1');
    assert(whoami.json?.appId === 3, 'appId should be 3');

    const badToken = jwt.sign({ dat: { user_id: 1 } }, 'wrongsecret', { algorithm: 'HS256' });
    const badRes = await request('/api/debug/verify', {
      headers: { Authorization: `Bearer ${badToken}` }
    });
    assert(badRes.status === 401, 'verify with wrong secret should return 401');

    console.log('test-auth ok');
  } finally {
    child.kill('SIGTERM');
  }
};

run().catch((err) => {
  console.error('test-auth failed:', err.message);
  process.exit(1);
});
