import jwt from 'jsonwebtoken';

const baseUrl = process.env.TEST_BASE_URL || 'http://localhost:3001';

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

const run = async () => {
  const noAuth = await request('/api/debug/echo-auth');
  assert(noAuth.status === 200, 'echo-auth without header should return 200');
  assert(noAuth.json?.debug?.hasDots === false, 'expected hasDots=false without header');

  const fakeAuth = await request('/api/debug/echo-auth', {
    headers: { Authorization: 'Bearer abc.def.ghi' }
  });
  assert(fakeAuth.json?.debug?.hasDots === true, 'expected hasDots=true for abc.def.ghi');

  const secret = process.env.MONDAY_CLIENT_SECRET || 'testsecret';
  const token = jwt.sign({ dat: { user_id: 1, account_id: 2, app_id: 3 } }, secret, {
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

  console.log('test-auth ok');
};

run().catch((err) => {
  console.error('test-auth failed:', err.message);
  process.exit(1);
});
