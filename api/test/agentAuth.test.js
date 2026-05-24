/**
 * Tests for agent auth helpers — bcrypt hashing and verification.
 *
 * These intentionally avoid the db-backed token helpers; those are
 * exercised by the API integration smoke test below.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateAgentSecret,
  hashAgentSecret,
  verifyAgentSecret,
} from '../src/services/agentAuth.js';

test('generateAgentSecret returns a properly-prefixed random secret', () => {
  const s = generateAgentSecret();
  assert.match(s, /^as_[a-f0-9]{64}$/);
});

test('generateAgentSecret values do not collide on repeated calls', () => {
  const seen = new Set();
  for (let i = 0; i < 100; i++) seen.add(generateAgentSecret());
  assert.equal(seen.size, 100);
});

test('hashAgentSecret + verifyAgentSecret round-trip', () => {
  const secret = generateAgentSecret();
  const hash = hashAgentSecret(secret);
  assert.notEqual(hash, secret, 'hash must not equal the secret');
  assert.equal(verifyAgentSecret(secret, hash), true);
});

test('verifyAgentSecret rejects wrong secret', () => {
  const correct = generateAgentSecret();
  const wrong   = generateAgentSecret();
  const hash    = hashAgentSecret(correct);
  assert.equal(verifyAgentSecret(wrong, hash), false);
});

test('verifyAgentSecret returns false (not throws) on malformed hash', () => {
  // A real attacker may submit a non-bcrypt blob — we must return false,
  // never throw, so callers can issue a clean 401.
  assert.doesNotThrow(() => verifyAgentSecret('whatever', 'not-a-bcrypt-hash'));
  assert.equal(verifyAgentSecret('whatever', 'not-a-bcrypt-hash'), false);
});
