import test from 'node:test';
import assert from 'node:assert/strict';
import { totalAmounts } from '../src/totals.js';

test('adds the fictional invoice amounts', () => {
  assert.equal(totalAmounts([25.50, 40.00, 14.25]), 79.75);
});

test('handles an empty list', () => {
  assert.equal(totalAmounts([]), 0);
});

test('adds decimal amounts in cents', () => {
  assert.equal(totalAmounts([0.10, 0.20]), 0.30);
});

test('rejects invalid invoice amounts', () => {
  assert.throws(() => totalAmounts([NaN]), TypeError);
  assert.throws(() => totalAmounts([-1]), TypeError);
});
