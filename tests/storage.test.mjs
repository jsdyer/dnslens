import test from 'node:test';
import assert from 'node:assert/strict';
import { readMigrated } from '../web/storage.mjs';
function storage(entries, failWrite = false) {
  const values = new Map(entries);
  return { values, getItem: key => values.get(key) ?? null,
    setItem(key, value) { if (failWrite) throw new Error('quota'); values.set(key, value); },
    removeItem: key => values.delete(key) };
}
test('migration preserves exact saved data and runs once', () => {
  const original = JSON.stringify([{request_number:'A-2026-001', summary:'é & <text>'}]);
  const s = storage([['old', original]]);
  assert.equal(readMigrated(s, 'new', 'old'), original);
  assert.equal(s.values.get('new'), original);
  assert.equal(s.values.has('old'), false);
  assert.equal(readMigrated(s, 'new', 'old'), original);
});
test('a newer value, including an intentionally empty value, takes precedence', () => {
  for (const current of ['[]', '', 'dark']) {
    const s = storage([['new', current], ['old', 'light']]);
    assert.equal(readMigrated(s, 'new', 'old'), current);
    assert.equal(s.values.get('new'), current);
  }
});
test('full or blocked storage does not discard legacy data', () => {
  const s = storage([['old','saved requests']], true);
  assert.equal(readMigrated(s,'new','old'),'saved requests');
  assert.equal(s.values.get('old'),'saved requests');
  assert.equal(s.values.has('new'),false);
  assert.equal(readMigrated({getItem(){throw new Error('blocked');}},'new','old'),null);
});
test('failed legacy cleanup retains the successfully copied value', () => {
  const s = storage([['old','light']]);
  s.removeItem=()=>{throw new Error('blocked');};
  assert.equal(readMigrated(s,'new','old'),'light');
  assert.equal(s.values.get('new'),'light');
  assert.equal(s.values.get('old'),'light');
});
