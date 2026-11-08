import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { issue, inspect } from '../proof.mjs'
const a = generateKeyPairSync('ed25519'), b = generateKeyPairSync('ed25519')
const {statement,signature} = await issue(a.privateKey, 'app', '1', ['hel','lo'])

test('validates chunked bytes independently of chunk boundaries', async () => {
  assert.equal(await inspect(a.publicKey,statement,signature,['hello'],'app','1'), 'verified')
  assert.equal(await inspect(a.publicKey,statement,signature,['Hello'],'app','1'), 'digest_mismatch')
})

test('rejects substituted key and modified statement before reading artifact', async () => {
  async function* forbidden() { throw new Error('unexpected artifact read') }
  assert.equal(await inspect(b.publicKey,statement,signature,forbidden(),'app','1'), 'invalid_signature')
  const changed = Buffer.concat([statement,Buffer.from(' ')])
  assert.equal(await inspect(a.publicKey,changed,signature,forbidden(),'app','1'), 'invalid_signature')
})

test('rejects replay of another signed version or product', async () => {
  assert.equal(await inspect(a.publicKey,statement,signature,['hello'],'app','2'), 'identity_mismatch')
  assert.equal(await inspect(a.publicKey,statement,signature,['hello'],'other','1'), 'identity_mismatch')
})
