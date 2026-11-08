import { createHash, createPublicKey, sign, verify } from 'node:crypto'

async function digest(chunks) {
  const hash = createHash('sha256')
  for await (const chunk of chunks) hash.update(chunk)
  return hash.digest('hex')
}

export async function issue(privateKey, product, version, artifact) {
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('Expected Ed25519 signing key')
  const statement = Buffer.from(JSON.stringify({
    format: 'release-proof/v1', product, version, sha256: await digest(artifact)
  }))
  return { statement, signature: sign(null, statement, privateKey) }
}

export async function inspect(trustedKey, statement, signature, artifact, expectedProduct, expectedVersion) {
  const key = trustedKey.type === 'public' ? trustedKey : createPublicKey(trustedKey)
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Expected Ed25519 public key')
  if (!verify(null, statement, key, signature)) return 'invalid_signature'
  let claim
  try { claim = JSON.parse(statement) } catch { return 'invalid_statement' }
  if (claim?.format !== 'release-proof/v1' || !/^[0-9a-f]{64}$/.test(claim.sha256)) return 'invalid_statement'
  if (claim.product !== expectedProduct || claim.version !== expectedVersion) return 'identity_mismatch'
  return (await digest(artifact)) === claim.sha256 ? 'verified' : 'digest_mismatch'
}
