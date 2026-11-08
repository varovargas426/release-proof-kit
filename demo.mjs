import { generateKeyPairSync } from 'node:crypto'
import { issue, inspect } from './proof.mjs'

const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const payload = Buffer.from('release artifact 1')
const { statement, signature } = await issue(privateKey, 'lab-agent', '1.0', [payload])
for (const [bytes, version] of [[payload, '1.0'], [Buffer.from('release artifact 2'), '1.0'], [payload, '1.1']]) {
  console.log(await inspect(publicKey, statement, signature, [bytes], 'lab-agent', version))
}
