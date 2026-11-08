import { readFileSync, createReadStream } from 'node:fs'
import { inspect } from './proof.mjs'

try {
  const [key, statement, signature, artifact, product, version] = process.argv.slice(2)
  if (process.argv.length !== 8) throw new Error('Expected PUBLIC.pem STATEMENT.json SIGNATURE.bin ARTIFACT PRODUCT VERSION')
  // Delay opening the artifact until the authenticated statement requires it.
  async function* content() { yield* createReadStream(artifact) }
  const status = await inspect(readFileSync(key), readFileSync(statement), readFileSync(signature),
    content(), product, version)
  console.log(status)
  process.exitCode = status === 'verified' ? 0 : 1
} catch (error) {
  console.error(error.message)
  process.exitCode = 2
}
