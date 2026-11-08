# Release Proof Kit

Verify that a downloaded artifact matches an Ed25519-signed release statement, the expected product, and the exact version requested by the operator.

## Reproduce the case

Requires Node.js 22+. All examples use synthetic data and run locally with the standard library. Run from the repository root.

```sh
node demo.mjs
```

The demo generates a temporary signing key in memory. The original artifact verifies; changing one byte triggers digest_mismatch. Asking for a newer version while presenting the original statement triggers identity_mismatch.

## Design and limits

The signer covers the exact JSON bytes, including a format tag, product, version and SHA-256. The verifier authenticates the statement with a separately trusted public key before parsing it. Artifact bytes are hashed as a stream. To verify your own release, run `node verify.mjs PUBLIC.pem STATEMENT.json SIGNATURE.bin ARTIFACT EXPECTED_PRODUCT EXPECTED_VERSION`. A trusted channel must supply the public key and expected version. Key rotation, transparency logs and proof of build provenance are outside this protocol.

## Verification

```sh
node --test
```

Tests check tampered manifest bytes, artifact substitution, a different signing key, and an older release signed by the correct key.
