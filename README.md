# xmip-core-authenticate-api-key

Authenticate by API key: verifies a key against a key store, hashed at rest, with its owner and expiry. A technology of [xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

The store is the capability's hashed secret store, `authenticate::secret`, which
`api-key` and `bearer` share; until 2026-09-24 each carried one of its own.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
