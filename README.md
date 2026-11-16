# app-store-jws

Verify data signed by the App Store - server notifications, transactions and
renewal info - using WebCrypto alone, so it runs on Cloudflare Workers and
other runtimes that do not have Node's `crypto` module.

## What it is

The App Store signs what it sends a server as a compact JWS (JSON Web
Signature): App Store Server Notifications V2 (`signedPayload`), and the
`signedTransactionInfo` and `signedRenewalInfo` values in those notifications
and in App Store Server API responses. Each JWS carries its certificate chain in
the `x5c` header, and a server has to check that chain before it believes the
payload.

This package does that check and returns the decoded payload only when it
passes. It has no runtime dependencies. It is two small modules:

- `app-store-jws` - `verifyAppleSignedData`, which checks one JWS against a root
  certificate you pin, and `appleRootCertificate`, the Apple Root CA - G3 bytes
  to pin.
- `app-store-jws/x509` - the strict DER reader the check stands on: it reads one
  X.509 certificate into the fields a chain check needs, and nothing more.

## Why it exists

Apple's own [App Store Server Library](https://github.com/apple/app-store-server-library-node)
for JavaScript is a Node.js library and depends on Node-only packages such as
`node-fetch`. Community packages that verify these payloads, such as
`app-store-server-api`, read the certificates with Node's `X509Certificate`.
Cloudflare Workers has no X.509 API unless the Worker turns on Node
compatibility, and general-purpose X.509 parsers carry far more than a chain
check needs.

Everything the check needs is in WebCrypto: ECDSA verification on P-256 and
P-384, plus `atob` and `TextDecoder`. What is missing is reading the
certificates, so this package does that itself: every DER element it reads is
read at its declared tag and length inside its parent's bounds, and a structure
it cannot read that way is a refusal rather than a guess.

## How to use it

It is not on the npm registry. Install a release's tarball from GitHub, which
pins it by the integrity hash your lockfile records:

```sh
npm install https://github.com/curlewlabs-com/app-store-jws/releases/download/v0.1.0/app-store-jws-0.1.0.tgz
```

Each release's notes give its tarball's SHA-512 integrity, and the tarball has a
GitHub build provenance attestation (`gh attestation verify <file> -R
curlewlabs-com/app-store-jws`).

A Worker receiving App Store Server Notifications:

```ts
import { appleRootCertificate, verifyAppleSignedData } from "app-store-jws";

const appleRoot = appleRootCertificate();

export default {
  async fetch(request: Request): Promise<Response> {
    const { signedPayload } = await request.json<{ signedPayload: string }>();
    const result = await verifyAppleSignedData(signedPayload, appleRoot);
    if (result.kind === "refused") {
      // result.reason is one of a fixed set of strings, safe to log.
      console.warn("App Store notification refused", result.reason);
      return new Response(null, { status: 400 });
    }
    const data = result.payload["data"] as Record<string, unknown>;
    // Verification says Apple signed this. Whether it is about your app is
    // yours to check - see below.
    if (data["bundleId"] !== "com.example.app") {
      return new Response(null, { status: 400 });
    }
    // data.signedTransactionInfo is a JWS of its own: verify it the same way
    // before reading it.
    return new Response(null, { status: 200 });
  },
};
```

`verifyAppleSignedData(jws, trustedRoot)` resolves to one of:

- `{ kind: "verified", payload }` - the decoded JSON object.
- `{ kind: "refused", reason }` - it never throws on bad input. `reason` is an
  `AppleSignatureRefusal`: `malformed_jws`, `unsupported_algorithm`,
  `unexpected_chain_length`, `untrusted_root`, `unreadable_certificate`,
  `broken_chain_link`, `missing_role_marker`, `bad_chain_signature`,
  `bad_payload_signature`, `malformed_payload` or
  `certificate_outside_validity`.

Pass `appleRootCertificate()` as the root in production. A test can pass a root
of its own, with a chain it signed, to exercise its handler end to end;
[`test/fixtures/make-test-chain.sh`](test/fixtures/make-test-chain.sh) makes one
with the OpenSSL CLI.

`unverifiedAppleClaims(jws)` decodes a JWS payload with no checks at all, for a
decision that has to come before verification, such as a rate limit keyed on the
transaction a request names. Nothing it returns has been checked, so nothing it
returns should decide anything about a purchase.

## What is verified, and what is not

A payload is returned only when all of these hold:

- The JWS is compact (three base64url parts), its header names `alg: ES256`, and
  its `x5c` chain is exactly three certificates: leaf, intermediate, root.
- The root in the chain is byte for byte the root you passed. The root is the
  whole of the trust, so it is compared, not parsed and judged.
- Every certificate is strict DER, X.509 version 3, with matching signed and
  unsigned signature algorithms.
- Each certificate's issuer name matches the next one's subject, and the root
  signed the intermediate and the intermediate signed the leaf (ECDSA over P-256
  or P-384, with SHA-256 or SHA-384).
- The intermediate is a CA and carries Apple's intermediate marker
  (`1.2.840.113635.100.6.2.1`), and the leaf carries Apple's App Store signing
  marker (`1.2.840.113635.100.6.11.1`). These matter: Apple's WWDR
  intermediates also issue ordinary developer certificates, so a chain that
  reaches Apple's root is something anyone in the Apple Developer Program can
  build.
- The leaf's P-256 key signed exactly the header and payload bytes received.
- The payload is a JSON object with a numeric `signedDate`, and the leaf and
  intermediate were both valid at that instant.

What it does **not** do:

- **No revocation check.** There is no OCSP or CRL lookup. A certificate is
  judged at the payload's own `signedDate`, as Apple's library does with online
  checks off, so a payload signed while its certificates were valid stays
  verifiable after they expire. The flip side is that a revoked certificate's
  payloads still verify.
- **Nothing about which app or environment a payload is for.** A verified
  payload is something the App Store said, to someone. Check `bundleId`,
  `appAppleId` and `environment` (and anything else your server relies on) on
  the payload yourself.
- **No nested verification.** A notification's `signedTransactionInfo` and
  `signedRenewalInfo` are separate JWS values; verify each one.
- **Not full RFC 5280 path validation.** Key usage, path length constraints and
  unrecognised critical extensions are not checked, and neither is the pinned
  root's own validity period. The pinned root and Apple's role markers are what
  this check relies on instead.
- **No replay protection.** The same signed payload verifies every time it is
  sent.
- **The X.509 reader is not a certificate validator.** It reads the fields a
  chain check needs, and does not hold the rest to every DER rule: INTEGER
  minimality, calendar-valid times, a nested element's trailing content and
  duplicate extensions all pass. The chain check does not depend on them, because
  every field it reads lies inside bytes the issuer's signature covers, apart
  from the signature value, which is only ever verified. If you use
  `app-store-jws/x509` on certificates you do not verify against a pinned root,
  do not rely on it to reject malformed ones.

## Runtime requirements

Global `crypto.subtle` with ECDSA P-256 and P-384, `atob`, `TextEncoder` and
`TextDecoder`. Cloudflare Workers provides all of them without Node
compatibility, and so do current Node.js, Deno, Bun and browsers. It runs in
production on Cloudflare Workers; the tests here run on Node.js 24.

## Versioning

Releases are fixed `vMAJOR.MINOR.PATCH` tags with immutable GitHub Releases.
While the version is 0.x, a minor release may change the API; read the release
notes before moving the pin.

## Development

```sh
npm ci
npm run typecheck
npm test
```

The tests use Apple's real root and WWDR G6 intermediate to check the DER
reader against an encoding this package did not produce, and a throwaway chain
from `test/fixtures/make-test-chain.sh` for everything that needs a signature.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## License

[MIT](LICENSE), copyright Curlew Labs.
