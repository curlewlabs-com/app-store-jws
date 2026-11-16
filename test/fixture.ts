// Certificates for the signing tests, and a signer over them, with the real and
// the throwaway kept apart on purpose:
//   - REAL_* are Apple's published certificates, unmodified, from
//     https://www.apple.com/certificateauthority/. They are the instance of a
//     format this package does not own, so they are what can falsify the DER
//     reader.
//   - TEST_* come from test/fixtures/make-test-chain.sh, a throwaway chain
//     shaped like Apple's, because signing a payload needs a private key. Each
//     variant lacks one thing a real chain has.

import * as chain from "./fixtures/test-chain.ts";

function base64Bytes(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

// Apple Worldwide Developer Relations - G6, issued by Apple Root CA - G3.
const REAL_WWDR_G6_BASE64 =
  "MIIDFjCCApygAwIBAgIUIsGhRwp0c2nvU4YSycafPTjzbNcwCgYIKoZIzj0EAwMw" +
  "ZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBD" +
  "ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkG" +
  "A1UEBhMCVVMwHhcNMjEwMzE3MjAzNzEwWhcNMzYwMzE5MDAwMDAwWjB1MUQwQgYD" +
  "VQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZp" +
  "Y2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzYxEzARBgNVBAoMCkFwcGxlIElu" +
  "Yy4xCzAJBgNVBAYTAlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEbsQKC94PrlWm" +
  "ZXnXgtxzdVJL8T0SGYngDRGpngn3N6PT8JMEb7FDi4bBmPhCnZ3/sq6PF/cGcKXW" +
  "sL5vOteRhyJ45x3ASP7cOB+aao90fcpxSv/EZFbniAbNgZGhIhpIo4H6MIH3MBIG" +
  "A1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUu7DeoVgziJqkipnevr3rr9rL" +
  "JKswRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBs" +
  "ZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNhZzMwNwYDVR0fBDAwLjAsoCqgKIYmaHR0" +
  "cDovL2NybC5hcHBsZS5jb20vYXBwbGVyb290Y2FnMy5jcmwwHQYDVR0OBBYEFD8v" +
  "lCNR01DJmig97bB85c+lkGKZMA4GA1UdDwEB/wQEAwIBBjAQBgoqhkiG92NkBgIB" +
  "BAIFADAKBggqhkjOPQQDAwNoADBlAjBAXhSq5IyKogMCPtw490BaB677CaEGJXuf" +
  "QB/EqZGd6CSjiCtOnuMTbXVXmxxcxfkCMQDTSPxarZXvNrkxU3TkUMI33yzvFVVR" +
  "T4wxWJC994OsdcZ4+RGNsYDyR5gmdr0nDGg=";

export const REAL_WWDR_G6 = base64Bytes(REAL_WWDR_G6_BASE64);
export const TEST_ROOT = base64Bytes(chain.root);

// An instant inside the test chain's validity, so the tests never read a clock.
export const TEST_CHAIN_VALID_AT_MS = Date.UTC(2030, 0, 1);

export const TEST_CHAIN = {
  good: [chain.leaf, chain.intermediate, chain.root],
  leafWithoutMarker: [chain.leaf_no_marker, chain.intermediate, chain.root],
  intermediateWithoutMarker: [
    chain.leaf,
    chain.intermediate_no_marker,
    chain.root,
  ],
  intermediateNotCa: [chain.leaf, chain.intermediate_not_ca, chain.root],
  noIntermediate: [chain.leaf, chain.root],
  // Names that link, signatures by a key with the right name but not the
  // chain's.
  intermediateWrongSigner: [
    chain.leaf,
    chain.intermediate_wrong_signer,
    chain.root,
  ],
  leafWrongSigner: [chain.leaf_wrong_signer, chain.intermediate, chain.root],
  // Signatures that hold, under names that do not link.
  intermediateWrongIssuer: [
    chain.leaf,
    chain.intermediate_wrong_issuer,
    chain.root,
  ],
  intermediateRenamed: [chain.leaf, chain.intermediate_renamed, chain.root],
} as const;

export const TEST_LEAF = base64Bytes(chain.leaf);

export function jwsPart(value: unknown): string {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)));
}

// A compact JWS over `payload`, signed by the test leaf the way the App Store
// signs.
export async function signAsAppleTest(
  payload: unknown,
  x5c: readonly string[] = TEST_CHAIN.good,
  alg = "ES256",
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    base64Bytes(chain.leaf_key_pkcs8),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signingInput = `${jwsPart({ alg, x5c })}.${jwsPart(payload)}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64Url(new Uint8Array(signature))}`;
}
