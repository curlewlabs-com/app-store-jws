// Verifies a JWS signed by the App Store and returns its payload: the signed
// notification, transaction, and renewal info all use this one format. A payload
// is returned only when its certificate chain reaches Apple's root, each link
// carries the marker Apple documents for its role, and the leaf signed exactly
// these bytes. There is no online revocation check; a certificate is judged at the
// payload's own signedDate, as Apple's App Store Server Library does with online
// checks off, so a payload signed while its certificates were valid stays
// verifiable after they expire.
//
// A signed value is data the App Store said, and says nothing about whether it
// concerns the caller's app or environment. Callers check those on the payload.
//
// unverifiedAppleClaims reads the same format with none of those checks, for a
// caller that must act on what a JWS claims before verification can run, such
// as a rate limit keyed on the transaction it names, or choosing which records
// of a history page to verify. Nothing read that way should decide anything
// about a purchase.

import {
  bytesEqual,
  ecdsaSignatureToRaw,
  parseX509Certificate,
  type X509Certificate,
} from "./x509-certificate.ts";

// Apple Root CA - G3, from https://www.apple.com/certificateauthority/. SHA-256
// 63343ABFB89A6A03EBB57E9B3F5FA7BE7C4F5C756F3017B3A8C488C3653E9179. Compared byte
// for byte, because the root is the whole of the trust here. It expires in 2039.
const APPLE_ROOT_CA_G3_BASE64 =
  "MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwS" +
  "QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u" +
  "IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN" +
  "MTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBS" +
  "b290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9y" +
  "aXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49" +
  "AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtf" +
  "TjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517" +
  "IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySr" +
  "MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gA" +
  "MGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4" +
  "at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM" +
  "6BgD56KyKA==";

export function appleRootCertificate(): Uint8Array {
  return base64ToBytes(APPLE_ROOT_CA_G3_BASE64);
}

// Apple's documented markers for each role in the chain. The WWDR intermediates
// also issue ordinary developer certificates, so reaching the root proves nothing
// on its own: these are what say this leaf is the App Store's signing certificate.
const OID_INTERMEDIATE_MARKER = "1.2.840.113635.100.6.2.1";
const OID_LEAF_MARKER = "1.2.840.113635.100.6.11.1";

const CHAIN_LENGTH = 3;

const ECDSA_HASH_BY_SIGNATURE_OID: ReadonlyMap<string, string> = new Map([
  ["1.2.840.10045.4.3.2", "SHA-256"],
  ["1.2.840.10045.4.3.3", "SHA-384"],
]);

const OID_P256 = "1.2.840.10045.3.1.7";

const CURVE_BY_OID: ReadonlyMap<
  string,
  { readonly name: string; readonly componentBytes: number }
> = new Map([
  [OID_P256, { name: "P-256", componentBytes: 32 }],
  ["1.3.132.0.34", { name: "P-384", componentBytes: 48 }],
]);

// Why a JWS was refused. A bounded set of constants, so it is safe to log from
// this pre-auth surface where the input itself is not.
export type AppleSignatureRefusal =
  | "malformed_jws"
  | "unsupported_algorithm"
  | "unexpected_chain_length"
  | "untrusted_root"
  | "unreadable_certificate"
  | "broken_chain_link"
  | "missing_role_marker"
  | "bad_chain_signature"
  | "bad_payload_signature"
  | "malformed_payload"
  | "certificate_outside_validity";

export type AppleSignatureResult =
  | {
      readonly kind: "verified";
      readonly payload: Readonly<Record<string, unknown>>;
    }
  | { readonly kind: "refused"; readonly reason: AppleSignatureRefusal };

const BASE64URL_TEXT = /^[A-Za-z0-9_-]+$/;

function base64ToBytes(text: string): Uint8Array {
  const binary = atob(text);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function base64UrlToBytes(text: string): Uint8Array | null {
  if (!BASE64URL_TEXT.test(text) || text.length % 4 === 1) return null;
  return base64ToBytes(text.replaceAll("-", "+").replaceAll("_", "/"));
}

function jsonObject(bytes: Uint8Array): Record<string, unknown> | null {
  let value: unknown;
  try {
    value = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes),
    );
  } catch {
    // Invalid UTF-8 and invalid JSON mean one thing here: not a JSON object. The
    // caller's refusal reason is the whole diagnostic.
    return null;
  }
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function decodeChain(x5c: unknown): Uint8Array[] | null {
  if (!Array.isArray(x5c)) return null;
  const chain: Uint8Array[] = [];
  for (const entry of x5c) {
    if (typeof entry !== "string") return null;
    try {
      chain.push(base64ToBytes(entry));
    } catch {
      return null;
    }
  }
  return chain;
}

// The return type is inferred: Node's typings declare CryptoKey as a value
// rather than a global type, so the spelling Workers and DOM typings accept does
// not compile under them.
async function importCertificateKey(certificate: X509Certificate) {
  const curve = CURVE_BY_OID.get(certificate.curveOid);
  if (curve === undefined) return null;
  return crypto.subtle.importKey(
    "spki",
    certificate.subjectPublicKeyInfo,
    { name: "ECDSA", namedCurve: curve.name },
    false,
    ["verify"],
  );
}

async function issuerSigned(
  issuer: X509Certificate,
  subject: X509Certificate,
): Promise<boolean> {
  const hash = ECDSA_HASH_BY_SIGNATURE_OID.get(subject.signatureAlgorithmOid);
  const curve = CURVE_BY_OID.get(issuer.curveOid);
  if (hash === undefined || curve === undefined) return false;
  const signature = ecdsaSignatureToRaw(
    subject.signature,
    curve.componentBytes,
  );
  const key = await importCertificateKey(issuer);
  if (signature === null || key === null) return false;
  return crypto.subtle.verify(
    { name: "ECDSA", hash },
    key,
    signature,
    subject.tbsCertificate,
  );
}

function validAt(certificate: X509Certificate, atMs: number): boolean {
  return atMs >= certificate.notBeforeMs && atMs <= certificate.notAfterMs;
}

// The payload a JWS claims, unchecked, or null when it is not a JWS carrying a
// JSON object.
export function unverifiedAppleClaims(
  jws: string,
): Record<string, unknown> | null {
  const parts = jws.split(".");
  const payloadText = parts[1];
  if (parts.length !== 3 || payloadText === undefined) return null;
  const payloadBytes = base64UrlToBytes(payloadText);
  return payloadBytes === null ? null : jsonObject(payloadBytes);
}

export async function verifyAppleSignedData(
  jws: string,
  trustedRoot: Uint8Array,
): Promise<AppleSignatureResult> {
  const refused = (reason: AppleSignatureRefusal): AppleSignatureResult => ({
    kind: "refused",
    reason,
  });

  const parts = jws.split(".");
  const [headerText, payloadText, signatureText] = parts;
  if (
    parts.length !== 3 ||
    headerText === undefined ||
    payloadText === undefined ||
    signatureText === undefined
  ) {
    return refused("malformed_jws");
  }
  const headerBytes = base64UrlToBytes(headerText);
  const signature = base64UrlToBytes(signatureText);
  const payloadBytes = base64UrlToBytes(payloadText);
  if (headerBytes === null || signature === null || payloadBytes === null) {
    return refused("malformed_jws");
  }
  const header = jsonObject(headerBytes);
  if (header === null) return refused("malformed_jws");
  if (header["alg"] !== "ES256") return refused("unsupported_algorithm");

  const chain = decodeChain(header["x5c"]);
  if (chain === null) return refused("malformed_jws");
  if (chain.length !== CHAIN_LENGTH) return refused("unexpected_chain_length");
  const [leafDer, intermediateDer, rootDer] = chain;
  if (
    leafDer === undefined ||
    intermediateDer === undefined ||
    rootDer === undefined
  ) {
    return refused("unexpected_chain_length");
  }
  if (!bytesEqual(rootDer, trustedRoot)) return refused("untrusted_root");

  const leaf = parseX509Certificate(leafDer);
  const intermediate = parseX509Certificate(intermediateDer);
  const root = parseX509Certificate(rootDer);
  if (leaf === null || intermediate === null || root === null) {
    return refused("unreadable_certificate");
  }
  if (
    !bytesEqual(leaf.issuer, intermediate.subject) ||
    !bytesEqual(intermediate.issuer, root.subject)
  ) {
    return refused("broken_chain_link");
  }
  if (
    !leaf.extensionOids.has(OID_LEAF_MARKER) ||
    !intermediate.extensionOids.has(OID_INTERMEDIATE_MARKER) ||
    !intermediate.isCertificateAuthority
  ) {
    return refused("missing_role_marker");
  }
  if (
    !(await issuerSigned(root, intermediate)) ||
    !(await issuerSigned(intermediate, leaf))
  ) {
    return refused("bad_chain_signature");
  }

  // ES256 fixes the curve, so a leaf on any other key cannot verify this header's
  // algorithm even though the chain above allows P-384 links.
  if (leaf.curveOid !== OID_P256) {
    return refused("bad_payload_signature");
  }
  const leafKey = await importCertificateKey(leaf);
  if (leafKey === null) return refused("bad_payload_signature");
  const signedText = new TextEncoder().encode(`${headerText}.${payloadText}`);
  const signatureHolds = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    leafKey,
    signature,
    signedText,
  );
  if (!signatureHolds) return refused("bad_payload_signature");

  const payload = jsonObject(payloadBytes);
  if (payload === null) return refused("malformed_payload");
  const signedDate = payload["signedDate"];
  if (typeof signedDate !== "number") return refused("malformed_payload");
  if (!validAt(leaf, signedDate) || !validAt(intermediate, signedDate)) {
    return refused("certificate_outside_validity");
  }
  return { kind: "verified", payload };
}
