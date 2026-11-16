// The DER reader sits in front of every App Store signature check and reads
// bytes a stranger chose, so these cases hold it to reading Apple's real
// certificates correctly and to refusing anything that is not strict DER rather
// than guessing, because a certificate that parses more than one way is how
// signature checks get bypassed.

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { appleRootCertificate } from "../src/apple-signed-data.ts";
import {
  ecdsaSignatureToRaw,
  parseX509Certificate,
} from "../src/x509-certificate.ts";
import { REAL_WWDR_G6, TEST_ROOT } from "./fixture.ts";

const OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
const OID_P384 = "1.3.132.0.34";
const OID_INTERMEDIATE_MARKER = "1.2.840.113635.100.6.2.1";

function requireParsed(der: Uint8Array<ArrayBuffer>) {
  const certificate = parseX509Certificate(der);
  if (certificate === null) throw new Error("certificate did not parse");
  return certificate;
}

describe("Apple's published certificates", () => {
  it("reads the root and the WWDR G6 intermediate as OpenSSL does", () => {
    const root = requireParsed(appleRootCertificate());
    assert.equal(root.signatureAlgorithmOid, OID_ECDSA_SHA384);
    assert.equal(root.curveOid, OID_P384);
    assert.equal(root.isCertificateAuthority, true);
    assert.equal(root.notBeforeMs, Date.UTC(2014, 3, 30, 18, 19, 6));
    assert.equal(root.notAfterMs, Date.UTC(2039, 3, 30, 18, 19, 6));

    const intermediate = requireParsed(REAL_WWDR_G6);
    assert.deepEqual(intermediate.issuer, root.subject);
    assert.equal(intermediate.extensionOids.has(OID_INTERMEDIATE_MARKER), true);
    assert.equal(intermediate.isCertificateAuthority, true);
    assert.equal(intermediate.notAfterMs, Date.UTC(2036, 2, 19, 0, 0, 0));
  });

  // The whole path a chain link takes - the signed bytes, the key, the
  // signature conversion - against a signature Apple actually made. Generated
  // fixtures cannot show the reader slices Apple's encoding at the right
  // offsets.
  it("verifies Apple's own signature over the intermediate", async () => {
    const root = requireParsed(appleRootCertificate());
    const intermediate = requireParsed(REAL_WWDR_G6);
    const key = await crypto.subtle.importKey(
      "spki",
      root.subjectPublicKeyInfo,
      { name: "ECDSA", namedCurve: "P-384" },
      false,
      ["verify"],
    );
    const signature = ecdsaSignatureToRaw(intermediate.signature, 48);
    if (signature === null) throw new Error("signature did not convert");
    const verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-384" },
      key,
      signature,
      intermediate.tbsCertificate,
    );
    assert.equal(verified, true);

    const flipped = intermediate.tbsCertificate.slice();
    flipped[20] = (flipped[20] ?? 0) ^ 1;
    const tampered = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-384" },
      key,
      signature,
      flipped,
    );
    assert.equal(tampered, false);
  });
});

describe("refusing what is not strict DER", () => {
  const der = TEST_ROOT;

  function withOuterLength(lengthBytes: number[]): Uint8Array<ArrayBuffer> {
    const header = der[1] === undefined ? 0 : der[1];
    const start = header >= 0x80 ? 2 + (header & 0x7f) : 2;
    return Uint8Array.from([0x30, ...lengthBytes, ...der.subarray(start)]);
  }

  it("parses the unmodified input the cases below start from", () => {
    assert.notEqual(parseX509Certificate(der), null);
  });

  it("refuses a truncated certificate", () => {
    assert.equal(parseX509Certificate(der.subarray(0, der.length - 1)), null);
  });

  it("refuses trailing bytes, which would give one certificate two encodings", () => {
    assert.equal(parseX509Certificate(Uint8Array.from([...der, 0])), null);
  });

  it("refuses an indefinite length, which is BER and not DER", () => {
    assert.equal(parseX509Certificate(withOuterLength([0x80])), null);
  });

  it("refuses a length in more bytes than it needs", () => {
    const length = der.length - 4;
    const padded = [0x83, 0, Math.floor(length / 256), length % 256];
    assert.equal(parseX509Certificate(withOuterLength(padded)), null);
  });

  it("refuses a length running past the end of the input", () => {
    assert.equal(
      parseX509Certificate(withOuterLength([0x82, 0xff, 0xff])),
      null,
    );
  });

  it("refuses an empty input and random bytes without throwing", () => {
    assert.equal(parseX509Certificate(new Uint8Array(0)), null);
    assert.equal(parseX509Certificate(Uint8Array.from([1, 2, 3, 4])), null);
  });
});

describe("ecdsaSignatureToRaw", () => {
  it("pads a short integer and strips a sign byte to the curve's width", () => {
    const der = Uint8Array.from([
      0x30, 0x08, 0x02, 0x01, 0x05, 0x02, 0x03, 0x00, 0x80, 0x01,
    ]);
    assert.deepEqual(
      ecdsaSignatureToRaw(der, 4),
      Uint8Array.from([0, 0, 0, 5, 0, 0, 0x80, 1]),
    );
  });

  it("refuses an integer wider than the curve", () => {
    const der = Uint8Array.from([
      0x30, 0x08, 0x02, 0x03, 1, 2, 3, 0x02, 0x01, 0x05,
    ]);
    assert.equal(ecdsaSignatureToRaw(der, 2), null);
  });
});
