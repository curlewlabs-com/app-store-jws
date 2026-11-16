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
import {
  REAL_APP_STORE_LEAVES,
  REAL_WWDR_G6,
  TEST_LEAF,
  TEST_ROOT,
} from "./fixture.ts";

const OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
const OID_P384 = "1.3.132.0.34";
const OID_INTERMEDIATE_MARKER = "1.2.840.113635.100.6.2.1";
const OID_APP_STORE_MARKER = "1.2.840.113635.100.6.11.1";

function requireParsed(der: Uint8Array) {
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

  // The strict reader's test against Apple's own encoding: a production leaf
  // it refused would be every genuine notification refused.
  it("reads Apple's production App Store leaves, each signed by WWDR G6", async () => {
    const intermediate = requireParsed(REAL_WWDR_G6);
    const key = await crypto.subtle.importKey(
      "spki",
      intermediate.subjectPublicKeyInfo,
      { name: "ECDSA", namedCurve: "P-384" },
      false,
      ["verify"],
    );
    for (const expected of REAL_APP_STORE_LEAVES) {
      const leaf = requireParsed(expected.der);
      assert.deepEqual(leaf.issuer, intermediate.subject);
      assert.equal(leaf.extensionOids.has(OID_APP_STORE_MARKER), true);
      assert.equal(leaf.isCertificateAuthority, false);
      assert.equal(leaf.notBeforeMs, expected.notBeforeMs);
      assert.equal(leaf.notAfterMs, expected.notAfterMs);
      const signature = ecdsaSignatureToRaw(leaf.signature, 48);
      if (signature === null) throw new Error("signature did not convert");
      const verified = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-384" },
        key,
        signature,
        leaf.tbsCertificate,
      );
      assert.equal(verified, true);
    }
  });
});

describe("object identifiers", () => {
  // OpenSSL encodes 2.999.1 with a two-byte first subidentifier (88 37), which
  // a reader that takes that subidentifier as one byte names 2.56.55.1.
  it("decodes a first subidentifier longer than one byte", () => {
    const leaf = requireParsed(TEST_LEAF);
    assert.equal(leaf.extensionOids.has("2.999.1"), true);
    assert.equal(leaf.extensionOids.has("1.2.840.113635.100.6.11.1"), true);
  });
});

describe("refusing what is not strict DER", () => {
  const der = TEST_ROOT;

  function withOuterLength(lengthBytes: number[]): Uint8Array {
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

// Certificates built element by element, so each case below differs from a
// baseline that parses by exactly one encoding DER forbids. Every one of them
// must be refused: a reader that accepted a second encoding of a field would
// let two parses of one certificate disagree. Nothing here is signed, because
// parsing comes before any signature is checked.
function tlv(tag: number, ...parts: number[][]): number[] {
  const content = parts.flat();
  const length = content.length;
  const header =
    length < 0x80
      ? [length]
      : length < 0x100
        ? [0x81, length]
        : [0x82, length >> 8, length & 0xff];
  return [tag, ...header, ...content];
}

const OID_BYTES = {
  ecdsaWithSha256: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
  ecPublicKey: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
  p256: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
  basicConstraints: [0x55, 0x1d, 0x13],
  keyUsage: [0x55, 0x1d, 0x0f],
};
const oid = (bytes: number[]) => tlv(0x06, bytes);
const sequence = (...parts: number[][]) => tlv(0x30, ...parts);
const TRUE = tlv(0x01, [0xff]);
const utcTime = (text: string) =>
  tlv(
    0x17,
    [...text].map((c) => c.charCodeAt(0)),
  );
const generalizedTime = (text: string) =>
  tlv(
    0x18,
    [...text].map((c) => c.charCodeAt(0)),
  );
const extension = (oidBytes: number[], ...rest: number[][]) =>
  sequence(oid(oidBytes), ...rest);

interface CertificateParts {
  version: number[];
  serial: number[];
  algorithm: number[];
  validity: number[];
  publicKeyInfo: number[];
  extensions: number[];
}

const BASELINE: CertificateParts = {
  version: tlv(0xa0, tlv(0x02, [0x02])),
  serial: tlv(0x02, [0x00, 0x80]),
  algorithm: sequence(oid(OID_BYTES.ecdsaWithSha256)),
  validity: sequence(utcTime("260101000000Z"), utcTime("460101000000Z")),
  publicKeyInfo: sequence(
    sequence(oid(OID_BYTES.ecPublicKey), oid(OID_BYTES.p256)),
    tlv(0x03, [0x00, 0x04, ...new Array<number>(64).fill(1)]),
  ),
  extensions: tlv(
    0xa3,
    sequence(
      extension(OID_BYTES.basicConstraints, TRUE, tlv(0x04, sequence(TRUE))),
    ),
  ),
};

function certificate(changes: Partial<CertificateParts> = {}): Uint8Array {
  const parts = { ...BASELINE, ...changes };
  const name = sequence();
  const tbs = sequence(
    parts.version,
    parts.serial,
    parts.algorithm,
    name,
    parts.validity,
    name,
    parts.publicKeyInfo,
    parts.extensions,
  );
  return Uint8Array.from(
    sequence(tbs, parts.algorithm, tlv(0x03, [0x00, 0x30, 0x00])),
  );
}

function withExtensions(...extensions: number[][]): Partial<CertificateParts> {
  return { extensions: tlv(0xa3, sequence(...extensions)) };
}

describe("refusing a field encoded any way but DER's one way", () => {
  it("reads the baseline the cases below each change in one place", () => {
    const parsed = requireParsed(certificate());
    assert.equal(parsed.isCertificateAuthority, true);
    assert.equal(parsed.curveOid, "1.2.840.10045.3.1.7");
    assert.equal(parsed.notBeforeMs, Date.UTC(2026, 0, 1));
  });

  const refused: Record<string, Partial<CertificateParts>> = {
    "a version padded with a zero byte": {
      version: tlv(0xa0, tlv(0x02, [0x00, 0x02])),
    },
    "content after the version": {
      version: tlv(0xa0, tlv(0x02, [0x02]), tlv(0x05, [])),
    },
    "a negative serial number": { serial: tlv(0x02, [0x80]) },
    "a serial number padded with a zero byte": {
      serial: tlv(0x02, [0x00, 0x01]),
    },
    "an empty serial number": { serial: tlv(0x02, []) },
    "a BOOLEAN two bytes long": withExtensions(
      extension(
        OID_BYTES.basicConstraints,
        tlv(0x01, [0xff, 0xff]),
        tlv(0x04, sequence(TRUE)),
      ),
    ),
    "a BOOLEAN that is neither 00 nor FF": withExtensions(
      extension(
        OID_BYTES.basicConstraints,
        TRUE,
        tlv(0x04, sequence(tlv(0x01, [0x01]))),
      ),
    ),
    "a critical flag written out as FALSE, its default": withExtensions(
      extension(
        OID_BYTES.basicConstraints,
        tlv(0x01, [0x00]),
        tlv(0x04, sequence(TRUE)),
      ),
    ),
    "a cA written out as FALSE, its default": withExtensions(
      extension(
        OID_BYTES.basicConstraints,
        TRUE,
        tlv(0x04, sequence(tlv(0x01, [0x00]))),
      ),
    ),
    "content after basicConstraints' fields": withExtensions(
      extension(
        OID_BYTES.basicConstraints,
        TRUE,
        tlv(0x04, sequence(TRUE, tlv(0x05, []))),
      ),
    ),
    "content after basicConstraints' SEQUENCE": withExtensions(
      extension(
        OID_BYTES.basicConstraints,
        TRUE,
        tlv(0x04, sequence(TRUE), tlv(0x05, [])),
      ),
    ),
    "content after an extension's value": withExtensions(
      extension(
        OID_BYTES.basicConstraints,
        TRUE,
        tlv(0x04, sequence(TRUE)),
        tlv(0x05, []),
      ),
    ),
    "the same extension twice": withExtensions(
      extension(OID_BYTES.keyUsage, tlv(0x04, [0x03, 0x02, 0x01, 0x06])),
      extension(OID_BYTES.keyUsage, tlv(0x04, [0x03, 0x02, 0x01, 0x06])),
    ),
    "an empty extensions list": withExtensions(),
    "a third time in the validity": {
      validity: sequence(
        utcTime("260101000000Z"),
        utcTime("460101000000Z"),
        utcTime("460101000000Z"),
      ),
    },
    // Signed and unsigned algorithms still match, so only the trailing
    // content can refuse it.
    "content after an algorithm's parameters": {
      algorithm: sequence(
        oid(OID_BYTES.ecdsaWithSha256),
        tlv(0x05, []),
        tlv(0x05, []),
      ),
    },
    "a key's algorithm with no curve": {
      publicKeyInfo: sequence(
        sequence(oid(OID_BYTES.ecPublicKey)),
        tlv(0x03, [0x00, 0x04, 0x01]),
      ),
    },
    "a SubjectPublicKeyInfo without its key": {
      publicKeyInfo: sequence(
        sequence(oid(OID_BYTES.ecPublicKey), oid(OID_BYTES.p256)),
      ),
    },
    "a key with unused bits": {
      publicKeyInfo: sequence(
        sequence(oid(OID_BYTES.ecPublicKey), oid(OID_BYTES.p256)),
        tlv(0x03, [0x01, 0x04, 0x02]),
      ),
    },
    "content after the key": {
      publicKeyInfo: sequence(
        sequence(oid(OID_BYTES.ecPublicKey), oid(OID_BYTES.p256)),
        tlv(0x03, [0x00, 0x04, 0x01]),
        tlv(0x05, []),
      ),
    },
    // Date.UTC would read these as 3 March and the next day's midnight.
    "31 February": {
      validity: sequence(utcTime("260231000000Z"), utcTime("460101000000Z")),
    },
    "hour 24": {
      validity: sequence(utcTime("260101240000Z"), utcTime("460101000000Z")),
    },
    "month 13": {
      validity: sequence(utcTime("261301000000Z"), utcTime("460101000000Z")),
    },
  };

  for (const [defect, changes] of Object.entries(refused)) {
    it(`refuses ${defect}`, () => {
      assert.equal(parseX509Certificate(certificate(changes)), null);
    });
  }

  it("reads 29 February in a leap year", () => {
    const parsed = requireParsed(
      certificate({
        validity: sequence(utcTime("280229000000Z"), utcTime("460101000000Z")),
      }),
    );
    assert.equal(parsed.notBeforeMs, Date.UTC(2028, 1, 29));
  });

  // Date.UTC maps a year below 100 into the 1900s.
  it("reads a GeneralizedTime year below 100 as written", () => {
    const parsed = requireParsed(
      certificate({
        validity: sequence(
          generalizedTime("00500101000000Z"),
          utcTime("460101000000Z"),
        ),
      }),
    );
    const year50 = new Date(0);
    year50.setUTCFullYear(50, 0, 1);
    assert.equal(parsed.notBeforeMs, year50.getTime());
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

  // r and s are positive by definition, so a sign byte or padding is a second
  // encoding of the same signature.
  it("refuses an integer that is negative, padded or empty", () => {
    const signatureWith = (r: number[]) =>
      Uint8Array.from(sequence(tlv(0x02, r), tlv(0x02, [0x05])));
    assert.notEqual(ecdsaSignatureToRaw(signatureWith([0x05]), 4), null);
    for (const r of [[0x80], [0x00, 0x05], []]) {
      assert.equal(ecdsaSignatureToRaw(signatureWith(r), 4), null);
    }
  });
});
