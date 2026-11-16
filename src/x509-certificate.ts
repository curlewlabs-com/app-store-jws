// Strict DER reading of one X.509 certificate into the fields a signature chain
// check needs. Cloudflare Workers has no X.509 API without nodejs_compat, and the
// third-party parsers carry far more than these few fields, so this walks the
// structure itself.
// DER is length-prefixed, so nothing here guesses at a boundary: every element it
// reads is read at its declared tag and length, inside its parent's bounds, and
// a structure it cannot read that way answers null. The input is
// attacker-supplied until a signature proves otherwise, which is why a failure
// is a value rather than a throw.
//
// It is a reader for a chain check, not a validator. It does not hold the
// fields it skips, or the values it reads, to every X.690 rule: INTEGER
// minimality, calendar-valid times, a nested element's trailing content, and
// duplicate extensions all pass. A chain check does not depend on them: every
// field read from a certificate lies inside the tbsCertificate bytes its
// issuer's signature covers, except the signature value itself, which is only
// ever verified. So a malformed field can come only from a certificate its
// issuer signed, and leniency can change which refusal a forgery gets but not
// whether it verifies. Code reading certificates it will not verify against a
// pinned root should not rely on this reader to reject malformed ones.

const TAG_BOOLEAN = 0x01;
const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_UTC_TIME = 0x17;
const TAG_GENERALIZED_TIME = 0x18;
const TAG_SEQUENCE = 0x30;
const TAG_VERSION = 0xa0;
const TAG_EXTENSIONS = 0xa3;

const OID_BASIC_CONSTRAINTS = "2.5.29.19";
// X.509 version 3 is encoded as the integer 2.
const VERSION_3 = 2;

export interface X509Certificate {
  // The exact signed bytes, so a signature is checked against what was sent rather
  // than a re-encoding of it.
  readonly tbsCertificate: Uint8Array<ArrayBuffer>;
  readonly signatureAlgorithmOid: string;
  // The BIT STRING's content: an ASN.1 ECDSA-Sig-Value for the curves used here.
  readonly signature: Uint8Array<ArrayBuffer>;
  // Compared byte for byte to link a certificate to its issuer.
  readonly issuer: Uint8Array<ArrayBuffer>;
  readonly subject: Uint8Array<ArrayBuffer>;
  readonly notBeforeMs: number;
  readonly notAfterMs: number;
  readonly subjectPublicKeyInfo: Uint8Array<ArrayBuffer>;
  readonly curveOid: string;
  readonly extensionOids: ReadonlySet<string>;
  readonly isCertificateAuthority: boolean;
}

interface DerElement {
  readonly content: Uint8Array<ArrayBuffer>;
  // The element including its tag and length, for fields signed or imported whole.
  readonly encoded: Uint8Array<ArrayBuffer>;
}

class DerReader {
  private readonly bytes: Uint8Array<ArrayBuffer>;
  private offset = 0;

  constructor(bytes: Uint8Array<ArrayBuffer>) {
    this.bytes = bytes;
  }

  get exhausted(): boolean {
    return this.offset === this.bytes.length;
  }

  peekTag(): number | undefined {
    return this.bytes[this.offset];
  }

  read(expectedTag: number): DerElement | null {
    const start = this.offset;
    if (this.bytes[start] !== expectedTag) return null;
    const first = this.bytes[start + 1];
    if (first === undefined) return null;
    let length = first;
    let headerLength = 2;
    if (first >= 0x80) {
      const lengthBytes = first & 0x7f;
      // 0x80 is BER's indefinite length, which DER forbids. Four length bytes
      // already exceed any certificate.
      if (lengthBytes === 0 || lengthBytes > 4) return null;
      length = 0;
      for (let i = 0; i < lengthBytes; i++) {
        const byte = this.bytes[start + 2 + i];
        if (byte === undefined) return null;
        length = length * 256 + byte;
      }
      // DER requires the shortest form, so a value that fit in fewer bytes is not
      // DER, and a certificate has exactly one accepted encoding.
      const fitsShortForm = length < 0x80;
      const leadingZero = this.bytes[start + 2] === 0;
      if (fitsShortForm || leadingZero) return null;
      headerLength += lengthBytes;
    }
    const end = start + headerLength + length;
    if (end > this.bytes.length) return null;
    this.offset = end;
    return {
      content: this.bytes.subarray(start + headerLength, end),
      encoded: this.bytes.subarray(start, end),
    };
  }
}

function decodeOid(content: Uint8Array): string | null {
  const subidentifiers: number[] = [];
  let value = 0;
  let started = false;
  for (const byte of content) {
    // A leading 0x80 pads a subidentifier, which DER forbids.
    if (!started && byte === 0x80) return null;
    value = value * 128 + (byte & 0x7f);
    if (!Number.isSafeInteger(value)) return null;
    started = (byte & 0x80) !== 0;
    if (!started) {
      subidentifiers.push(value);
      value = 0;
    }
  }
  const first = subidentifiers[0];
  if (started || first === undefined) return null;
  // The first subidentifier packs the first two arcs as 40 * first + second.
  // The first arc is 0, 1 or 2, and only under 2 can the second exceed 39, so
  // the subidentifier can run to several bytes like any other.
  const firstArc = Math.min(Math.floor(first / 40), 2);
  return [firstArc, first - firstArc * 40, ...subidentifiers.slice(1)].join(
    ".",
  );
}

function readOid(reader: DerReader): string | null {
  const element = reader.read(TAG_OID);
  return element === null ? null : decodeOid(element.content);
}

const MAX_TIME_TEXT_BYTES = 15;
const UTC_TIME_TEXT = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;
const GENERALIZED_TIME_TEXT = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;

function readTimeMs(reader: DerReader): number | null {
  const tag = reader.peekTag();
  if (tag !== TAG_UTC_TIME && tag !== TAG_GENERALIZED_TIME) return null;
  const element = reader.read(tag);
  // Longer than any time this reader accepts, and spreading an attacker-sized
  // element into call arguments would throw rather than refuse.
  if (element === null || element.content.length > MAX_TIME_TEXT_BYTES) {
    return null;
  }
  const text = String.fromCharCode(...element.content);
  const match = (
    tag === TAG_UTC_TIME ? UTC_TIME_TEXT : GENERALIZED_TIME_TEXT
  ).exec(text);
  if (match === null) return null;
  const [, yearText, month, day, hour, minute, second] = match;
  let year = Number(yearText);
  // RFC 5280's UTCTime rule: a two-digit year of 50 or above is in the 1900s.
  if (tag === TAG_UTC_TIME) year += year >= 50 ? 1900 : 2000;
  return Date.UTC(
    year,
    Number(month) - 1,
    Number(day),
    Number(hour),
    Number(minute),
    Number(second),
  );
}

function readBasicConstraintsIsCa(
  extensionValue: Uint8Array<ArrayBuffer>,
): boolean {
  const outer = new DerReader(extensionValue).read(TAG_SEQUENCE);
  if (outer === null) return false;
  const constraints = new DerReader(outer.content);
  // DER leaves a DEFAULT FALSE boolean out, so an absent cA means not a CA.
  if (constraints.peekTag() !== TAG_BOOLEAN) return false;
  const value = constraints.read(TAG_BOOLEAN);
  return value?.content[0] === 0xff;
}

interface Extensions {
  readonly oids: ReadonlySet<string>;
  readonly isCertificateAuthority: boolean;
}

function readExtensions(tbs: DerReader): Extensions | null {
  const wrapper = tbs.read(TAG_EXTENSIONS);
  if (wrapper === null) return null;
  const sequence = new DerReader(wrapper.content).read(TAG_SEQUENCE);
  if (sequence === null) return null;
  const list = new DerReader(sequence.content);
  const oids = new Set<string>();
  let isCertificateAuthority = false;
  while (!list.exhausted) {
    const extension = list.read(TAG_SEQUENCE);
    if (extension === null) return null;
    const fields = new DerReader(extension.content);
    const oid = readOid(fields);
    if (oid === null) return null;
    if (fields.peekTag() === TAG_BOOLEAN && fields.read(TAG_BOOLEAN) === null) {
      return null;
    }
    const value = fields.read(TAG_OCTET_STRING);
    if (value === null) return null;
    oids.add(oid);
    if (oid === OID_BASIC_CONSTRAINTS) {
      isCertificateAuthority = readBasicConstraintsIsCa(value.content);
    }
  }
  return { oids, isCertificateAuthority };
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

export function parseX509Certificate(
  der: Uint8Array<ArrayBuffer>,
): X509Certificate | null {
  const outer = new DerReader(der);
  const certificate = outer.read(TAG_SEQUENCE);
  if (certificate === null || !outer.exhausted) return null;

  const body = new DerReader(certificate.content);
  const tbs = body.read(TAG_SEQUENCE);
  const outerAlgorithm = body.read(TAG_SEQUENCE);
  const signatureBits = body.read(TAG_BIT_STRING);
  if (
    tbs === null ||
    outerAlgorithm === null ||
    signatureBits === null ||
    !body.exhausted
  ) {
    return null;
  }
  // The first content byte counts unused trailing bits, which a signature never has.
  if (signatureBits.content[0] !== 0) return null;
  const signatureAlgorithmOid = readOid(new DerReader(outerAlgorithm.content));
  if (signatureAlgorithmOid === null) return null;

  const fields = new DerReader(tbs.content);
  const version = fields.read(TAG_VERSION);
  if (version === null) return null;
  const versionNumber = new DerReader(version.content).read(TAG_INTEGER);
  if (versionNumber?.content[0] !== VERSION_3) return null;
  if (fields.read(TAG_INTEGER) === null) return null;
  const innerAlgorithm = fields.read(TAG_SEQUENCE);
  const issuer = fields.read(TAG_SEQUENCE);
  const validity = fields.read(TAG_SEQUENCE);
  const subject = fields.read(TAG_SEQUENCE);
  const subjectPublicKeyInfo = fields.read(TAG_SEQUENCE);
  if (
    innerAlgorithm === null ||
    issuer === null ||
    validity === null ||
    subject === null ||
    subjectPublicKeyInfo === null
  ) {
    return null;
  }
  // RFC 5280 requires the signed algorithm to match the unsigned one, which is
  // otherwise free for an attacker to edit.
  if (!bytesEqual(innerAlgorithm.encoded, outerAlgorithm.encoded)) return null;

  const validityFields = new DerReader(validity.content);
  const notBeforeMs = readTimeMs(validityFields);
  const notAfterMs = readTimeMs(validityFields);
  if (notBeforeMs === null || notAfterMs === null) return null;

  const keyInfo = new DerReader(subjectPublicKeyInfo.content).read(
    TAG_SEQUENCE,
  );
  if (keyInfo === null) return null;
  const keyAlgorithm = new DerReader(keyInfo.content);
  if (readOid(keyAlgorithm) === null) return null;
  const curveOid = readOid(keyAlgorithm);
  if (curveOid === null) return null;

  const extensions = readExtensions(fields);
  if (extensions === null || !fields.exhausted) return null;

  return {
    tbsCertificate: tbs.encoded,
    signatureAlgorithmOid,
    signature: signatureBits.content.subarray(1),
    issuer: issuer.encoded,
    subject: subject.encoded,
    notBeforeMs,
    notAfterMs,
    subjectPublicKeyInfo: subjectPublicKeyInfo.encoded,
    curveOid,
    extensionOids: extensions.oids,
    isCertificateAuthority: extensions.isCertificateAuthority,
  };
}

// An ASN.1 ECDSA-Sig-Value as the fixed-width r || s Web Crypto verifies, or null
// when it is not one. Each integer has its sign padding removed and is left-padded
// to the curve's width.
export function ecdsaSignatureToRaw(
  der: Uint8Array<ArrayBuffer>,
  componentBytes: number,
): Uint8Array<ArrayBuffer> | null {
  const outer = new DerReader(der);
  const sequence = outer.read(TAG_SEQUENCE);
  if (sequence === null || !outer.exhausted) return null;
  const parts = new DerReader(sequence.content);
  const r = parts.read(TAG_INTEGER);
  const s = parts.read(TAG_INTEGER);
  if (r === null || s === null || !parts.exhausted) return null;
  const raw = new Uint8Array(componentBytes * 2);
  for (const [index, integer] of [r, s].entries()) {
    let value = integer.content;
    while (value.length > 1 && value[0] === 0) value = value.subarray(1);
    if (value.length > componentBytes) return null;
    raw.set(value, componentBytes * (index + 1) - value.length);
  }
  return raw;
}
