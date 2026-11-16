// Strict DER reading of one X.509 certificate into the fields a signature chain
// check needs. Cloudflare Workers has no X.509 API without nodejs_compat, and the
// third-party parsers carry far more than these few fields, so this walks the
// structure itself.
// DER gives every value exactly one encoding, and this reader accepts only that
// one: every element it reads is read at its declared tag and length, inside
// its parent's bounds, with nothing after the last element a structure
// defines, and every value it reads is held to X.690's DER rules - minimal
// non-negative INTEGERs, one-byte BOOLEANs, no DEFAULT value written out,
// calendar-valid times. A structure it cannot read that way answers null.
// A certificate that parses more than one way is how signature checks get
// bypassed, and the input is attacker-supplied until a signature proves
// otherwise, which is also why a failure is a value rather than a throw.
//
// It reads the fields a chain check needs, and no more. Names are carried as
// their encoded bytes and compared whole, and the values of extensions other
// than basicConstraints are skipped; it judges neither.

const TAG_BOOLEAN = 0x01;
const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_UTC_TIME = 0x17;
const TAG_GENERALIZED_TIME = 0x18;
const TAG_SEQUENCE = 0x30;
// The low five bits all set mean a tag continued in further bytes, which no
// certificate field uses.
const TAG_NUMBER_CONTINUES = 0x1f;
const TAG_VERSION = 0xa0;
const TAG_EXTENSIONS = 0xa3;

const OID_BASIC_CONSTRAINTS = "2.5.29.19";
// X.509 version 3 is encoded as the integer 2.
const VERSION_3 = 2;

export interface X509Certificate {
  // The exact signed bytes, so a signature is checked against what was sent rather
  // than a re-encoding of it.
  readonly tbsCertificate: Uint8Array;
  readonly signatureAlgorithmOid: string;
  // The BIT STRING's content: an ASN.1 ECDSA-Sig-Value for the curves used here.
  readonly signature: Uint8Array;
  // Compared byte for byte to link a certificate to its issuer.
  readonly issuer: Uint8Array;
  readonly subject: Uint8Array;
  readonly notBeforeMs: number;
  readonly notAfterMs: number;
  readonly subjectPublicKeyInfo: Uint8Array;
  readonly curveOid: string;
  readonly extensionOids: ReadonlySet<string>;
  readonly isCertificateAuthority: boolean;
}

interface DerElement {
  readonly content: Uint8Array;
  // The element including its tag and length, for fields signed or imported whole.
  readonly encoded: Uint8Array;
}

class DerReader {
  private readonly bytes: Uint8Array;
  private offset = 0;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  get exhausted(): boolean {
    return this.offset === this.bytes.length;
  }

  peekTag(): number | undefined {
    return this.bytes[this.offset];
  }

  // The next element whatever its tag, for an ANY field.
  readAny(): DerElement | null {
    const tag = this.peekTag();
    if (
      tag === undefined ||
      (tag & TAG_NUMBER_CONTINUES) === TAG_NUMBER_CONTINUES
    ) {
      return null;
    }
    return this.read(tag);
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

// The one element `bytes` holds: content after it would give the structure a
// second encoding.
function readSole(bytes: Uint8Array, tag: number): DerElement | null {
  const reader = new DerReader(bytes);
  const element = reader.read(tag);
  return element !== null && reader.exhausted ? element : null;
}

// An INTEGER's value as unsigned big-endian bytes, its sign byte removed, or
// null when it is negative or not in its shortest two's-complement form.
function readNonNegativeInteger(reader: DerReader): Uint8Array | null {
  const element = reader.read(TAG_INTEGER);
  if (element === null) return null;
  const [first, second] = element.content;
  if (first === undefined || first >= 0x80) return null;
  if (first === 0 && second !== undefined) {
    // A zero byte is there only to keep a high bit from reading as a sign.
    return second >= 0x80 ? element.content.subarray(1) : null;
  }
  return element.content;
}

function readBoolean(reader: DerReader): boolean | null {
  const element = reader.read(TAG_BOOLEAN);
  if (element === null || element.content.length !== 1) return null;
  const value = element.content[0];
  if (value === 0xff) return true;
  return value === 0 ? false : null;
}

// A BOOLEAN DEFAULT FALSE field. DER leaves a default out, so an absent field
// is false and a written-out FALSE is not DER.
function readDefaultFalse(reader: DerReader): boolean | null {
  if (reader.peekTag() !== TAG_BOOLEAN) return false;
  return readBoolean(reader) === true ? true : null;
}

// An AlgorithmIdentifier: the algorithm's OID, then at most one parameters
// element of whatever type the algorithm defines.
function readAlgorithm(
  content: Uint8Array,
): { oid: string; parameters: DerElement | null } | null {
  const fields = new DerReader(content);
  const oid = readOid(fields);
  if (oid === null) return null;
  const parameters = fields.exhausted ? null : fields.readAny();
  if (!fields.exhausted) return null;
  return { oid, parameters };
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

function decodeOidElement(element: DerElement): string | null {
  return element.encoded[0] === TAG_OID ? decodeOid(element.content) : null;
}

const MAX_TIME_TEXT_BYTES = 15;
const UTC_TIME_TEXT = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;
const GENERALIZED_TIME_TEXT = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function daysInMonth(year: number, month: number): number {
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  return month === 2 && leap ? 29 : (DAYS_IN_MONTH[month - 1] ?? 0);
}

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
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
  if (
    year === undefined ||
    month === undefined ||
    day === undefined ||
    hour === undefined ||
    minute === undefined ||
    second === undefined
  ) {
    return null;
  }
  // RFC 5280's UTCTime rule: a two-digit year of 50 or above is in the 1900s.
  const fullYear =
    tag === TAG_UTC_TIME ? year + (year >= 50 ? 1900 : 2000) : year;
  // Date.UTC would carry an out-of-range field into the next one, reading
  // 31 February as 3 March, so each field is held to its own range here.
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth(fullYear, month) ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return null;
  }
  // Date.UTC reads a year below 100 as 19xx; setUTCFullYear takes it as given.
  const date = new Date(0);
  date.setUTCFullYear(fullYear, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  return date.getTime();
}

// basicConstraints' cA, or null when the value is not its DER encoding.
function readBasicConstraintsIsCa(extensionValue: Uint8Array): boolean | null {
  const sequence = readSole(extensionValue, TAG_SEQUENCE);
  if (sequence === null) return null;
  const constraints = new DerReader(sequence.content);
  const isCa = readDefaultFalse(constraints);
  if (isCa === null) return null;
  if (
    constraints.peekTag() === TAG_INTEGER &&
    readNonNegativeInteger(constraints) === null
  ) {
    return null;
  }
  return constraints.exhausted ? isCa : null;
}

interface Extensions {
  readonly oids: ReadonlySet<string>;
  readonly isCertificateAuthority: boolean;
}

function readExtensions(tbs: DerReader): Extensions | null {
  const wrapper = tbs.read(TAG_EXTENSIONS);
  if (wrapper === null) return null;
  const sequence = readSole(wrapper.content, TAG_SEQUENCE);
  // X.509 gives the list SIZE (1..MAX): present means at least one.
  if (sequence === null || sequence.content.length === 0) return null;
  const list = new DerReader(sequence.content);
  const oids = new Set<string>();
  let isCertificateAuthority = false;
  while (!list.exhausted) {
    const extension = list.read(TAG_SEQUENCE);
    if (extension === null) return null;
    const fields = new DerReader(extension.content);
    const oid = readOid(fields);
    // RFC 5280 allows one instance of an extension, and with two the
    // certificate would say two things about the same field.
    if (oid === null || oids.has(oid)) return null;
    if (readDefaultFalse(fields) === null) return null;
    const value = fields.read(TAG_OCTET_STRING);
    if (value === null || !fields.exhausted) return null;
    oids.add(oid);
    if (oid === OID_BASIC_CONSTRAINTS) {
      const isCa = readBasicConstraintsIsCa(value.content);
      if (isCa === null) return null;
      isCertificateAuthority = isCa;
    }
  }
  return { oids, isCertificateAuthority };
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

export function parseX509Certificate(der: Uint8Array): X509Certificate | null {
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
  const signatureAlgorithm = readAlgorithm(outerAlgorithm.content);
  if (signatureAlgorithm === null) return null;

  const fields = new DerReader(tbs.content);
  const version = fields.read(TAG_VERSION);
  if (version === null) return null;
  const versionFields = new DerReader(version.content);
  const versionNumber = readNonNegativeInteger(versionFields);
  if (
    versionNumber?.length !== 1 ||
    versionNumber[0] !== VERSION_3 ||
    !versionFields.exhausted
  ) {
    return null;
  }
  // The serial number is only read past, but it is held to DER like the rest.
  if (readNonNegativeInteger(fields) === null) return null;
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
  if (
    notBeforeMs === null ||
    notAfterMs === null ||
    !validityFields.exhausted
  ) {
    return null;
  }

  const keyFields = new DerReader(subjectPublicKeyInfo.content);
  const keyAlgorithmElement = keyFields.read(TAG_SEQUENCE);
  const publicKey = keyFields.read(TAG_BIT_STRING);
  if (
    keyAlgorithmElement === null ||
    publicKey === null ||
    !keyFields.exhausted ||
    // A key is whole bytes after the unused-bits count, and there must be one.
    publicKey.content.length < 2 ||
    publicKey.content[0] !== 0
  ) {
    return null;
  }
  // An EC key's parameters name its curve.
  const keyAlgorithm = readAlgorithm(keyAlgorithmElement.content);
  if (keyAlgorithm?.parameters == null) return null;
  const curveOid = decodeOidElement(keyAlgorithm.parameters);
  if (curveOid === null) return null;

  const extensions = readExtensions(fields);
  if (extensions === null || !fields.exhausted) return null;

  return {
    tbsCertificate: tbs.encoded,
    signatureAlgorithmOid: signatureAlgorithm.oid,
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
// when it is not one in DER. Each integer has its sign padding removed and is
// left-padded to the curve's width.
export function ecdsaSignatureToRaw(
  der: Uint8Array,
  componentBytes: number,
): Uint8Array | null {
  const outer = new DerReader(der);
  const sequence = outer.read(TAG_SEQUENCE);
  if (sequence === null || !outer.exhausted) return null;
  const parts = new DerReader(sequence.content);
  const r = readNonNegativeInteger(parts);
  const s = readNonNegativeInteger(parts);
  if (r === null || s === null || !parts.exhausted) return null;
  const raw = new Uint8Array(componentBytes * 2);
  for (const [index, value] of [r, s].entries()) {
    if (value.length > componentBytes) return null;
    raw.set(value, componentBytes * (index + 1) - value.length);
  }
  return raw;
}
