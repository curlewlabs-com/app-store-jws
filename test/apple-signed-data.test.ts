// A receiver of App Store notifications is a public endpoint, so these cases are
// the forgeries verifyAppleSignedData has to stop. The marker cases matter most:
// Apple's WWDR intermediates also issue ordinary developer certificates, so a
// chain that reaches Apple's root is something anyone in the Apple Developer
// Program can build.

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  appleRootCertificate,
  unverifiedAppleClaims,
  verifyAppleSignedData,
} from "../src/apple-signed-data.ts";
import {
  jwsPart,
  signAsAppleTest,
  TEST_CHAIN,
  TEST_CHAIN_VALID_AT_MS,
  TEST_ROOT,
} from "./fixture.ts";

const payload = { signedDate: TEST_CHAIN_VALID_AT_MS, hello: "world" };

function verifyTest(jws: string) {
  return verifyAppleSignedData(jws, TEST_ROOT);
}

describe("verifyAppleSignedData", () => {
  it("returns the payload of a chain ending at the trusted root", async () => {
    assert.deepEqual(await verifyTest(await signAsAppleTest(payload)), {
      kind: "verified",
      payload,
    });
  });

  it("refuses a well-made chain ending anywhere but Apple's real root", async () => {
    const forged = await signAsAppleTest(payload);
    assert.deepEqual(
      await verifyAppleSignedData(forged, appleRootCertificate()),
      { kind: "refused", reason: "untrusted_root" },
    );
  });

  it("refuses a payload edited after signing", async () => {
    const [header, , signature] = (await signAsAppleTest(payload)).split(".");
    const edited = `${header}.${jwsPart({ ...payload, hello: "mars" })}.${signature}`;
    assert.deepEqual(await verifyTest(edited), {
      kind: "refused",
      reason: "bad_payload_signature",
    });
  });

  it("refuses a signature of the wrong length without throwing", async () => {
    const [header, body] = (await signAsAppleTest(payload)).split(".");
    assert.deepEqual(await verifyTest(`${header}.${body}.AAAA`), {
      kind: "refused",
      reason: "bad_payload_signature",
    });
  });

  // A developer certificate chains to the root through the same intermediate.
  it("refuses a leaf without the App Store signing marker", async () => {
    const jws = await signAsAppleTest(payload, TEST_CHAIN.leafWithoutMarker);
    assert.deepEqual(await verifyTest(jws), {
      kind: "refused",
      reason: "missing_role_marker",
    });
  });

  it("refuses an intermediate without its marker", async () => {
    const jws = await signAsAppleTest(
      payload,
      TEST_CHAIN.intermediateWithoutMarker,
    );
    assert.deepEqual(await verifyTest(jws), {
      kind: "refused",
      reason: "missing_role_marker",
    });
  });

  // The classic chain attack: an end-entity certificate acting as an issuer.
  it("refuses an intermediate that is not a CA", async () => {
    const jws = await signAsAppleTest(payload, TEST_CHAIN.intermediateNotCa);
    assert.deepEqual(await verifyTest(jws), {
      kind: "refused",
      reason: "missing_role_marker",
    });
  });

  it("refuses a chain of any other length", async () => {
    const jws = await signAsAppleTest(payload, TEST_CHAIN.noIntermediate);
    assert.deepEqual(await verifyTest(jws), {
      kind: "refused",
      reason: "unexpected_chain_length",
    });
  });

  // Choosing the algorithm in the header is how `alg: none` forgeries work.
  it("refuses any algorithm but ES256", async () => {
    const jws = await signAsAppleTest(payload, TEST_CHAIN.good, "none");
    assert.deepEqual(await verifyTest(jws), {
      kind: "refused",
      reason: "unsupported_algorithm",
    });
  });

  it("refuses a payload dated outside the certificates' validity", async () => {
    const jws = await signAsAppleTest({ signedDate: Date.UTC(2020, 0, 1) });
    assert.deepEqual(await verifyTest(jws), {
      kind: "refused",
      reason: "certificate_outside_validity",
    });
  });

  it("refuses a signed payload with no signedDate to judge it at", async () => {
    const jws = await signAsAppleTest({ hello: "world" });
    assert.deepEqual(await verifyTest(jws), {
      kind: "refused",
      reason: "malformed_payload",
    });
  });

  it("answers text that is no JWS with a refusal, not a throw", async () => {
    for (const junk of ["", "a.b", "a.b.c.d", "!!.@@.##", "e30.e30.e30"]) {
      const result = await verifyTest(junk);
      assert.equal(result.kind, "refused");
    }
  });
});

// Reading without verifying is the documented hazard of this function, so the
// case that matters is that it reads a forgery as readily as a real payload:
// nothing about its answer may be taken as checked.
describe("unverifiedAppleClaims", () => {
  it("reads the claims of a JWS that would not verify", async () => {
    const [header, , signature] = (await signAsAppleTest(payload)).split(".");
    const forged = `${header}.${jwsPart({ transactionId: "1" })}.${signature}`;
    assert.deepEqual(unverifiedAppleClaims(forged), { transactionId: "1" });
  });

  it("answers null for text that is no JWS carrying a JSON object", () => {
    for (const junk of [
      "",
      "a.b",
      "a.b.c.d",
      "!!.@@.##",
      `x.${jwsPart([1])}.y`,
    ]) {
      assert.equal(unverifiedAppleClaims(junk), null);
    }
  });
});
