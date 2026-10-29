import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  RECEIPT_CANONICAL_VERSION,
  buildReceiptEnvelope,
  receiptSignerInfo,
  resetReceiptKeyCache,
  signReceiptEnvelope,
  trustedReceiptKeys,
  verifyReceiptProof,
} from "../src/domain/receipt-integrity.js";

// Keys are generated per run and only ever live in this process's memory.
function freshKey(keyId) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    keyId,
    privateB64: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
    publicB64: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
  };
}

const KEY_ENV = [
  "RECEIPT_SIGNING_KEY_ID",
  "RECEIPT_SIGNING_PRIVATE_KEY_B64",
  "RECEIPT_SIGNING_PUBLIC_KEY_B64",
  "RECEIPT_RETIRED_PUBLIC_KEYS_JSON",
];
const savedEnv = Object.fromEntries(KEY_ENV.map((name) => [name, process.env[name]]));

function useKeys(active, retired = []) {
  process.env.RECEIPT_SIGNING_KEY_ID = active.keyId;
  process.env.RECEIPT_SIGNING_PRIVATE_KEY_B64 = active.privateB64;
  process.env.RECEIPT_SIGNING_PUBLIC_KEY_B64 = active.publicB64;
  if (retired.length) {
    process.env.RECEIPT_RETIRED_PUBLIC_KEYS_JSON = JSON.stringify(
      Object.fromEntries(retired.map((key) => [key.keyId, key.publicB64])),
    );
  } else {
    delete process.env.RECEIPT_RETIRED_PUBLIC_KEYS_JSON;
  }
  resetReceiptKeyCache();
}

test.afterEach(() => {
  for (const [name, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  resetReceiptKeyCache();
});

function signedProof(description) {
  const signer = receiptSignerInfo();
  const envelope = buildReceiptEnvelope({
    id: "11111111-1111-4111-8111-111111111111",
    tenant_id: "22222222-2222-4222-8222-222222222222",
    evidence_id: "33333333-3333-4333-8333-333333333333",
    receipt_type: "artifact",
    uri: null,
    source_digest: null,
    description,
    grade: "B",
    is_demo: false,
    intent_token_id: null,
    external_reference: null,
    reversal_of: null,
    metadata: {},
    chain_sequence: 1,
    previous_hash: null,
    created_by: null,
    correlation_id: null,
    created_at: "2026-10-29T00:00:00.000Z",
    integrity_origin: "native-v1",
    canonical_version: RECEIPT_CANONICAL_VERSION,
    key_id: signer.key_id,
    signing_key_fingerprint: signer.fingerprint,
  });
  const signed = signReceiptEnvelope(envelope);
  return {
    envelope,
    receipt_hash: signed.receipt_hash,
    signature: signed.signature,
    signature_algorithm: signed.signature_algorithm,
    key_id: signed.key_id,
    signing_key_fingerprint: signed.signing_key_fingerprint,
    public_key_b64: signed.public_key_b64,
  };
}

test("rotation: a receipt signed with the old key still verifies", () => {
  const oldKey = freshKey("rotation-old");
  const newKey = freshKey("rotation-new");
  useKeys(oldKey);
  const proof = signedProof("Signed before rotation");

  useKeys(newKey, [oldKey]);
  const result = verifyReceiptProof(proof, { trustedKeys: trustedReceiptKeys() });
  assert.equal(result.verified, true);
  assert.equal(result.checks.key_trusted, true);
  assert.equal(proof.key_id, "rotation-old");
});

test("rotation: dropping the old key from the retired list makes its receipts untrusted", () => {
  const oldKey = freshKey("rotation-old");
  const newKey = freshKey("rotation-new");
  useKeys(oldKey);
  const proof = signedProof("Signed before rotation");

  useKeys(newKey);
  const result = verifyReceiptProof(proof, { trustedKeys: trustedReceiptKeys() });
  assert.equal(result.verified, false);
  assert.equal(result.checks.key_trusted, false);
  assert.equal(result.checks.signature, true, "the signature itself is still mathematically valid");
});

test("rotation: new receipts carry the new key ID", () => {
  const oldKey = freshKey("rotation-old");
  const newKey = freshKey("rotation-new");
  useKeys(newKey, [oldKey]);

  const proof = signedProof("Signed after rotation");
  assert.equal(proof.key_id, "rotation-new");
  assert.equal(proof.envelope.key_id, "rotation-new");
  assert.equal(proof.public_key_b64, newKey.publicB64);
  assert.equal(verifyReceiptProof(proof, { trustedKeys: trustedReceiptKeys() }).verified, true);

  // The active signer refuses to sign under the retired key ID.
  const oldEnvelope = { ...proof.envelope, key_id: "rotation-old" };
  assert.throws(() => signReceiptEnvelope(oldEnvelope), /key_id does not match active signer/);
});

test("rotation: a tampered old-key receipt still fails", () => {
  const oldKey = freshKey("rotation-old");
  const newKey = freshKey("rotation-new");
  useKeys(oldKey);
  const proof = signedProof("Signed before rotation");

  useKeys(newKey, [oldKey]);
  const trustedKeys = trustedReceiptKeys();
  const altered = { ...proof, envelope: { ...proof.envelope, description: "Altered after rotation" } };
  const result = verifyReceiptProof(altered, { trustedKeys });
  assert.equal(result.verified, false);
  assert.equal(result.checks.hash, false);
  assert.equal(result.checks.key_trusted, true, "only the content changed");
});

test("rotation: a receipt re-signed with an untrusted key fails", () => {
  const oldKey = freshKey("rotation-old");
  const newKey = freshKey("rotation-new");
  const attackerKey = freshKey("rotation-old"); // claims the retired key's ID

  useKeys(attackerKey);
  const forged = signedProof("Forged after rotation");

  useKeys(newKey, [oldKey]);
  const result = verifyReceiptProof(forged, { trustedKeys: trustedReceiptKeys() });
  assert.equal(result.checks.signature, true, "self-consistent with the key stored beside it");
  assert.equal(result.checks.key_trusted, false);
  assert.equal(result.verified, false);
});

test("rotation: a retired key may not reuse the active key ID", () => {
  const key = freshKey("rotation-same");
  const other = freshKey("rotation-same");
  useKeys(key, [other]);
  assert.throws(() => trustedReceiptKeys(), /reuses the active key ID/);
});

test("rotation: a malformed retired key list fails closed", () => {
  const key = freshKey("rotation-active");
  useKeys(key);
  process.env.RECEIPT_RETIRED_PUBLIC_KEYS_JSON = "{not json";
  assert.throws(() => trustedReceiptKeys(), /not valid JSON/);

  resetReceiptKeyCache();
  process.env.RECEIPT_RETIRED_PUBLIC_KEYS_JSON = JSON.stringify({ "rotation-bad": "bm90LWEta2V5" });
  assert.throws(() => trustedReceiptKeys(), /not a valid public key/);
});
