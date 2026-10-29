import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

export const RECEIPT_CANONICAL_VERSION = "fable.receipt.v1";
export const RECEIPT_SIGNATURE_ALGORITHM = "Ed25519";

function sortValue(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortValue);
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] !== undefined) out[key] = sortValue(value[key]);
  }
  return out;
}

/** Deterministic JSON: same semantic envelope -> same bytes -> same hash. */
export function canonicalJson(value) {
  return JSON.stringify(sortValue(value));
}

function iso(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error("Receipt created_at is not a valid timestamp");
  return date.toISOString();
}

export function publicKeyFingerprint(publicKeyB64) {
  const der = Buffer.from(String(publicKeyB64 ?? ""), "base64");
  if (der.length === 0) throw new Error("Receipt public key is missing");
  return `sha256:${createHash("sha256").update(der).digest("hex")}`;
}

/**
 * The exact signed object. Keep this intentionally explicit: adding a field to
 * a database row does not silently change what a receipt means. A future
 * envelope must use a new canonical version.
 */
export function buildReceiptEnvelope(receipt) {
  return {
    version: receipt.canonical_version ?? RECEIPT_CANONICAL_VERSION,
    receipt_id: String(receipt.id),
    tenant_id: String(receipt.tenant_id),
    evidence_id: String(receipt.evidence_id),
    receipt_type: String(receipt.receipt_type),
    uri: receipt.uri ?? null,
    source_digest: receipt.source_digest ?? null,
    description: String(receipt.description),
    grade: String(receipt.grade),
    is_demo: Boolean(receipt.is_demo),
    intent_token_id: receipt.intent_token_id ?? null,
    external_reference: receipt.external_reference ?? null,
    reversal_of: receipt.reversal_of ?? null,
    metadata: receipt.metadata ?? {},
    chain_sequence: String(receipt.chain_sequence),
    previous_hash: receipt.previous_hash ?? null,
    created_by: receipt.created_by ?? null,
    correlation_id: receipt.correlation_id ?? null,
    created_at: iso(receipt.created_at),
    integrity_origin: String(receipt.integrity_origin),
    key_id: String(receipt.key_id),
    signing_key_fingerprint: String(receipt.signing_key_fingerprint),
  };
}

export function hashReceiptEnvelope(envelope) {
  return createHash("sha256").update(canonicalJson(envelope), "utf8").digest("hex");
}

function privateKeyFromSeed(seed) {
  // RFC 8410 PKCS#8 prefix for an Ed25519 32-byte private seed.
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({
    key: Buffer.concat([prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function developmentPrivateKey() {
  const seed = createHash("sha256")
    .update("FABLE-5 DEVELOPMENT RECEIPT KEY - NOT FOR PRODUCTION")
    .digest()
    .subarray(0, 32);
  return privateKeyFromSeed(seed);
}

let cachedSigner = null;
let cachedTrustedKeys = null;

/**
 * Load the active signing key. Production refuses to operate without a key
 * supplied out-of-repository. Non-production uses an explicitly labelled,
 * deterministic dev key so local tests remain reproducible across restarts.
 */
export function getReceiptSigner() {
  if (cachedSigner) return cachedSigner;

  const encodedPrivate = String(process.env.RECEIPT_SIGNING_PRIVATE_KEY_B64 ?? "").trim();
  const isProduction = process.env.NODE_ENV === "production";
  let privateKey;
  let devOnly = false;

  if (encodedPrivate) {
    privateKey = createPrivateKey({
      key: Buffer.from(encodedPrivate, "base64"),
      format: "der",
      type: "pkcs8",
    });
  } else {
    if (isProduction) {
      throw new Error(
        "RECEIPT_SIGNING_PRIVATE_KEY_B64 is required in production — refusing unsigned receipt operation",
      );
    }
    privateKey = developmentPrivateKey();
    devOnly = true;
  }

  const publicKey = createPublicKey(privateKey);
  const publicKeyB64 = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const configuredPublic = String(process.env.RECEIPT_SIGNING_PUBLIC_KEY_B64 ?? "").trim();
  if (configuredPublic && configuredPublic !== publicKeyB64) {
    throw new Error("RECEIPT_SIGNING_PUBLIC_KEY_B64 does not match the configured private key");
  }

  const keyId = String(process.env.RECEIPT_SIGNING_KEY_ID ?? "").trim()
    || (devOnly ? "dev-insecure-ed25519-v1" : "");
  if (!keyId) {
    throw new Error("RECEIPT_SIGNING_KEY_ID is required when a production signing key is configured");
  }

  cachedSigner = {
    algorithm: RECEIPT_SIGNATURE_ALGORITHM,
    keyId,
    privateKey,
    publicKey,
    publicKeyB64,
    fingerprint: publicKeyFingerprint(publicKeyB64),
    devOnly,
  };
  return cachedSigner;
}

/**
 * Public keys that receipts may be signed with: the active signer plus every
 * retired key listed in RECEIPT_RETIRED_PUBLIC_KEYS_JSON as
 * {"<key_id>": "<public_key_b64>"}. Only public keys belong here, so the value
 * is safe to keep in ordinary deployment config. Rotation moves the outgoing
 * key into this list; dropping a key from it makes its receipts untrusted.
 */
export function trustedReceiptKeys() {
  if (cachedTrustedKeys) return cachedTrustedKeys;

  const signer = getReceiptSigner();
  const keys = new Map([[signer.keyId, signer.publicKeyB64]]);
  const raw = String(process.env.RECEIPT_RETIRED_PUBLIC_KEYS_JSON ?? "").trim();
  if (raw) {
    let retired;
    try {
      retired = JSON.parse(raw);
    } catch {
      throw new Error("RECEIPT_RETIRED_PUBLIC_KEYS_JSON is not valid JSON");
    }
    if (!retired || typeof retired !== "object" || Array.isArray(retired)) {
      throw new Error("RECEIPT_RETIRED_PUBLIC_KEYS_JSON must be an object of key_id -> public_key_b64");
    }
    for (const [keyId, publicKeyB64] of Object.entries(retired)) {
      const encoded = String(publicKeyB64 ?? "").trim();
      if (keyId === signer.keyId) {
        throw new Error(`Retired receipt key ${keyId} reuses the active key ID; rotate to a new key ID`);
      }
      try {
        createPublicKey({ key: Buffer.from(encoded, "base64"), format: "der", type: "spki" });
      } catch {
        throw new Error(`Retired receipt key ${keyId} is not a valid public key`);
      }
      keys.set(keyId, encoded);
    }
  }

  cachedTrustedKeys = keys;
  return cachedTrustedKeys;
}

/** Drop cached key material so the next call re-reads the environment. */
export function resetReceiptKeyCache() {
  cachedSigner = null;
  cachedTrustedKeys = null;
}

export function receiptSignerInfo() {
  const signer = getReceiptSigner();
  return {
    algorithm: signer.algorithm,
    key_id: signer.keyId,
    public_key_b64: signer.publicKeyB64,
    fingerprint: signer.fingerprint,
    development_only: signer.devOnly,
  };
}

export function signReceiptEnvelope(envelope) {
  const signer = getReceiptSigner();
  if (envelope.key_id !== signer.keyId) throw new Error("Receipt envelope key_id does not match active signer");
  if (envelope.signing_key_fingerprint !== signer.fingerprint) {
    throw new Error("Receipt envelope key fingerprint does not match active signer");
  }

  const receiptHash = hashReceiptEnvelope(envelope);
  const signature = cryptoSign(null, Buffer.from(receiptHash, "hex"), signer.privateKey).toString("base64");
  return {
    receipt_hash: receiptHash,
    signature,
    signature_algorithm: RECEIPT_SIGNATURE_ALGORITHM,
    key_id: signer.keyId,
    signing_key_fingerprint: signer.fingerprint,
    public_key_b64: signer.publicKeyB64,
  };
}

/**
 * Pure verification; this is also used by the offline verifier script.
 * Pass `trustedKeys` (key_id -> public_key_b64) to also require that the
 * proof was signed by a key this deployment issued, not merely by the key
 * stored next to it.
 */
export function verifyReceiptProof(proof, { trustedKeys } = {}) {
  const envelope = proof?.envelope;
  const claimedHash = String(proof?.receipt_hash ?? "");
  const signature = String(proof?.signature ?? "");
  const publicKeyB64 = String(proof?.public_key_b64 ?? "");
  const algorithm = String(proof?.signature_algorithm ?? "");

  const checks = {
    canonical_version: envelope?.version === RECEIPT_CANONICAL_VERSION,
    algorithm: algorithm === RECEIPT_SIGNATURE_ALGORITHM,
    hash: false,
    key_fingerprint: false,
    key_id_bound: false,
    signature: false,
  };
  if (trustedKeys) checks.key_trusted = false;

  try {
    const computedHash = hashReceiptEnvelope(envelope);
    checks.hash = computedHash === claimedHash;

    const fingerprint = publicKeyFingerprint(publicKeyB64);
    checks.key_fingerprint = fingerprint === envelope?.signing_key_fingerprint;
    checks.key_id_bound = String(proof?.key_id ?? "") === String(envelope?.key_id ?? "");
    if (trustedKeys) {
      checks.key_trusted = trustedKeys.get(String(proof?.key_id ?? "")) === publicKeyB64;
    }

    const publicKey = createPublicKey({
      key: Buffer.from(publicKeyB64, "base64"),
      format: "der",
      type: "spki",
    });
    checks.signature = cryptoVerify(
      null,
      Buffer.from(claimedHash, "hex"),
      publicKey,
      Buffer.from(signature, "base64"),
    );
  } catch {
    // Malformed proofs stay false rather than turning verification into a 500.
  }

  return {
    verified: Object.values(checks).every(Boolean),
    checks,
  };
}
