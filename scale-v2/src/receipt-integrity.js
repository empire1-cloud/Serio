import { randomUUID } from "node:crypto";
import { withTenant } from "./db.js";
import {
  RECEIPT_CANONICAL_VERSION,
  RECEIPT_SIGNATURE_ALGORITHM,
  buildReceiptEnvelope,
  getReceiptSigner,
  receiptSignerInfo,
  signReceiptEnvelope,
  trustedReceiptKeys,
  verifyReceiptProof,
} from "./domain/receipt-integrity.js";

const notFound = (message) => Object.assign(new Error(message), { status: 404 });
const badRequest = (message) => Object.assign(new Error(message), { status: 400 });

function normalizeGrade(value) {
  const grade = String(value ?? "C").toUpperCase();
  return ["A", "B", "C"].includes(grade) ? grade : "C";
}

function normalizeMetadata(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value;
}

function proofForRow(row) {
  const envelope = buildReceiptEnvelope(row);
  return {
    envelope,
    receipt_hash: row.receipt_hash,
    signature: row.signature,
    signature_algorithm: row.signature_algorithm,
    key_id: row.key_id,
    signing_key_fingerprint: row.signing_key_fingerprint,
    public_key_b64: row.public_key_b64,
  };
}

function serializeReceipt(row) {
  return {
    id: row.id,
    evidence_id: row.evidence_id,
    receipt_type: row.receipt_type,
    uri: row.uri,
    // `digest` remains for API compatibility, but it is now the authoritative
    // server-generated receipt hash. A caller-supplied artifact digest lives
    // separately as source_digest.
    digest: row.receipt_hash ?? row.digest ?? null,
    source_digest: row.source_digest ?? null,
    description: row.description,
    grade: row.grade,
    is_demo: row.is_demo,
    intent_token_id: row.intent_token_id ?? null,
    external_reference: row.external_reference ?? null,
    reversal_of: row.reversal_of ?? null,
    metadata: row.metadata ?? {},
    created_by: row.created_by ?? null,
    correlation_id: row.correlation_id ?? null,
    created_at: row.created_at,
    integrity: {
      sealed: Boolean(row.receipt_hash && row.signature),
      canonical_version: row.canonical_version ?? null,
      receipt_hash: row.receipt_hash ?? null,
      previous_hash: row.previous_hash ?? null,
      chain_sequence: row.chain_sequence == null ? null : Number(row.chain_sequence),
      signature: row.signature ?? null,
      signature_algorithm: row.signature_algorithm ?? null,
      key_id: row.key_id ?? null,
      signing_key_fingerprint: row.signing_key_fingerprint ?? null,
      public_key_b64: row.public_key_b64 ?? null,
      integrity_origin: row.integrity_origin ?? null,
      sealed_at: row.sealed_at ?? null,
    },
  };
}

async function lockTenantChain(client, tenantId) {
  // One receipt chain writer per tenant. This closes the race where two
  // concurrent writes could both select the same previous_hash/sequence.
  await client.query(
    "SELECT pg_advisory_xact_lock(hashtext('fable5_receipts'), hashtext($1::text))",
    [tenantId],
  );
}

async function latestSealedReceipt(client) {
  const result = await client.query(
    `SELECT *
       FROM evidence_receipts
      WHERE receipt_hash IS NOT NULL
      ORDER BY chain_sequence DESC
      LIMIT 1`,
  );
  return result.rows[0] ?? null;
}

/**
 * One-way upgrade of receipts created before migration 008. Their historical
 * facts remain untouched. Any old caller-provided digest is preserved as
 * source_digest, then a new authoritative hash/signature is added around the
 * historical row and linked into the current chain.
 */
async function sealLegacyReceipts(client, tenantId) {
  const legacy = await client.query(
    `SELECT *
       FROM evidence_receipts
      WHERE receipt_hash IS NULL
      ORDER BY created_at, id`,
  );
  if (legacy.rows.length === 0) return 0;

  const signer = getReceiptSigner();
  let previous = await latestSealedReceipt(client);
  let sequence = previous ? Number(previous.chain_sequence) : 0;
  let previousHash = previous?.receipt_hash ?? null;

  await client.query("SELECT set_config('app.allow_receipt_seal', 'on', true)");

  for (const row of legacy.rows) {
    sequence += 1;
    const sourceDigest = row.source_digest ?? row.digest ?? null;
    const sealBase = {
      ...row,
      tenant_id: tenantId,
      source_digest: sourceDigest,
      chain_sequence: sequence,
      previous_hash: previousHash,
      canonical_version: RECEIPT_CANONICAL_VERSION,
      signature_algorithm: RECEIPT_SIGNATURE_ALGORITHM,
      key_id: signer.keyId,
      signing_key_fingerprint: signer.fingerprint,
      public_key_b64: signer.publicKeyB64,
      integrity_origin: signer.devOnly ? "legacy-sealed-v1-dev" : "legacy-sealed-v1",
    };
    const envelope = buildReceiptEnvelope(sealBase);
    const signed = signReceiptEnvelope(envelope);
    const sealedAt = new Date().toISOString();

    await client.query(
      `UPDATE evidence_receipts
          SET source_digest=$1,
              digest=$2,
              previous_hash=$3,
              receipt_hash=$2,
              chain_sequence=$4,
              canonical_version=$5,
              signature=$6,
              signature_algorithm=$7,
              key_id=$8,
              signing_key_fingerprint=$9,
              public_key_b64=$10,
              integrity_origin=$11,
              sealed_at=$12
        WHERE id=$13`,
      [
        sourceDigest,
        signed.receipt_hash,
        previousHash,
        sequence,
        RECEIPT_CANONICAL_VERSION,
        signed.signature,
        signed.signature_algorithm,
        signed.key_id,
        signed.signing_key_fingerprint,
        signed.public_key_b64,
        sealBase.integrity_origin,
        sealedAt,
        row.id,
      ],
    );
    previousHash = signed.receipt_hash;
  }

  return legacy.rows.length;
}

async function assertEvidenceOwned(client, evidenceId) {
  const result = await client.query("SELECT 1 FROM evidence_records WHERE id=$1", [evidenceId]);
  if (!result.rows[0]) throw notFound("Evidence not found");
}

async function assertIntentTokenOwned(client, tokenId) {
  if (!tokenId) return;
  const result = await client.query("SELECT 1 FROM intent_tokens WHERE id=$1", [tokenId]);
  if (!result.rows[0]) throw notFound("Intent Token not found");
}

async function assertReversalTargetOwned(client, receiptId) {
  if (!receiptId) return;
  const result = await client.query("SELECT 1 FROM evidence_receipts WHERE id=$1", [receiptId]);
  if (!result.rows[0]) throw notFound("Reversal target receipt not found");
}

export function assertReceiptIntegrityReady() {
  // Loading the signer and trusted keys performs every key validation and
  // fails production closed when key custody is not configured.
  trustedReceiptKeys();
  return receiptSignerInfo();
}

export function currentReceiptKey() {
  return receiptSignerInfo();
}

export async function createSignedReceipt(actor, evidenceId, body, options = {}) {
  return withTenant(actor.tenantId, async (client) => {
    await assertEvidenceOwned(client, evidenceId);
    await lockTenantChain(client, actor.tenantId);

    // Upgrade old history before extending the chain. A tenant can never have
    // a signed present sitting on top of an unsealed past.
    await sealLegacyReceipts(client, actor.tenantId);

    const description = String(body.description ?? body.content ?? "").trim();
    if (!description) throw badRequest("receipt description is required");

    const intentTokenId = body.intent_token_id ?? body.intentTokenId ?? null;
    const reversalOf = body.reversal_of ?? body.reversalOf ?? null;
    await assertIntentTokenOwned(client, intentTokenId);
    await assertReversalTargetOwned(client, reversalOf);

    const previous = await latestSealedReceipt(client);
    const chainSequence = previous ? Number(previous.chain_sequence) + 1 : 1;
    const previousHash = previous?.receipt_hash ?? null;
    const signer = getReceiptSigner();
    const id = randomUUID();
    const createdAt = new Date().toISOString();
    const sourceDigest = body.source_digest ?? body.sourceDigest ?? body.digest ?? null;
    const metadata = normalizeMetadata(body.metadata);
    const receiptBase = {
      id,
      tenant_id: actor.tenantId,
      evidence_id: evidenceId,
      receipt_type: body.receipt_type ?? body.kind ?? "artifact",
      uri: body.uri ?? null,
      source_digest: sourceDigest,
      description,
      grade: normalizeGrade(body.grade),
      is_demo: Boolean(body.is_demo ?? false),
      intent_token_id: intentTokenId,
      external_reference: body.external_reference ?? body.externalReference ?? null,
      reversal_of: reversalOf,
      metadata,
      chain_sequence: chainSequence,
      previous_hash: previousHash,
      created_by: actor.userId ?? null,
      correlation_id: options.correlationId ?? null,
      created_at: createdAt,
      canonical_version: RECEIPT_CANONICAL_VERSION,
      key_id: signer.keyId,
      signing_key_fingerprint: signer.fingerprint,
      public_key_b64: signer.publicKeyB64,
      integrity_origin: signer.devOnly ? "native-v1-dev" : "native-v1",
    };
    const envelope = buildReceiptEnvelope(receiptBase);
    const signed = signReceiptEnvelope(envelope);
    const sealedAt = new Date().toISOString();

    const inserted = await client.query(
      `INSERT INTO evidence_receipts
        (id, tenant_id, evidence_id, receipt_type, uri, digest, source_digest,
         description, grade, is_demo, previous_hash, receipt_hash,
         chain_sequence, canonical_version, signature, signature_algorithm,
         key_id, signing_key_fingerprint, public_key_b64, integrity_origin,
         created_by, correlation_id, intent_token_id, external_reference,
         reversal_of, metadata, created_at, sealed_at)
       VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$6,$12,$13,$14,$15,$16,$17,$18,
         $19,$20,$21,$22,$23,$24,$25,$26,$27)
       RETURNING *`,
      [
        id,
        actor.tenantId,
        evidenceId,
        receiptBase.receipt_type,
        receiptBase.uri,
        signed.receipt_hash,
        sourceDigest,
        description,
        receiptBase.grade,
        receiptBase.is_demo,
        previousHash,
        chainSequence,
        RECEIPT_CANONICAL_VERSION,
        signed.signature,
        signed.signature_algorithm,
        signed.key_id,
        signed.signing_key_fingerprint,
        signed.public_key_b64,
        receiptBase.integrity_origin,
        receiptBase.created_by,
        receiptBase.correlation_id,
        intentTokenId,
        receiptBase.external_reference,
        reversalOf,
        metadata,
        createdAt,
        sealedAt,
      ],
    );

    return serializeReceipt(inserted.rows[0]);
  });
}

export async function verifyReceipt(actor, receiptId) {
  return withTenant(actor.tenantId, async (client) => {
    const result = await client.query("SELECT * FROM evidence_receipts WHERE id=$1", [receiptId]);
    const row = result.rows[0];
    if (!row) throw notFound("Receipt not found");

    if (!row.receipt_hash || !row.signature || row.chain_sequence == null) {
      return {
        verified: false,
        status: "LEGACY_UNSEALED",
        reason: "Receipt predates cryptographic sealing and has not yet been upgraded",
        receipt: serializeReceipt(row),
      };
    }

    const proof = proofForRow(row);
    const cryptographic = verifyReceiptProof(proof, { trustedKeys: trustedReceiptKeys() });
    const sequence = Number(row.chain_sequence);
    let previousLink = true;
    let nextLink = true;

    if (sequence === 1) {
      previousLink = row.previous_hash == null;
    } else {
      const previous = await client.query(
        "SELECT receipt_hash FROM evidence_receipts WHERE chain_sequence=$1",
        [sequence - 1],
      );
      previousLink = previous.rows[0]?.receipt_hash === row.previous_hash;
    }

    const next = await client.query(
      "SELECT previous_hash FROM evidence_receipts WHERE chain_sequence=$1",
      [sequence + 1],
    );
    if (next.rows[0]) nextLink = next.rows[0].previous_hash === row.receipt_hash;

    const checks = {
      ...cryptographic.checks,
      previous_link: previousLink,
      next_link: nextLink,
    };
    return {
      verified: Object.values(checks).every(Boolean),
      status: Object.values(checks).every(Boolean) ? "VERIFIED" : "TAMPER_DETECTED",
      checks,
      receipt: serializeReceipt(row),
      proof,
    };
  });
}

export async function verifyReceiptChain(actor) {
  return withTenant(actor.tenantId, async (client) => {
    const result = await client.query(
      `SELECT * FROM evidence_receipts
        ORDER BY chain_sequence NULLS LAST, created_at, id`,
    );
    const rows = result.rows;
    const unsealed = rows.filter((row) => !row.receipt_hash || row.chain_sequence == null);
    const sealed = rows.filter((row) => row.receipt_hash && row.chain_sequence != null);
    const failures = [];
    let previousHash = null;
    let expectedSequence = 1;

    for (const row of sealed) {
      const sequence = Number(row.chain_sequence);
      const proof = proofForRow(row);
      const crypto = verifyReceiptProof(proof, { trustedKeys: trustedReceiptKeys() });
      const sequenceOk = sequence === expectedSequence;
      const linkOk = row.previous_hash === previousHash;
      if (!crypto.verified || !sequenceOk || !linkOk) {
        failures.push({
          receipt_id: row.id,
          chain_sequence: sequence,
          cryptographic_checks: crypto.checks,
          sequence: sequenceOk,
          previous_link: linkOk,
        });
      }
      previousHash = row.receipt_hash;
      expectedSequence = sequence + 1;
    }

    if (unsealed.length > 0) {
      failures.push({
        code: "LEGACY_UNSEALED",
        count: unsealed.length,
        receipt_ids: unsealed.map((row) => row.id),
      });
    }

    return {
      verified: failures.length === 0,
      tenant_id: actor.tenantId,
      total_receipts: rows.length,
      sealed_receipts: sealed.length,
      unsealed_receipts: unsealed.length,
      chain_tip: sealed.length
        ? {
            chain_sequence: Number(sealed[sealed.length - 1].chain_sequence),
            receipt_hash: sealed[sealed.length - 1].receipt_hash,
          }
        : null,
      failures,
    };
  });
}
