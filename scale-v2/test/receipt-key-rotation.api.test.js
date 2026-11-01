import "dotenv/config";
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

// Runs the real server with key A, then restarts it rotated to key B, and
// checks receipts from both sides of the rotation through the HTTP API.
// Keys are generated per run and only passed to the child via its env.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverEntry = path.resolve(__dirname, "../src/server.js");
const PORT = Number(process.env.TEST_ROTATION_PORT ?? 3112);
const BASE = `http://127.0.0.1:${PORT}`;

function freshKey(keyId) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    keyId,
    privateB64: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
    publicB64: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
  };
}

async function startServer(active, retired = []) {
  const env = {
    ...process.env,
    PORT: String(PORT),
    RECEIPT_SIGNING_KEY_ID: active.keyId,
    RECEIPT_SIGNING_PRIVATE_KEY_B64: active.privateB64,
    RECEIPT_SIGNING_PUBLIC_KEY_B64: active.publicB64,
    RECEIPT_RETIRED_PUBLIC_KEYS_JSON: JSON.stringify(
      Object.fromEntries(retired.map((key) => [key.keyId, key.publicB64])),
    ),
  };
  const child = spawn(process.execPath, [serverEntry], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
    cwd: path.resolve(__dirname, ".."),
  });
  child.stdout.on("data", () => {});
  child.stderr.on("data", () => {});

  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE}/api/health`);
      if (res.ok) return child;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  child.kill("SIGTERM");
  throw new Error("server did not become healthy in time");
}

async function stopServer(child) {
  if (child && child.exitCode === null) {
    child.kill("SIGTERM");
    await once(child, "exit").catch(() => {});
  }
}

async function req(method, pathname, { token, body } = {}) {
  const res = await fetch(`${BASE}${pathname}`, {
    method,
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let payload = null;
  try { payload = text ? JSON.parse(text) : null; } catch { payload = text; }
  return { status: res.status, body: payload };
}

async function adminQuery(sql, params) {
  const pg = await import("pg");
  const client = new pg.default.Client({ connectionString: process.env.DATABASE_ADMIN_URL });
  await client.connect();
  try {
    return await client.query(sql, params);
  } finally {
    await client.end();
  }
}

async function attachReceipt(token, evidenceId, description, known) {
  const attached = await req("POST", `/api/evidence/${evidenceId}/receipts`, {
    token,
    body: { receipt_type: "log", description },
  });
  assert.equal(attached.status, 201);
  const added = attached.body.receipts.filter((r) => !known.includes(r.id));
  assert.equal(added.length, 1, "each attach adds exactly one receipt");
  known.push(added[0].id);
  return added[0];
}

test("rotation: old receipts verify, new receipts use the new key, tampering still fails", async () => {
  const oldKey = freshKey(`rotation-old-${randomUUID().slice(0, 8)}`);
  const newKey = freshKey(`rotation-new-${randomUUID().slice(0, 8)}`);
  const receiptIds = [];
  let token;
  let evidenceId;

  // Before rotation: sign two receipts with the old key.
  await adminQuery("DELETE FROM auth_attempts");
  let server = await startServer(oldKey);
  try {
    const suffix = randomUUID().slice(0, 8);
    const created = await req("POST", "/api/auth/signup", {
      body: {
        organisationName: `Key Rotation ${suffix}`,
        email: `key-rotation-${suffix}@example.com`,
        password: "a-long-enough-passphrase",
      },
    });
    assert.equal(created.status, 201);
    token = created.body.token;

    const evidence = await req("POST", "/api/evidence", { token, body: { claim: `Key rotation ${suffix}` } });
    assert.equal(evidence.status, 201);
    evidenceId = evidence.body.id;
    for (const to of ["AUTHORIZED", "EXECUTED"]) {
      const moved = await req("POST", `/api/evidence/${evidenceId}/transition`, { token, body: { to, reason: "rotation setup" } });
      assert.equal(moved.status, 200);
    }
    for (const n of [1, 2]) {
      const receipt = await attachReceipt(token, evidenceId, `Before rotation ${n}`, receiptIds);
      const check = await req("GET", `/api/receipts/${receipt.id}/verify`, { token });
      assert.equal(check.body.status, "VERIFIED");
      assert.equal(check.body.proof.key_id, oldKey.keyId);
    }
  } finally {
    await stopServer(server);
  }

  // After rotation: the old key is retired, the new key signs.
  server = await startServer(newKey, [oldKey]);
  try {
    const current = await req("GET", "/api/receipt-keys/current");
    assert.equal(current.status, 200);
    assert.equal(current.body.key_id, newKey.keyId);

    const fresh = await attachReceipt(token, evidenceId, "After rotation", receiptIds);
    const freshCheck = await req("GET", `/api/receipts/${fresh.id}/verify`, { token });
    assert.equal(freshCheck.status, 200);
    assert.equal(freshCheck.body.status, "VERIFIED");
    assert.equal(freshCheck.body.proof.key_id, newKey.keyId, "new receipts carry the new key ID");

    const oldCheck = await req("GET", `/api/receipts/${receiptIds[0]}/verify`, { token });
    assert.equal(oldCheck.status, 200);
    assert.equal(oldCheck.body.status, "VERIFIED", "old-key receipts still verify");
    assert.equal(oldCheck.body.proof.key_id, oldKey.keyId);
    assert.equal(oldCheck.body.checks.key_trusted, true);

    const chain = await req("GET", "/api/receipts/verify-chain", { token });
    assert.equal(chain.status, 200);
    assert.equal(chain.body.verified, true, "the chain verifies across the rotation");
    assert.equal(chain.body.sealed_receipts, 3);

    // Tamper with an old-key receipt directly in the database, bypassing the
    // append-only trigger as an attacker with database access could.
    const pg = await import("pg");
    const client = new pg.default.Client({ connectionString: process.env.DATABASE_ADMIN_URL });
    await client.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL session_replication_role = replica");
      const updated = await client.query(
        "UPDATE evidence_receipts SET description = description || ' (altered)' WHERE id = $1",
        [receiptIds[0]],
      );
      assert.equal(updated.rowCount, 1);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      await client.end();
    }

    const tampered = await req("GET", `/api/receipts/${receiptIds[0]}/verify`, { token });
    assert.equal(tampered.status, 200);
    assert.equal(tampered.body.status, "TAMPER_DETECTED");
    assert.equal(tampered.body.checks.hash, false);
    assert.equal(tampered.body.checks.key_trusted, true, "only the content changed");

    const brokenChain = await req("GET", "/api/receipts/verify-chain", { token });
    assert.equal(brokenChain.body.verified, false);
    assert.deepEqual(brokenChain.body.failures.map((f) => f.receipt_id), [receiptIds[0]]);
  } finally {
    await stopServer(server);
  }
});
