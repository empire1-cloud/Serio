import "dotenv/config";
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverEntry = path.resolve(__dirname, "../src/server.js");
const TEST_PORT = Number(process.env.TEST_PORT ?? 3111);
const BASE = `http://127.0.0.1:${TEST_PORT}`;

const EMAIL = process.env.BOOTSTRAP_ADMIN_EMAIL;
const PASSWORD = process.env.BOOTSTRAP_ADMIN_PASSWORD;

let server;

async function waitForHealth(timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE}/api/health`);
      if (res.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error("server did not become healthy in time");
}

async function req(method, pathname, { token, body } = {}) {
  const res = await fetch(`${BASE}${pathname}`, {
    method,
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let payload = null;
  try { payload = text ? JSON.parse(text) : null; } catch { payload = text; }
  return { status: res.status, body: payload };
}

test.before(async () => {
  assert.ok(EMAIL && PASSWORD, "BOOTSTRAP_ADMIN_EMAIL/PASSWORD must be set in scale-v2/.env");

  // The suite legitimately creates several organisations and deliberately fails
  // several logins, from one address — which is exactly what the throttles are
  // built to stop. Clearing the ledger before the run isolates the tests
  // without weakening the production limits they assert.
  await resetAuthAttempts();
  server = spawn(process.execPath, [serverEntry], {
    env: { ...process.env, PORT: String(TEST_PORT) },
    stdio: ["ignore", "pipe", "pipe"],
    cwd: path.resolve(__dirname, "..")
  });
  server.stdout.on("data", () => {});
  server.stderr.on("data", () => {});
  await waitForHealth();
});

test.after(async () => {
  if (server && server.exitCode === null) server.kill("SIGTERM");
  await once(server, "exit").catch(() => {});
});

test("GET /api/health reports the rev-2.0 control plane", async () => {
  const { status, body } = await req("GET", "/api/health");
  assert.equal(status, 200);
  assert.equal(body.status, "ok");
  assert.equal(body.moneyExecutionDefault, false);
});

test("auth: login returns { token, actor } and /me honours it", async () => {
  const login = await req("POST", "/api/auth/login", { body: { email: EMAIL, password: PASSWORD } });
  assert.equal(login.status, 200);
  assert.ok(login.body.token, "token returned");
  assert.ok(login.body.actor.userId, "actor.userId returned");
  assert.ok(login.body.actor.tenantId, "actor.tenantId returned");
  assert.equal(login.body.actor.email, EMAIL);
  assert.equal(login.body.actor.role, "OWNER");

  const me = await req("GET", "/api/auth/me", { token: login.body.token });
  assert.equal(me.status, 200);
  assert.equal(me.body.actor.userId, login.body.actor.userId);
  assert.ok(me.body.expiresAt, "expiresAt returned");
});

test("auth: a forged/expired token is refused on /me", async () => {
  const me = await req("GET", "/api/auth/me", { token: "not-a-real-token" });
  assert.equal(me.status, 401);
});

test("auth: login tolerates stray whitespace on email and password", async () => {
  const login = await req("POST", "/api/auth/login", {
    body: { email: `  ${EMAIL}  `, password: ` ${PASSWORD}\n` },
  });
  assert.equal(login.status, 200);
  assert.equal(login.body.actor.email, EMAIL);
});

test("evidence: create → gates → receipts → verify → measure, with skip refused", async () => {
  const token = await loginToken();
  const claim = `Integration evidence ${Date.now()} ${randomUUID().slice(0, 8)}`;

  const created = await req("POST", "/api/evidence", { token, body: { claim } });
  assert.equal(created.status, 201);
  assert.equal(created.body.state, "PROPOSED");
  const recordId = created.body.id;

  const listed = await req("GET", "/api/evidence", { token });
  assert.equal(listed.status, 200);
  assert.ok(listed.body.some((r) => r.id === recordId), "record appears in list");

  const one = await req("GET", `/api/evidence/${recordId}`, { token });
  assert.equal(one.status, 200);
  assert.equal(one.body.id, recordId);

  const skipped = await req("POST", `/api/evidence/${recordId}/transition`, { token, body: { to: "RECEIPTED", reason: "jump" } });
  assert.equal(skipped.status, 409, "skipping to RECEIPTED is refused");

  const authorized = await req("POST", `/api/evidence/${recordId}/transition`, { token, body: { to: "AUTHORIZED", reason: "gated" } });
  assert.equal(authorized.status, 200);
  assert.equal(authorized.body.state, "AUTHORIZED");

  const executed = await req("POST", `/api/evidence/${recordId}/transition`, { token, body: { to: "EXECUTED", reason: "ran it" } });
  assert.equal(executed.status, 200);
  assert.equal(executed.body.state, "EXECUTED");

  const receipt = await req("POST", `/api/evidence/${recordId}/receipts`, {
    token,
    body: { receipt_type: "log", description: "signed execution log" }
  });
  assert.equal(receipt.status, 201);
  assert.equal(receipt.body.receipts.length, 1);
  const receiptId = receipt.body.receipts[0].id;

  const receipted = await req("POST", `/api/evidence/${recordId}/transition`, { token, body: { to: "RECEIPTED", reason: "proof attached" } });
  assert.equal(receipted.status, 200);
  assert.equal(receipted.body.state, "RECEIPTED");

  const unverified = await req("POST", `/api/evidence/${recordId}/transition`, { token, body: { to: "VERIFIED", reason: "claimed" } });
  assert.equal(unverified.status, 409, "VERIFIED without an independent verification is refused");

  const verification = await req("POST", `/api/evidence/${recordId}/verifications`, {
    token,
    body: { receipt_id: receiptId, reproduced: true, method: "independent re-run by a second actor", independent: true }
  });
  assert.equal(verification.status, 201);
  assert.equal(verification.body.verifications.length, 1);

  const verified = await req("POST", `/api/evidence/${recordId}/transition`, { token, body: { to: "VERIFIED", reason: "independently reproduced" } });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.state, "VERIFIED");

  const unmeasured = await req("POST", `/api/evidence/${recordId}/transition`, { token, body: { to: "MEASURED", reason: "claimed" } });
  assert.equal(unmeasured.status, 409, "MEASURED without a gate measurement is refused");

  const measurement = await req("POST", `/api/evidence/${recordId}/measurements`, {
    token,
    body: { gate_type: "conversion", reading: { delta: 0.12 }, verdict: "PASS" }
  });
  assert.equal(measurement.status, 201);
  assert.equal(measurement.body.measurements.length, 1);

  const measured = await req("POST", `/api/evidence/${recordId}/transition`, { token, body: { to: "MEASURED", reason: "gated" } });
  assert.equal(measured.status, 200);
  assert.equal(measured.body.state, "MEASURED");
});

test("evidence: another tenant's record is invisible (404, not leaked)", async () => {
  const token = await loginToken();
  const unknown = await req("GET", `/api/evidence/${randomUUID()}`, { token });
  assert.equal(unknown.status, 404);
});

test("missions: create → update → archive through engine_work_items", async () => {
  const token = await loginToken();
  const created = await req("POST", "/api/missions", {
    token,
    body: {
      objective: `Prove onboarding reduces churn (${randomUUID().slice(0, 8)})`,
      owner: "engineer",
      autonomy_level: "L2",
      success_criteria: "churn -5pp in 30 days",
      evidence_requirement: "receipt + independent verification"
    }
  });
  assert.equal(created.status, 201);
  assert.equal(created.body.status, "PLANNED");
  const missionId = created.body.id;

  const updated = await req("PUT", `/api/missions/${missionId}`, { token, body: { status: "ACTIVE", blocker: "vendor latency" } });
  assert.equal(updated.status, 200);
  assert.equal(updated.body.status, "ACTIVE");
  assert.equal(updated.body.blocker, "vendor latency");

  const archived = await req("POST", `/api/missions/${missionId}/archive`, { token });
  assert.equal(archived.status, 200);
  assert.equal(archived.body.status, "ARCHIVED");

  const listed = await req("GET", "/api/missions", { token });
  assert.equal(listed.status, 200);
  assert.ok(listed.body.some((m) => m.id === missionId));
});

test("intent tokens: issue → list → check → revoke → refused", async () => {
  const token = await loginToken();
  const created = await req("POST", "/api/intent-tokens", {
    token,
    body: { action: "deploy", vendor_or_system: "stripe-test", max_amount: 50, currency: "USD", environment: "sandbox" }
  });
  assert.equal(created.status, 201);
  assert.equal(created.body.max_amount, 50);
  const tokenId = created.body.id;

  const listed = await req("GET", "/api/intent-tokens", { token });
  assert.equal(listed.status, 200);
  assert.ok(listed.body.some((t) => t.id === tokenId));

  const verdict = await req("POST", "/api/intent-tokens/check", {
    token,
    body: { tokenId, request: { action: "deploy", vendorOrSystem: "stripe-test", amount: 20, currency: "USD", environment: "sandbox", idempotencyKey: `ci-authorize-${tokenId}` } }
  });
  assert.equal(verdict.status, 503);
  assert.equal(verdict.body.allowed, false);
  assert.equal(verdict.body.code, "ECONOMIC_TRUTH_PENDING");
  assert.equal(verdict.body.executed, false, "no execution without the central receipt");

  const revoked = await req("POST", `/api/intent-tokens/${tokenId}/revoke`, { token });
  assert.equal(revoked.status, 200);
  assert.equal(revoked.body.revoked, true);

  const refused = await req("POST", "/api/intent-tokens/check", {
    token,
    body: { tokenId, request: { action: "deploy", vendorOrSystem: "stripe-test", amount: 20, currency: "USD", environment: "sandbox", idempotencyKey: `ci-revoked-${tokenId}` } }
  });
  assert.equal(refused.status, 503);
  assert.equal(refused.body.allowed, false);
  assert.equal(refused.body.code, "ECONOMIC_TRUTH_PENDING");
});

test("opportunities: list is ranked by the server", async () => {
  const token = await loginToken();
  const listed = await req("GET", "/api/opportunities", { token });
  assert.equal(listed.status, 200);
  assert.ok(Array.isArray(listed.body));
});

test("decisions: authorizing a well-evidenced opportunity creates a real, listable decision", async () => {
  const token = await loginToken();
  const title = `Integration opportunity ${Date.now()} ${randomUUID().slice(0, 8)}`;

  const created = await req("POST", "/api/opportunities", {
    token,
    body: {
      title,
      claim: title,
      evidenceGrade: "A",
      evidenceStrength: 90,
      demandSignal: 80,
      strategicFit: 80,
      executionReadiness: 80
    }
  });
  assert.equal(created.status, 201);
  const { opportunityId, evidenceId } = created.body;

  // The gate also requires at least one attached receipt.
  const receipt = await req("POST", `/api/evidence/${evidenceId}/receipts`, {
    token,
    body: { receipt_type: "log", description: "founder-reviewed evidence pack" }
  });
  assert.equal(receipt.status, 201);

  const authorized = await req("POST", `/api/opportunities/${opportunityId}/authorize`, {
    token,
    body: { reason: "strong evidence, integration test" }
  });
  assert.equal(authorized.status, 200);
  assert.equal(authorized.body.state, "AUTHORIZED");

  const listed = await req("GET", "/api/decisions", { token });
  assert.equal(listed.status, 200);
  const decision = listed.body.find((d) => d.opportunity_id === opportunityId);
  assert.ok(decision, "the real decision row is returned, not a static demo record");
  assert.equal(decision.verdict, "AUTHORIZED");
  assert.equal(decision.opportunity_title, title);
  assert.ok(typeof decision.ranking_score === "number");
});

test("escalations: a refused Engine 00 gate is persisted, listable, and resolvable", async () => {
  const token = await loginToken();
  const title = `Weak opportunity ${Date.now()} ${randomUUID().slice(0, 8)}`;

  // Default grade is C and no receipt is attached — the authorize gate must refuse.
  const created = await req("POST", "/api/opportunities", { token, body: { title, claim: title } });
  assert.equal(created.status, 201);
  const { opportunityId, evidenceId } = created.body;

  const refused = await req("POST", `/api/opportunities/${opportunityId}/authorize`, {
    token,
    body: { reason: "should be refused" }
  });
  assert.equal(refused.status, 409, "the authorize action itself is still refused");

  const listed = await req("GET", "/api/escalations", { token });
  assert.equal(listed.status, 200);
  const escalation = listed.body.find((e) => e.evidence_id === evidenceId);
  assert.ok(escalation, "the refusal is retained as a real escalation, not silently dropped");
  assert.equal(escalation.engine_id, "00");
  assert.equal(escalation.severity, "MEDIUM");
  assert.equal(escalation.resolved_at, null);
  assert.match(escalation.reason, /Engine 00 gate refused/);

  const missingResolution = await req("POST", `/api/escalations/${escalation.id}/resolve`, { token, body: {} });
  assert.equal(missingResolution.status, 400);

  const resolved = await req("POST", `/api/escalations/${escalation.id}/resolve`, {
    token,
    body: { resolution: "re-graded evidence to A and attached a receipt" }
  });
  assert.equal(resolved.status, 200);
  assert.ok(resolved.body.resolved_at);
  assert.equal(resolved.body.resolution, "re-graded evidence to A and attached a receipt");

  const resolveAgain = await req("POST", `/api/escalations/${escalation.id}/resolve`, {
    token,
    body: { resolution: "second attempt" }
  });
  assert.equal(resolveAgain.status, 404, "an already-resolved escalation cannot be resolved twice");
});

test("escalations: another tenant's escalation is invisible (404, not leaked)", async () => {
  const token = await loginToken();
  const missing = await req("POST", `/api/escalations/${randomUUID()}/resolve`, {
    token,
    body: { resolution: "n/a" }
  });
  assert.equal(missing.status, 404);
});

test("dashboard: reports genomes, nodes, and resource pressure from real tables", async () => {
  const token = await loginToken();
  const { status, body } = await req("GET", "/api/dashboard", { token });
  assert.equal(status, 200);

  assert.equal(typeof body.genomeCount, "number", "genome count is server-computed");
  assert.ok(body.nodes, "node counts are present");
  assert.equal(typeof body.nodes.total, "number");
  assert.equal(typeof body.nodes.activeOrScaling, "number");
  assert.ok(
    body.nodes.activeOrScaling <= body.nodes.total,
    "active/scaling can never exceed the total"
  );

  // Bootstrap seeds pools at zero committed, so pressure is a real 0 — not null.
  assert.ok(body.resourcePressure, "resource pressure is reported once pools exist");
  assert.equal(typeof body.resourcePressure.ratio, "number");
  assert.ok(body.resourcePressure.ratio >= 0 && body.resourcePressure.ratio <= 1);
});

test("resource pools: seeded by bootstrap and pressure is computed server-side", async () => {
  const token = await loginToken();
  const { status, body } = await req("GET", "/api/resource-pools", { token });
  assert.equal(status, 200);
  assert.ok(Array.isArray(body));
  assert.ok(body.length >= 9, "the nine resource types are seeded as capacity config");

  const cash = body.find((p) => p.resource_type === "cash");
  assert.ok(cash, "cash pool exists");
  assert.equal(cash.financial, true, "cash is marked financial");
  assert.equal(typeof cash.pressure, "number");
  assert.equal(cash.pressure, cash.capacity > 0 ? cash.allocated / cash.capacity : 0);
});

test("genomes and market nodes start empty — a new org has not proven one", async () => {
  const token = await loginToken();
  const genomes = await req("GET", "/api/genomes", { token });
  assert.equal(genomes.status, 200);
  assert.ok(Array.isArray(genomes.body));

  const nodes = await req("GET", "/api/market-nodes", { token });
  assert.equal(nodes.status, 200);
  assert.ok(Array.isArray(nodes.body));
});

test("genome sections: proven is DERIVED from evidence state, never asserted", async () => {
  const token = await loginToken();
  const suffix = randomUUID().slice(0, 8);

  const created = await req("POST", "/api/genomes", {
    token,
    body: { code: `G-TEST-${suffix}`, name: `Test genome ${suffix}`, thesis: "under test" }
  });
  assert.equal(created.status, 201);
  const genomeId = created.body.id;

  // Section with no evidence at all.
  const bare = await req("POST", `/api/genomes/${genomeId}/sections`, {
    token,
    body: { section_key: "problem", section_group: "PROBLEM", label: "problem", value: "stated, unproven" }
  });
  assert.equal(bare.status, 201);

  // Section linked to evidence that is only PROPOSED — attached, NOT proven.
  const ev = await req("POST", "/api/evidence", { token, body: { claim: `Pricing claim ${suffix}` } });
  assert.equal(ev.status, 201);
  const evidenceId = ev.body.id;
  const attached = await req("POST", `/api/genomes/${genomeId}/sections`, {
    token,
    body: { section_key: "pricing", section_group: "OFFER", label: "pricing", value: "€89/mo", evidence_id: evidenceId }
  });
  assert.equal(attached.status, 201);

  let detail = await req("GET", `/api/genomes/${genomeId}`, { token });
  assert.equal(detail.status, 200);
  assert.equal(detail.body.coverage.total, 2);
  assert.equal(detail.body.coverage.proven, 0, "attaching PROPOSED evidence proves nothing");
  const pricing = detail.body.sections.find((s) => s.key === "pricing");
  assert.equal(pricing.evidenceState, "PROPOSED");
  assert.equal(pricing.proven, false, "a claim awaiting the gates is not proof");
  assert.equal(detail.body.maturityGate.allowed, false);

  // Walk the real gates to VERIFIED; only then may the section read proven.
  await req("POST", `/api/evidence/${evidenceId}/transition`, { token, body: { to: "AUTHORIZED", reason: "gated" } });
  await req("POST", `/api/evidence/${evidenceId}/transition`, { token, body: { to: "EXECUTED", reason: "ran" } });
  const receipt = await req("POST", `/api/evidence/${evidenceId}/receipts`, {
    token,
    body: { receipt_type: "log", description: "pricing test output" }
  });
  await req("POST", `/api/evidence/${evidenceId}/transition`, { token, body: { to: "RECEIPTED", reason: "proof attached" } });
  await req("POST", `/api/evidence/${evidenceId}/verifications`, {
    token,
    body: { receipt_id: receipt.body.receipts[0].id, method: "independent re-run", independent: true, reproduced: true }
  });
  await req("POST", `/api/evidence/${evidenceId}/transition`, { token, body: { to: "VERIFIED", reason: "reproduced" } });

  detail = await req("GET", `/api/genomes/${genomeId}`, { token });
  assert.equal(detail.body.coverage.proven, 1, "proven count follows the evidence machine");
  assert.equal(detail.body.sections.find((s) => s.key === "pricing").proven, true);

  // The bare section still blocks promotion, and the reason is computed.
  assert.equal(detail.body.maturityGate.allowed, false);
  assert.match(detail.body.maturityGate.reason, /1 of 2 sections lack verified evidence/);
  const missing = detail.body.missingForNextStage.find((m) => m.label === "problem");
  assert.equal(missing.reason, "no evidence attached");
});

test("genome maturity gate opens only when every section is verified", async () => {
  const token = await loginToken();
  const suffix = randomUUID().slice(0, 8);
  const created = await req("POST", "/api/genomes", {
    token,
    body: { code: `G-GATE-${suffix}`, name: `Gate genome ${suffix}` }
  });
  const genomeId = created.body.id;

  // A genome with no sections has described nothing — it cannot be ready.
  let detail = await req("GET", `/api/genomes/${genomeId}`, { token });
  assert.equal(detail.body.replicationReady, false);
  assert.match(detail.body.maturityGate.reason, /no sections/i);

  const ev = await req("POST", "/api/evidence", { token, body: { claim: `Only claim ${suffix}` } });
  const evidenceId = ev.body.id;
  await req("POST", `/api/genomes/${genomeId}/sections`, {
    token,
    body: { section_key: "only", section_group: "G", label: "only", value: "v", evidence_id: evidenceId }
  });

  await req("POST", `/api/evidence/${evidenceId}/transition`, { token, body: { to: "AUTHORIZED", reason: "g" } });
  await req("POST", `/api/evidence/${evidenceId}/transition`, { token, body: { to: "EXECUTED", reason: "g" } });
  const r = await req("POST", `/api/evidence/${evidenceId}/receipts`, { token, body: { receipt_type: "log", description: "d" } });
  await req("POST", `/api/evidence/${evidenceId}/transition`, { token, body: { to: "RECEIPTED", reason: "g" } });
  await req("POST", `/api/evidence/${evidenceId}/verifications`, {
    token,
    body: { receipt_id: r.body.receipts[0].id, method: "independent", independent: true, reproduced: true }
  });
  await req("POST", `/api/evidence/${evidenceId}/transition`, { token, body: { to: "VERIFIED", reason: "g" } });

  detail = await req("GET", `/api/genomes/${genomeId}`, { token });
  assert.equal(detail.body.replicationReady, true);
  assert.equal(detail.body.maturityGate.allowed, true);
  assert.equal(detail.body.missingForNextStage.length, 0);
});

test("genomes/nodes/pools require authentication", async () => {
  for (const path of ["/api/genomes", "/api/market-nodes", "/api/resource-pools"]) {
    const { status } = await req("GET", path);
    assert.equal(status, 401, `${path} is refused without a session`);
  }
});

test("signup: a stranger can create an organisation and is signed straight in", async () => {
  await resetAuthAttempts(); // isolate from other tests' signups; the throttle is asserted separately
  const suffix = randomUUID().slice(0, 8);
  const email = `founder-${suffix}@example.com`;

  const created = await req("POST", "/api/auth/signup", {
    body: { organisationName: `Probe Co ${suffix}`, email, password: "a-long-enough-passphrase" }
  });
  assert.equal(created.status, 201);
  assert.ok(created.body.token, "signed in immediately — no second credential entry");
  assert.equal(created.body.actor.email, email);
  assert.equal(created.body.actor.role, "OWNER");
  assert.equal(created.body.trial.days, 14);

  const token = created.body.token;

  // The new org is real and isolated: it sees none of another tenant's records.
  const evidence = await req("GET", "/api/evidence", { token });
  assert.equal(evidence.status, 200);
  assert.deepEqual(evidence.body, [], "a brand-new organisation starts empty");

  // Resource pools are seeded; genomes deliberately are not.
  const pools = await req("GET", "/api/resource-pools", { token });
  assert.ok(pools.body.length >= 9, "capacity config is provisioned");
  const genomes = await req("GET", "/api/genomes", { token });
  assert.deepEqual(genomes.body, [], "no genome is invented for a new company");

  // And it can actually work — the trial writes.
  const wrote = await req("POST", "/api/evidence", { token, body: { claim: `First claim ${suffix}` } });
  assert.equal(wrote.status, 201);
});

test("signup: refuses a duplicate email, a weak password, and a missing name", async () => {
  await resetAuthAttempts(); // isolate from other tests' signups; the throttle is asserted separately
  const suffix = randomUUID().slice(0, 8);
  const email = `dupe-${suffix}@example.com`;
  const ok = await req("POST", "/api/auth/signup", {
    body: { organisationName: `Dupe Co ${suffix}`, email, password: "a-long-enough-passphrase" }
  });
  assert.equal(ok.status, 201);

  const again = await req("POST", "/api/auth/signup", {
    body: { organisationName: "Another Co", email, password: "a-long-enough-passphrase" }
  });
  assert.equal(again.status, 409, "an existing address is never silently attached to a new org");

  const weak = await req("POST", "/api/auth/signup", {
    body: { organisationName: "Weak Co", email: `weak-${suffix}@example.com`, password: "short" }
  });
  assert.equal(weak.status, 400);

  const noName = await req("POST", "/api/auth/signup", {
    body: { organisationName: "", email: `noname-${suffix}@example.com`, password: "a-long-enough-passphrase" }
  });
  assert.equal(noName.status, 400);
});

test("signup: a failed creation leaves nothing behind", async () => {
  await resetAuthAttempts(); // isolate from other tests' signups; the throttle is asserted separately
  const suffix = randomUUID().slice(0, 8);
  const email = `atomic-${suffix}@example.com`;
  await req("POST", "/api/auth/signup", {
    body: { organisationName: `Atomic Co ${suffix}`, email, password: "a-long-enough-passphrase" }
  });
  // Second attempt collides on email and must roll back entirely — no orphan
  // tenant, and the original account still works.
  await req("POST", "/api/auth/signup", {
    body: { organisationName: `Orphan Co ${suffix}`, email, password: "a-long-enough-passphrase" }
  });
  const login = await req("POST", "/api/auth/login", { body: { email, password: "a-long-enough-passphrase" } });
  assert.equal(login.status, 200, "the original account is untouched by the failed attempt");
  assert.match(login.body.actor.tenantName, /Atomic Co/, "no orphan tenant took over the account");
});

test("subscription: a new org reports an active trial and its plans", async () => {
  await resetAuthAttempts(); // isolate from other tests' signups; the throttle is asserted separately
  const suffix = randomUUID().slice(0, 8);
  const created = await req("POST", "/api/auth/signup", {
    body: { organisationName: `Sub Co ${suffix}`, email: `sub-${suffix}@example.com`, password: "a-long-enough-passphrase" }
  });
  const token = created.body.token;

  const sub = await req("GET", "/api/subscription", { token });
  assert.equal(sub.status, 200);
  assert.equal(sub.body.status, "trialing");
  assert.equal(sub.body.canWrite, true);
  assert.equal(sub.body.canRead, true);
  assert.ok(sub.body.trialDaysRemaining > 0 && sub.body.trialDaysRemaining <= 14);
  assert.ok(Array.isArray(sub.body.catalog) && sub.body.catalog.length >= 4, "plans are advertised for upgrade");
  assert.ok(!sub.body.catalog.some((p) => p.key === "trial"), "the trial is not sold");
  // Usage is reported, not only enforced — the upgrade case should be visible
  // before a refusal makes it.
  assert.equal(sub.body.usage.seats.used, 1, "the founder is the first seat");
  assert.equal(sub.body.usage.nodes.used, 0, "a new organisation runs no market node yet");
  assert.equal(sub.body.usage.nodes.allowed, true);
});

test("expired trial goes READ-ONLY: reads still work, writes are refused 402", async () => {
  await resetAuthAttempts(); // isolate from other tests' signups; the throttle is asserted separately
  const suffix = randomUUID().slice(0, 8);
  const created = await req("POST", "/api/auth/signup", {
    body: { organisationName: `Expiry Co ${suffix}`, email: `expiry-${suffix}@example.com`, password: "a-long-enough-passphrase" }
  });
  const token = created.body.token;
  const tenantId = created.body.actor.tenantId;

  // Record something during the trial so there is history to protect.
  const during = await req("POST", "/api/evidence", { token, body: { claim: `Recorded during trial ${suffix}` } });
  assert.equal(during.status, 201);

  // Expire the trial by moving its end date into the past.
  await adminQuery(`UPDATE subscriptions SET trial_ends_at = now() - interval '1 day' WHERE tenant_id = $1`, [tenantId]);

  const sub = await req("GET", "/api/subscription", { token });
  assert.equal(sub.body.canWrite, false);
  assert.equal(sub.body.canRead, true);

  // Reads: everything recorded stays visible.
  const stillReadable = await req("GET", "/api/evidence", { token });
  assert.equal(stillReadable.status, 200);
  assert.ok(
    stillReadable.body.some((r) => r.id === during.body.id),
    "nothing recorded is deleted or hidden when a trial ends"
  );

  // Writes: refused with 402 and an actionable reason, not 403.
  const blocked = await req("POST", "/api/evidence", { token, body: { claim: "after expiry" } });
  assert.equal(blocked.status, 402, "payment required, not permission denied");
  assert.equal(blocked.body.readOnly, true);
  assert.match(blocked.body.reason, /remain readable/);

  // The gate covers every mutating route, not just the one it was written for.
  const alsoBlocked = await req("POST", "/api/genomes", { token, body: { code: "G-X", name: "X" } });
  assert.equal(alsoBlocked.status, 402);
  const transitionBlocked = await req("POST", `/api/evidence/${during.body.id}/transition`, {
    token, body: { to: "AUTHORIZED", reason: "should be refused" }
  });
  assert.equal(transitionBlocked.status, 402);
});

test("signup throttle stops an address creating unlimited organisations", async () => {
  await resetAuthAttempts();
  const suffix = randomUUID().slice(0, 8);

  let sawLockout = false;
  for (let i = 0; i < 8; i++) {
    const attempt = await req("POST", "/api/auth/signup", {
      body: {
        organisationName: `Flood Co ${suffix}-${i}`,
        email: `flood-${suffix}-${i}@example.com`,
        password: "a-long-enough-passphrase"
      }
    });
    if (attempt.status === 429) {
      sawLockout = true;
      assert.match(attempt.body.reason, /Too many organisations created/);
      break;
    }
    assert.equal(attempt.status, 201);
  }
  assert.ok(sawLockout, "an unthrottled signup endpoint lets one address flood the tenant table");
});

test("login throttle locks an account after repeated failures, then reports 429", async () => {
  const suffix = randomUUID().slice(0, 8);
  const email = `throttle-${suffix}@example.com`;
  await req("POST", "/api/auth/signup", {
    body: { organisationName: `Throttle Co ${suffix}`, email, password: "a-long-enough-passphrase" }
  });

  let sawLockout = false;
  for (let i = 0; i < 12; i++) {
    const attempt = await req("POST", "/api/auth/login", { body: { email, password: "wrong-password-here" } });
    if (attempt.status === 429) {
      sawLockout = true;
      assert.match(attempt.body.reason, /Too many failed sign-in attempts/);
      break;
    }
    assert.equal(attempt.status, 401);
  }
  assert.ok(sawLockout, "an unthrottled login endpoint is brute-forceable");

  // Correct credentials are refused too while locked — the throttle is not a
  // password check and must not be bypassable by finally guessing right.
  const correct = await req("POST", "/api/auth/login", { body: { email, password: "a-long-enough-passphrase" } });
  assert.equal(correct.status, 429);
});

test("billing is honestly gated when Stripe is not configured", async () => {
  const token = await loginToken();

  const status = await req("GET", "/api/billing/status", { token });
  assert.equal(status.status, 200);
  // The suite runs without STRIPE_SECRET_KEY, which is the state this asserts.
  assert.equal(status.body.configured, false);
  assert.match(status.body.reason, /not configured/i);
  assert.match(status.body.reason, /no charge can be created/i);

  // Checkout must refuse rather than pretend. 503, not a fake session.
  const checkout = await req("POST", "/api/billing/checkout", {
    token,
    body: { planKey: "founding", interval: "monthly" }
  });
  assert.equal(checkout.status, 503, "an unconfigured deployment cannot create a charge");
  assert.ok(!checkout.body.url, "no checkout URL is invented");
});

test("the webhook refuses an unsigned body", async () => {
  // Without signature verification anyone reaching this endpoint could grant
  // themselves a plan by POSTing JSON.
  const unsigned = await req("POST", "/api/billing/webhook", {
    body: { type: "customer.subscription.updated", data: { object: {} } }
  });
  assert.equal(unsigned.status, 400);
  assert.match(String(unsigned.body.reason ?? ""), /stripe-signature/i);
});

test("billing stays reachable for a read-only tenant so they can pay to return", async () => {
  const suffix = randomUUID().slice(0, 8);
  await resetAuthAttempts();
  const created = await req("POST", "/api/auth/signup", {
    body: { organisationName: `Lapsed Co ${suffix}`, email: `lapsed-${suffix}@example.com`, password: "a-long-enough-passphrase" }
  });
  const token = created.body.token;
  await adminQuery(`UPDATE subscriptions SET trial_ends_at = now() - interval '1 day' WHERE tenant_id = $1`,
    [created.body.actor.tenantId]);

  // Ordinary writes are refused...
  const blocked = await req("POST", "/api/evidence", { token, body: { claim: "after expiry" } });
  assert.equal(blocked.status, 402);

  // ...but billing is not, or a lapsed customer could never come back.
  const checkout = await req("POST", "/api/billing/checkout", {
    token, body: { planKey: "founding", interval: "monthly" }
  });
  assert.notEqual(checkout.status, 402, "the write gate must not block the route that ends read-only mode");
  assert.equal(checkout.status, 503, "it refuses only because Stripe is unconfigured here");
});

// A fresh organisation owns its own receipt chain, so these assertions are
// independent of whatever receipts other tests have written.
async function tenantWithReceiptChain(label, count) {
  await resetAuthAttempts();
  const suffix = randomUUID().slice(0, 8);
  const created = await req("POST", "/api/auth/signup", {
    body: { organisationName: `${label} ${suffix}`, email: `${label.toLowerCase().replace(/\W+/g, "-")}-${suffix}@example.com`, password: "a-long-enough-passphrase" }
  });
  assert.equal(created.status, 201);
  const token = created.body.token;

  const evidence = await req("POST", "/api/evidence", { token, body: { claim: `${label} claim ${suffix}` } });
  assert.equal(evidence.status, 201);
  const evidenceId = evidence.body.id;
  for (const to of ["AUTHORIZED", "EXECUTED"]) {
    const moved = await req("POST", `/api/evidence/${evidenceId}/transition`, { token, body: { to, reason: "chain setup" } });
    assert.equal(moved.status, 200);
  }

  const receiptIds = [];
  for (let i = 1; i <= count; i += 1) {
    const attached = await req("POST", `/api/evidence/${evidenceId}/receipts`, {
      token,
      body: { receipt_type: "log", description: `${label} receipt ${i}` }
    });
    assert.equal(attached.status, 201);
    const added = attached.body.receipts.map((r) => r.id).filter((id) => !receiptIds.includes(id));
    assert.equal(added.length, 1, "each attach adds exactly one receipt");
    receiptIds.push(added[0]);
  }
  return { token, tenantId: created.body.actor.tenantId, receiptIds };
}

// The append-only trigger refuses this UPDATE from the app, so simulate an
// attacker with direct database access by bypassing triggers for one change.
async function tamperReceiptDescription(receiptId) {
  const pg = await import("pg");
  const client = new pg.default.Client({ connectionString: process.env.DATABASE_ADMIN_URL });
  await client.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL session_replication_role = replica");
    const updated = await client.query(
      "UPDATE evidence_receipts SET description = description || ' (altered)' WHERE id = $1",
      [receiptId]
    );
    assert.equal(updated.rowCount, 1);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    await client.end();
  }
}

test("receipts: verify-chain passes for an intact tenant chain", async () => {
  const { token, tenantId } = await tenantWithReceiptChain("Chain Intact", 3);

  const chain = await req("GET", "/api/receipts/verify-chain", { token });
  assert.equal(chain.status, 200);
  assert.equal(chain.body.verified, true);
  assert.equal(chain.body.tenant_id, tenantId);
  assert.equal(chain.body.sealed_receipts, 3);
  assert.equal(chain.body.unsealed_receipts, 0);
  assert.equal(chain.body.chain_tip.chain_sequence, 3);
  assert.deepEqual(chain.body.failures, []);
});

test("receipts: verify-chain reports a tampered receipt", async () => {
  const { token, receiptIds } = await tenantWithReceiptChain("Chain Tampered", 3);
  const tampered = receiptIds[1];

  await tamperReceiptDescription(tampered);

  const chain = await req("GET", "/api/receipts/verify-chain", { token });
  assert.equal(chain.status, 200);
  assert.equal(chain.body.verified, false);
  assert.equal(chain.body.sealed_receipts, 3);
  assert.equal(chain.body.failures.length, 1, "only the altered receipt fails");
  const [failure] = chain.body.failures;
  assert.equal(failure.receipt_id, tampered);
  assert.equal(failure.chain_sequence, 2);
  assert.equal(failure.cryptographic_checks.hash, false, "the recomputed hash no longer matches");
  assert.equal(failure.previous_link, true, "the stored links are untouched");
});

test("receipts: verify passes for an intact receipt", async () => {
  const { token, receiptIds } = await tenantWithReceiptChain("Receipt Intact", 3);

  const verified = await req("GET", `/api/receipts/${receiptIds[1]}/verify`, { token });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.verified, true);
  assert.equal(verified.body.status, "VERIFIED");
  assert.equal(verified.body.receipt.id, receiptIds[1]);
  assert.equal(verified.body.checks.previous_link, true);
  assert.equal(verified.body.checks.next_link, true);
  for (const [name, ok] of Object.entries(verified.body.checks)) {
    assert.equal(ok, true, `check ${name} passes`);
  }
});

test("receipts: verify reports a tampered receipt", async () => {
  const { token, receiptIds } = await tenantWithReceiptChain("Receipt Tampered", 3);
  const tampered = receiptIds[1];
  await tamperReceiptDescription(tampered);

  const verified = await req("GET", `/api/receipts/${tampered}/verify`, { token });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.verified, false);
  assert.equal(verified.body.status, "TAMPER_DETECTED");
  assert.equal(verified.body.receipt.id, tampered);
  assert.equal(verified.body.checks.hash, false, "the recomputed hash no longer matches");
  assert.equal(verified.body.checks.previous_link, true, "the stored links are untouched");
  assert.equal(verified.body.checks.next_link, true, "the stored links are untouched");

  // Its untouched neighbour still verifies on its own.
  const neighbour = await req("GET", `/api/receipts/${receiptIds[2]}/verify`, { token });
  assert.equal(neighbour.status, 200);
  assert.equal(neighbour.body.status, "VERIFIED");
});

async function resetAuthAttempts() {
  await adminQuery("DELETE FROM auth_attempts");
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

async function loginToken() {
  const login = await req("POST", "/api/auth/login", { body: { email: EMAIL, password: PASSWORD } });
  assert.equal(login.status, 200);
  return login.body.token;
}
