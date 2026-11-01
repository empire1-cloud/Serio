import "dotenv/config";
import { createHash, generateKeyPairSync } from "node:crypto";
import { getReceiptSigner, trustedReceiptKeys } from "../src/domain/receipt-integrity.js";

// Prints the environment for the next signing key. It reads the current key
// from the environment and writes nothing to disk: the new private key goes
// straight from stdout into the secret manager. See RECEIPT_KEY_ROTATION.md.

function argValue(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? null : process.argv[index + 1] ?? null;
}

try {
  const current = getReceiptSigner();
  if (current.devOnly) {
    throw new Error(
      "No production signing key is configured; use `npm run receipts:keygen` for the first key. "
        + "Development-key receipts must not be trusted by a production deployment.",
    );
  }

  const trusted = trustedReceiptKeys();
  const newKeyId = argValue("--key-id")
    ?? `empire1-receipts-${new Date().toISOString().replace(/[-:]/g, "").slice(0, 15)}Z`;
  if (trusted.has(newKeyId)) {
    throw new Error(`Key ID ${newKeyId} is already in use; pass --key-id with a new versioned ID`);
  }

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyB64 = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
  const publicKeyB64 = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const fingerprint = `sha256:${createHash("sha256").update(Buffer.from(publicKeyB64, "base64")).digest("hex")}`;

  // Every key that is trusted today stays trusted, now as a retired key.
  const retired = Object.fromEntries(trusted);

  console.log("# Store the PRIVATE value in your secret manager. Never commit it.");
  console.log(`# Retiring ${current.keyId} (${current.fingerprint})`);
  console.log(`RECEIPT_SIGNING_KEY_ID=${newKeyId}`);
  console.log(`RECEIPT_SIGNING_PRIVATE_KEY_B64=${privateKeyB64}`);
  console.log(`RECEIPT_SIGNING_PUBLIC_KEY_B64=${publicKeyB64}`);
  console.log(`RECEIPT_RETIRED_PUBLIC_KEYS_JSON=${JSON.stringify(retired)}`);
  console.log(`# fingerprint=${fingerprint}`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
