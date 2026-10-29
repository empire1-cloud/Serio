# Receipt signing key rotation

Receipts are signed with Ed25519. Each receipt stores the key ID and public key
it was signed with, so a key can be replaced without re-signing history.

Verification (`GET /api/receipts/:id/verify` and `GET /api/receipts/verify-chain`)
also checks `key_trusted`: the receipt's key ID must map to the same public key
in this deployment's trusted set. The trusted set is the active signing key plus
every key listed in `RECEIPT_RETIRED_PUBLIC_KEYS_JSON`. Without this check, a
receipt re-signed with any key stored beside it would verify.

## Configuration

| Variable | Contains | Secret? |
|---|---|---|
| `RECEIPT_SIGNING_KEY_ID` | Active key ID, versioned and never reused | No |
| `RECEIPT_SIGNING_PRIVATE_KEY_B64` | Active private key (PKCS#8 DER, base64) | **Yes, secret manager only** |
| `RECEIPT_SIGNING_PUBLIC_KEY_B64` | Active public key, checked against the private key | No |
| `RECEIPT_RETIRED_PUBLIC_KEYS_JSON` | `{"<key_id>": "<public_key_b64>"}` for retired keys | No |

Startup fails closed if the retired list is malformed, holds an invalid public
key, or reuses the active key ID.

## Procedure

1. In an environment that already holds the current key, run:

   ```
   npm run receipts:rotate -- --key-id empire1-receipts-2026-11-01
   ```

   It prints the new key ID, the new private and public keys, and an updated
   `RECEIPT_RETIRED_PUBLIC_KEYS_JSON` that keeps every currently trusted key.
   It writes nothing to disk. Omit `--key-id` to use a timestamped ID.
2. Put `RECEIPT_SIGNING_PRIVATE_KEY_B64` in the secret manager. Never commit it
   or paste it into tickets or chat.
3. Set the other three values in the deployment config and deploy.
4. Confirm `GET /api/receipt-keys/current` reports the new key ID and fingerprint.
5. Run `GET /api/receipts/verify-chain` for each tenant. Expect `verified: true`,
   with receipts before the rotation still on the old key ID.
6. Publish the new fingerprint to verifiers, and record the rotation (old and
   new key IDs, fingerprints, verify-chain results) as an evidence receipt.
7. Destroy the old private key once the new key is confirmed. Keep its public
   key in `RECEIPT_RETIRED_PUBLIC_KEYS_JSON` for as long as its receipts must verify.

The first production key comes from `npm run receipts:keygen`; the rotate script
refuses to retire the development key, whose receipts production must not trust.

## Compromised key

Rotate as above, but leave the compromised key out of
`RECEIPT_RETIRED_PUBLIC_KEYS_JSON` (edit the printed value before deploying).
Its receipts then fail `key_trusted` and show up in verify-chain as failures to
investigate and re-issue.
