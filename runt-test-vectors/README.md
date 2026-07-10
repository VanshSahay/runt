# Runt Test Vectors

Test vectors for all verifier types. Each vector includes proof data, public inputs,
and expected verification results.

## State Proofs (EIP-1186)

- `valid_account_proof.json` — Valid Ethereum account proof
- `invalid_proof.json` — Intentionally malformed proof

## Transaction Proofs

- `valid_receipt_proof.json` — Valid transaction receipt inclusion proof

## Consensus Proofs (Altair Light Client)

- `valid_update.json` — Valid sync committee update

## Groth16 Proofs

- `valid_proof.json` — Valid Groth16 proof on BN254
- `invalid_proof.json` — Invalid Groth16 proof
