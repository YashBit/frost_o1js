
### Core Algorithm:

1. Each participant initiates key generation:
    - `keygen_begin`
        - Calls `generate_shares` internally
        - Calls `generate_dkg_challenge` internally
2. Participants exchange commitments and validate peers:
    - `keygen_receive_commitments_and_validate_peers`
        - Calls `generate_dkg_challenge` internally
        - Calls `is_valid_zkp` internally
3. Participants finalize their keys:
    - `keygen_finalize`
        - Calls `verify_share` internally for each received share

So the complete call sequence for a participant would be:

1. keygen_begin → generate_shares → generate_dkg_challenge
2. keygen_receive_commitments_and_validate_peers → is_valid_zkp → generate_dkg_challenge
3. keygen_finalize → verify_share

- First, implement the low-level primitives:
    - `generateDkgChallenge` (fundamental for proofs)
    - Helper functions for scalar operations
    - Helper functions for polynomial evaluation
- Next, implement the key share generation core:
    - `generateShares` (builds on polynomial operations)
    - `verifyShare` (relies on share generation logic)
- Then build the proof validation:
    - `isValidZkp` (needed for commitment verification)
- Implement the main protocol functions in this order:
    - `keygenBegin` (initiates the DKG process)
    - `keygenReceiveCommitmentsAndValidatePeers` (handles verification)
    - `keygenFinalize` (completes the process)
- Finally, implement the optional dealer-based function:
    - `keygenWithDealer` (uses components from above)