// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./AgeVerifier.sol";
import "./NationalityVerifier.sol";
import "./AgeVerifierSigned.sol";
import "./NationalityVerifierSigned.sol";
import "./AgeVerifierRevocable.sol";
import "./PredicateVerifier.sol";

/**
 * @title ZkIdVerifier
 * @notice High-level contract for verifying zk-id proofs on-chain
 * @dev Wraps the auto-generated Groth16 verifiers with semantic function names
 *
 * Use cases:
 * - DeFi KYC: Verify age eligibility for regulated DeFi protocols
 * - DAO voting: Age-gate governance participation
 * - NFT minting: Age-restricted NFT collections
 * - Token transfers: Compliant token transfers with on-chain age verification
 * - Smart contract access control: Age or nationality-based permissions
 */
contract ZkIdVerifier {
    // Verifier contracts
    AgeVerifier private immutable ageVerifier;
    NationalityVerifier private immutable nationalityVerifier;
    AgeVerifierSigned private immutable ageVerifierSigned;
    NationalityVerifierSigned private immutable nationalityVerifierSigned;
    AgeVerifierRevocable private immutable ageVerifierRevocable;
    PredicateVerifier private immutable predicateVerifier;

    // Events
    event AgeProofVerified(
        address indexed user,
        uint256 currentYear,
        uint256 minAge,
        bytes32 credentialHash,
        uint256 nonce,
        uint256 requestTimestamp
    );

    event NationalityProofVerified(
        address indexed user,
        uint256 nationalityCode,
        bytes32 credentialHash,
        uint256 nonce,
        uint256 requestTimestamp
    );

    event PredicateProofVerified(
        address indexed user,
        bytes32 credentialCommitment,
        uint256 predicateType,
        uint256 targetValue,
        uint256 nonce,
        uint256 timestamp
    );

    /**
     * @notice Deploy the ZkIdVerifier with verifier contract addresses
     * @param _ageVerifier Address of the deployed AgeVerifier contract
     * @param _nationalityVerifier Address of the deployed NationalityVerifier contract
     * @param _ageVerifierSigned Address of the deployed AgeVerifierSigned contract
     * @param _nationalityVerifierSigned Address of the deployed NationalityVerifierSigned contract
     * @param _ageVerifierRevocable Address of the deployed AgeVerifierRevocable contract
     * @param _predicateVerifier Address of the deployed PredicateVerifier contract
     */
    constructor(
        address _ageVerifier,
        address _nationalityVerifier,
        address _ageVerifierSigned,
        address _nationalityVerifierSigned,
        address _ageVerifierRevocable,
        address _predicateVerifier
    ) {
        ageVerifier = AgeVerifier(_ageVerifier);
        nationalityVerifier = NationalityVerifier(_nationalityVerifier);
        ageVerifierSigned = AgeVerifierSigned(_ageVerifierSigned);
        nationalityVerifierSigned = NationalityVerifierSigned(_nationalityVerifierSigned);
        ageVerifierRevocable = AgeVerifierRevocable(_ageVerifierRevocable);
        predicateVerifier = PredicateVerifier(_predicateVerifier);
    }

    /**
     * @notice Verify an age proof on-chain
     * @dev Public signals order: [currentYear, minAge, credentialHash, nonce, requestTimestamp]
     * @param pA Proof component A (Groth16)
     * @param pB Proof component B (Groth16)
     * @param pC Proof component C (Groth16)
     * @param currentYear The current year for age calculation
     * @param minAge Minimum required age (e.g., 18 or 21)
     * @param credentialHash Poseidon hash of the credential
     * @param nonce Replay protection nonce
     * @param requestTimestamp Unix timestamp of the proof request
     * @return bool True if the proof is valid
     */
    function verifyAgeProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256 currentYear,
        uint256 minAge,
        uint256 credentialHash,
        uint256 nonce,
        uint256 requestTimestamp
    ) external view returns (bool) {
        uint256[5] memory publicSignals = [
            currentYear,
            minAge,
            credentialHash,
            nonce,
            requestTimestamp
        ];

        return ageVerifier.verifyProof(pA, pB, pC, publicSignals);
    }

    /**
     * @notice Verify an age proof and emit an event
     * @dev Use this when you want the verification event logged on-chain
     * @param pA Proof component A (Groth16)
     * @param pB Proof component B (Groth16)
     * @param pC Proof component C (Groth16)
     * @param currentYear The current year for age calculation
     * @param minAge Minimum required age (e.g., 18 or 21)
     * @param credentialHash Poseidon hash of the credential
     * @param nonce Replay protection nonce
     * @param requestTimestamp Unix timestamp of the proof request
     * @return bool True if the proof is valid
     */
    function verifyAgeProofWithEvent(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256 currentYear,
        uint256 minAge,
        uint256 credentialHash,
        uint256 nonce,
        uint256 requestTimestamp
    ) external returns (bool) {
        uint256[5] memory publicSignals = [
            currentYear,
            minAge,
            credentialHash,
            nonce,
            requestTimestamp
        ];

        bool verified = ageVerifier.verifyProof(pA, pB, pC, publicSignals);

        if (verified) {
            emit AgeProofVerified(
                msg.sender,
                currentYear,
                minAge,
                bytes32(credentialHash),
                nonce,
                requestTimestamp
            );
        }

        return verified;
    }

    /**
     * @notice Verify a nationality proof on-chain
     * @dev Public signals order: [nationalityCode, credentialHash, nonce, requestTimestamp]
     * @param pA Proof component A (Groth16)
     * @param pB Proof component B (Groth16)
     * @param pC Proof component C (Groth16)
     * @param nationalityCode ISO 3166-1 numeric nationality code
     * @param credentialHash Poseidon hash of the credential
     * @param nonce Replay protection nonce
     * @param requestTimestamp Unix timestamp of the proof request
     * @return bool True if the proof is valid
     */
    function verifyNationalityProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256 nationalityCode,
        uint256 credentialHash,
        uint256 nonce,
        uint256 requestTimestamp
    ) external view returns (bool) {
        uint256[4] memory publicSignals = [
            nationalityCode,
            credentialHash,
            nonce,
            requestTimestamp
        ];

        return nationalityVerifier.verifyProof(pA, pB, pC, publicSignals);
    }

    /**
     * @notice Verify a nationality proof and emit an event
     * @dev Use this when you want the verification event logged on-chain
     * @param pA Proof component A (Groth16)
     * @param pB Proof component B (Groth16)
     * @param pC Proof component C (Groth16)
     * @param nationalityCode ISO 3166-1 numeric nationality code
     * @param credentialHash Poseidon hash of the credential
     * @param nonce Replay protection nonce
     * @param requestTimestamp Unix timestamp of the proof request
     * @return bool True if the proof is valid
     */
    function verifyNationalityProofWithEvent(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256 nationalityCode,
        uint256 credentialHash,
        uint256 nonce,
        uint256 requestTimestamp
    ) external returns (bool) {
        uint256[4] memory publicSignals = [
            nationalityCode,
            credentialHash,
            nonce,
            requestTimestamp
        ];

        bool verified = nationalityVerifier.verifyProof(pA, pB, pC, publicSignals);

        if (verified) {
            emit NationalityProofVerified(
                msg.sender,
                nationalityCode,
                bytes32(credentialHash),
                nonce,
                requestTimestamp
            );
        }

        return verified;
    }

    /**
     * @notice Verify an age proof with issuer signature verification
     * @dev Use this when you need to verify both the ZK proof and the issuer's signature in-circuit
     * @dev Public signals (261 total): issuerPublicKey (256 bits), currentYear, minAge, credentialHash, nonce, requestTimestamp
     * @param pA Proof component A (Groth16)
     * @param pB Proof component B (Groth16)
     * @param pC Proof component C (Groth16)
     * @param publicSignals Public signals array (261 elements: 256 issuer pubkey bits + 5 claim signals)
     * @return bool True if the proof is valid
     */
    function verifyAgeProofSigned(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[261] calldata publicSignals
    ) external view returns (bool) {
        return ageVerifierSigned.verifyProof(pA, pB, pC, publicSignals);
    }

    /**
     * @notice Verify a nationality proof with issuer signature verification
     * @dev Public signals (260 total): issuerPublicKey (256 bits), nationalityCode, credentialHash, nonce, requestTimestamp
     * @param pA Proof component A (Groth16)
     * @param pB Proof component B (Groth16)
     * @param pC Proof component C (Groth16)
     * @param publicSignals Public signals array (260 elements: 256 issuer pubkey bits + 4 claim signals)
     * @return bool True if the proof is valid
     */
    function verifyNationalityProofSigned(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[260] calldata publicSignals
    ) external view returns (bool) {
        return nationalityVerifierSigned.verifyProof(pA, pB, pC, publicSignals);
    }

    /**
     * @notice Verify an age proof with revocation check (Merkle inclusion)
     * @dev Use this when you need to verify the credential is in the valid-set (not revoked)
     * @dev Public signals (6 total): currentYear, minAge, credentialHash, nonce, requestTimestamp, merkleRoot
     * @param pA Proof component A (Groth16)
     * @param pB Proof component B (Groth16)
     * @param pC Proof component C (Groth16)
     * @param publicSignals Public signals array (6 elements: 5 age claim signals + merkle root)
     * @return bool True if the proof is valid
     */
    function verifyAgeProofRevocable(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[6] calldata publicSignals
    ) external view returns (bool) {
        return ageVerifierRevocable.verifyProof(pA, pB, pC, publicSignals);
    }

    /**
     * @notice Verify a generic predicate proof on-chain
     * @dev Public signals order: [credentialCommitment, predicateType, targetValue, rangeMax, fieldSelector, nonce, timestamp, satisfied]
     * @param pA Proof component A (Groth16)
     * @param pB Proof component B (Groth16)
     * @param pC Proof component C (Groth16)
     * @param credentialCommitment Poseidon hash commitment of the credential
     * @param predicateType Type of predicate (0=EQ, 1=GT, 2=LT, 3=RANGE)
     * @param targetValue Target value for comparison
     * @param rangeMax Maximum value for range proofs
     * @param fieldSelector Which credential field to evaluate
     * @param nonce Replay protection nonce
     * @param timestamp Unix timestamp of the proof request
     * @param satisfied Result of predicate evaluation (must be 1)
     * @return bool True if the proof is valid and satisfied == 1
     */
    function verifyPredicateProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256 credentialCommitment,
        uint256 predicateType,
        uint256 targetValue,
        uint256 rangeMax,
        uint256 fieldSelector,
        uint256 nonce,
        uint256 timestamp,
        uint256 satisfied
    ) external view returns (bool) {
        // Validate satisfied == 1
        require(satisfied == 1, "Predicate not satisfied");

        uint256[8] memory publicSignals = [
            credentialCommitment,
            predicateType,
            targetValue,
            rangeMax,
            fieldSelector,
            nonce,
            timestamp,
            satisfied
        ];

        return predicateVerifier.verifyProof(pA, pB, pC, publicSignals);
    }

    /**
     * @notice Verify a predicate proof and emit an event
     * @dev Use this when you want the verification event logged on-chain
     * @param pA Proof component A (Groth16)
     * @param pB Proof component B (Groth16)
     * @param pC Proof component C (Groth16)
     * @param credentialCommitment Poseidon hash commitment of the credential
     * @param predicateType Type of predicate (0=EQ, 1=GT, 2=LT, 3=RANGE)
     * @param targetValue Target value for comparison
     * @param rangeMax Maximum value for range proofs
     * @param fieldSelector Which credential field to evaluate
     * @param nonce Replay protection nonce
     * @param timestamp Unix timestamp of the proof request
     * @param satisfied Result of predicate evaluation (must be 1)
     * @return bool True if the proof is valid
     */
    function verifyPredicateProofWithEvent(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256 credentialCommitment,
        uint256 predicateType,
        uint256 targetValue,
        uint256 rangeMax,
        uint256 fieldSelector,
        uint256 nonce,
        uint256 timestamp,
        uint256 satisfied
    ) external returns (bool) {
        // Validate satisfied == 1
        require(satisfied == 1, "Predicate not satisfied");

        uint256[8] memory publicSignals = [
            credentialCommitment,
            predicateType,
            targetValue,
            rangeMax,
            fieldSelector,
            nonce,
            timestamp,
            satisfied
        ];

        bool verified = predicateVerifier.verifyProof(pA, pB, pC, publicSignals);

        if (verified) {
            emit PredicateProofVerified(
                msg.sender,
                bytes32(credentialCommitment),
                predicateType,
                targetValue,
                nonce,
                timestamp
            );
        }

        return verified;
    }
}
