// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./AgeVerifier.sol";
import "./NationalityVerifier.sol";
import "./AgeVerifierSigned.sol";
import "./NationalityVerifierSigned.sol";
import "./AgeVerifierRevocable.sol";

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

    /**
     * @notice Deploy the ZkIdVerifier with verifier contract addresses
     * @param _ageVerifier Address of the deployed AgeVerifier contract
     * @param _nationalityVerifier Address of the deployed NationalityVerifier contract
     * @param _ageVerifierSigned Address of the deployed AgeVerifierSigned contract
     * @param _nationalityVerifierSigned Address of the deployed NationalityVerifierSigned contract
     * @param _ageVerifierRevocable Address of the deployed AgeVerifierRevocable contract
     */
    constructor(
        address _ageVerifier,
        address _nationalityVerifier,
        address _ageVerifierSigned,
        address _nationalityVerifierSigned,
        address _ageVerifierRevocable
    ) {
        ageVerifier = AgeVerifier(_ageVerifier);
        nationalityVerifier = NationalityVerifier(_nationalityVerifier);
        ageVerifierSigned = AgeVerifierSigned(_ageVerifierSigned);
        nationalityVerifierSigned = NationalityVerifierSigned(_nationalityVerifierSigned);
        ageVerifierRevocable = AgeVerifierRevocable(_ageVerifierRevocable);
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
}
