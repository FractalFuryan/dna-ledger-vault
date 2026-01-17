// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Stores *commitments only* (no media, no user traits).
///         Intended for GeoPhase provenance + ethics-anchor pinning.
/// @custom:security-contact security@dna-ledger-vault.example
contract AnankeAttestationRegistry {
    event Attested(
        bytes32 indexed geoCommit,
        bytes32 indexed ethicsAnchor,
        bytes32 indexed policyId,
        uint32 version,
        address attestor,
        uint64 timestamp
    );

    struct Attestation {
        bytes32 ethicsAnchor;
        bytes32 policyId;
        uint32 version;
        address attestor;
        uint64 timestamp;
    }

    // geoCommit => attestation
    mapping(bytes32 => Attestation) public attestations;

    /// @notice Attest to a GeoPhase commitment
    /// @param geoCommit Hash commitment to GeoPhase parameters
    /// @param ethicsAnchor SHA-256 hash of ethics invariants
    /// @param policyId Hash of policy document version
    /// @param version Protocol version number
    function attest(
        bytes32 geoCommit,
        bytes32 ethicsAnchor,
        bytes32 policyId,
        uint32 version
    ) external {
        require(geoCommit != bytes32(0), "geoCommit=0");
        require(ethicsAnchor != bytes32(0), "ethicsAnchor=0");
        require(policyId != bytes32(0), "policyId=0");

        // One-shot attestation for this commit (simple + auditable).
        require(attestations[geoCommit].timestamp == 0, "already attested");

        attestations[geoCommit] = Attestation({
            ethicsAnchor: ethicsAnchor,
            policyId: policyId,
            version: version,
            attestor: msg.sender,
            timestamp: uint64(block.timestamp)
        });

        emit Attested(geoCommit, ethicsAnchor, policyId, version, msg.sender, uint64(block.timestamp));
    }

    /// @notice Get attestation for a commitment
    /// @param geoCommit The commitment to query
    /// @return Attestation struct
    function getAttestation(bytes32 geoCommit) external view returns (Attestation memory) {
        return attestations[geoCommit];
    }

    /// @notice Check if commitment is attested
    /// @param geoCommit The commitment to check
    /// @return true if attested
    function isAttested(bytes32 geoCommit) external view returns (bool) {
        return attestations[geoCommit].timestamp != 0;
    }
}
