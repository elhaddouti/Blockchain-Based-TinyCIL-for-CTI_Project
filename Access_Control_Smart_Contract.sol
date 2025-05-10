// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Interface of VSSC contract to retrieve wrapped symmetric keys
interface IVSSC {
    struct WrappedKey {
        address collaborator;
        bytes encryptedSymmetricKey;
    }

    function getWrappedKeys(bytes32 deviceID) external view returns (WrappedKey[] memory);
    function ctiToCID(bytes32 deviceID) external view returns (string memory);
}

contract ACSC {
    enum PermissionType { None, Read, ReadWrite }

    struct Participant {
        address pubKey;     // Address used as public key (e.g., wallet or encryption ID)
        string role;        // Role of the participant (e.g., "SOC Analyst")
        uint256[] unitIDs;  // Units the participant is associated with
        bool registered;
    }

    struct CTIMetadata {
        uint256 unitID;             // Operational unit of the CTI
        bytes32 deviceID;           // Device ID for the CTI
    }

    address public vsscAddress;
    mapping(address => Participant) public participants;                 // Registered participants
    mapping(bytes32 => CTIMetadata) public ctiInfo;                      // deviceID => metadata
    mapping(address => mapping(bytes32 => PermissionType)) public permissions; // participant => deviceID => permission

    event AccessGranted(address indexed participant, string cid, bytes wrappedKey);
    event AccessDenied(address indexed participant, string reason);

    constructor(address _vsscAddress) {
        vsscAddress = _vsscAddress;
    }

    /**
     * @notice Register a participant (can be done via RASC beforehand)
     */
    function registerParticipant(
        address participant,
        string calldata role,
        uint256[] calldata unitIDs
    ) external {
        participants[participant] = Participant({
            pubKey: participant,
            role: role,
            unitIDs: unitIDs,
            registered: true
        });
    }

    /**
     * @notice Set metadata for a given CTI dataset (called during VSSC store)
     */
    function setCTIMetadata(bytes32 deviceID, uint256 unitID) external {
        require(msg.sender == vsscAddress, "Only VSSC can set CTI metadata");
        ctiInfo[deviceID] = CTIMetadata({unitID: unitID, deviceID: deviceID});
    }

    /**
     * @notice Assign access permission to a participant over specific CTI
     */
    function assignPermission(
        address participant,
        bytes32 deviceID,
        PermissionType permission
    ) external {
        require(participants[participant].registered, "Participant not registered");
        permissions[participant][deviceID] = permission;
    }

    /**
     * @notice Enforce access policy: if valid, retrieve encrypted key for the participant
     * @param deviceID Identifier of the CTI data
     */
    function enforceAccessPolicy(bytes32 deviceID, string calldata cid) external {
        Participant memory p = participants[msg.sender];
        if (!p.registered) {
            emit AccessDenied(msg.sender, "Participant not registered");
            return;
        }

        CTIMetadata memory meta = ctiInfo[deviceID];
        if (meta.unitID == 0) {
            emit AccessDenied(msg.sender, "CTI metadata not found");
            return;
        }

        // Check if the participant is authorized by UnitID and permission
        bool unitMatch = false;
        for (uint256 i = 0; i < p.unitIDs.length; i++) {
            if (p.unitIDs[i] == meta.unitID) {
                unitMatch = true;
                break;
            }
        }

        if (!unitMatch) {
            emit AccessDenied(msg.sender, "Unit mismatch");
            return;
        }

        PermissionType perm = permissions[msg.sender][deviceID];
        if (perm == PermissionType.None) {
            emit AccessDenied(msg.sender, "No permission");
            return;
        }

        // Fetch encrypted symmetric key from VSSC
        IVSSC vssc = IVSSC(vsscAddress);
        IVSSC.WrappedKey[] memory wrappedKeys = vssc.getWrappedKeys(deviceID);

        for (uint256 i = 0; i < wrappedKeys.length; i++) {
            if (wrappedKeys[i].collaborator == msg.sender) {
                emit AccessGranted(msg.sender, cid, wrappedKeys[i].encryptedSymmetricKey);
                return;
            }
        }

        emit AccessDenied(msg.sender, "Encrypted key not found");
    }
}

