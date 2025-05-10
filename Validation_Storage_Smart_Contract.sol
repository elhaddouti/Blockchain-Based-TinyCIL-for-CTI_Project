// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VSSC {
    address public acscContract;

    // Event emitted when CTI is stored
    event CTIStored(bytes32 indexed deviceID, string cid, bytes encryptedCTIData);

    // Event emitted when symmetric key is encrypted for a collaborator
    event KeyWrapped(address indexed collaborator, bytes encryptedKey);

    // Structure to hold encrypted key per collaborator
    struct WrappedKey {
        address collaborator;
        bytes encryptedSymmetricKey; // K_enc_i = Encrypt_PubKey_i(K)
    }

    // Mapping from CTI ID to IPFS CID and encrypted key list
    mapping(bytes32 => string) public ctiToCID;
    mapping(bytes32 => WrappedKey[]) public ctiToWrappedKeys;

    constructor(address _acscContract) {
        acscContract = _acscContract;
    }

    /**
     * @notice Store encrypted CTI data and dispatch to ACSC for access policy enforcement.
     * @param deviceID The ID of the IoT device
     * @param cid The IPFS CID for the encrypted CTI data
     * @param encryptedCTIData Encrypted CTI payload C_D = Encrypt_K(D)
     * @param collaborators List of collaborator addresses
     * @param wrappedKeys List of encrypted symmetric keys for each collaborator
     */
    function storeCTIData(
        bytes32 deviceID,
        string calldata cid,
        bytes calldata encryptedCTIData,
        address[] calldata collaborators,
        bytes[] calldata wrappedKeys
    ) external {
        require(collaborators.length == wrappedKeys.length, "Mismatched collaborators and keys");

        // Record the CID
        ctiToCID[deviceID] = cid;

        // Store encrypted keys per collaborator
        delete ctiToWrappedKeys[deviceID]; // reset first if it exists
        for (uint256 i = 0; i < collaborators.length; i++) {
            ctiToWrappedKeys[deviceID].push(
                WrappedKey({
                    collaborator: collaborators[i],
                    encryptedSymmetricKey: wrappedKeys[i]
                })
            );
            emit KeyWrapped(collaborators[i], wrappedKeys[i]);
        }

        emit CTIStored(deviceID, cid, encryptedCTIData);

        // Trigger ACSC to enforce access policy
        triggerACSCPolicy(deviceID, cid);
    }

    /**
     * @notice Internal call to ACSC to enforce access control policy for the stored CTI
     * @param deviceID Device identifier
     * @param cid The IPFS CID where CTI is stored
     */
    function triggerACSCPolicy(bytes32 deviceID, string memory cid) internal {
        (bool success, ) = acscContract.call(
            abi.encodeWithSignature(
                "enforceAccessPolicy(bytes32,string)",
                deviceID,
                cid
            )
        );
        require(success, "ACSC policy enforcement failed");
    }

    /**
     * @notice Retrieve all wrapped keys for a given CTI data
     * @param deviceID Device identifier
     */
    function getWrappedKeys(bytes32 deviceID) external view returns (WrappedKey[] memory) {
        return ctiToWrappedKeys[deviceID];
    }
}

