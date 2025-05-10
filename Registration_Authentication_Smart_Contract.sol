// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// zk-SNARK Verifier Interface with verifying key VK_{zk} 
interface IZKVerifier {
    function verifyProof(
        uint256[2] calldata a,          // π.a
        uint256[2][2] calldata b,       // π.b
        uint256[2] calldata c,          // π.c
        uint256[] calldata input        // x = (R_device, deviceID, Pub_key)
    ) external view returns (bool);
}

contract RASC {
    struct Device {
        uint256 unitID;
        bytes32 pubKey;
        bool isRegistered;
        bool isBlacklisted;
    }

    struct AccessToken {
        bytes32 deviceID;
        string permissions;
        uint256 expirationTime;
    }

    mapping(bytes32 => Device) public devices;
    mapping(bytes32 => AccessToken) public accessTokens;

    IZKVerifier public verifier;  // uses VK_{zk}'

    event DeviceRegistered(bytes32 indexed deviceID, uint256 unitID, bytes32 pubKey);
    event RegistrationFailed(bytes32 indexed deviceID, string reason);
    event AccessTokenIssued(bytes32 indexed deviceID, string permissions, uint256 expirationTime);
    event ZKProofFailed(bytes32 indexed deviceID);

    constructor(address _verifierAddress) {
        verifier = IZKVerifier(_verifierAddress); // VK_{zk}' is hardcoded in that verifier
    }

    // Registration phase: unchanged
    function registerDevice(bytes32 deviceID, uint256 unitID)
        external
        returns (
            bytes32 privKey,
            bytes32 pubKey,
            address bcAddress
        )
    {
        if (!devices[deviceID].isRegistered) {
            privKey = keccak256(abi.encodePacked(block.timestamp, deviceID, msg.sender));
            pubKey = keccak256(abi.encodePacked(privKey));
            bcAddress = address(uint160(uint256(keccak256(abi.encodePacked(pubKey)))));

            devices[deviceID] = Device({
                unitID: unitID,
                pubKey: pubKey,
                isRegistered: true,
                isBlacklisted: false
            });

            emit DeviceRegistered(deviceID, unitID, pubKey);
            return (privKey, pubKey, bcAddress);
        } else {
            emit RegistrationFailed(deviceID, "Device already exists");
            revert("Device already registered.");
        }
    }

    // zk-SNARK verification + access token generation
    function verifyZKProofAndIssueToken(
        bytes32 deviceID,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256 R_device,           // e.g., challenge response or nonce
        uint256 pubKey_uint         // pubKey cast as uint256
    ) external returns (bool) {
        require(devices[deviceID].isRegistered, "Device not registered");
        require(!devices[deviceID].isBlacklisted, "Device is blacklisted");

        // Construct public inputs x = (R_device, deviceID, Pub_key)
        uint256 ;
        publicInputs[0] = R_device;
        publicInputs[1] = uint256(deviceID);     // deviceID as uint256
        publicInputs[2] = pubKey_uint;           // already passed as uint256

        bool isValid = verifier.verifyProof(a, b, c, publicInputs);

        if (isValid) {
            uint256 expiration = block.timestamp + 600; // 10 minutes
            string memory defaultPermissions = "read-write"; // can be customized

            accessTokens[deviceID] = AccessToken({
                deviceID: deviceID,
                permissions: defaultPermissions,
                expirationTime: expiration
            });

            emit AccessTokenIssued(deviceID, defaultPermissions, expiration);
            return true;
        } else {
            devices[deviceID].isBlacklisted = true;
            emit ZKProofFailed(deviceID);
            revert("Invalid zk-SNARK proof. Device blacklisted.");
        }
    }
}
