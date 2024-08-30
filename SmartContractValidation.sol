// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CTIValidation {
    struct CTIResult {
        uint256 Timestamp;        // Timestamp when the threat was detected
        string DeviceID;          // Identifier of the device where the threat was detected
        string ThreatType;        // Type of threat (e.g., "DDoS", "Spoofing")
        uint256 ConfidenceScore;  // The model’s confidence score
        string AdditionalInfo;    // List of related indicators (e.g., IP addresses, URLs)
        bytes32 r;                // r value of the ECC signature
        bytes32 s;                // s value of the ECC signature
        uint8 v;                  // v value of the ECC signature
    }

    CTIResult[] public globalCTI;
    CTIResult[] public aggregatedCTI;
    address[] public validators;
    mapping(bytes32 => bool) public existingRecords;

    event CTIValidationResult(bool isValid, string message);

    constructor(address[] memory _validators) {
        validators = _validators;
    }

    function validateCTI(CTIResult memory ctiResult) public returns (bool) {
        // Validation Process
        bool isFormatValid = checkRequiredFields(ctiResult);
        if (!isFormatValid) {
            emit CTIValidationResult(false, "Invalid format");
            return false;
        }

        bool isDuplicateValid = checkForDuplicate(ctiResult);
        if (!isDuplicateValid) {
            emit CTIValidationResult(false, "Duplicate record");
            return false;
        }

        bool isSignatureValid = verifyDigitalSignature(ctiResult);
        if (!isSignatureValid) {
            emit CTIValidationResult(false, "Invalid signature");
            return false;
        }

        // Proceed to Aggregation
        aggregateCTI(ctiResult);

        // Consensus Algorithm
        uint256 validCount = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            if (consensus(validators[i], ctiResult)) {
                validCount++;
            }
        }

        // Check if validCount is greater than half of the number of validators
        if (validCount > validators.length / 2) {
            // Update the global CTI repository
            updateGlobalCTI(ctiResult);
            emit CTIValidationResult(true, "CTI is valid");
            return true;
        } else {
            emit CTIValidationResult(false, "Consensus not reached");
            return false;
        }
    }

    function checkRequiredFields(CTIResult memory ctiResult) internal pure returns (bool) {
        return (bytes(ctiResult.ThreatType).length > 0 &&
                bytes(ctiResult.AdditionalInfo).length > 0 &&
                ctiResult.Timestamp > 0 &&
                bytes(ctiResult.DeviceID).length > 0 &&
                ctiResult.ConfidenceScore > 0 &&
                ctiResult.r != bytes32(0) &&
                ctiResult.s != bytes32(0) &&
                ctiResult.v >= 27 && ctiResult.v <= 28);
    }

    function checkForDuplicate(CTIResult memory ctiResult) internal view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(ctiResult.Timestamp, ctiResult.DeviceID, ctiResult.ThreatType));
        return !existingRecords[hash];
    }

    function verifyDigitalSignature(CTIResult memory ctiResult) internal pure returns (bool) {
        // Simplified verification (real verification would require off-chain computation)
        return true;
    }

    function aggregateCTI(CTIResult memory ctiResult) internal {
        aggregatedCTI.push(ctiResult);
    }

    function consensus(address validator, CTIResult memory ctiResult) internal view returns (bool) {
        bool isValidator = false;
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i] == validator) {
                isValidator = true;
                break;
            }
        }
        require(isValidator, "Validator not registered");

        // Validation Process
        bool isFormatValid = checkRequiredFields(ctiResult);
        bool isDuplicateValid = checkForDuplicate(ctiResult);
        bool isSignatureValid = verifyDigitalSignature(ctiResult);

        return isFormatValid && isDuplicateValid && isSignatureValid;
    }

    function updateGlobalCTI(CTIResult memory ctiResult) internal {
        globalCTI.push(ctiResult);
        bytes32 hash = keccak256(abi.encodePacked(ctiResult.Timestamp, ctiResult.DeviceID, ctiResult.ThreatType));
        existingRecords[hash] = true;
    }
}
