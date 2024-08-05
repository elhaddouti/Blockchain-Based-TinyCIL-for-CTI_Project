// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CTIValidation {
    struct CTIResult {
        uint256 Timestamp;     // Timestamp when the threat was detected
        string DeviceID;       // Identifier of the device where the threat was detected
        string ThreatType;     // Type of threat (e.g., "DDoS", "Spoofing")
        uint256 ConfidenceScore; // The model’s confidence score
        string AdditionalInfo; // List of related indicators (e.g., IP addresses, URLs)
        string DeviceSignature; // Digital signature for data integrity
    }

    CTIResult[] globalCTI;
    CTIResult[] aggregatedCTI;
    address[] public validators;
    mapping(bytes32 => bool) public existingRecords;

    event CTIValidationResult(bool isValid, string message);

    constructor(address[] memory _validators) {
        validators = _validators;
    }

    function submitCTI(CTIResult memory ctiResult) public returns (bool) {
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
            if (validate(validators[i], ctiResult)) {
                validCount++;
            }
        }

        if (validCount >= (validators.length + 1) / 2) {
            // Update the global CTI repository
            updateGlobalCTI(ctiResult);
            emit CTIValidationResult(true, "CTI is valid");
            return true;
        }

        emit CTIValidationResult(false, "Consensus not reached");
        return false;

    
    }

    function checkRequiredFields(CTIResult memory ctiResult) internal pure returns (bool) {
        return (bytes(ctiResult.ThreatType).length > 0 &&
                bytes(ctiResult.AdditionalInfo).length > 0 &&
                ctiResult.Timestamp > 0 &&
                bytes(ctiResult.DeviceID).length > 0 &&
                ctiResult.ConfidenceScore > 0 &&
                bytes(ctiResult.DeviceSignature).length > 0);
    }

    function checkForDuplicate(CTIResult memory ctiResult) internal view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(ctiResult.Timestamp, ctiResult.DeviceID, ctiResult.ThreatType));
        return !existingRecords[hash];
    }

    function verifyDigitalSignature(CTIResult memory ctiResult) internal pure returns (bool) {
       // Implement digital signature verification logic
        if (bytes(ctiResult.DeviceID).length != bytes(ctiResult.DeviceSignature).length) {
            return true;
        } else {
            return false;
        }
    }

    function aggregateCTI(CTIResult memory ctiResult) internal {
    aggregatedCTI.push(ctiResult);
    }

    function validate(address validator, CTIResult memory ctiResult) internal view returns (bool) {
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

        if (isFormatValid && isDuplicateValid && isSignatureValid) {
            return true;
        } else {
            return false;
        }
    }

    function updateGlobalCTI(CTIResult memory ctiResult) internal {
        globalCTI.push(ctiResult);
        bytes32 hash = keccak256(abi.encodePacked(ctiResult.Timestamp, ctiResult.DeviceID, ctiResult.ThreatType));
        existingRecords[hash] = true;
         
    }
}

