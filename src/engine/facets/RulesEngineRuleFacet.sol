// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;
import "src/engine/facets/RulesEngineAdminRolesFacet.sol";
import "src/engine/facets/RulesEngineComponentFacet.sol";
import {RulesEngineStorageLib as StorageLib} from "src/engine/facets/RulesEngineStorageLib.sol";
/**
 * @title Rules Engine Policy Facet
 * @dev This contract serves as the primary data facet for the Rules Engine rules. It is responsible for creating, updating,
 *      retrieving, and managing rules. It enforces role-based access control and ensures that only authorized
 *      users can modify or retrieve data. The contract also supports policy cementing to prevent further modifications.
 * @notice This contract is a critical component of the Rules Engine, enabling secure and flexible policy management.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract RulesEngineRuleFacet is FacetCommonImports {
    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Rule Management
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Creates a rule in storage.
     * @dev Adds a new rule to the specified policy. Only accessible by policy admins.
     * @param policyId ID of the policy the rule will be added to.
     * @param rule The rule to create.
     * @param ruleName The name of the rule
     * @param ruleDescription The description of the rule
     * @return ruleId The generated rule ID.
     */
    function createRule(
        uint256 policyId,
        Rule calldata rule,
        string calldata ruleName,
        string calldata ruleDescription
    ) external returns (uint256) {
        if (policyId == 0) revert(POLICY_ID_0);
        _policyAdminOnly(policyId, msg.sender);
        _validateRule(rule, policyId);
        StorageLib._notCemented(policyId);
        RuleStorage storage data = lib._getRuleStorage();
        uint256 ruleId = _incrementRuleId(data, policyId);
        _storeRuleData(data, policyId, ruleId, rule, ruleName, ruleDescription);
        emit RuleCreated(policyId, ruleId);
        return ruleId;
    }

    /**
     * @notice Updates a rule in storage.
     * @dev Modifies an existing rule in the specified policy. Only accessible by policy admins.
     * @param policyId ID of the policy the rule belongs to.
     * @param ruleId The ID of the rule to update.
     * @param rule The updated rule data.
     * @return ruleId The updated rule ID.
     */
    function updateRule(
        uint256 policyId,
        uint256 ruleId,
        Rule calldata rule,
        string calldata ruleName,
        string calldata ruleDescription
    ) external returns (uint256) {
        if (policyId == 0) revert(POLICY_ID_0);
        _policyAdminOnly(policyId, msg.sender);
        _validateRule(rule, policyId);
        if (!StorageLib._isRuleSet(policyId, ruleId)) revert(RULE_NOT_SET);
        StorageLib._notCemented(policyId);
        // Load the rule data from storage
        RuleStorage storage data = lib._getRuleStorage();
        _storeRuleData(data, policyId, ruleId, rule, ruleName, ruleDescription);
        emit RuleUpdated(policyId, ruleId);
        return ruleId;
    }

    /**
     * @notice Retrieves all rules associated with a specific policy.
     * @param policyId The ID of the policy.
     * @return rules A two-dimensional array of rules grouped by calling functions.
     */
    function getAllRules(uint256 policyId) external view returns (Rule[][] memory) {
        if (policyId == 0) revert(POLICY_ID_0);
        // Load the policy data from storage
        Policy storage data = lib._getPolicyStorage().policyStorageSets[policyId].policy;
        bytes4[] memory callingFunctions = data.callingFunctions;
        Rule[][] memory rules = new Rule[][](callingFunctions.length);
        // Data validation will always ensure callingFunctions.length will be less than MAX_LOOP
        for (uint256 i = 0; i < callingFunctions.length; i++) {
            uint256[] memory ruleIds = data.callingFunctionsToRuleIds[callingFunctions[i]];
            rules[i] = new Rule[](ruleIds.length);
            // Data validation will always ensure ruleIds.length will be less than MAX_LOOP
            for (uint256 j = 0; j < ruleIds.length; j++) {
                if (StorageLib._isRuleSet(policyId, ruleIds[j])) {
                    rules[i][j] = lib._getRuleStorage().ruleStorageSets[policyId][ruleIds[j]].rule;
                }
            }
        }
        return rules;
    }

    /**
     * @notice Retrieves the metadata of a rule.
     * @param policyId The ID of the policy the rule belongs to.
     * @param ruleId The ID of the rule to retrieve metadata for.
     * @return RuleMetadata The metadata of the specified rule.
     */
    function getRuleMetadata(uint256 policyId, uint256 ruleId) external view returns (RuleMetadata memory) {
        if (policyId == 0) revert(POLICY_ID_0);
        return (lib._getRulesMetadataStorage().ruleMetadata[policyId][ruleId]);
    }

    /**
     * @notice Deletes a rule from storage.
     * @param policyId The ID of the policy the rule belongs to.
     * @param ruleId The ID of the rule to delete.
     */
    function deleteRule(uint256 policyId, uint256 ruleId) public {
        if (policyId == 0) revert(POLICY_ID_0);
        if (!lib._getRuleStorage().ruleStorageSets[policyId][ruleId].set) revert(INVALID_RULE);
        _policyAdminOnly(policyId, msg.sender);
        StorageLib._notCemented(policyId);
        bytes4[] memory callingFunctions = lib._getPolicyStorage().policyStorageSets[policyId].policy.callingFunctions;
        for (uint256 i = 0; i < callingFunctions.length; i++) {
            uint256[] memory ruleIds = lib._getPolicyStorage().policyStorageSets[policyId].policy.callingFunctionsToRuleIds[
                callingFunctions[i]
            ];
            uint256[] memory newRuleIds = new uint256[](ruleIds.length - 1);
            uint256 k = 0;
            for (uint256 j = 0; j < ruleIds.length; j++) {
                if (ruleIds[j] == ruleId) {
                    continue;
                }
                newRuleIds[k] = ruleIds[j];
                k++;
            }
            lib._getPolicyStorage().policyStorageSets[policyId].policy.callingFunctionsToRuleIds[callingFunctions[i]] = newRuleIds;
        }
        _removeRuleFromTrackerIdMapping(policyId, ruleId);
        delete lib._getRuleStorage().ruleStorageSets[policyId][ruleId];

        emit RuleDeleted(policyId, ruleId);
    }

    /**
     * @notice Retrieves a rule from storage.
     * @param policyId The ID of the policy the rule belongs to.
     * @param ruleId The ID of the rule to retrieve.
     * @return ruleStorageSets The rule data.
     */
    function getRule(uint256 policyId, uint256 ruleId) public view returns (RuleStorageSet memory) {
        if (policyId == 0) revert(POLICY_ID_0);
        // Load the rule data from storage
        return lib._getRuleStorage().ruleStorageSets[policyId][ruleId];
    }

    function getMemorySize() external pure returns (uint) {
        return memorySize;
    }
    function getMaxLoopSize() external pure returns (uint) {
        return MAX_LOOP;
    }
    function getOpsSize1() external pure returns (uint) {
        return opsSize1;
    }
    function getOpsSizeUpTo2() external pure returns (uint) {
        return opsSizeUpTo2;
    }
    function getOpsSizeUpTo3() external pure returns (uint) {
        return opsSizeUpTo3;
    }
    function getOpsTotalSize() external pure returns (uint) {
        return opsTotalSize;
    }

    /**
     * @notice Stores rule data in storage.
     * @dev This function is used to store the rule and its metadata.
     * @param data The rule storage structure.
     * @param policyId The ID of the policy the rule belongs to.
     * @param ruleId The ID of the rule to store.
     * @param rule The rule to store.
     * @param ruleName The name of the rule.
     * @param ruleDescription The description of the rule.
     */
    function _storeRuleData(
        RuleStorage storage data,
        uint256 policyId,
        uint256 ruleId,
        Rule calldata rule,
        string calldata ruleName,
        string calldata ruleDescription
    ) private {
        _storeRule(data, policyId, ruleId, rule);
        _storeRuleMetadata(policyId, ruleId, ruleName, ruleDescription);
    }

    /**
     * @notice Stores a rule in storage.
     * @dev Validates the policy existence before storing the rule.
     * @param _data The rule storage structure.
     * @param _policyId The ID of the policy the rule belongs to.
     * @param _ruleId The ID of the rule to store.
     * @param _rule The rule to store.
     * @return ruleId The stored rule ID.
     */
    function _storeRule(RuleStorage storage _data, uint256 _policyId, uint256 _ruleId, Rule calldata _rule) internal returns (uint256) {
        // Validate that the policy exists
        if (!lib._getPolicyStorage().policyStorageSets[_policyId].set) revert(POLICY_DOES_NOT_EXIST);

        _data.ruleStorageSets[_policyId][_ruleId].set = true;
        _data.ruleStorageSets[_policyId][_ruleId].rule = _rule;
        _updateTrackerIdMapping(_data, _policyId, _ruleId);
        return _ruleId;
    }

    /**
     * @notice Updates the mapping of tracker IDs to rule IDs for a specific policy.
     * @dev This function checks if a tracker is used in the instruction set of the rule and updates the mapping accordingly.
     * @param _data The rule storage structure.
     * @param _policyId The ID of the policy to update the mapping for.
     * @param _ruleId The ID of the rule to check for tracker usage.
     */
    function _updateTrackerIdMapping(RuleStorage storage _data, uint256 _policyId, uint256 _ruleId) internal {
        TrackerStorage storage trackerData = lib._getTrackerStorage();
        Placeholder[] memory placeHolders = _data.ruleStorageSets[_policyId][_ruleId].rule.placeHolders;
        Placeholder[] memory effectPlaceHolders = _data.ruleStorageSets[_policyId][_ruleId].rule.effectPlaceHolders;
        // check if a tracker is used in the instruction set of the rule
        // if so, we update the mapping to point to the rule ID
        for (uint256 i = 0; i < placeHolders.length; i++) {
            // check for tracker flag on placeholder
            if (FacetUtils._isTrackerValue(placeHolders[i])) {
                // if the placeholder flag is a tracker, save the ruleID to array
                uint256 index = placeHolders[i].typeSpecificIndex;
                bool exists = false;
                for (uint256 j = 0; j < trackerData.trackerIdToRuleIds[_policyId][index].length; j++) {
                    // check if the rule ID is already in the array
                    if (trackerData.trackerIdToRuleIds[_policyId][index][j] == _ruleId) {
                        exists = true;
                        break;
                    }
                }
                if (!exists) {
                    trackerData.trackerIdToRuleIds[_policyId][index].push(_ruleId);
                }
            }
        }

        // repeat for effectPlaceHolders
        for (uint256 k = 0; k < effectPlaceHolders.length; k++) {
            // check for tracker flag on placeholder
            if (FacetUtils._isTrackerValue(effectPlaceHolders[k])) {
                // retrieve the tracker ID from the placeholder
                uint256 trackerId = effectPlaceHolders[k].typeSpecificIndex;
                // check if the rule ID is already in the array
                bool exists = false;
                for (uint256 l = 0; l < trackerData.trackerIdToRuleIds[_policyId][trackerId].length; l++) {
                    // check if the rule ID is already in the array
                    if (trackerData.trackerIdToRuleIds[_policyId][trackerId][l] == _ruleId) {
                        exists = true;
                        break;
                    }
                }
                if (!exists) {
                    trackerData.trackerIdToRuleIds[_policyId][trackerId].push(_ruleId);
                }
            }
        }
    }

    /**
     * @notice Removes a rule from the tracker ID mapping.
     * @dev This function checks if a tracker is used in the instruction set of the rule and removes the rule ID from the mapping.
     * @param _policyId The ID of the policy to update the mapping for.
     * @param _ruleId The ID of the rule to check for tracker usage.
     */
    function _removeRuleFromTrackerIdMapping(uint256 _policyId, uint256 _ruleId) internal {
        TrackerStorage storage trackerData = lib._getTrackerStorage();

        Placeholder[] memory placeHolders = lib._getRuleStorage().ruleStorageSets[_policyId][_ruleId].rule.placeHolders;
        Placeholder[] memory effectPlaceHolders = lib._getRuleStorage().ruleStorageSets[_policyId][_ruleId].rule.effectPlaceHolders;
        // check if a tracker is used in the instruction set of the rule
        // if so, we update the mapping to remove rule ID
        for (uint256 i = 0; i < placeHolders.length; i++) {
            // check for tracker flag on placeholder
            if (FacetUtils._isTrackerValue(placeHolders[i])) {
                // if the placeholder flag is a tracker, retrieve the tracker ID and remove the rule ID from the mapping
                for (uint256 j = 0; j < trackerData.trackerIdToRuleIds[_policyId][placeHolders[i].typeSpecificIndex].length; ) {
                    // check if the rule ID is already in the array
                    if (trackerData.trackerIdToRuleIds[_policyId][placeHolders[i].typeSpecificIndex][j] == _ruleId) {
                        trackerData.trackerIdToRuleIds[_policyId][placeHolders[i].typeSpecificIndex][j] = trackerData.trackerIdToRuleIds[
                            _policyId
                        ][placeHolders[i].typeSpecificIndex][
                                trackerData.trackerIdToRuleIds[_policyId][placeHolders[i].typeSpecificIndex].length - 1
                            ];
                        trackerData.trackerIdToRuleIds[_policyId][placeHolders[i].typeSpecificIndex].pop();
                        break; // Exit the loop after removal
                    } else {
                        j++; // Only increment if no removal occurred
                    }
                }
            }
        }
        // repeat for effectPlaceHolders
        for (uint256 k = 0; k < effectPlaceHolders.length; k++) {
            // check for tracker flag on effect placeholder
            if (FacetUtils._isTrackerValue(effectPlaceHolders[k])) {
                // if the placeholder flag is a tracker, retrieve the tracker ID and remove the rule ID from the mapping
                for (uint256 l = 0; l < trackerData.trackerIdToRuleIds[_policyId][effectPlaceHolders[k].typeSpecificIndex].length; ) {
                    // check if the rule ID is already in the array
                    if (trackerData.trackerIdToRuleIds[_policyId][effectPlaceHolders[k].typeSpecificIndex][l] == _ruleId) {
                        trackerData.trackerIdToRuleIds[_policyId][effectPlaceHolders[k].typeSpecificIndex][l] = trackerData
                            .trackerIdToRuleIds[_policyId][effectPlaceHolders[k].typeSpecificIndex][
                                trackerData.trackerIdToRuleIds[_policyId][effectPlaceHolders[k].typeSpecificIndex].length - 1
                            ];
                        trackerData.trackerIdToRuleIds[_policyId][effectPlaceHolders[k].typeSpecificIndex].pop();
                        break; // Exit the loop after removal
                    } else {
                        l++; // Only increment if no removal occurred
                    }
                }
            }
        }
    }

    /**
     * @notice Increments the rule ID counter for a specific policy.
     * @dev This function is used to generate a new rule ID for a policy.
     * @param data The rule storage structure.
     * @param _policyId The ID of the policy to increment the rule ID for.
     * @return The incremented rule ID.
     */
    function _incrementRuleId(RuleStorage storage data, uint256 _policyId) private returns (uint256) {
        return ++data.ruleIdCounter[_policyId];
    }

    /**
     * @notice function to store the metadata for a rule.
     * @dev This function is used to store the metadata for a rule, such as its name and description.
     * @param _policyId The ID of the policy the rule belongs to.
     * @param _ruleId The ID of the rule to store metadata for.
     * @param _ruleName The name of the rule.
     * @param _description The description of the rule.
     */
    function _storeRuleMetadata(uint256 _policyId, uint256 _ruleId, string calldata _ruleName, string calldata _description) internal {
        RulesMetadataStruct storage metadata = lib._getRulesMetadataStorage();
        metadata.ruleMetadata[_policyId][_ruleId].ruleName = _ruleName;
        metadata.ruleMetadata[_policyId][_ruleId].ruleDescription = _description;
    }

    function _validateRule(Rule calldata rule, uint256 policyId) internal view {
        // instructionSet
        if (rule.instructionSet.length == 0) revert(EMPTY_INSTRUCTION_SET); // only applies to top level instruction set
        _validateInstructionSet(rule.instructionSet, policyId);
        for (uint i = 0; i < rule.rawData.argumentTypes.length; i++) {
            _validateParamType(rule.rawData.argumentTypes[i]);
        }
        // placeholders
        _validatePlaceholders(rule.placeHolders);
        _validatePlaceholders(rule.effectPlaceHolders);
        // effects
        require(rule.posEffects.length > 0 || rule.negEffects.length > 0, EFFECT_REQ);
        _validateEffects(rule.posEffects, policyId);
        _validateEffects(rule.negEffects, policyId);
    }

    /**
     * @notice Validates an array of effects.
     * @param effects The effects to validate.
     * @param policyId The policyId 
     */
    function _validateEffects(Effect[] calldata effects, uint256 policyId) internal view {
        for (uint256 i = 0; i < effects.length; i++) {
            _validateEffectType(effects[i].effectType);
            _validateParamType(effects[i].pType);
            _validateInstructionSet(effects[i].instructionSet, policyId);
        }
    }

    /**
     * @notice Validates an array of placeholders.
     * @param placeholders The placeholders to validate.
     */
    function _validatePlaceholders(Placeholder[] calldata placeholders) internal pure {
        if (placeholders.length > MAX_LOOP) revert(MEMORY_OVERFLOW);
        for (uint256 i = 0; i < placeholders.length; i++) {
            _validateParamType(placeholders[i].pType);
        }
    }

    /**
     * @notice Validates an instruction set.
     * @param instructionSet The instructionSet to validate.
     * @param policyId The policyId.
     */
    function _validateInstructionSet(uint256[] calldata instructionSet, uint256 policyId) internal view {
        uint expectedDataElements; // the number of expected data elements in the instruction set (memory pointers)
        bool isData; // the first item of an instruction set must be an opcode, so isData must be "initialized" to false
        uint totalInstructions; // the total number of instructions in the instruction set (opcodes)
        uint instructionHold; // The current instruction used as it iterates through data elements
        uint dataCounter; // The current data element within the opCode
        // we loop through the instructionSet to validate it
        for (uint256 i = 0; i < instructionSet.length; i++) {
            // we extract the specific item from the validation set which is in memory, and we place it in the stack to save some gas
            uint instruction = instructionSet[i];
            if (isData) {  
                dataCounter++;
                if (!_isLessLimitedOpCode(instructionHold)) {  
                    // if the instruction is data, we just check that it won't point to an index outside of max memory size
                    if (instruction > memorySize) revert(MEMORY_OVERFLOW);             
                } else {
                    // Verify that the tracker exists in the policy
                    if (dataCounter == 1){
                        if (instructionHold == uint(LogicalOp.PLH)) {// PLH is only limited by the Max loop size
                            if (instruction > MAX_LOOP) revert(MEMORY_OVERFLOW);
                        } else {
                            TrackerStorage storage trackerData = lib._getTrackerStorage();
                            if (!trackerData.trackers[policyId][instruction].set) revert(TRACKER_NOT_SET);
                        }
                    }

                }
                // we reduce the expectedDataElements count by one, but only if necessary
                if (expectedDataElements > 1) --expectedDataElements;
                else {
                    // if we have no more expected data elements, we can reset the isData flag, and we set the expectedDataElements to 0
                    isData = false;
                    delete expectedDataElements;
                }
            } else {
                ++totalInstructions;
                // if the instruction is not data, we check that it is a valid opcode
                if (instruction > opsTotalSize) revert(INVALID_INSTRUCTION);
                // NUM is a special case since it can expect any data, so no check is needed next
                if (instruction == uint(LogicalOp.NUM)) {
                    unchecked {
                        ++i; // we simply incrememt the iterator to skip the next data element
                    }
                    // we skip setting the isData flag and the expectedDataElements since we won't go through any data
                    continue;
                }
                //we set the expectedDataElements based its position inside the LogicalOp enum
                if (instruction < opsSize1) expectedDataElements = 1;
                else if (instruction < opsSizeUpTo2) expectedDataElements = 2;
                else if (instruction < opsSizeUpTo3) expectedDataElements = 3;
                else expectedDataElements = 4;
                isData = true; // we know that following instruction(s) is a data pointer
                dataCounter = 0;
                instructionHold = instructionSet[i]; // load the hold variable with the actual op code
            }
        }
        // if we have any expected data elements left, it means the instruction set is invalid
        if (expectedDataElements > 0 || isData) revert(INVALID_INSTRUCTION_SET);
        // if the instruction set will overflow the memory size, we revert
        if (totalInstructions > memorySize) revert(INSTRUCTION_SET_TOO_LARGE);
    }

    /**
     * @dev Determines whether the given operation code's data is considered "less limited" and can be upwards of the max loop size
     * @param opCode The operation code to evaluate.
     * @return bool Returns `true` if the operation code is less limited, otherwise `false`.
     */
    function _isLessLimitedOpCode(uint opCode) internal pure returns (bool) {
        return (
            opCode == uint(LogicalOp.PLHM) ||
            opCode == uint(LogicalOp.PLH) ||
            opCode == uint(LogicalOp.TRUM) ||
            opCode == uint(LogicalOp.TRU)
        ); 
    }

    /**
     * @notice Validates a paramType.
     * @param paramType The paramType to validate.
     */
    function _validateParamType(ParamTypes paramType) internal pure {
        uint paramTypesSize = 8;
        if (uint(paramType) >= paramTypesSize) revert(INVALID_PARAM_TYPE);
    }

    /**
     * @notice Validates an effect type.
     * @param effectType The effectType to validate.
     */
    function _validateEffectType(EffectTypes effectType) internal pure {
        uint EffectTypesSize = 3;
        if (uint(effectType) >= EffectTypesSize) revert(INVALID_EFFECT_TYPE);
    }

    /**
     * @notice Checks that the caller is a policy admin
     * @param _policyId The ID of the policy.
     * @param _address The address to check for policy admin status.
     */
    function _policyAdminOnly(uint256 _policyId, address _address) internal {
        // 0x901cee11 = isPolicyAdmin(uint256,address)
        (bool success, bytes memory res) = _callAnotherFacet(
            0x901cee11,
            abi.encodeWithSignature("isPolicyAdmin(uint256,address)", _policyId, _address)
        );
        bool returnBool;
        if (success) {
            if (res.length >= 4) {
                assembly {
                    returnBool := mload(add(res, 32))
                }
            } else {
                returnBool = false;
            }
            // returned false so revert with error
            if (!returnBool) revert(NOT_AUTH_POLICY);
        }
    }
}
