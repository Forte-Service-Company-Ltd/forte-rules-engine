/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "@openzeppelin/utils/Strings.sol";

abstract contract storageTest is RulesEngineCommon {
    Effect[] effectArray;
    using Strings for uint256;
    /**
     * Storage tests for policies within the rules engine
     */

    function testPolicyStorageFuzz(uint16 total) public {
        uint256 index = bound(uint256(total), 0, 3000);
        for (uint256 i = 0; i < index; i++) {
            policyName = index.toString();
            uint256 policyId = _createBlankPolicy();
            PolicyMetadata memory metadata2 = RulesEnginePolicyFacet(address(red)).getPolicyMetadata(policyId);
            assertEq(policyName, metadata2.policyName);
        }
    }

    function testRuleStorageFuzz(uint16 total) public {
        uint256 index = bound(uint256(total), 0, 2000);
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        uint256 ruleId;
        for (uint256 i = 0; i < index; i++) {
            ruleName = index.toString();
            // Save the rule
            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);
            RuleMetadata memory metadata2 = RulesEngineRuleFacet(address(red)).getRuleMetadata(policyId, ruleId);
            assertEq(ruleName, metadata2.ruleName);
        }
    }

    function testRuleAssociationStorageFuzz(uint16 total) public {
        uint256 index = bound(uint256(total), 0, 1000);
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        ruleName = "testRule";
        ruleIds.push(new uint256[](1));
        uint256 ruleId;
        for (uint256 i = 0; i < index; i++) {
            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);
            ruleIds[0].push(ruleId);
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                callingFunctions,
                ruleIds,
                PolicyType.CLOSED_POLICY,
                policyName,
                policyDescription
            );
            RuleMetadata memory metadata2 = RulesEngineRuleFacet(address(red)).getRuleMetadata(policyId, ruleId);
            assertEq(ruleName, metadata2.ruleName);
        }
    }

    function testCallingFunctionAssociationStorage(uint16 total) public {
        uint256 index = bound(uint256(total), 0, 300);
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        for (uint256 i = 0; i < index; i++) {
            bytes4 selector = bytes4(bytes4(keccak256(bytes(callingFunction2))) ^ (bytes32(i) << (256 - 4 * 8)));
            RulesEngineComponentFacet(address(red)).createCallingFunction(policyIds[0], selector, pTypes, callingFunction, "");
            callingFunctions.push(selector);
            uint256[][] memory blankRuleIds = new uint256[][](0);
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyIds[0],
                callingFunctions,
                blankRuleIds,
                PolicyType.CLOSED_POLICY,
                policyName,
                policyDescription
            );
            assertTrue(RulesEngineComponentFacet(address(red)).getCallingFunction(policyIds[0], callingFunctions[i]).set);
        }
    }

    function testCallingFunctionStorage(uint16 total) public {
        uint256 index = bound(uint256(total), 0, 1000);
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        for (uint256 i = 0; i < index; i++) {
            // Save the calling function
            RulesEngineComponentFacet(address(red)).createCallingFunction(
                policyIds[0],
                bytes4(bytes4(keccak256(bytes(callingFunction))) ^ (bytes32(i) << (256 - 8 * 4))),
                pTypes,
                callingFunction,
                ""
            );
            assertTrue(
                RulesEngineComponentFacet(address(red))
                    .getCallingFunction(policyIds[0], bytes4(bytes4(keccak256(bytes(callingFunction))) ^ (bytes32(i) << (256 - 8 * 4))))
                    .set
            );
        }
    }

    function testForeignCallStorage(uint16 total) public {
        uint256 index = bound(uint256(total), 0, 2500);
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        uint256 id;
        for (uint256 i = 0; i < index; i++) {
            // Save the calling function
            ParamTypes[] memory fcArgs = new ParamTypes[](1);
            fcArgs[0] = ParamTypes.UINT;
            ForeignCall memory fc;
            fc.encodedIndices = new ForeignCallEncodedIndex[](1);
            fc.encodedIndices[0].index = 1;
            fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

            fc.parameterTypes = fcArgs;
            fc.foreignCallAddress = address(pfcContractAddress);
            fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
            fc.returnType = ParamTypes.UINT;
            fc.foreignCallIndex = 0;
            id = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");
            assertEq(uint(RulesEngineForeignCallFacet(address(red)).getForeignCall(policyIds[0], id).parameterTypes[0]), uint(fcArgs[0]));
        }
    }

    function testTrackerStorage(uint16 total) public {
        uint256 index = bound(uint256(total), 0, 5000);
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        Trackers memory tracker;
        Trackers memory tracker2;
        uint256 id;
        for (uint256 i = 0; i < index; i++) {
            /// build the members of the struct:
            tracker.pType = ParamTypes.UINT;
            tracker.trackerValue = abi.encode(index);
            id = RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName");
            tracker2 = RulesEngineComponentFacet(address(red)).getTracker(policyIds[0], id);
            assertEq(tracker.trackerValue, tracker2.trackerValue);
        }
    }

    function testEffectStorage(uint16 total) public {
        uint256 index = bound(uint256(total), 0, 10);
        uint256[] memory policyIds = new uint256[](1);
        Rule memory rule;
        policyIds[0] = _createBlankPolicy();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        Effect memory effect;
        effectArray.push(effect);
        rule.negEffects = effectArray;
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        for (uint256 i = 0; i < index; i++) {
            effectArray.push(effect);
            rule.negEffects = effectArray;
            RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], ruleId, rule, ruleName, ruleDescription);
            assertEq(RulesEngineRuleFacet(address(red)).getRule(policyIds[0], ruleId).rule.negEffects.length, i + 2);
        }
    }
}
