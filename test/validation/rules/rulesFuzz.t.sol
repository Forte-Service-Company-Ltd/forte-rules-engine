/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract rulesFuzz is RulesEngineCommon {
    uint[4] lessLimitedOpCodes = [17, 18, 4, 2];

    /**
     *
     *
     * Validation fuzz tests for rules within the rules engine
     *
     *
     */

    function testRulesEngine_Fuzz_createRule_InvalidInstruction(uint8 _opA, uint8 _opB) public {
        uint256 opA = uint256(_opA);
        uint256 opB = uint256(_opB);
        // we avoid less limited opcodes: PLH, PLHM, TRU, TRUM
        if (opA == 17 || opA == 18 || opA == 4 || opA == 2) opA = 6;
        if (opB == 17 || opB == 18 || opB == 4 || opB == 2) opB = 6;

        (uint opAElements, uint opBElements) = findArgumentSizes(opA, opB);
        uint256[] memory instructionSet = buildInstructionSet2Opcodes(opA, opB, opAElements, opBElements, 0);

        // rule setup
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        rule.instructionSet = instructionSet;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;
        // test
        if (opA > RulesEngineRuleFacet(address(red)).getOpsTotalSize() || opB > RulesEngineRuleFacet(address(red)).getOpsTotalSize())
            vm.expectRevert("Invalid Instruction");
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testRulesEngine_Fuzz_createRule_negInvalidInstructionSet(uint8 _opA, uint8 _opB, uint _opAElements, uint _opBElements) public {
        uint256 opA = bound(_opA, 0, RulesEngineRuleFacet(address(red)).getOpsTotalSize() - 1);
        uint256 opB = bound(_opB, 0, RulesEngineRuleFacet(address(red)).getOpsTotalSize() - 1);
        // we avoid less limited opcodes: PLH, PLHM, TRU, TRUM
        if (opA == 17 || opA == 18 || opA == 4 || opA == 2) opA = 6;
        if (opB == 17 || opB == 18 || opB == 4 || opB == 2) opB = 6;
        _opAElements = bound(_opAElements, 1, 4);
        _opBElements = bound(_opBElements, 1, 4);

        (uint opAElements, uint opBElements) = findArgumentSizes(opA, opB);
        uint totalElements = _opAElements + _opBElements + 2; // 2 for the opA and opB themselves
        uint256[] memory instructionSet = buildInstructionSet2Opcodes(opA, opB, _opAElements, _opBElements, 20);

        // rule setup
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        rule.instructionSet = instructionSet;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;
        // test
        /// @notice we could revert for 2 reasons so we cannot check for a specific string
        /// @notice we can also run into a scenario where instruction _a_ can take 3 or 4 elements and total instructions are 4 or 5,
        /// which would match a valid case, so we have to account for that exception
        if ((opAElements != _opAElements || opBElements != _opBElements) && totalElements != opAElements + 1) vm.expectRevert();
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testRulesEngine_Fuzz_createRule_memoryOverFlow(uint8 _opA, uint8 _opB, uint8 _plhIdx, uint8 _data) public {
        // we avoid opcode 0 as it is the only one whose element won't be checked
        uint256 opA = bound(_opA, 1, RulesEngineRuleFacet(address(red)).getOpsTotalSize() - 1);
        uint256 opB = bound(_opB, 1, RulesEngineRuleFacet(address(red)).getOpsTotalSize() - 1);
        // we avoid less limited opcodes: PLH, PLHM, TRU, TRUM
        if (opA == 17 || opA == 18 || opA == 4 || opA == 2) opA = 6;
        if (opB == 17 || opB == 18 || opB == 4 || opB == 2) opB = 6;

        (uint opAElements, uint opBElements) = findArgumentSizes(opA, opB);
        uint256[] memory instructionSet = buildInstructionSet2Opcodes(opA, opB, opAElements, opBElements, uint256(_data));

        // rule setup
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        rule.instructionSet = instructionSet;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;
        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[1].typeSpecificIndex = _plhIdx;
        // test
        if (_data > RulesEngineRuleFacet(address(red)).getMemorySize()) vm.expectRevert("Memory Overflow");
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testRulesEngine_Fuzz_createRule_WithPLHmemoryOverFlow(uint8 _plhIdx, uint8 _data) public {
        // We set both opcodes to PLH
        uint256 opA = 2;
        uint256 opB = 2;

        (uint opAElements, uint opBElements) = findArgumentSizes(opA, opB);
        uint256[] memory instructionSet = buildInstructionSet2Opcodes(opA, opB, opAElements, opBElements, uint256(_data));

        // rule setup
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        rule.instructionSet = instructionSet;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;
        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[1].typeSpecificIndex = _plhIdx;
        // test

        if (_data > RulesEngineRuleFacet(address(red)).getMaxLoopSize()){
            vm.expectRevert("Memory Overflow");
        } 
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testRulesEngine_Fuzz_createRule_instructionSetLength(uint opA, uint opB, bool causesOverflow) public {
        opA = bound(opA, 0, RulesEngineRuleFacet(address(red)).getOpsTotalSize() - 1);
        opB = bound(opB, 0, RulesEngineRuleFacet(address(red)).getOpsTotalSize() - 1);

        // we avoid problematic opcodes to avoid complex setups: PLH, PLHM, DIV, TRU, TRUM
        if (opA == 17 || opA == 18 || opA == 4 || opA == 2 || opA == 8) opA = 6;
        if (opB == 17 || opB == 18 || opB == 4 || opB == 2 || opB == 8) opB = 6;
        (uint opAElements, uint opBElements) = findArgumentSizes(opA, opB);
        // the instruction set will have 90 or 91 instructions depending on the causesOverflow flag.
        uint[] memory instructionSet = buildInstructionSetMax(opA, opB, opAElements, opBElements, causesOverflow, 1);

        // rule setup
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        rule.instructionSet = instructionSet;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_revert;
        // test
        if (causesOverflow) vm.expectRevert("Instruction Set Too Large");
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        // if the instruction set is valid, we execute the rule to make sure it won't revert due to unexpected reasons
        if (!causesOverflow) savePolicyAndExecuteInstructionSet(ruleId, policyIds);
    }

    function testRulesEngine_Fuzz_createRule_instructionSetLengthForLessLimited(uint opA, uint opB, bool causesTrackerNotSet) public {
        opA = bound(opA, 0, RulesEngineRuleFacet(address(red)).getOpsTotalSize() - 1);
        opB = bound(opB, 0, RulesEngineRuleFacet(address(red)).getOpsTotalSize() - 1);
        uint8[3] memory lessLimitedOps = [4,17,18];
        // we only use less limited opcodes: PLHM, TRU, TRUM
        opA = lessLimitedOps[opA% 3];
        opB = lessLimitedOps[opB% 3];
        (uint opAElements, uint opBElements) = findArgumentSizes(opA, opB);
        // the instruction set will have 90 or 91 instructions depending on the causesOverflow flag.
        uint[] memory instructionSet = buildInstructionSetMax(opA, opB, opAElements, opBElements, false, 1);
        // rule setup
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Only create a tracker some of the time
        if (!causesTrackerNotSet){
            Trackers memory tracker;
            /// build the members of the struct
            tracker.pType = ParamTypes.UINT;
            tracker.trackerValue = abi.encode(2);
            // Add the tracker
            RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName", TrackerArrayTypes.VOID);
        }
        rule.instructionSet = instructionSet;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_revert;
        // test
        if (causesTrackerNotSet) vm.expectRevert("Tracker referenced in rule not set");
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testRulesEngine_Fuzz_createRule_simple(uint256 _ruleValue, uint256 _transferValue) public {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"

        // _createAllEffects();
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(_ruleValue);

        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        // Save the calling function
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(keccak256(bytes(callingFunction))),
            pTypes,
            callingFunction,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), _transferValue);
        if (_ruleValue >= _transferValue) vm.expectRevert();
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function findArgumentSizes(uint opA, uint opB) internal view returns (uint opAElements, uint opBElements) {
        opAElements = findInstructionArgSize(opA);
        opBElements = findInstructionArgSize(opB);
    }

    function findInstructionArgSize(uint op) internal view returns (uint argSize) {
        argSize = 1;
        if (op >= RulesEngineRuleFacet(address(red)).getOpsSize1()) argSize = 2;
        if (op >= RulesEngineRuleFacet(address(red)).getOpsSizeUpTo2()) argSize = 3;
        if (op >= RulesEngineRuleFacet(address(red)).getOpsSizeUpTo3()) argSize = 4;
    }

    function savePolicyAndExecuteInstructionSet(uint ruleId, uint[] memory policyIds) internal {
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        // Save the calling function
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(keccak256(bytes(callingFunction))),
            pTypes,
            callingFunction,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1e18);
        vm.expectRevert(abi.encode(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function buildInstructionSet2Opcodes(
        uint256 opA,
        uint256 opB,
        uint256 opAElements,
        uint256 opBElements,
        uint256 data
    ) internal pure returns (uint256[] memory) {
        uint totalElements = opAElements + opBElements + 2; // 2 for the opA and opB themselves
        uint256[] memory instructionSet = new uint256[](totalElements);
        instructionSet[0] = opA;
        instructionSet[1 + opAElements] = opB;
        // we fill the instructions with the data
        for (uint i = 1; i < 1 + opAElements; i++) instructionSet[i] = uint(data);
        for (uint i = 2 + opAElements; i < instructionSet.length; i++) instructionSet[i] = uint(data);
        return instructionSet;
    }

    function buildInstructionSetMax(
        uint256 opA,
        uint256 opB,
        uint256 opAElements,
        uint256 opBElements,
        bool causesOverflow,
        uint256 data
    ) internal view returns (uint256[] memory instructionSet) {
        uint instructionSetLength = (opAElements + opBElements + 2) *
            (RulesEngineRuleFacet(address(red)).getMemorySize() / 2 + (causesOverflow ? 1 : 0));
        instructionSet = new uint256[](instructionSetLength);
        // we build the instruction set by alternating opA and opB. We assign all data elements with the "data" parameter
        bool isOpBTurn;
        bool isData;
        uint dataElements;
        for (uint i = 0; i < instructionSetLength; i++) {
            if (isData) {
                instructionSet[i] = data;
                if (dataElements > 1) {
                    --dataElements;
                } else {
                    isData = false;
                }
            } else {
                if (isOpBTurn) {
                    instructionSet[i] = opB;
                    dataElements = opBElements;
                    isOpBTurn = false;
                } else {
                    instructionSet[i] = opA;
                    dataElements = opAElements;
                    isOpBTurn = true;
                }
                isData = true;
            }
        }
        return instructionSet;
    }

    function buildInstructionSetDataMax(
        uint256 opA,
        uint256 opB,
        uint256 opAElements,
        uint256 opBElements,
        bool causesOverflow,
        uint256 data
    ) internal view returns (uint256[] memory instructionSet) {
        uint instructionSetLength = (opAElements + opBElements + 2) *
            (RulesEngineRuleFacet(address(red)).getMemorySize() / 2);
        instructionSet = new uint256[](instructionSetLength);
        // we build the instruction set by alternating opA and opB. We assign all data elements with the "data" parameter
        bool isOpBTurn;
        bool isData;
        uint dataElements;
        for (uint i = 0; i < instructionSetLength; i++) {
            if (isData) {
                instructionSet[i] = data+ (causesOverflow ? 1 : 0);
                if (dataElements > 1) {
                    --dataElements;
                } else {
                    isData = false;
                }
            } else {
                if (isOpBTurn) {
                    instructionSet[i] = opB;
                    dataElements = opBElements;
                    isOpBTurn = false;
                } else {
                    instructionSet[i] = opA;
                    dataElements = opAElements;
                    isOpBTurn = true;
                }
                isData = true;
            }
        }
        return instructionSet;
    }
}
