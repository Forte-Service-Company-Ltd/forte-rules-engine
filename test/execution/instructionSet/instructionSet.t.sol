/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract instructionSet is RulesEngineCommon {
    /**
     *
     *
     * Execution tests for instruction sets within the rules engine
     *
     *
     */

    function testInstructionSet_Unit_LogicalOperator_Add() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Test the addition of two registers
        _logicalOperatorSetUpArthimetic(5, 10, 15, LogicalOp.ADD);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testInstructionSet_Unit_LogicalOperator_Sub() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Test the subtraction of two registers
        _logicalOperatorSetUpArthimetic(5, 10, 5, LogicalOp.SUB);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testInstructionSet_Unit_LogicalOperator_Mul() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Test the multiplication of two registers
        _logicalOperatorSetUpArthimetic(5, 10, 50, LogicalOp.MUL);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testInstructionSet_Unit_LogicalOperator_Div() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Test the division of two registers
        _logicalOperatorSetUpArthimetic(10, 5, 2, LogicalOp.DIV);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testInstructionSet_Unit_LogicalOperator_Mul_Overflow() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Test the multiplication of two registers to induce overflow
        _logicalOperatorSetUpArthimetic(5, type(uint256).max, 50, LogicalOp.MUL);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        vm.expectRevert("panic: arithmetic underflow or overflow (0x11)");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testInstructionSet_Unit_LogicalOperator_Sub_Underflow() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Test the subtraction of two registers to induce underflow
        _logicalOperatorSetUpArthimetic(100, 10, 2, LogicalOp.SUB);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        vm.expectRevert("panic: arithmetic underflow or overflow (0x11)");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testInstructionSet_Unit_LogicalOperator_Div_byZero() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Test the division of two registers
        _logicalOperatorSetUpArthimetic(0, 10, 2, LogicalOp.DIV);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        vm.expectRevert("panic: division or modulo by zero (0x12)");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function _logicalOperatorSetUpArthimetic(uint256 opValue, uint256 compValue, uint256 expectedResult, LogicalOp logicOperator) internal {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        Rule memory rule;

        rule.instructionSet = new uint256[](10);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = compValue;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = opValue;
        rule.instructionSet[4] = uint(logicOperator);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        rule.instructionSet[7] = uint(LogicalOp.EQ);
        rule.instructionSet[8] = 3;
        rule.instructionSet[9] = expectedResult;

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    /// memory register tests
    function testInstructionSet_Unit_MemoryRegisters_OneExpected() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        Rule memory rule;

        rule.instructionSet = new uint256[](8);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = 500; // extra memory register larger than 18 to avoid enum confusion
        rule.instructionSet[3] = uint(LogicalOp.NUM);
        rule.instructionSet[4] = 1;
        rule.instructionSet[5] = uint(LogicalOp.GT);
        rule.instructionSet[6] = 0;
        rule.instructionSet[7] = 1;

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        vm.expectRevert("Invalid Instruction");
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testInstructionSet_Unit_MemoryRegisters_TwoExpected() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        Rule memory rule;

        rule.instructionSet = new uint256[](8);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.GT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        rule.instructionSet[7] = 1000; // extra memory register larger than 18 to avoid enum confusion

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        vm.expectRevert("Invalid Instruction");
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testInstructionSet_Unit_MemoryRegisters_TwoExpected_OneGiven() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        Rule memory rule;

        rule.instructionSet = new uint256[](6);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.GT);
        rule.instructionSet[5] = 0;

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        vm.expectRevert("Invalid Instruction Set");
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testInstructionSet_Unit_MemoryRegisters_ThreeExpected_TwoGiven() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        Rule memory rule;

        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.BOOL;
        tracker.trackerKeyType = ParamTypes.UINT;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(true); // value 1
        trackerValues[1] = abi.encode(false); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        uint256 trackerIndex = RulesEngineComponentFacet(address(red)).createMappedTracker(
            policyIds[0],
            tracker,
            trackerName,
            trackerKeys,
            trackerValues,
            TrackerArrayTypes.VOID
        );        

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = type(uint).max;
        rule.instructionSet[4] = uint(LogicalOp.GT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        Effect memory effect;
        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](8);
        effect.instructionSet[0] = uint(LogicalOp.NUM);
        effect.instructionSet[1] = 0;
        effect.instructionSet[2] = uint(LogicalOp.NUM);
        effect.instructionSet[3] = 1;
        // Tracker Placeholder
        effect.instructionSet[4] = uint(LogicalOp.TRUM);
        effect.instructionSet[5] = 1;
        effect.instructionSet[6] = 1;

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effect;
        vm.expectRevert("Invalid Instruction Set");
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testInstructionSet_Unit_MemoryRegisters_TRU_TRUM_Last(bool isMapped) public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        Rule memory rule;

        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.BOOL;
        tracker.trackerKeyType = ParamTypes.UINT;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(true); // value 1
        trackerValues[1] = abi.encode(false); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        uint256 trackerIndex = RulesEngineComponentFacet(address(red)).createMappedTracker(
            policyIds[0],
            tracker,
            trackerName,
            trackerKeys,
            trackerValues,
            TrackerArrayTypes.VOID
        );        

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = type(uint).max;
        rule.instructionSet[4] = uint(LogicalOp.GT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        Effect memory effect;
        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](8);
        effect.instructionSet[0] = uint(LogicalOp.NUM);
        effect.instructionSet[1] = 0;
        effect.instructionSet[2] = uint(LogicalOp.NUM);
        effect.instructionSet[3] = 1;
        // Tracker Placeholder
        if (isMapped) effect.instructionSet[4] = uint(LogicalOp.TRUM);
            else effect.instructionSet[4] = uint(LogicalOp.TRU);

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effect;
        vm.expectRevert("Tracker referenced in rule not set");
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testInstructionSet_Unit_ConditionsNoChangeState(bool isMapped) public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        Rule memory rule;

        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.BOOL;
        tracker.trackerKeyType = ParamTypes.UINT;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(true); // value 1
        trackerValues[1] = abi.encode(false); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        uint256 trackerIndex = RulesEngineComponentFacet(address(red)).createMappedTracker(
            policyIds[0],
            tracker,
            trackerName,
            trackerKeys,
            trackerValues,
            TrackerArrayTypes.VOID
        );        
        if (isMapped) rule.instructionSet = new uint256[](8);
            else rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        // Tracker Placeholder
        if (isMapped){
            rule.instructionSet[4] = uint(LogicalOp.TRUM);
            rule.instructionSet[5] = 1;
            rule.instructionSet[6] = 1;
            rule.instructionSet[7] = 0;
        } else {
            rule.instructionSet[4] = uint(LogicalOp.TRU);
            rule.instructionSet[5] = 1;
            rule.instructionSet[6] = 1;
        }

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        vm.expectRevert("OpCode Not Allowed in Conditional");
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testInstructionSet_Unit_TRUM_TrackerExists_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        Rule memory rule;


        // Condition: always true (1 == 1)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint256(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint256(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint256(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        Effect memory effect;
        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](8);
        effect.instructionSet[0] = uint(LogicalOp.NUM);
        effect.instructionSet[1] = 0;
        effect.instructionSet[2] = uint(LogicalOp.NUM);
        effect.instructionSet[3] = 1;
        // Tracker Placeholder
        effect.instructionSet[4] = uint(LogicalOp.TRUM);
        effect.instructionSet[5] = 1;
        effect.instructionSet[6] = 0;
        effect.instructionSet[6] = 1;

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effect;
        vm.expectRevert("Tracker referenced in rule not set");
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testInstructionSet_Unit_PLHM_TrackerExists_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        Rule memory rule;


        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.PLHM);
        rule.instructionSet[5] = 1;
        rule.instructionSet[6] = 1;

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        vm.expectRevert("Tracker referenced in rule not set");
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    ///  bound tests
    function testInstructionSet_Unit_BoundsTesting_MaxUint() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        Rule memory rule;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = type(uint).max;
        rule.instructionSet[4] = uint(LogicalOp.GT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testInstructionSet_Unit_BoundsTesting_PlaceHolder_StringBounds() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithStringComparison();

        // test passing long string
        string
            memory longString = "This is a very long string that exceeds the normal bounds of a string comparison in the rules engine. It is meant to test how the rules engine handles strings that are larger than expected and whether it can still process them correctly without running into issues or errors.";
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction2))), address(0x7654321), longString);
        vm.startPrank(address(userContract));
        vm.expectRevert("Rules Engine Revert"); // Revert on rule check not from the string length
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testInstructionSet_Unit_BoundsTesting_PlaceHolder_UintBounds() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        Rule memory rule;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = type(uint).max;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), type(uint).max);
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }
}
