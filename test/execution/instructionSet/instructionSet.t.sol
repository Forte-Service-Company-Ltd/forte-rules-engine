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
        _logicalOperatorSetUpArthimetic("Add", 5, 10, 15, LogicalOp.ADD);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testInstructionSet_Unit_LogicalOperator_Sub() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Test the subtraction of two registers
        _logicalOperatorSetUpArthimetic("Sub", 5, 10, 5, LogicalOp.SUB);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testInstructionSet_Unit_LogicalOperator_Mul() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Test the multiplication of two registers
        _logicalOperatorSetUpArthimetic("Mul", 5, 10, 50, LogicalOp.MUL);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testInstructionSet_Unit_LogicalOperator_Div() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Test the division of two registers
        _logicalOperatorSetUpArthimetic("Div", 10, 5, 2, LogicalOp.DIV);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testInstructionSet_Unit_LogicalOperator_Mul_Overflow() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Test the multiplication of two registers to induce overflow
        _logicalOperatorSetUpArthimetic("Mul", 5, type(uint256).max, 50, LogicalOp.MUL);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        vm.expectRevert("panic: arithmetic underflow or overflow (0x11)");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testInstructionSet_Unit_LogicalOperator_Sub_Underflow() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Test the subtraction of two registers to induce underflow
        _logicalOperatorSetUpArthimetic("Sub", 100, 10, 2, LogicalOp.SUB);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        vm.expectRevert("panic: arithmetic underflow or overflow (0x11)");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testInstructionSet_Unit_LogicalOperator_Div_byZero() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Test the division of two registers
        _logicalOperatorSetUpArthimetic("Div", 0, 10, 2, LogicalOp.DIV);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        vm.expectRevert("panic: division or modulo by zero (0x12)");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function _logicalOperatorSetUpArthimetic(
        string memory operatorTypeString,
        uint256 opValue,
        uint256 compValue,
        uint256 expectedResult,
        LogicalOp logicOperator
    ) internal {
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
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
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
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testInstructionSet_Unit_MemoryRegisters_ThreeExpected() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        Rule memory rule;

        rule.instructionSet = new uint256[](9);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.TRUM);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        rule.instructionSet[7] = 1;
        rule.instructionSet[8] = 1000; // extra memory register larger than 18 to avoid enum confusion

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        vm.expectRevert("Memory Overflow");
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
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
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
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

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.TRUM);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        vm.expectRevert("Invalid Instruction Set");
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
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
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
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
