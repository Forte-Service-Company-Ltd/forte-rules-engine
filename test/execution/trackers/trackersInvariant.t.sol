/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "src/engine/facets/RulesEngineProcessorFacet.sol";


contract SuperSetProcessor is RulesEngineProcessorFacet {
    function run(
        uint256[] memory _prog,
        Placeholder[] memory _placeHolders,
        uint256 _policyId,
        bytes[] memory _arguments
    ) public returns (bool) {
        return super._run(_prog, _placeHolders, _policyId, _arguments);
    }
}

enum TestType {
    STRING_FROM_TRACKER,
    BYTES_FROM_TRACKER,
    STRING_FROM_PLACEHOLDER,
    BYTES_FROM_PLACEHOLDER,
    STRING_FROM_MAPPED_TRACKER
}

contract trackersInvariant is RulesEngineCommon {

    SuperSetProcessor ded;
    
    function setUp() public {
        ded = new SuperSetProcessor();
    }

    function addStringTracker(string memory _input, TestType _testType) internal returns (uint256 ruleId) {
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Rule: info == "Bad Info" -> revert -> updateInfo(address _to, string info) returns (bool)"
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, *uint256 representation of Bad Info*, LogicalOp.EQ, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(keccak256(_input));
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.STR;
        rule.rawData.dataValues[0] = abi.encode(_input);
        rule.rawData.instructionSetIndex[0] = 3;

        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.STR;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule, ruleName, ruleDescription);

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.STR;
        // Save the calling function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(keccak256(bytes(callingFunction2))),
            pTypes,
            callingFunction2,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction2))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        return ruleId;
    }

    function test_stringFromTracker(string memory _trackerName) public {
        ded.run(0, 0, 0, new bytes(0));
    }

    function test_bytesFromTracker(bytes memory _trackerName) public {
        ded.run(0, 0, 0, new bytes(0));
    }

    function test_stringFromPlaceholder(string memory _placeholderName) public {
        ded.run(0, 0, 0, new bytes(0));
    }

    function test_bytesFromPlaceholder(bytes memory _placeholderName) public {
        ded.run(0, 0, 0, new bytes(0));
    }

    function test_stringFromMappedTracker(string memory _argumentName) public {
        ded.run(0, 0, 0, new bytes(0));
    }

    function test_bytesFromMappedTracker(bytes memory _argumentName) public {
        ded.run(0, 0, 0, new bytes(0));
    }
}