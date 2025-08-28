/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "src/example/ExampleERC20.sol";

abstract contract policiesExecution is RulesEngineCommon {
    /**
     *
     *
     * Execution tests for policies within the rules engine
     *
     *
     */

    function testPolicyClosingDoesntDeleteContractAssociations() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](3);
        uint256 policy1 = _createBlankPolicyOpen();
        uint256 policy2 = _createBlankPolicyOpen();
        uint256 policy3 = _createBlankPolicyOpen();
        policyIds[0] = policy1;
        policyIds[1] = policy2;
        policyIds[2] = policy3;
        address[] memory contracts = new address[](3);

        vm.startPrank(callingContractAdmin);
        contracts[0] = address(new ExampleERC20("Test", "TEST"));
        contracts[1] = address(new ExampleERC20("Test2", "TEST2"));
        contracts[2] = address(new ExampleERC20("Test3", "TEST3"));
        vm.stopPrank();

        for (uint256 i = 0; i < contracts.length; i++) {
            vm.startPrank(callingContractAdmin);
            ExampleERC20(contracts[i]).setRulesEngineAddress(address(red));
            ExampleERC20(contracts[i]).setCallingContractAdmin(callingContractAdmin);
            RulesEnginePolicyFacet(address(red)).applyPolicy(contracts[i], policyIds);
            vm.stopPrank();
        }

        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).closePolicy(policyIds[0]);
        vm.stopPrank();

        uint256[] memory appliedPolicies = RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(contracts[0]);
        assertEq(appliedPolicies.length, 2);
        assertEq(appliedPolicies[0], policyIds[1]);
        assertEq(appliedPolicies[1], policyIds[2]);

        appliedPolicies = RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(contracts[1]);
        assertEq(appliedPolicies.length, 2);
        assertEq(appliedPolicies[0], policyIds[1]);
        assertEq(appliedPolicies[1], policyIds[2]);

        appliedPolicies = RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(contracts[2]);
        assertEq(appliedPolicies.length, 2);
        assertEq(appliedPolicies[0], policyIds[1]);
        assertEq(appliedPolicies[1], policyIds[2]);
    }

    function testRulesArrayStillFullAfterCallingFunctionDeletion() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);
        uint256 policy1 = _createBlankPolicy();
        policyIds[0] = policy1;
        Rule[] memory initialRules = createArrayOfRules();
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policy1, initialRules[0], "rule1", "rule1");
        assertEq(ruleId, 1);
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policy1, initialRules[1], "rule2", "rule2");
        assertEq(ruleId, 2);
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policy1, initialRules[2], "rule3", "rule3");
        assertEq(ruleId, 3);

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transfer2(address,uint256)")))),
            pTypes,
            "transfer2(address,uint256)",
            ""
        );

        pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;

        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transferFrom(address,address,uint256)")))),
            pTypes,
            "transferFrom(address,address,uint256)",
            ""
        );

        bytes4[] memory callingFunctions = new bytes4[](2);
        callingFunctions[0] = bytes4(bytes4(keccak256(bytes("transfer2(address,uint256)"))));
        callingFunctions[1] = bytes4(bytes4(keccak256(bytes("transferFrom(address,address,uint256)"))));
        uint256[][] memory ruleIds = new uint256[][](2);
        ruleIds[0] = new uint256[](3);
        ruleIds[0][0] = 1;
        ruleIds[0][1] = 2;
        ruleIds[0][2] = 3;
        ruleIds[1] = new uint256[](2);
        ruleIds[1][0] = 1;
        ruleIds[1][1] = 2;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            "policyName",
            "policyDescription"
        );

        Rule[][] memory rules = RulesEngineRuleFacet(address(red)).getAllRules(policy1);
        assertEq(rules.length, 2);
        assertEq(rules[0].length, 3);
        assertEq(rules[1].length, 2);
        assertEq(keccak256(abi.encodePacked(rules[0][0].instructionSet)), keccak256(abi.encodePacked(initialRules[0].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[0][1].instructionSet)), keccak256(abi.encodePacked(initialRules[1].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[0][2].instructionSet)), keccak256(abi.encodePacked(initialRules[2].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[1][0].instructionSet)), keccak256(abi.encodePacked(initialRules[0].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[1][1].instructionSet)), keccak256(abi.encodePacked(initialRules[1].instructionSet)));

        RulesEngineComponentFacet(address(red)).deleteCallingFunction(
            policy1,
            bytes4(keccak256(bytes("transferFrom(address,address,uint256)")))
        );
        rules = RulesEngineRuleFacet(address(red)).getAllRules(policy1);
        assertEq(rules.length, 1);
        assertEq(rules[0].length, 3);
        assertEq(keccak256(abi.encodePacked(rules[0][0].instructionSet)), keccak256(abi.encodePacked(initialRules[0].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[0][1].instructionSet)), keccak256(abi.encodePacked(initialRules[1].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[0][2].instructionSet)), keccak256(abi.encodePacked(initialRules[2].instructionSet)));
    }

    function testRulesArrayStillFullAfterMultiCallingFunctionRuleDeletion() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);
        uint256 policy1 = _createBlankPolicy();
        policyIds[0] = policy1;
        Rule[] memory initialRules = createArrayOfRules();
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policy1, initialRules[0], "rule1", "rule1");
        assertEq(ruleId, 1);
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policy1, initialRules[1], "rule2", "rule2");
        assertEq(ruleId, 2);
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policy1, initialRules[2], "rule3", "rule3");
        assertEq(ruleId, 3);

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transfer2(address,uint256)")))),
            pTypes,
            "transfer2(address,uint256)",
            ""
        );

        pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;

        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transferFrom(address,address,uint256)")))),
            pTypes,
            "transferFrom(address,address,uint256)",
            ""
        );

        bytes4[] memory callingFunctions = new bytes4[](2);
        callingFunctions[0] = bytes4(bytes4(keccak256(bytes("transfer2(address,uint256)"))));
        callingFunctions[1] = bytes4(bytes4(keccak256(bytes("transferFrom(address,address,uint256)"))));
        uint256[][] memory ruleIds = new uint256[][](2);
        ruleIds[0] = new uint256[](3);
        ruleIds[0][0] = 1;
        ruleIds[0][1] = 2;
        ruleIds[0][2] = 3;
        ruleIds[1] = new uint256[](2);
        ruleIds[1][0] = 1;
        ruleIds[1][1] = 2;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            "policyName",
            "policyDescription"
        );

        Rule[][] memory rules = RulesEngineRuleFacet(address(red)).getAllRules(policy1);
        assertEq(rules.length, 2);
        assertEq(rules[0].length, 3);
        assertEq(rules[1].length, 2);
        assertEq(keccak256(abi.encodePacked(rules[0][0].instructionSet)), keccak256(abi.encodePacked(initialRules[0].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[0][1].instructionSet)), keccak256(abi.encodePacked(initialRules[1].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[0][2].instructionSet)), keccak256(abi.encodePacked(initialRules[2].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[1][0].instructionSet)), keccak256(abi.encodePacked(initialRules[0].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[1][1].instructionSet)), keccak256(abi.encodePacked(initialRules[1].instructionSet)));

        RulesEngineRuleFacet(address(red)).deleteRule(policy1, 2);
        rules = RulesEngineRuleFacet(address(red)).getAllRules(policy1);
        assertEq(rules.length, 2);
        assertEq(rules[0].length, 2);
        assertEq(rules[1].length, 1);
        assertEq(keccak256(abi.encodePacked(rules[0][0].instructionSet)), keccak256(abi.encodePacked(initialRules[0].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[0][1].instructionSet)), keccak256(abi.encodePacked(initialRules[2].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[1][0].instructionSet)), keccak256(abi.encodePacked(initialRules[0].instructionSet)));
    }

    function testRulesArrayDeletionIsStillFull() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);
        uint256 policy1 = _createBlankPolicy();
        policyIds[0] = policy1;
        Rule[] memory initialRules = createArrayOfRules();
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policy1, initialRules[0], "rule1", "rule1");
        assertEq(ruleId, 1);
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policy1, initialRules[1], "rule2", "rule2");
        assertEq(ruleId, 2);
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policy1, initialRules[2], "rule3", "rule3");
        assertEq(ruleId, 3);

        _addCallingFunctionToPolicy(policyIds[0]);

        uint256[][] memory ruleIds = new uint256[][](1);
        ruleIds[0] = new uint256[](3);
        ruleIds[0][0] = 1;
        ruleIds[0][1] = 2;
        ruleIds[0][2] = 3;

        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);

        Rule[][] memory rules = RulesEngineRuleFacet(address(red)).getAllRules(policy1);
        assertEq(rules.length, 1);
        assertEq(rules[0].length, 3);
        assertEq(keccak256(abi.encodePacked(rules[0][0].instructionSet)), keccak256(abi.encodePacked(initialRules[0].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[0][1].instructionSet)), keccak256(abi.encodePacked(initialRules[1].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[0][2].instructionSet)), keccak256(abi.encodePacked(initialRules[2].instructionSet)));

        RulesEngineRuleFacet(address(red)).deleteRule(policy1, 2);
        rules = RulesEngineRuleFacet(address(red)).getAllRules(policy1);
        assertEq(rules.length, 1);
        assertEq(rules[0].length, 2);
        assertEq(keccak256(abi.encodePacked(rules[0][0].instructionSet)), keccak256(abi.encodePacked(initialRules[0].instructionSet)));
        assertEq(keccak256(abi.encodePacked(rules[0][1].instructionSet)), keccak256(abi.encodePacked(initialRules[2].instructionSet)));
    }

    function testPolicyExecutionOrder() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](5);
        // create 5 separate policies
        uint256 policy1 = _createBlankPolicy();
        uint256 policy2 = _createBlankPolicy();
        uint256 policy3 = _createBlankPolicy();
        uint256 policy4 = _createBlankPolicy();
        uint256 policy5 = _createBlankPolicy();
        policyIds[0] = policy1;
        policyIds[1] = policy2;
        policyIds[2] = policy3;
        policyIds[3] = policy4;
        policyIds[4] = policy5;
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        uint256[] memory appliedPolicyIds = RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress);
        // make sure that the policies applied were saved in the correct order
        assertEq(appliedPolicyIds.length, policyIds.length);
        assertEq(policyIds[0], appliedPolicyIds[0]);
        assertEq(policyIds[1], appliedPolicyIds[1]);
        assertEq(policyIds[2], appliedPolicyIds[2]);
        assertEq(policyIds[3], appliedPolicyIds[3]);
        assertEq(policyIds[4], appliedPolicyIds[4]);
        // reverse the policy order
        policyIds[0] = policy5;
        policyIds[1] = policy4;
        policyIds[2] = policy3;
        policyIds[3] = policy2;
        policyIds[4] = policy1;
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        appliedPolicyIds = RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress);
        // make sure that the policies applied were saved in the correct order
        assertEq(appliedPolicyIds.length, policyIds.length);
        assertEq(policyIds[0], appliedPolicyIds[0]);
        assertEq(policyIds[1], appliedPolicyIds[1]);
        assertEq(policyIds[2], appliedPolicyIds[2]);
        assertEq(policyIds[3], appliedPolicyIds[3]);
        assertEq(policyIds[4], appliedPolicyIds[4]);
        // change it to a single policy and ensure that the rest are removed.
        policyIds = new uint256[](1);
        policyIds[0] = 1;
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        appliedPolicyIds = RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress);
        assertEq(appliedPolicyIds.length, policyIds.length);
    }
}
