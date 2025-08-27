/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "src/example/ExampleERC20.sol";
import "test/utils/ForeignCallTestCommon.sol";

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

        uint256 callingFunctionId1 = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transfer(address,uint256)")))),
            pTypes,
            "transfer(address,uint256)",
            ""
        );

        pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;

        uint256 callingFunctionId2 = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transferFrom(address,address,uint256)")))),
            pTypes,
            "transferFrom(address,address,uint256)",
            ""
        );

        bytes4[] memory callingFunctions = new bytes4[](2);
        callingFunctions[0] = bytes4(bytes4(keccak256(bytes("transfer(address,uint256)"))));
        callingFunctions[1] = bytes4(bytes4(keccak256(bytes("transferFrom(address,address,uint256)"))));
        uint256[] memory callingFunctionIds = new uint256[](2);
        callingFunctionIds[0] = callingFunctionId1;
        callingFunctionIds[1] = callingFunctionId2;
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
            callingFunctionIds,
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

        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policy1, callingFunctionId2);
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

        uint256 callingFunctionId1 = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transfer(address,uint256)")))),
            pTypes,
            "transfer(address,uint256)",
            ""
        );

        pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;

        uint256 callingFunctionId2 = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transferFrom(address,address,uint256)")))),
            pTypes,
            "transferFrom(address,address,uint256)",
            ""
        );

        bytes4[] memory callingFunctions = new bytes4[](2);
        callingFunctions[0] = bytes4(bytes4(keccak256(bytes("transfer(address,uint256)"))));
        callingFunctions[1] = bytes4(bytes4(keccak256(bytes("transferFrom(address,address,uint256)"))));
        uint256[] memory callingFunctionIds = new uint256[](2);
        callingFunctionIds[0] = callingFunctionId1;
        callingFunctionIds[1] = callingFunctionId2;
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
            callingFunctionIds,
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

    function testRulesEngine_Unit_deleteRule_deletePolicy_Confirmation() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(user1);
        uint policyId = _createBlankPolicy();

        uint ruleId;
        {
            Rule memory rule;
            // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, *uint256 representation of Bad Info*, LogicalOp.EQ, 0, 1
            // Build the instruction set for the rule (including placeholders)
            rule.instructionSet = new uint256[](7);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 0;
            rule.instructionSet[2] = uint(LogicalOp.NUM);
            rule.instructionSet[3] = uint256(keccak256(abi.encode("Bad Info")));
            rule.instructionSet[4] = uint(LogicalOp.EQ);
            rule.instructionSet[5] = 0;
            rule.instructionSet[6] = 1;

            rule.rawData.argumentTypes = new ParamTypes[](1);
            rule.rawData.dataValues = new bytes[](1);
            rule.rawData.instructionSetIndex = new uint256[](1);
            rule.rawData.argumentTypes[0] = ParamTypes.STR;
            rule.rawData.dataValues[0] = abi.encode("Bad Info");
            rule.rawData.instructionSetIndex[0] = 3;

            // Build the calling function argument placeholder
            rule.placeHolders = new Placeholder[](1);
            rule.placeHolders[0].pType = ParamTypes.STR;
            rule.placeHolders[0].typeSpecificIndex = 1;
            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            // Save the rule
            ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule, "My rule", "My way or the highway");
        }

        uint functionId;
        bytes4 sigCallingFunction;
        {
            ParamTypes[] memory pTypes = new ParamTypes[](2);
            pTypes[0] = ParamTypes.ADDR;
            pTypes[1] = ParamTypes.UINT;
            sigCallingFunction = bytes4(keccak256(bytes(callingFunction)));
            functionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                policyId,
                sigCallingFunction,
                pTypes,
                callingFunction,
                ""
            );
        }
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = sigCallingFunction;
        uint256[] memory functionIds = new uint256[](1);
        functionIds[0] = functionId;
        uint256[][] memory _ruleIds = new uint256[][](1);
        uint256[] memory _ids = new uint256[](1);
        _ids[0] = ruleId;
        _ruleIds[0] = _ids;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            selectors,
            functionIds,
            _ruleIds,
            PolicyType.OPEN_POLICY,
            "Test Policy",
            "This is a test policy"
        );

        // now we can delete the policy
        RulesEngineRuleFacet(address(red)).deleteRule(policyId, ruleId);

        RulesEnginePolicyFacet(address(red)).deletePolicy(policyId);

        // Verify that the policy has been completely deleted
        // attempting to create a rule for the deleted policy should revert with "Policy does not exist"
        {
            Rule memory rule;
            rule.instructionSet = new uint256[](7);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 0;
            rule.instructionSet[2] = uint(LogicalOp.NUM);
            rule.instructionSet[3] = uint256(keccak256(abi.encode("Test")));
            rule.instructionSet[4] = uint(LogicalOp.EQ);
            rule.instructionSet[5] = 0;
            rule.instructionSet[6] = 1;

            rule.rawData.argumentTypes = new ParamTypes[](1);
            rule.rawData.dataValues = new bytes[](1);
            rule.rawData.instructionSetIndex = new uint256[](1);
            rule.rawData.argumentTypes[0] = ParamTypes.STR;
            rule.rawData.dataValues[0] = abi.encode("Test");
            rule.rawData.instructionSetIndex[0] = 3;

            rule.placeHolders = new Placeholder[](1);
            rule.placeHolders[0].pType = ParamTypes.STR;
            rule.placeHolders[0].typeSpecificIndex = 1;
            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;

            vm.expectRevert("Policy does not exist");
            RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule, "Test rule", "Test description");
        }

        // attempting to create a calling function for the deleted policy should revert
        {
            ParamTypes[] memory pTypes = new ParamTypes[](2);
            pTypes[0] = ParamTypes.ADDR;
            pTypes[1] = ParamTypes.UINT;
            vm.expectRevert("Policy does not exist");
            RulesEngineComponentFacet(address(red)).createCallingFunction(
                policyId,
                bytes4(keccak256(bytes("test(address,uint256)"))),
                pTypes,
                "test(address,uint256)",
                ""
            );
        }

        // verify that getPolicy shows cleared mappings for the deleted policy
        // Note: The calling functions array may still exist, but the mappings should be cleared
        {
            (bytes4[] memory callingFunctions, uint256[] memory callingFunctionIds, uint256[][] memory ruleIds) = RulesEnginePolicyFacet(
                address(red)
            ).getPolicy(policyId);
            // The calling functions array may still contain the function signature
            if (callingFunctions.length > 0) {
                // But the function IDs should be cleared (set to 0)
                assertEq(callingFunctionIds[0], 0, "Deleted policy should have cleared calling function IDs");
                // And rule associations should be empty
                assertEq(ruleIds[0].length, 0, "Deleted policy should have no rule associations");
            }
        }
    }

    function testRulesEngine_Unit_OFACDenyListPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        (uint256 policyId, ForeignCallTestContractOFAC denyListContract) = _setupOFACPolicyAndContract();
        (uint256 transferFcId, uint256 transferFromFcId) = _createOFACForeignCalls(policyId, address(denyListContract));
        (uint256 transferRuleId, uint256 transferFromRuleId) = _createOFACRules(policyId, transferFcId, transferFromFcId);
        _updateOFACPolicy(policyId, transferRuleId, transferFromRuleId);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);

        ExampleERC20 testERC20 = _deployAndConfigureERC20(policyId);
        _testOFACTransfers(testERC20, denyListContract);

        vm.stopPrank();
    }

    function _setupOFACPolicyAndContract() internal returns (uint256 policyId, ForeignCallTestContractOFAC denyListContract) {
        // Create OFAC Deny List Policy
        policyId = RulesEnginePolicyFacet(address(red)).createPolicy(
            PolicyType.OPEN_POLICY,
            "OFAC Deny List Policy [Sepolia]",
            "This policy is used to check if the receiver is on the OFAC Deny List"
        );

        // Deploy the deny list contract
        denyListContract = new ForeignCallTestContractOFAC();

        // Add some addresses to the deny list for testing
        address deniedAddress1 = address(0x1111111111111111111111111111111111111111);
        address deniedAddress2 = address(0x2222222222222222222222222222222222222222);

        denyListContract.addToNaughtyList(deniedAddress1);
        denyListContract.addToNaughtyList(deniedAddress2);
    }

    function _createOFACForeignCalls(
        uint256 policyId,
        address denyListContractAddr
    ) internal returns (uint256 transferFcId, uint256 transferFromFcId) {
        // foreign call for transfer function - checks if 'to' address (parameter 0) is denied
        ParamTypes[] memory transferFcArgs = new ParamTypes[](1);
        transferFcArgs[0] = ParamTypes.ADDR;

        ForeignCall memory transferFc;
        transferFc.encodedIndices = new ForeignCallEncodedIndex[](1);
        transferFc.encodedIndices[0].index = 0; // 'to' parameter in transfer(address to, uint256 value)
        transferFc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        transferFc.parameterTypes = transferFcArgs;
        transferFc.foreignCallAddress = denyListContractAddr;
        transferFc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        transferFc.returnType = ParamTypes.UINT;
        transferFc.foreignCallIndex = 1;

        transferFcId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, transferFc, "getNaughty(address)");

        // foreign call for transferFrom function - checks if 'to' address (parameter 1) is denied
        ParamTypes[] memory transferFromFcArgs = new ParamTypes[](1);
        transferFromFcArgs[0] = ParamTypes.ADDR;

        ForeignCall memory transferFromFc;
        transferFromFc.encodedIndices = new ForeignCallEncodedIndex[](1);
        transferFromFc.encodedIndices[0].index = 1; // 'to' parameter in transferFrom(address from, address to, uint256 value)
        transferFromFc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        transferFromFc.parameterTypes = transferFromFcArgs;
        transferFromFc.foreignCallAddress = denyListContractAddr;
        transferFromFc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        transferFromFc.returnType = ParamTypes.UINT;
        transferFromFc.foreignCallIndex = 2;

        transferFromFcId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, transferFromFc, "getNaughty(address)");
    }

    function _createOFACRules(
        uint256 policyId,
        uint256 transferFcId,
        uint256 transferFromFcId
    ) internal returns (uint256 transferRuleId, uint256 transferFromRuleId) {
        // Rule 1: OFAC Deny List Transfer
        Rule memory transferRule;
        transferRule.instructionSet = new uint256[](7);
        transferRule.instructionSet[0] = uint(LogicalOp.PLH);
        transferRule.instructionSet[1] = 0;
        transferRule.instructionSet[2] = uint(LogicalOp.NUM);
        transferRule.instructionSet[3] = 0; // false (not on deny list)
        transferRule.instructionSet[4] = uint(LogicalOp.EQ);
        transferRule.instructionSet[5] = 0;
        transferRule.instructionSet[6] = 1;

        transferRule.placeHolders = new Placeholder[](1);
        transferRule.placeHolders[0].pType = ParamTypes.UINT;
        transferRule.placeHolders[0].typeSpecificIndex = uint128(transferFcId);
        transferRule.placeHolders[0].flags = FLAG_FOREIGN_CALL;

        transferRule.negEffects = new Effect[](1);
        transferRule.negEffects[0].valid = true;
        transferRule.negEffects[0].dynamicParam = false;
        transferRule.negEffects[0].effectType = EffectTypes.REVERT;
        transferRule.negEffects[0].pType = ParamTypes.STR;
        transferRule.negEffects[0].param = abi.encode("Receiver is on OFAC Deny List");
        transferRule.negEffects[0].text = "";
        transferRule.negEffects[0].errorMessage = "Receiver is on OFAC Deny List";
        transferRule.negEffects[0].instructionSet = new uint256[](0);

        transferRuleId = RulesEngineRuleFacet(address(red)).createRule(
            policyId,
            transferRule,
            "OFAC Deny List Transfer",
            "This rule checks if the receiver is on the OFAC Deny List for the transfer function"
        );

        // Rule 2: OFAC Deny List TransferFrom
        Rule memory transferFromRule;
        transferFromRule.instructionSet = new uint256[](7);
        transferFromRule.instructionSet[0] = uint(LogicalOp.PLH);
        transferFromRule.instructionSet[1] = 0;
        transferFromRule.instructionSet[2] = uint(LogicalOp.NUM);
        transferFromRule.instructionSet[3] = 0; // false (not on deny list)
        transferFromRule.instructionSet[4] = uint(LogicalOp.EQ);
        transferFromRule.instructionSet[5] = 0;
        transferFromRule.instructionSet[6] = 1;

        transferFromRule.placeHolders = new Placeholder[](1);
        transferFromRule.placeHolders[0].pType = ParamTypes.UINT;
        transferFromRule.placeHolders[0].typeSpecificIndex = uint128(transferFromFcId);
        transferFromRule.placeHolders[0].flags = FLAG_FOREIGN_CALL;

        transferFromRule.negEffects = new Effect[](1);
        transferFromRule.negEffects[0].valid = true;
        transferFromRule.negEffects[0].dynamicParam = false;
        transferFromRule.negEffects[0].effectType = EffectTypes.REVERT;
        transferFromRule.negEffects[0].pType = ParamTypes.STR;
        transferFromRule.negEffects[0].param = abi.encode("Receiver is on OFAC Deny List");
        transferFromRule.negEffects[0].text = "";
        transferFromRule.negEffects[0].errorMessage = "Receiver is on OFAC Deny List";
        transferFromRule.negEffects[0].instructionSet = new uint256[](0);

        transferFromRuleId = RulesEngineRuleFacet(address(red)).createRule(
            policyId,
            transferFromRule,
            "OFAC Deny List TransferFrom",
            "This rule checks if the receiver is on the OFAC Deny List for the transferFrom function"
        );
    }

    function _updateOFACPolicy(uint256 policyId, uint256 transferRuleId, uint256 transferFromRuleId) internal {
        // Create calling functions
        ParamTypes[] memory transferPTypes = new ParamTypes[](2);
        transferPTypes[0] = ParamTypes.ADDR;
        transferPTypes[1] = ParamTypes.UINT;

        uint256 transferFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256(bytes("transfer(address,uint256)"))),
            transferPTypes,
            "transfer(address,uint256)",
            "address to, uint256 value"
        );

        ParamTypes[] memory transferFromPTypes = new ParamTypes[](3);
        transferFromPTypes[0] = ParamTypes.ADDR;
        transferFromPTypes[1] = ParamTypes.ADDR;
        transferFromPTypes[2] = ParamTypes.UINT;

        uint256 transferFromFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256(bytes("transferFrom(address,address,uint256)"))),
            transferFromPTypes,
            "transferFrom(address,address,uint256)",
            "address from, address to, uint256 value"
        );

        // Update policy with calling functions and rules
        bytes4[] memory callingFunctions = new bytes4[](2);
        callingFunctions[0] = bytes4(keccak256(bytes("transfer(address,uint256)")));
        callingFunctions[1] = bytes4(keccak256(bytes("transferFrom(address,address,uint256)")));

        uint256[] memory callingFunctionIds = new uint256[](2);
        callingFunctionIds[0] = transferFunctionId;
        callingFunctionIds[1] = transferFromFunctionId;

        uint256[][] memory ruleIds = new uint256[][](2);
        ruleIds[0] = new uint256[](1);
        ruleIds[0][0] = transferRuleId;
        ruleIds[1] = new uint256[](1);
        ruleIds[1][0] = transferFromRuleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.OPEN_POLICY,
            "OFAC Deny List Policy [Sepolia]",
            "This policy is used to check if the receiver is on the OFAC Deny List"
        );
    }

    function _deployAndConfigureERC20(uint256 policyId) internal returns (ExampleERC20) {
        ExampleERC20 testERC20 = new ExampleERC20("Test Token", "TEST");
        testERC20.setRulesEngineAddress(address(red));
        testERC20.setCallingContractAdmin(callingContractAdmin);

        // Apply policy to the contract
        uint256[] memory policyIdsToApply = new uint256[](1);
        policyIdsToApply[0] = policyId;
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(testERC20), policyIdsToApply);

        // Mint tokens for testing
        address user2 = address(0x456);
        testERC20.mint(user1, 1000 * 10 ** 18);
        testERC20.mint(user2, 1000 * 10 ** 18);

        return testERC20;
    }

    function _testOFACTransfers(ExampleERC20 testERC20, ForeignCallTestContractOFAC denyListContract) internal {
        address deniedAddress1 = address(0x1111111111111111111111111111111111111111);
        address deniedAddress2 = address(0x2222222222222222222222222222222222222222);
        address allowedAddress = address(0x3333333333333333333333333333333333333333);
        address user2 = address(0x456);

        // Test transfer to allowed address (should succeed)
        vm.stopPrank();
        vm.startPrank(user1);
        testERC20.transfer(allowedAddress, 100 * 10 ** 18);
        assertEq(testERC20.balanceOf(allowedAddress), 100 * 10 ** 18, "Transfer to allowed address should succeed");

        // Test transfer to denied address (should revert)
        vm.expectRevert("Receiver is on OFAC Deny List");
        testERC20.transfer(deniedAddress1, 50 * 10 ** 18);

        // Test transferFrom to allowed address (should succeed)
        testERC20.approve(user2, 200 * 10 ** 18);
        vm.stopPrank();
        vm.startPrank(user2);
        testERC20.transferFrom(user1, allowedAddress, 50 * 10 ** 18);
        assertEq(testERC20.balanceOf(allowedAddress), 150 * 10 ** 18, "TransferFrom to allowed address should succeed");

        // Test transferFrom to denied address (should revert)
        vm.expectRevert("Receiver is on OFAC Deny List");
        testERC20.transferFrom(user1, deniedAddress2, 25 * 10 ** 18);

        // Verify deny list contract is working correctly
        assertTrue(denyListContract.getNaughty(deniedAddress1), "Denied address 1 should be on deny list");
        assertTrue(denyListContract.getNaughty(deniedAddress2), "Denied address 2 should be on deny list");
        assertFalse(denyListContract.getNaughty(allowedAddress), "Allowed address should not be on deny list");
    }
}
