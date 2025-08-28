/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract policies is RulesEngineCommon {
    /**
     *
     *
     * Validation tests for policies within the rules engine
     *
     *
     */

    // CRUD Functions: Policies

    // Update
    function testRulesEngine_Unit_UpdatePolicy_InvalidRule() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        (uint256 policyId, uint256 ruleId) = setUpRuleSimple();
        // the following calling function doesn't exist in the policy yet, but the test won't reach this selector, so we skip the unnecessary setup.
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction3))));
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = 666; // we add the inexistent rule (will cause the revert)
        ruleIds[1][0] = 1; // this is a valid rule id, but the test won't reach this value
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        vm.expectRevert("Invalid Rule");
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
    }

    // Test attempt to add a policy with no callingFunctions saved.
    function testRulesEngine_Unit_UpdatePolicy_InvalidCallingFunction() public ifDeploymentTestsEnabled endWithStopPrank {
        // setUpRuleSimple helper not used as test does not set the calling Function ID intentionally
        uint256 policyId = _createBlankPolicy();
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        callingFunctionIds.push(1);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = 1;
        vm.expectRevert("Invalid Signature");
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
    }

    function testRulesEngine_Unit_UpdatePolicy_InvalidSignatureSelector() public ifDeploymentTestsEnabled endWithStopPrank {
        // we first add a good policy info
        (uint256 policyId, uint256 ruleId) = setUpRuleSimple();
        ruleId;
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        assertGt(
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                callingFunctions,
                ruleIds,
                PolicyType.CLOSED_POLICY,
                policyName,
                policyDescription
            ),
            0
        );
        // now we try to update it with a corrupted selector
        callingFunctions[0] = bytes4(keccak256(bytes("maliciousCallingFunction(badType,evenWorseType)")));
        // we shouldn't be able to
        vm.expectRevert("Invalid Signature");
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
    }

    // Test attempt to add a policy with valid parts.
    function testRulesEngine_Unit_UpdatePolicy_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        (uint256 policyId, uint256 ruleId) = setUpRuleSimple();
        ruleId;
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        assertGt(
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                callingFunctions,
                ruleIds,
                PolicyType.CLOSED_POLICY,
                policyName,
                policyDescription
            ),
            0
        );
    }

    function testRulesEngine_Unit_UpdatePolicy_ValidatesForeignCalls() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.instructionSet = new uint256[](2);
        rule.instructionSet[0] = 0;
        rule.instructionSet[1] = 0;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        vm.expectRevert("Foreign Call referenced in rule not set");
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
    }

    function testRulesEngine_Unit_UpdatePolicy_ValidatesTrackers() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0, 1);

        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        vm.expectRevert("Tracker referenced in rule not set");
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
    }

    // Create
    function testRulesEngine_Unit_createBlankPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = RulesEnginePolicyFacet(address(red)).createPolicy(PolicyType.CLOSED_POLICY, policyName, policyDescription);
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, callingContractAdmin);
        assertEq(policyId, 1);
    }

    // Delete

    /// Test the getter functions for Policy. These are specifically tested(rather than the other view functions that are used within the update tests) because they digest the policy into individual arrays.
    function testRulesEngine_Unit_GetPolicy_Blank() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        bytes4[] memory _functionSigs;
        uint256[] memory _functionSigIds;
        uint256[][] memory _ruleIds;

        policyIds[0] = _createBlankPolicy();
        assertEq(_functionSigs.length, 0);
        assertEq(_functionSigIds.length, 0);
        assertEq(_ruleIds.length, 0);
    }

    function testRulesEngine_Unit_GetPolicy_FunctionSig() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        bytes4[] memory _functionSigs;
        uint256[][] memory _ruleIds;

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);
        (_functionSigs, _ruleIds) = RulesEnginePolicyFacet(address(red)).getPolicy(policyIds[0]);
        assertEq(_functionSigs.length, 1);
    }

    function testRulesEngine_Unit_GetPolicy_Rules() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        bytes4[] memory _functionSigs;
        uint256[][] memory _ruleIds;

        policyIds[0] = setupEffectWithTrackerUpdateUint();

        (_functionSigs, _ruleIds) = RulesEnginePolicyFacet(address(red)).getPolicy(policyIds[0]);
        assertEq(_ruleIds.length, 1);
        assertEq(_ruleIds[0].length, 1);
        assertEq(_ruleIds[0][0], 1);
    }

    function testRulesEngine_Unit_ApplyPolicy_ClosedPolicy_NotSubscriber() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        address potentialSubscriber = address(0xdeadbeef);
        vm.startPrank(address(1));
        vm.expectRevert("Not Calling Contract Admin");
        RulesEnginePolicyFacet(address(red)).applyPolicy(potentialSubscriber, policyIds);
    }

    function testRulesEngine_Unit_UpdatePolicy_ClosePolicy_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
        ExampleUserContract potentialSubscriber = new ExampleUserContract();
        potentialSubscriber.setRulesEngineAddress(address(red));
        potentialSubscriber.setCallingContractAdmin(callingContractAdmin);
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(potentialSubscriber), policyIds);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(address(potentialSubscriber)).length, 1);
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(address(potentialSubscriber)).length, 0);
    }

    function testRulesEngine_Unit_UpdatePolicy_With_Rules_Delete_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 ruleCount = 50;
        uint256 policyId = _createBlankPolicy();
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        Rule memory r;
        // Set up the parameter types for the calling function
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        uint256[][] memory ruleIds = new uint256[][](50);
        ruleIds[0] = new uint256[](50);
        bytes4[] memory selectors = new bytes4[](50);
        uint256[] memory functionIds = new uint256[](50);
        // This loop will create 50 calling functions with a rule on each one.
        for (uint i = 0; i < ruleCount; i++) {
            bytes4 selector = bytes4(keccak256(bytes(callingFunction)) ^ (bytes32(i) << (256 - 4 * 8)));
            RulesEngineComponentFacet(address(red)).createCallingFunction(policyId, selector, pTypes, callingFunction, "");
            selectors[i] = selector;

            r = _createLTRule();
            ruleIds[i] = new uint256[](1);
            ruleIds[i][0] = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], r, "rule", "ruleDescription");
        }
        ruleCount -= 1;
        uint256 lastRuleId = ruleIds[ruleCount][0];
        uint256 lastFunctionId = functionIds[ruleCount];
        bytes4 lastSelector = selectors[ruleCount];
        // Remove all but the last calling function and rule.
        selectors = new bytes4[](1);
        functionIds = new uint256[](1);
        ruleIds = new uint256[][](1);
        selectors[0] = lastSelector;
        functionIds[0] = lastFunctionId;
        ruleIds[0] = new uint256[](1);
        ruleIds[0][0] = lastRuleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            selectors,
            ruleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
        // verify that only the single rule and calling function exist in this policy
        (selectors, ruleIds) = RulesEnginePolicyFacet(address(red)).getPolicy(policyId);
        assertEq(selectors.length, 1, "Rules delete in updatePolicy did not remove all the function selectors");
        assertEq(ruleIds.length, 1, "Rules delete in updatePolicy did not remove all the calling function associations");
        assertEq(ruleIds[0].length, 1, "Rules delete in updatePolicy did not remove all the rules");

        // verify that the old rules and calling functions cannot be used
        selectors[0] = lastSelector;
        functionIds[0] = 0;
        ruleIds[0] = new uint256[](1);
        ruleIds[0][0] = 0;
        vm.expectRevert("Invalid Rule");
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            selectors,
            ruleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
    }

    function testRulesEngine_Unit_ClosePolicy_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
        ExampleUserContract potentialSubscriber = new ExampleUserContract();
        potentialSubscriber.setRulesEngineAddress(address(red));
        potentialSubscriber.setCallingContractAdmin(callingContractAdmin);
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(potentialSubscriber), policyIds);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(address(potentialSubscriber)).length, 1);
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).closePolicy(policyId);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(address(potentialSubscriber)).length, 0);
    }

    function testRulesEngine_Unit_OpenPolicy_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        assertTrue(RulesEnginePolicyFacet(address(red)).isClosedPolicy(policyId));
        RulesEnginePolicyFacet(address(red)).openPolicy(policyId);
        assertFalse(RulesEnginePolicyFacet(address(red)).isClosedPolicy(policyId));
    }

    function testRulesEngine_Unit_OpenPolicy_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        assertTrue(RulesEnginePolicyFacet(address(red)).isClosedPolicy(policyId));
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);

        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).openPolicy(policyId);
    }

    function testRulesEngine_Unit_OpenPolicy_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        assertTrue(RulesEnginePolicyFacet(address(red)).isClosedPolicy(policyId));

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEnginePolicyFacet(address(red)).openPolicy(policyId);
    }

    function testRulesEngine_Unit_ApplyPolicy_OpenPolicy_NotSubscriber() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        ExampleUserContract potentialSubscriber = new ExampleUserContract();
        potentialSubscriber.setRulesEngineAddress(address(red));
        potentialSubscriber.setCallingContractAdmin(callingContractAdmin);
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(potentialSubscriber), policyIds);
    }

    function testRulesEngine_Unit_ApplyPolicy_ClosedPolicy_Subscriber() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, callingContractAdmin);
        assertTrue(RulesEngineComponentFacet(address(red)).isClosedPolicySubscriber(policyId, callingContractAdmin));
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContract), policyIds);
    }

    function testRulesEngine_Unit_UpdatePolicy_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
    }

    function testRulesEngine_Unit_UpdatePolicy_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
    }

    function testRulesEngine_Unit_DeletePolicy_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).deletePolicy(policyId);
    }

    function testRulesEngine_Unit_DeletePolicy_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEnginePolicyFacet(address(red)).deletePolicy(policyId);
    }

    ////// Apply and Un Apply Policy Tests
    function testRulesEngine_Unit_ApplyPolicy_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function testRulesEngine_Unit_ApplyPolicy_Negative_Non_CallingContractAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        vm.stopPrank();

        // Prank a random, non-calling contract admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Calling Contract Admin");
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function testRulesEngine_Unit_UnapplyPolicy_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankSignatures,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        RulesEnginePolicyFacet(address(red)).unapplyPolicy(address(userContract), policyIds);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress).length, 0);
    }

    function testRulesEngine_Unit_UnapplyPolicyMultiple_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](2);

        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankSignatures,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );

        uint256 policyId2 = _createBlankPolicy();
        bytes4[] memory blankSignatures2 = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds2 = new uint256[](0);
        uint256[][] memory blankRuleIds2 = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId2,
            blankSignatures2,
            blankRuleIds2,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
        policyIds[0] = policyId;
        policyIds[1] = policyId2;
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        RulesEnginePolicyFacet(address(red)).unapplyPolicy(address(userContract), policyIds);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress).length, 0);
    }

    function testRulesEngine_Unit_UnapplyPolicyMultipleApplied_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](2);
        // Create a second and third user contract for the test
        newUserContract = new ExampleUserContract();
        newUserContractAddress = address(newUserContract);
        newUserContract.setRulesEngineAddress(address(red));
        newUserContract.setCallingContractAdmin(callingContractAdmin);
        ExampleUserContract userContractC = new ExampleUserContract();
        address userContractCAddress = address(userContractC);
        userContractC.setRulesEngineAddress(address(red));
        userContractC.setCallingContractAdmin(callingContractAdmin);

        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankSignatures,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );

        uint256 policyId2 = _createBlankPolicy();
        bytes4[] memory blankSignatures2 = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds2 = new uint256[](0);
        uint256[][] memory blankRuleIds2 = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId2,
            blankSignatures2,
            blankRuleIds2,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
        policyIds[0] = policyId;
        policyIds[1] = policyId2;
        vm.startPrank(callingContractAdmin);
        // Apply policies to the user contract A
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        policyIds = new uint256[](1);
        policyIds[0] = policyId;
        // Apply only one policy to a user contract B.
        RulesEnginePolicyFacet(address(red)).applyPolicy(newUserContractAddress, policyIds);
        // Unapply both policies from the user contract A
        policyIds = new uint256[](2);
        policyIds[0] = policyId;
        policyIds[1] = policyId2;
        RulesEnginePolicyFacet(address(red)).unapplyPolicy(userContractAddress, policyIds);
        // make sure that all policies were unapplied from user contract A
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress).length, 0);
        // make sure that user contract B's applied policies were not affected.
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(newUserContractAddress).length, 1);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(newUserContractAddress)[0], policyId);
        // make sure that no policies are applied to user contract C
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractCAddress).length, 0);
    }

    function testRulesEngine_Unit_UnapplyPolicy_Multiple_OnlyRemoveOne_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankSignatures,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
        uint256[] memory policyIds = new uint256[](2);
        uint256 policyId2 = _createBlankPolicy();
        bytes4[] memory blankSignatures2 = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds2 = new uint256[](0);
        uint256[][] memory blankRuleIds2 = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId2,
            blankSignatures2,
            blankRuleIds2,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
        policyIds[0] = policyId;
        policyIds[1] = policyId2;
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        policyIds = new uint256[](1);
        policyIds[0] = policyId;
        RulesEnginePolicyFacet(address(red)).unapplyPolicy(address(userContract), policyIds);
        policyIds = RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress);
        assertEq(policyIds.length, 1);
        assertEq(policyIds[0], policyId2);
    }

    function testRulesEngine_Unit_UnapplyPolicy_Negative_NotCallingContractAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankSignatures,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        vm.startPrank(policyAdmin);
        vm.expectRevert("Not Calling Contract Admin");
        RulesEnginePolicyFacet(address(red)).unapplyPolicy(address(userContract), policyIds);
    }

    function testRulesEngine_Unit_CementedPolicy_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);

        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
    }

    function testRulesEngine_Unit_CementedPolicy_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
    }

    ///////////////////////////// Event Emission Tests
    function testRulesEngine_Unit_CreatePolicyEvent() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = 1;
        vm.expectEmit(true, false, false, false);
        emit PolicyCreated(policyId);
        emit PolicyAdminRoleGranted(policyAdmin, policyId);
        RulesEnginePolicyFacet(address(red)).createPolicy(PolicyType.CLOSED_POLICY, policyName, policyDescription);
    }

    function testRulesEngine_Unit_UpdatePolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        (uint256 policyId, uint256 ruleId) = setUpRuleSimple();
        ruleId;
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        vm.expectEmit(true, false, false, false);
        emit PolicyUpdated(policyId);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
    }

    function testRulesEngine_Unit_DeletePolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        vm.expectEmit(true, false, false, false);
        emit PolicyDeleted(policyId);
        RulesEnginePolicyFacet(address(red)).deletePolicy(policyId);
    }

    function testRulesEngine_Unit_AppliedPolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        vm.expectEmit(true, false, false, false);
        emit PolicyApplied(policyIds, userContractAddress);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function testRulesEngine_Unit_CementedPolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        vm.expectEmit(true, false, false, false);
        emit PolicyCemented(policyId);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
    }

    function testRulesEngine_Unit_OpenPolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        vm.expectEmit(true, false, false, false);
        emit PolicyOpened(policyId);
        RulesEnginePolicyFacet(address(red)).openPolicy(policyId);
    }

    function testRulesEngine_Unit_ClosePolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        vm.expectEmit(true, false, false, false);
        emit PolicyClosed(policyId);
        RulesEnginePolicyFacet(address(red)).closePolicy(policyId);
    }

    function testRulesEngine_Unit_ClosePolicy_Negative_CemetedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).closePolicy(policyId);
    }

    function testRulesEngine_Unit_ClosePolicy_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEnginePolicyFacet(address(red)).closePolicy(policyId);
    }

    function testRulesEngine_Unit_DisablePolicy_Negative_CemetedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).disablePolicy(policyId);
    }

    function testRulesEngine_Unit_DisablePolicy_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEnginePolicyFacet(address(red)).disablePolicy(policyId);
    }

    function testRulesEngine_Unit_ClosedPolicySubscriber_AddRemove_Events() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.expectEmit(true, false, false, false);
        emit PolicySubsciberAdded(policyId, callingContractAdmin);
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, callingContractAdmin);

        vm.expectEmit(true, false, false, false);
        emit PolicySubsciberRemoved(policyId, callingContractAdmin);
        RulesEngineComponentFacet(address(red)).removeClosedPolicySubscriber(policyId, callingContractAdmin);
    }

    // Retrieve raw data tests
    function testRulesEngine_Unit_CheckPolicies_Explicit_StringComparison_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithStringComparison();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction2))), address(0x7654321), "Bad Info");
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_StringComparison_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithStringComparison();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction2))), address(0x7654321), "test");
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_RetrieveRawStringFromInstructionSet() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 ruleId = setupRuleWithStringComparison();
        StringVerificationStruct memory retVal = RulesEngineInitialFacet(address(red)).retrieveRawStringFromInstructionSet(1, ruleId, 3);
        console2.log(retVal.instructionSetValue);
        console2.log(retVal.rawData);
        assertEq(retVal.instructionSetValue, uint256(keccak256(abi.encode(retVal.rawData))));
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_AddressComparison_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithAddressComparison();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction2))), address(0x1234567), "test");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_AddressComparison_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithAddressComparison();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction2))), address(0x7654321), "test");
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_RetrieveRawAddressFromInstructionSet() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 ruleId = setupRuleWithAddressComparison();
        AddressVerificationStruct memory retVal = RulesEngineInitialFacet(address(red)).retrieveRawAddressFromInstructionSet(1, ruleId, 3);
        console2.log(retVal.instructionSetValue);
        console2.log(retVal.rawData);
        assertEq(retVal.instructionSetValue, uint256(uint160(address(retVal.rawData))));
    }

    function testRulesEngine_unit_RetreivePolicyMetadata_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        PolicyMetadata memory data = RulesEnginePolicyFacet(address(red)).getPolicyMetadata(policyId);
        assertEq(data.policyName, policyName);
        assertEq(data.policyDescription, policyDescription);
    }

    function testRulesEngine_Unit_deletePolicy() public ifDeploymentTestsEnabled endWithStopPrank {
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
            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, "My rule", "My way or the highway");
        }

        bytes4 sigCallingFunction;
        {
            ParamTypes[] memory pTypes = new ParamTypes[](2);
            pTypes[0] = ParamTypes.ADDR;
            pTypes[1] = ParamTypes.UINT;
            sigCallingFunction = bytes4(keccak256(bytes(callingFunction)));
            RulesEngineComponentFacet(address(red)).createCallingFunction(policyId, sigCallingFunction, pTypes, callingFunction, "");
        }
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = sigCallingFunction;
        uint256[][] memory _ruleIds = new uint256[][](1);
        uint256[] memory _ids = new uint256[](1);
        _ids[0] = ruleId;
        _ruleIds[0] = _ids;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            selectors,
            _ruleIds,
            PolicyType.OPEN_POLICY,
            "Test Policy",
            "This is a test policy"
        );

        // now we can delete the policy
        RulesEnginePolicyFacet(address(red)).deletePolicy(policyId);
        // we check that we can't create a rule for a deleted policy
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
            // we check that a rule cannot be made for the erased policy
            vm.expectRevert("Rule not set");
            ruleId = RulesEngineRuleFacet(address(red)).updateRule(1, ruleId, rule, "My rule", "My way or the highway");
        }
        // we check that we can't create a calling function for a deleted policy
        {
            ParamTypes[] memory pTypes = new ParamTypes[](2);
            pTypes[0] = ParamTypes.ADDR;
            pTypes[1] = ParamTypes.UINT;
            sigCallingFunction = bytes4(keccak256(bytes(callingFunction)));
            vm.expectRevert("Policy does not exist");
            RulesEngineComponentFacet(address(red)).createCallingFunction(policyId, sigCallingFunction, pTypes, callingFunction, "");
        }
        // we check that we can't update a deleted policy
        vm.expectRevert("Invalid Rule");
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            selectors,
            _ruleIds,
            PolicyType.OPEN_POLICY,
            "Test Policy",
            "This is a test policy"
        );
    }

    function testRulesEngine_unit_RetrieveTrackerToRuleIdList() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.ADDR;
        tracker.set = true;
        tracker.trackerValue = abi.encode(0xD00D);
        setupRuleWithTrackerFlag(policyId, tracker);

        uint256[] memory trackerToRuleIdList = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 2);
        assertEq(trackerToRuleIdList.length, 1);
    }

    function testRulesEngine_unit_DeleteRuleFromTrackerToRuleIdList() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.ADDR;
        tracker.set = true;
        tracker.trackerValue = abi.encode(0xD00D);
        setupRuleWithTrackerFlag(policyId, tracker);

        uint256[] memory trackerToRuleIdList = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 2);
        assertEq(trackerToRuleIdList.length, 1);

        // delete the rule
        vm.startPrank(policyAdmin);
        RulesEngineRuleFacet(address(red)).deleteRule(policyId, 1);

        trackerToRuleIdList = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 2);
        assertEq(trackerToRuleIdList.length, 0);
    }

    function testRulesEngine_unit_UpdateRuleFromTrackerToRuleIdList() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.ADDR;
        tracker.set = true;
        tracker.trackerValue = abi.encode(0xD00D);
        setupRuleWithTrackerFlag(policyIds[0], tracker);

        uint256[] memory trackerToRuleIdList = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 2);
        assertEq(trackerToRuleIdList.length, 1);
        // update the rule
        vm.startPrank(policyAdmin);
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = ParamTypes.ADDR;
        rule.placeHolders[2].typeSpecificIndex = 2;
        Trackers memory tracker1;
        Trackers memory tracker2;
        Trackers memory tracker3;
        Trackers memory tracker4;
        Trackers memory tracker5;
        /// build the members of the struct:
        tracker1.pType = ParamTypes.ADDR;
        tracker1.set = true;
        tracker1.trackerValue = abi.encode(0xD00D);

        tracker2.pType = ParamTypes.UINT;
        tracker2.set = true;
        tracker2.trackerValue = abi.encode(500);

        tracker3.pType = ParamTypes.BOOL;
        tracker3.set = true;
        tracker3.trackerValue = abi.encode(true);

        tracker4.pType = ParamTypes.UINT;
        tracker4.set = true;
        tracker4.trackerValue = abi.encode(1000);

        tracker5.pType = ParamTypes.ADDR;
        tracker5.set = true;
        tracker5.trackerValue = abi.encode(0x0033);

        rule.effectPlaceHolders = new Placeholder[](5);
        rule.effectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule.effectPlaceHolders[0].typeSpecificIndex = 1;
        rule.effectPlaceHolders[0].flags = FLAG_TRACKER_VALUE;

        rule.effectPlaceHolders[1].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[1].typeSpecificIndex = 2;
        rule.effectPlaceHolders[1].flags = FLAG_TRACKER_VALUE;

        rule.effectPlaceHolders[2].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[2].typeSpecificIndex = 3;
        rule.effectPlaceHolders[2].flags = FLAG_TRACKER_VALUE;

        rule.effectPlaceHolders[3].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[3].typeSpecificIndex = 4;
        rule.effectPlaceHolders[3].flags = FLAG_TRACKER_VALUE;

        rule.effectPlaceHolders[4].pType = ParamTypes.ADDR;
        rule.effectPlaceHolders[4].typeSpecificIndex = 5;
        rule.effectPlaceHolders[4].flags = FLAG_TRACKER_VALUE;

        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = _createEffectExpressionTrackerUpdateMultiTrackerUpdate();

        // Add the trackers
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker1, "trName1");
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker2, "trName2");
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker3, "trName3");
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker4, "trName4");
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker5, "trName5");

        // update the rule
        vm.startPrank(policyAdmin);
        RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 1, rule, "My rule", "My way or the highway");

        uint256[] memory trackerToRuleIdList1 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 1);
        assertEq(trackerToRuleIdList1.length, 1);

        uint256[] memory trackerToRuleIdList2 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 2);
        assertEq(trackerToRuleIdList2.length, 1);

        uint256[] memory trackerToRuleIdList3 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 3);
        assertEq(trackerToRuleIdList3.length, 1);

        uint256[] memory trackerToRuleIdList4 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 4);
        assertEq(trackerToRuleIdList4.length, 1);

        uint256[] memory trackerToRuleIdList5 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 5);
        assertEq(trackerToRuleIdList5.length, 1);
    }

    function testRulesEngine_unit_RetrieveTrackerToRuleIdList_MultipleTrackers() public ifDeploymentTestsEnabled endWithStopPrank {
        _setUpRuleWithMultipleTrackers();

        uint256[] memory trackerToRuleIdList1 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 1);
        assertEq(trackerToRuleIdList1.length, 1);

        uint256[] memory trackerToRuleIdList2 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 2);
        assertEq(trackerToRuleIdList2.length, 1);

        uint256[] memory trackerToRuleIdList3 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 3);
        assertEq(trackerToRuleIdList3.length, 1);

        uint256[] memory trackerToRuleIdList4 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 4);
        assertEq(trackerToRuleIdList4.length, 1);

        uint256[] memory trackerToRuleIdList5 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 5);
        assertEq(trackerToRuleIdList5.length, 1);
    }

    function testRulesEngine_unit_DeleteRuleFromTrackerToRuleIdList_MultipleTrackers() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _setUpRuleWithMultipleTrackers();

        uint256[] memory trackerToRuleIdList1 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 1);
        assertEq(trackerToRuleIdList1.length, 1);

        uint256[] memory trackerToRuleIdList2 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 2);
        assertEq(trackerToRuleIdList2.length, 1);

        uint256[] memory trackerToRuleIdList3 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 3);
        assertEq(trackerToRuleIdList3.length, 1);

        uint256[] memory trackerToRuleIdList4 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 4);
        assertEq(trackerToRuleIdList4.length, 1);

        uint256[] memory trackerToRuleIdList5 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 5);
        assertEq(trackerToRuleIdList5.length, 1);

        // delete the rule
        vm.startPrank(policyAdmin);
        RulesEngineRuleFacet(address(red)).deleteRule(policyId, 1);

        trackerToRuleIdList1 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 1);
        assertEq(trackerToRuleIdList1.length, 0);

        trackerToRuleIdList2 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 2);
        assertEq(trackerToRuleIdList2.length, 0);

        trackerToRuleIdList3 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 3);
        assertEq(trackerToRuleIdList3.length, 0);

        trackerToRuleIdList4 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 4);
        assertEq(trackerToRuleIdList4.length, 0);

        trackerToRuleIdList5 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 5);
        assertEq(trackerToRuleIdList5.length, 0);
    }

    function testRulesEngine_unit_RetrieveTrackerToRuleIdList_MultipleRules() public ifDeploymentTestsEnabled endWithStopPrank {
        _setUpMultipleRulesWiTracker();

        uint256[] memory trackerToRuleIdList1 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 1);
        assertEq(trackerToRuleIdList1.length, 5);
    }

    function testRulesEngine_unit_DeleteRuleFromTrackerToRuleIdList_MultipleRules() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _setUpMultipleRulesWiTracker();

        uint256[] memory trackerToRuleIdList1 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 1);
        assertEq(trackerToRuleIdList1.length, 5);

        // delete the rule
        vm.startPrank(policyAdmin);
        RulesEngineRuleFacet(address(red)).deleteRule(policyId, 1);

        trackerToRuleIdList1 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 1);
        assertEq(trackerToRuleIdList1.length, 4);
    }

    function testRulesEngine_unit_UpdateRuleFromTrackerToRuleIdList_MultipleRules() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _setUpMultipleRulesWiTracker();

        uint256[] memory trackerToRuleIdList1 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 1);
        assertEq(trackerToRuleIdList1.length, 5);

        // delete the rule
        vm.startPrank(policyAdmin);

        Rule memory rule6;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule6.instructionSet = new uint256[](7);
        rule6.instructionSet[0] = uint(LogicalOp.NUM);
        rule6.instructionSet[1] = 1;
        rule6.instructionSet[2] = uint(LogicalOp.NUM);
        rule6.instructionSet[3] = 1;
        rule6.instructionSet[4] = uint(LogicalOp.EQ);
        rule6.instructionSet[5] = 0;
        rule6.instructionSet[6] = 1;

        rule6.negEffects = new Effect[](1);
        rule6.posEffects = new Effect[](1);
        rule6.negEffects[0] = effectId_revert;
        rule6.posEffects[0] = effectId_revert;
        // Test adding a rule without a tracker does not update the list
        RulesEngineRuleFacet(address(red)).createRule(policyId, rule6, ruleName, ruleDescription);

        trackerToRuleIdList1 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 1);
        assertEq(trackerToRuleIdList1.length, 5);

        // update to the rule to now include a tracker and ensure it updates the list
        rule6.effectPlaceHolders = new Placeholder[](1);
        rule6.effectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule6.effectPlaceHolders[0].typeSpecificIndex = 1;
        rule6.effectPlaceHolders[0].flags = FLAG_TRACKER_VALUE;

        rule6.negEffects = new Effect[](1);
        rule6.posEffects = new Effect[](1);
        rule6.negEffects[0] = effectId_revert;
        rule6.posEffects[0] = _createEffectExpressionTrackerUpdateParameterPlaceHolder();

        RulesEngineRuleFacet(address(red)).updateRule(policyId, 6, rule6, ruleName, ruleDescription);

        trackerToRuleIdList1 = RulesEngineComponentFacet(address(red)).getTrackerToRuleIds(1, 1);
        assertEq(trackerToRuleIdList1.length, 6);
    }

    function _setUpRuleWithMultipleTrackers() internal returns (uint256 policyId) {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        _addCallingFunctionToPolicyWithString(policyIds[0]);

        Rule memory rule;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = ParamTypes.ADDR;
        rule.placeHolders[2].typeSpecificIndex = 2;

        //build trackers
        Trackers memory tracker1;
        Trackers memory tracker2;
        Trackers memory tracker3;
        Trackers memory tracker4;
        Trackers memory tracker5;
        /// build the members of the struct:
        tracker1.pType = ParamTypes.ADDR;
        tracker1.set = true;
        tracker1.trackerValue = abi.encode(0xD00D);

        tracker2.pType = ParamTypes.UINT;
        tracker2.set = true;
        tracker2.trackerValue = abi.encode(500);

        tracker3.pType = ParamTypes.BOOL;
        tracker3.set = true;
        tracker3.trackerValue = abi.encode(true);

        tracker4.pType = ParamTypes.UINT;
        tracker4.set = true;
        tracker4.trackerValue = abi.encode(1000);

        tracker5.pType = ParamTypes.ADDR;
        tracker5.set = true;
        tracker5.trackerValue = abi.encode(0x0033);

        rule.effectPlaceHolders = new Placeholder[](5);
        rule.effectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule.effectPlaceHolders[0].typeSpecificIndex = 1;
        rule.effectPlaceHolders[0].flags = FLAG_TRACKER_VALUE;

        rule.effectPlaceHolders[1].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[1].typeSpecificIndex = 2;
        rule.effectPlaceHolders[1].flags = FLAG_TRACKER_VALUE;

        rule.effectPlaceHolders[2].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[2].typeSpecificIndex = 3;
        rule.effectPlaceHolders[2].flags = FLAG_TRACKER_VALUE;

        rule.effectPlaceHolders[3].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[3].typeSpecificIndex = 4;
        rule.effectPlaceHolders[3].flags = FLAG_TRACKER_VALUE;

        rule.effectPlaceHolders[4].pType = ParamTypes.ADDR;
        rule.effectPlaceHolders[4].typeSpecificIndex = 5;
        rule.effectPlaceHolders[4].flags = FLAG_TRACKER_VALUE;

        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = _createEffectExpressionTrackerUpdateMultiTrackerUpdate();

        // Add the trackers
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker1, "trName1");
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker2, "trName2");
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker3, "trName3");
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker4, "trName4");
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker5, "trName5");

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function _setUpMultipleRulesWiTracker() internal returns (uint256 policyId) {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        _addCallingFunctionToPolicyWithString(policyIds[0]);

        Rule memory rule;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = ParamTypes.ADDR;
        rule.placeHolders[2].typeSpecificIndex = 2;

        //build trackers
        Trackers memory tracker1;

        /// build the members of the struct:
        tracker1.pType = ParamTypes.ADDR;
        tracker1.set = true;
        tracker1.trackerValue = abi.encode(0xD00D);

        rule.effectPlaceHolders = new Placeholder[](1);
        rule.effectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule.effectPlaceHolders[0].typeSpecificIndex = 1;
        rule.effectPlaceHolders[0].flags = FLAG_TRACKER_VALUE;

        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = _createEffectExpressionTrackerUpdateParameterPlaceHolder();

        // Add the trackers
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker1, "trName1");

        // Save the rules
        uint256 ruleId1 = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        uint256 ruleId2 = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        uint256 ruleId3 = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        uint256 ruleId4 = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        uint256 ruleId5 = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](5));
        ruleIds[0][0] = ruleId1;
        ruleIds[0][1] = ruleId2;
        ruleIds[0][2] = ruleId3;
        ruleIds[0][3] = ruleId4;
        ruleIds[0][4] = ruleId5;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }
}
