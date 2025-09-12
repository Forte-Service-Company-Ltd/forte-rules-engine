/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "lib/diamond-std/core/DiamondCut/DiamondCutFacet.sol";

abstract contract components is RulesEngineCommon {
    /**
     *
     *
     * Validation tests for components of rules and policies within the rules engine
     * Validate CRUD operations for Trackers, Foreign Calls and Calling Functions
     *
     */

    // CRUD Functions: Compnents

    // CRUD: Calling Functions
    //Create Calling Functions
    function testRulesEngine_Unit_createCallingFunction_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        assertEq(callingFunctionId, bytes4(keccak256(bytes(callingFunction))));
        CallingFunctionStorageSet memory sig = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(sig.set, true);
        assertEq(uint8(sig.parameterTypes[0]), uint8(ParamTypes.ADDR));
        assertEq(uint8(sig.parameterTypes[1]), uint8(ParamTypes.UINT));
    }

    function testRulesEngine_Unit_createCallingFunction_DuplicatedSig() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        assertEq(callingFunctionId, bytes4(keccak256(bytes(callingFunction))));
        CallingFunctionStorageSet memory sig = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(sig.set, true);
        assertEq(uint8(sig.parameterTypes[0]), uint8(ParamTypes.ADDR));
        assertEq(uint8(sig.parameterTypes[1]), uint8(ParamTypes.UINT));
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        vm.expectRevert("Duplicates not allowed");
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
    }

    function testRulesEngine_Unit_CallingFunctionsArrayConsistency() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        // we add the first calling function
        bytes4 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        CallingFunctionStorageSet[] memory allCallingFunctions = RulesEngineComponentFacet(address(red)).getAllCallingFunctions(policyId);
        assertEq(bytes32(allCallingFunctions[0].signature), bytes32(callingFunctionId));
        assertEq(uint(allCallingFunctions[0].parameterTypes[0]), uint(ParamTypes.ADDR));
        assertEq(uint(allCallingFunctions[0].parameterTypes[1]), uint(ParamTypes.UINT));
        // we add the second calling function
        vm.startPrank(policyAdmin);
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.STR;
        bytes4 callingFunctionId2 = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(bytes4(keccak256(bytes(callingFunction2)))),
            pTypes,
            callingFunction,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction2))));
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        allCallingFunctions = RulesEngineComponentFacet(address(red)).getAllCallingFunctions(policyId);
        assertEq(bytes32(allCallingFunctions[0].signature), bytes32(callingFunctionId));
        assertEq(uint(allCallingFunctions[0].parameterTypes[0]), uint(ParamTypes.ADDR));
        assertEq(uint(allCallingFunctions[0].parameterTypes[1]), uint(ParamTypes.UINT));
        assertEq(bytes32(allCallingFunctions[1].signature), bytes32(callingFunctionId2));
        assertEq(uint(allCallingFunctions[1].parameterTypes[0]), uint(ParamTypes.ADDR));
        assertEq(uint(allCallingFunctions[1].parameterTypes[1]), uint(ParamTypes.STR));

        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        bytes4 callingFunctionId3 = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(bytes4(keccak256(bytes(callingFunction3)))),
            pTypes,
            callingFunction,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction3))));
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        allCallingFunctions = RulesEngineComponentFacet(address(red)).getAllCallingFunctions(policyId);
        assertEq(bytes32(allCallingFunctions[0].signature), bytes32(callingFunctionId));
        assertEq(uint(allCallingFunctions[0].parameterTypes[0]), uint(ParamTypes.ADDR));
        assertEq(uint(allCallingFunctions[0].parameterTypes[1]), uint(ParamTypes.UINT));
        assertEq(bytes32(allCallingFunctions[1].signature), bytes32(callingFunctionId2));
        assertEq(uint(allCallingFunctions[1].parameterTypes[0]), uint(ParamTypes.ADDR));
        assertEq(uint(allCallingFunctions[1].parameterTypes[1]), uint(ParamTypes.STR));
        assertEq(bytes32(allCallingFunctions[2].signature), bytes32(callingFunctionId3));
        assertEq(uint(allCallingFunctions[2].parameterTypes[0]), uint(ParamTypes.ADDR));
        assertEq(uint(allCallingFunctions[2].parameterTypes[1]), uint(ParamTypes.UINT));

        bytes4[] memory newSelectors = new bytes4[](2);
        newSelectors[0] = callingFunctionId3;
        newSelectors[1] = callingFunctionId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            newSelectors,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        allCallingFunctions = RulesEngineComponentFacet(address(red)).getAllCallingFunctions(policyId);
        assertEq(newSelectors.length, allCallingFunctions.length);
        assertEq(bytes32(allCallingFunctions[0].signature), bytes32(callingFunctionId3));
        assertEq(uint(allCallingFunctions[0].parameterTypes[0]), uint(ParamTypes.ADDR));
        assertEq(uint(allCallingFunctions[0].parameterTypes[1]), uint(ParamTypes.UINT));
        assertEq(bytes32(allCallingFunctions[1].signature), bytes32(callingFunctionId));
        assertEq(uint(allCallingFunctions[1].parameterTypes[0]), uint(ParamTypes.ADDR));
        assertEq(uint(allCallingFunctions[1].parameterTypes[1]), uint(ParamTypes.UINT));

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        allCallingFunctions = RulesEngineComponentFacet(address(red)).getAllCallingFunctions(policyId);
        assertEq(callingFunctions.length, allCallingFunctions.length);
        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId);
        allCallingFunctions = RulesEngineComponentFacet(address(red)).getAllCallingFunctions(policyId);
        assertEq(callingFunctions.length - 1, allCallingFunctions.length);
        // the order of the calling functions is rearranged when deleting one of them
        assertEq(bytes32(allCallingFunctions[0].signature), bytes32(callingFunctionId3));
        assertEq(uint(allCallingFunctions[0].parameterTypes[0]), uint(ParamTypes.ADDR));
        assertEq(uint(allCallingFunctions[0].parameterTypes[1]), uint(ParamTypes.UINT));
        assertEq(bytes32(allCallingFunctions[1].signature), bytes32(callingFunctionId2));
        assertEq(uint(allCallingFunctions[1].parameterTypes[0]), uint(ParamTypes.ADDR));
        assertEq(uint(allCallingFunctions[1].parameterTypes[1]), uint(ParamTypes.STR));
    }

    function testRulesEngine_Unit_updateCallingFunction_DoesNotExist() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        assertEq(callingFunctionId, bytes4(keccak256(bytes(callingFunction))));
        vm.startPrank(policyAdmin);
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        vm.expectRevert("calling function already exists");
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(bytes4(keccak256(bytes(callingFunction)))),
            pTypes,
            callingFunction,
            ""
        );
    }

    function testRulesEngine_Unit_createCallingFunction_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes,
            callingFunction,
            ""
        );
    }

    function testRulesEngine_Unit_createCallingFunction_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyID = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyID,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes,
            callingFunction,
            ""
        );
    }

    function testRulesEngine_Unit_createCallingFunction_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4 callingFunctionId = bytes4(bytes4(keccak256(bytes(callingFunction))));
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        vm.expectEmit(true, false, false, false);
        emit CallingFunctionCreated(policyId, callingFunctionId);
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(bytes4(keccak256(bytes(callingFunction)))),
            pTypes,
            callingFunction,
            ""
        );
    }

    // Update Calling Functions
    function testRulesEngine_Unit_updateCallingFunction_Negative_NewParameterTypesNotSameLength()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyId);
        ParamTypes[] memory pTypes2 = new ParamTypes[](1);
        pTypes2[0] = ParamTypes.ADDR;
        vm.expectRevert("New parameter types must be of greater or equal length to the original");
        RulesEngineComponentFacet(address(red)).updateCallingFunction(policyId, bytes4(keccak256(bytes(callingFunction))), pTypes2);
    }

    function testRulesEngine_Unit_updateCallingFunction_Negative_NewParameterTypesNotSameType()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyId);
        ParamTypes[] memory pTypes2 = new ParamTypes[](2);
        pTypes2[0] = ParamTypes.UINT;
        pTypes2[1] = ParamTypes.UINT;
        vm.expectRevert("New parameter types must be of the same type as the original");
        RulesEngineComponentFacet(address(red)).updateCallingFunction(policyId, bytes4(keccak256(bytes(callingFunction))), pTypes2);
    }

    function testRulesEngine_Unit_updateCallingFunction_Negative_CallingFunctionDoesNotExist()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyId);
        vm.expectRevert("Calling function not set");
        RulesEngineComponentFacet(address(red)).updateCallingFunction(policyId, bytes4(keccak256(bytes(callingFunction2))), pTypes);
    }

    function testRulesEngine_Unit_updateCallingFunction_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyId);
        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).updateCallingFunction(policyId, bytes4(keccak256(bytes(callingFunction2))), pTypes);
    }

    function testRulesEngine_Unit_updateCallingFunctionWithRuleCheck_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // create rule and set rule to user contract
        setUpRuleSimple();
        // test rule works for user contract
        bool response = userContract.transfer(address(0x7654321), 47);
        assertTrue(response);
        // create pTypes array for new contract + new transfer function
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        CallingFunctionStorageSet memory callingFunc = RulesEngineComponentFacet(address(red)).getCallingFunction(
            1,
            bytes4(keccak256(bytes(callingFunction)))
        );
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEngineComponentFacet(address(red)).updateCallingFunction(1, bytes4(keccak256(bytes(callingFunction))), pTypes);
        assertEq(callingFunc.set, true);
        // ensure orignal contract rule check works
        bool ruleCheck = userContract.transfer(address(0x7654321), 47);
        assertTrue(ruleCheck);
        // test new contract rule check works
        bool secondRuleCheck = userContract.transfer(address(0x7654321), 47);
        assertTrue(secondRuleCheck);
    }

    function testRulesEngine_Unit_updateCallingFunctionWithRuleCheck_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // create rule and set rule to user contract
        setUpRuleSimple();
        // test rule works for user contract

        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 3);
        // create pTypes array for new contract + new transfer function
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        CallingFunctionStorageSet memory callingFunc = RulesEngineComponentFacet(address(red)).getCallingFunction(
            1,
            bytes4(keccak256(bytes(callingFunction)))
        );
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEngineComponentFacet(address(red)).updateCallingFunction(1, bytes4(keccak256(bytes(callingFunction))), pTypes);
        assertEq(callingFunc.set, true);
        // ensure orignal contract rule check works
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 3);
        // test new contract rule check works
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 3);
    }

    function testRulesEngine_Unit_updateCallingFunction_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyId);
        ParamTypes[] memory pTypes2 = new ParamTypes[](4);
        pTypes2[0] = ParamTypes.ADDR;
        pTypes2[1] = ParamTypes.UINT;
        pTypes2[2] = ParamTypes.ADDR;
        pTypes2[3] = ParamTypes.UINT;
        bytes4 callingFunctionId = RulesEngineComponentFacet(address(red)).updateCallingFunction(
            policyId,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes2
        );
        CallingFunctionStorageSet memory sig = RulesEngineComponentFacet(address(red)).getCallingFunction(
            policyId,
            bytes4(keccak256(bytes(callingFunction)))
        );
        assertEq(sig.set, true);
        assertEq(callingFunctionId, bytes4(keccak256(bytes(callingFunction))));
        for (uint256 i = 0; i < pTypes2.length; i++) {
            assertEq(uint8(sig.parameterTypes[i]), uint8(pTypes2[i]));
        }
    }

    function testRulesEngine_Unit_updateCallingFunction_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        // create rule and set rule to user contract
        (uint256 policyID, uint256 ruleID) = setUpRuleSimple();
        ruleID;
        RulesEngineComponentFacet(address(red)).getCallingFunction(1, bytes4(keccak256(bytes(callingFunction))));
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).updateCallingFunction(1, bytes4(keccak256(bytes(callingFunction))), new ParamTypes[](3));
    }

    function testRulesEngine_Unit_updateCallingFunction_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        bytes4 callingFunctionId = bytes4(keccak256(bytes(callingFunction)));
        uint256 policyId = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyId);
        ParamTypes[] memory pTypes2 = new ParamTypes[](4);
        pTypes2[0] = ParamTypes.ADDR;
        pTypes2[1] = ParamTypes.UINT;
        pTypes2[2] = ParamTypes.ADDR;
        pTypes2[3] = ParamTypes.UINT;
        vm.expectEmit(true, false, false, false);
        emit CallingFunctionUpdated(policyId, callingFunctionId);
        RulesEngineComponentFacet(address(red)).updateCallingFunction(policyId, bytes4(keccak256(bytes(callingFunction))), pTypes2);
    }

    // Delete Calling Functions

    function testRulesEngine_Unit_deleteCallingFunction_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // Create a policy and add a calling function to it
        bytes4 callingFunctionId = bytes4(keccak256(bytes(callingFunction)));
        uint256 policyId = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyId);
        assertEq(callingFunctionId, bytes4(keccak256(bytes(callingFunction))));
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        // Attach a second calling function to the policyId
        bytes4 nextCallingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(bytes4(keccak256(bytes(callingFunction3)))),
            pTypes,
            callingFunction,
            ""
        );
        assertEq(nextCallingFunctionId, bytes4(bytes4(keccak256(bytes(callingFunction3)))));

        // Grab the first calling function
        CallingFunctionStorageSet memory matchingCallingFunction = RulesEngineComponentFacet(address(red)).getCallingFunction(
            policyId,
            callingFunctionId
        );

        // Grab the second calling function
        CallingFunctionStorageSet memory nextMatchingCallingFunction = RulesEngineComponentFacet(address(red)).getCallingFunction(
            policyId,
            nextCallingFunctionId
        );

        // Check that the calling function is intact
        assertEq(matchingCallingFunction.set, true);
        assertEq(matchingCallingFunction.parameterTypes.length, 2);

        // Check that the second calling function is intact
        assertEq(nextMatchingCallingFunction.set, true);
        assertEq(nextMatchingCallingFunction.parameterTypes.length, 2);

        // Delete the calling function
        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId);
        CallingFunctionStorageSet memory cf = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);

        // Check that the first calling function is deleted
        assertEq(cf.set, false);
        assertEq(cf.parameterTypes.length, 0);

        // Check that the next policy's calling function is still intact
        nextMatchingCallingFunction = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, nextCallingFunctionId);
        assertEq(nextMatchingCallingFunction.set, true);
        assertEq(nextMatchingCallingFunction.parameterTypes.length, 2);
    }

    function testRulesEngine_Unit_Calling_Function_Validate_Name_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        ParamTypes[] memory pTypes = new ParamTypes[](6);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.UINT;
        pTypes[4] = ParamTypes.UINT;
        pTypes[5] = ParamTypes.UINT;
        policyIds[0] = _createBlankPolicy();
        vm.expectRevert(abi.encodePacked(NAME_REQ));
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(keccak256(bytes("transfer()"))),
            pTypes,
            "", //name
            "address,uint256"
        );
    }

    function testRulesEngine_Unit_Calling_Function_Validate_Signature_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        ParamTypes[] memory pTypes = new ParamTypes[](1);
        pTypes[0] = ParamTypes.ADDR;
        policyIds[0] = _createBlankPolicy();
        vm.expectRevert(abi.encodePacked(SIG_REQ));
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(keccak256(bytes(""))), // function signature
            pTypes,
            "transfer(address,uint256)",
            "address,uint256"
        );
    }

    function testRulesEngine_Unit_deleteCallingFunctionMultiple_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory _callingFunctions;
        uint256[][] memory _ruleIds;
        // This test does not utilize helper _addCallingFunctionToPolicy(policyId) because it needs to individually set the function callingFunctions for deletion
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        bytes4 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes,
            callingFunction,
            ""
        );
        assertEq(callingFunctionId, bytes4(keccak256(bytes(callingFunction))));
        bytes4 callingFunctionId2 = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256(bytes(callingFunction2))),
            pTypes,
            callingFunction2,
            ""
        );
        assertEq(callingFunctionId2, bytes4(keccak256(bytes(callingFunction2))));
        RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);

        RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId2);

        _callingFunctions = new bytes4[](2);
        _callingFunctions[0] = bytes4(keccak256(bytes(callingFunction)));
        _callingFunctions[1] = bytes4(keccak256(bytes(callingFunction2)));
        _ruleIds = new uint256[][](2);
        _ruleIds[0] = new uint256[](0);
        _ruleIds[1] = new uint256[](0);

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            _callingFunctions,
            _ruleIds,
            PolicyType.OPEN_POLICY,
            "policyName",
            "policyDescription"
        );

        (_callingFunctions, _ruleIds) = RulesEnginePolicyFacet(address(red)).getPolicy(policyId);
        assertEq(_callingFunctions.length, 2);
        assertEq(_callingFunctions[0], bytes4(keccak256(bytes(callingFunction))));
        assertEq(_callingFunctions[1], bytes4(keccak256(bytes(callingFunction2))));

        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId);
        CallingFunctionStorageSet memory cf = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(cf.set, false);

        RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId2);

        //check that policy callingFunctions array is resized to 1
        (_callingFunctions, _ruleIds) = RulesEnginePolicyFacet(address(red)).getPolicy(policyId);
        assertEq(_callingFunctions.length, 1);
        assertEq(_callingFunctions[0], bytes4(keccak256(bytes(callingFunction2))));
    }

    function testRulesEngine_Unit_deleteCallingFunction_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        bytes4 callingFunctionId = bytes4(keccak256(bytes(callingFunction)));
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyId);

        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId);
    }

    function testRulesEngine_Unit_deleteCallingFunctionWithRuleCheck_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // create rule and set rule to user contract
        setupRuleWithoutForeignCall();
        // test rule works for user contract
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 3);
        // create pTypes array for new contract + new transfer function
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        RulesEngineComponentFacet(address(red)).getCallingFunction(1, 0);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEngineComponentFacet(address(red)).deleteCallingFunction(1, bytes4(keccak256(bytes(callingFunction))));
        // test that rule no longer checks
        bool ruleCheck = userContract.transfer(address(0x7654321), 3);
        assertTrue(ruleCheck);
    }

    function testRulesEngine_Unit_deleteCallingFunction_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        bytes4 callingFunctionId = bytes4(keccak256(bytes(callingFunction)));
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyId);
        assertEq(callingFunctionId, bytes4(keccak256(bytes(callingFunction))));
        RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);

        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId);
    }

    function testRulesEngine_Unit_deleteCallingFunction_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        bytes4 callingFunctionId = bytes4(keccak256(bytes(callingFunction)));
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyId);
        vm.expectEmit(true, false, false, false);
        emit CallingFunctionDeleted(policyId, callingFunctionId);
        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId);
    }

    // CRUD: Foreign Calls
    // Create Foreign Calls
    function testRulesEngine_Unit_CreateForeignCall_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
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

        ForeignCall memory fc;
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)", "simpleCheck(uint256 value)");
    }

    function testRulesEngine_Unit_CreateForeignCall_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );

        ForeignCall memory fc;
        // prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)", "simpleCheck(uint256 value)");
    }

    function testRulesEngine_unit_CreateForeignCall_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        uint256 foreignCallId = 1;
        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        vm.expectEmit(true, false, false, false);
        emit ForeignCallCreated(policyID, foreignCallId);
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyID, fc, "simpleCheck(uint256)", "simpleCheck(uint256 value)");
    }

    // Update Foreign Calls
    function testRulesEngine_unit_UpdateForeignCall_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        ForeignCall memory fc;
        fc = _setUpForeignCallSimple(policyID);

        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(
            policyID,
            fc,
            "simpleCheck(uint256)",
            "simpleCheck(uint256 value)"
        );
        fc.foreignCallAddress = address(userContractAddress);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineForeignCallFacet(address(red)).updateForeignCall(policyID, foreignCallId, fc);
    }

    function testRulesEngine_unit_UpdateForeignCall_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        ForeignCall memory fc;
        fc = _setUpForeignCallSimple(policyID);

        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(
            policyID,
            fc,
            "simpleCheck(uint256)",
            "simpleCheck(uint256 value)"
        );
        fc.foreignCallAddress = address(userContractAddress);

        //Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineForeignCallFacet(address(red)).updateForeignCall(policyID, foreignCallId, fc);
    }

    // Delete Foreign Calls
    function testRulesEngine_Unit_DeleteForeignCall_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        uint256 policyId = _setup_checkRule_ForeignCall_Positive(ruleValue, userContractAddress);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineForeignCallFacet(address(red)).deleteForeignCall(policyId, 0);
    }

    function testRulesEngine_Unit_DeleteForeignCall_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        uint256 policyId = _setup_checkRule_ForeignCall_Positive(ruleValue, userContractAddress);
        vm.stopPrank();

        // prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineForeignCallFacet(address(red)).deleteForeignCall(policyId, 0);
    }

    // Get Foreign Calls
    function testRulesEngine_Unit_GetAllForeignCallsTest() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        for (uint256 i = 0; i < 10; i++) {
            _setUpForeignCallSimpleReturnID(policyId);
        }

        ForeignCall[] memory foreignCalls = RulesEngineForeignCallFacet(address(red)).getAllForeignCalls(policyId);
        assertEq(foreignCalls.length, 10);
        RulesEngineForeignCallFacet(address(red)).deleteForeignCall(policyId, 3);

        foreignCalls = RulesEngineForeignCallFacet(address(red)).getAllForeignCalls(policyId);
        assertEq(foreignCalls.length, 10);

        for (uint256 i = 0; i < foreignCalls.length - 1; i++) {
            if (i >= 2) {
                assertEq(foreignCalls[i].foreignCallIndex, i + 2);
            } else {
                assertEq(foreignCalls[i].foreignCallIndex, i + 1);
            }
        }
    }

    function testRulesEngine_unit_CreateForeignCall_Negative_FRE_Address() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        ForeignCall memory fc;
        fc.foreignCallAddress = address(red);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        vm.expectRevert("Address not allowed to be a foreign call");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyID, fc, "simpleCheck(uint256)", "simpleCheck(uint256 value)");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_SetGeneratePolicyAdminRole_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](2);
        fcArgs[0] = ParamTypes.UINT;
        fcArgs[1] = ParamTypes.ADDR;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(red);
        fc.signature = bytes4(keccak256(bytes("generatePolicyAdminRole(uint256,address)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        vm.expectRevert("Address not allowed to be a foreign call");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(
            policyId,
            fc,
            "generatePolicyAdminRole(uint256,address)",
            "generatePolicyAdminRole(uint256,address value)"
        );
        vm.stopPrank();
    }

    // CRUD: Trackers
    // Create Trackers
    function testRulesEngine_unit_CreateTracker_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName", TrackerArrayTypes.VOID);
    }

    function testRulesEngine_unit_CreateTracker_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName", TrackerArrayTypes.VOID);
    }

    function testRulesEngine_unit_CreateTracker_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        uint256 trackerId = 1;
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;
        vm.expectEmit(true, false, false, false);
        emit TrackerCreated(policyID, trackerId);
        RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName", TrackerArrayTypes.VOID);
    }

    // Get Trackers
    function testRulesEngine_Unit_GetTrackerValue() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = setupRuleWithTracker(2);
        bool retVal = userContract.transfer(address(0x7654321), 3);
        assertTrue(retVal);
        Trackers memory testTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        assertTrue(abi.decode(testTracker.trackerValue, (uint256)) == 2);
        assertFalse(abi.decode(testTracker.trackerValue, (uint256)) == 3);
    }

    function testRulesEngine_Unit_GetAllTrackersTest() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();

        for (uint256 i = 0; i < 10; i++) {
            Trackers memory tracker;
            tracker.trackerValue = abi.encode(uint256(i));
            tracker.pType = ParamTypes.UINT;
            RulesEngineComponentFacet(address(red)).createTracker(policyId, tracker, "trName", TrackerArrayTypes.VOID);
        }

        Trackers[] memory trackers = RulesEngineComponentFacet(address(red)).getAllTrackers(policyId);
        assertEq(trackers.length, 10);
        RulesEngineComponentFacet(address(red)).deleteTracker(policyId, 3);

        trackers = RulesEngineComponentFacet(address(red)).getAllTrackers(policyId);
        assertEq(trackers.length, 10);
        for (uint256 i = 0; i < trackers.length - 1; i++) {
            if (i >= 2) {
                assertEq(trackers[i].trackerValue, abi.encode(uint256(i + 1)));
            } else {
                assertEq(trackers[i].trackerValue, abi.encode(uint256(i)));
            }
        }
    }

    // Update Trackers
    function testRulesEngine_unit_UpdateTracker_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName", TrackerArrayTypes.VOID);
        tracker.trackerValue = abi.encode(address(userContractAddress));
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).updateTracker(policyID, trackerId, tracker);
    }

    function testRulesEngine_unit_UpdateTracker_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName", TrackerArrayTypes.VOID);
        tracker.trackerValue = abi.encode(address(userContractAddress));

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).updateTracker(policyID, trackerId, tracker);
    }

    function testRulesEngine_unit_UpdateTracker_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName", TrackerArrayTypes.VOID);
        tracker.trackerValue = abi.encode(address(userContractAddress));
        vm.expectEmit(true, false, false, false);
        emit TrackerUpdated(policyID, trackerId);
        RulesEngineComponentFacet(address(red)).updateTracker(policyID, trackerId, tracker);
    }

    // Delete Trackers
    function testRulesEngine_unit_DeleteTracker_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName", TrackerArrayTypes.VOID);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).deleteTracker(policyID, trackerId);
    }

    function testRulesEngine_unit_DeleteTracker_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName", TrackerArrayTypes.VOID);

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).deleteTracker(policyID, trackerId);
    }

    function testRulesEngine_unit_DeleteTracker_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName", TrackerArrayTypes.VOID);

        vm.expectEmit(true, false, false, false);
        emit TrackerDeleted(policyID, trackerId);
        RulesEngineComponentFacet(address(red)).deleteTracker(policyID, trackerId);
    }

    function testRulesEngine_unit_RED_Non_Upgradable() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Get all current facet addresses to verify diamond state
        address[] memory facetAddresses = DiamondLoupeFacet(address(red)).facetAddresses();

        // Verify diamondCut function selector is NOT present in any facet
        bool diamondCutFound = false;
        bytes4 diamondCutSelector = DiamondCutFacet.diamondCut.selector;

        for (uint256 i = 0; i < facetAddresses.length; i++) {
            bytes4[] memory selectors = DiamondLoupeFacet(address(red)).facetFunctionSelectors(facetAddresses[i]);
            for (uint256 j = 0; j < selectors.length; j++) {
                if (selectors[j] == diamondCutSelector) {
                    diamondCutFound = true;
                    break;
                }
            }
            if (diamondCutFound) break;
        }

        //  Assert that diamondCut selector is not found
        assertFalse(diamondCutFound, "DiamondCut functionality should not be available");

        // Verify that calling diamondCut directly on the diamond reverts
        // Create dummy facet cut data for testing
        FacetCut[] memory cuts = new FacetCut[](1);
        cuts[0] = FacetCut({facetAddress: address(0x1337), action: FacetCutAction.Add, functionSelectors: new bytes4[](1)});
        cuts[0].functionSelectors[0] = bytes4(keccak256("dummyFunction()"));

        // Attempt to call diamondCut and expect it to fail
        vm.expectRevert("FunctionNotFound(0xc99346a4)");
        (bool success, ) = address(red).call(abi.encodeWithSelector(diamondCutSelector, cuts, address(0), ""));
        success; // This line is just to avoid compiler warning

        // Verify NativeFacet doesn't have diamondCut functionality
        // Check that NativeFacet only has DiamondLoupe and ERC173 functions
        address nativeFacetAddress = DiamondLoupeFacet(address(red)).facetAddress(DiamondLoupeFacet.facets.selector);

        bytes4[] memory nativeFacetSelectors = DiamondLoupeFacet(address(red)).facetFunctionSelectors(nativeFacetAddress);

        // Verify expected selectors are present (loupe + ownership)
        bool hasFacets = false;
        bool hasOwner = false;

        for (uint256 k = 0; k < nativeFacetSelectors.length; k++) {
            if (nativeFacetSelectors[k] == DiamondLoupeFacet.facets.selector) {
                hasFacets = true;
            }
            if (nativeFacetSelectors[k] == ERC173Facet.owner.selector) {
                hasOwner = true;
            }
            // Ensure no diamondCut selector
            assertFalse(nativeFacetSelectors[k] == diamondCutSelector, "NativeFacet should not have diamondCut functionality");
        }

        assertTrue(hasFacets, "NativeFacet should have diamond loupe functionality");
        assertTrue(hasOwner, "NativeFacet should have ownership functionality");

        vm.stopPrank();
    }

    function testRulesEngine_unit_RetreiveRuleMetadata_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        (uint256 policyId, uint256 ruleId) = setUpRuleSimple();
        RuleMetadata memory data = RulesEngineRuleFacet(address(red)).getRuleMetadata(policyId, ruleId);
        assertEq(data.ruleName, ruleName);
        assertEq(data.ruleDescription, ruleDescription);
    }

    function testRulesEngine_Unit_FC_PolicyAdmin_Interactions() public ifDeploymentTestsEnabled {
        // Tests that deleting a foreign call from one policy does not affect another policy's foreign calls
        // policy Admin 1 creates a policy with a foreign call
        uint256 policy1 = _createBlankPolicy();
        _setUpForeignCallSimpleReturnID(policy1);

        // Policy Admin 2 creates a policy with two foreign calls
        vm.stopPrank();
        vm.startPrank(address(0x12345678)); // Policy Admin 2
        uint256 policy2 = _createBlankPolicy();
        _setUpForeignCallSimpleReturnID(policy2);
        _setUpForeignCallSimpleReturnID(policy2);

        // Policy Admin 1 deletes FC
        vm.stopPrank();
        vm.startPrank(policyAdmin); // Policy Admin 1
        RulesEngineForeignCallFacet(address(red)).deleteForeignCall(policy1, 1);

        // ensure only that policy 1 is the only one deleted
        ForeignCall[] memory foreignCalls = RulesEngineForeignCallFacet(address(red)).getAllForeignCalls(policy2);
        assertEq(foreignCalls.length, 2);
    }
    function testRulesEngine_Unit_Function_Signature_Validation_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicyOpen();
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        vm.expectRevert(abi.encodePacked(SIG_REQ));
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)", "simpleCheck(uint256 value)");
    }

    function testRulesEngine_Unit_Function_Signature_Name_Validation_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicyOpen();
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        vm.expectRevert(abi.encodePacked(NAME_REQ));
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "", "simpleCheck(uint256 value)");
    }

    function testRulesEngine_Unit_ForeignCall_ValidateMappedTrackerKeyLengths_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](2);
        fcArgs[0] = ParamTypes.UINT;
        fcArgs[1] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
        fc.encodedIndices[1].index = 0;
        fc.encodedIndices[1].eType = EncodedIndexType.GLOBAL_VAR;
        fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](1);
        fc.mappedTrackerKeyIndices[0].index = 0;
        fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256,uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(
            policyId,
            fc,
            "simpleCheck(uint256,uint256)",
            "simpleCheck(uint256,uint256 value)"
        );
    }

    function testRulesEngine_Unit_ForeignCall_ValidateMappedTrackerKeyLengths_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](2);
        fcArgs[0] = ParamTypes.UINT;
        fcArgs[1] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
        fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](1);
        fc.mappedTrackerKeyIndices[0].index = 0;
        fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256,uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        vm.expectRevert("Mapped tracker key indices length mismatch.");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(
            policyId,
            fc,
            "simpleCheck(uint256,uint256)",
            "simpleCheck(uint256,uint256 value)"
        );
    }

    function testRulesEngine_Unit_ForeignCall_ValidateMappedTrackerKeyLengths_Negative_ExtraMappedTrackerKey()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // start test as address 0x55556666
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](2);
        fcArgs[0] = ParamTypes.UINT;
        fcArgs[1] = ParamTypes.UINT;
        ForeignCall memory fc;

        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
        fc.encodedIndices[1].index = 0;
        fc.encodedIndices[1].eType = EncodedIndexType.GLOBAL_VAR;
        fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](2);
        fc.mappedTrackerKeyIndices[0].index = 0;
        fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.mappedTrackerKeyIndices[1].index = 1;
        fc.mappedTrackerKeyIndices[1].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256,uint256)")));

        vm.expectRevert("Mapped tracker key indices length mismatch.");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(
            policyId,
            fc,
            "simpleCheck(uint256,uint256)",
            "simpleCheck(uint256,uint256 value)"
        );
    }

    function testRulesEngine_Unit_ForeignCall_ValidateMappedTrackerKeyLengths_Negative_DoubleNestedMappedTrackerKey()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // start test as address 0x55556666
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](2);
        fcArgs[0] = ParamTypes.UINT;
        fcArgs[1] = ParamTypes.UINT;
        ForeignCall memory fc;

        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
        fc.encodedIndices[1].index = 0;
        fc.encodedIndices[1].eType = EncodedIndexType.GLOBAL_VAR;
        fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](1);
        fc.mappedTrackerKeyIndices[0].index = 0;
        fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256,uint256)")));
        fc.returnType = ParamTypes.UINT;

        vm.expectRevert("Mapped tracker key cannot be double nested");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(
            policyId,
            fc,
            "simpleCheck(uint256,uint256)",
            "simpleCheck(uint256 value,uint256 value)"
        );
    }

    function testRulesEngine_Unit_Tracker_Name_Validation_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
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
        // Save the rule
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.BOOL;
        tracker.set = true;
        tracker.trackerValue = abi.encode(bool(false));
        vm.expectRevert(abi.encodePacked(NAME_REQ));
        RulesEngineComponentFacet(address(red)).createTracker(policyId, tracker, "", TrackerArrayTypes.VOID);
    }

    function testRulesEngine_Unit_TestTrackerArrayValue_Uint() public ifDeploymentTestsEnabled endWithStopPrank {
        // create policy and tracker array type

        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        uint256[] memory emptyArray = new uint256[](0);
        tracker.trackerValue = abi.encode(emptyArray);
        tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(
            policyID,
            tracker,
            "trName",
            TrackerArrayTypes.UINT_ARRAY
        );

        // ensure metadata is correct
        TrackerMetadataStruct memory metaData = RulesEngineComponentFacet(address(red)).getTrackerMetadata(policyID, trackerId);
        assertTrue(metaData.arrayType == TrackerArrayTypes.UINT_ARRAY);
    }

    function testRulesEngine_Unit_TestTrackerArrayValue_Bytes() public ifDeploymentTestsEnabled endWithStopPrank {
        // create policy and tracker array type

        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        bytes[] memory emptyArray = new bytes[](0);
        tracker.trackerValue = abi.encode(emptyArray);
        tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(
            policyID,
            tracker,
            "trName",
            TrackerArrayTypes.BYTES_ARRAY
        );

        // ensure metadata is correct
        TrackerMetadataStruct memory metaData = RulesEngineComponentFacet(address(red)).getTrackerMetadata(policyID, trackerId);
        assertTrue(metaData.arrayType == TrackerArrayTypes.BYTES_ARRAY);
    }

    function testRulesEngine_Unit_TestTrackerArrayValue_Address() public ifDeploymentTestsEnabled endWithStopPrank {
        // create policy and tracker array type

        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        address[] memory emptyArray = new address[](0);
        tracker.trackerValue = abi.encode(emptyArray);
        tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(
            policyID,
            tracker,
            "trName",
            TrackerArrayTypes.ADDR_ARRAY
        );

        // ensure metadata is correct
        TrackerMetadataStruct memory metaData = RulesEngineComponentFacet(address(red)).getTrackerMetadata(policyID, trackerId);
        assertTrue(metaData.arrayType == TrackerArrayTypes.ADDR_ARRAY);
    }

    function testRulesEngine_Unit_TestTrackerArrayValue_Strings() public ifDeploymentTestsEnabled endWithStopPrank {
        // create policy and tracker array type

        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        string[] memory emptyArray = new string[](0);
        tracker.trackerValue = abi.encode(emptyArray);
        tracker.pType = ParamTypes.DYNAMIC_TYPE_ARRAY;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName", TrackerArrayTypes.STR_ARRAY);

        // ensure metadata is correct
        TrackerMetadataStruct memory metaData = RulesEngineComponentFacet(address(red)).getTrackerMetadata(policyID, trackerId);
        assertTrue(metaData.arrayType == TrackerArrayTypes.STR_ARRAY);
    }

    function testRulesEngine_Unit_TestTrackerArrayValue_DynamicBytes() public ifDeploymentTestsEnabled endWithStopPrank {
        // create policy and tracker array type

        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        string[] memory initialArray = new string[](3);
        initialArray[0] = "helloWorldTest";
        initialArray[1] = "Test long string with spaces that is meant to simulate a realistic scenario.";
        initialArray[
            2
        ] = "test a second and even longer string to really make sure this is testing the dynamic bytes array functionality properly.";
        tracker.trackerValue = abi.encode(initialArray);
        tracker.pType = ParamTypes.DYNAMIC_TYPE_ARRAY;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(
            policyID,
            tracker,
            "trName",
            TrackerArrayTypes.BYTES_ARRAY
        );

        // ensure metadata is correct
        TrackerMetadataStruct memory metaData = RulesEngineComponentFacet(address(red)).getTrackerMetadata(policyID, trackerId);
        assertTrue(metaData.arrayType == TrackerArrayTypes.BYTES_ARRAY);
    }

    function testRulesEngine_Unit_TestTrackerArrayValue_Uint_InvalidType() public ifDeploymentTestsEnabled endWithStopPrank {
        // create policy and tracker array type

        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        uint256[] memory emptyArray = new uint256[](0);
        tracker.trackerValue = abi.encode(emptyArray);
        tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
        vm.expectRevert("Invalid type");
        RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName", TrackerArrayTypes.VOID);
    }

    // Mapped Tracker array value types
    function testRulesEngine_Unit_TestTrackerArrayValue_Uint_MappedTracker() public ifDeploymentTestsEnabled endWithStopPrank {
        // create policy and tracker array type

        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        // create tracker value arrays
        /// create tracker value arrays
        uint256[] memory trackerValues1 = new uint256[](2);
        trackerValues1[0] = 100;
        trackerValues1[1] = 200;

        /// create tracker value arrays
        uint256[] memory trackerValues2 = new uint256[](2);
        trackerValues2[0] = 300;
        trackerValues2[1] = 400;

        Trackers memory tracker;
        tracker.mapped = true;
        tracker.trackerKeyType = ParamTypes.UINT;
        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(trackerValues); // value 1
        trackerValues[1] = abi.encode(trackerValues2); // value

        /// create tracker name
        string memory trackerName = "tracker1";

        /// build the members of the struct:
        tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
        tracker.trackerValue = abi.encode(trackerValues);
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createMappedTracker(
            policyID,
            tracker,
            trackerName,
            trackerKeys,
            trackerValues,
            TrackerArrayTypes.UINT_ARRAY
        );

        // ensure metadata is correct
        TrackerMetadataStruct memory metaData = RulesEngineComponentFacet(address(red)).getTrackerMetadata(policyID, trackerId);
        assertTrue(metaData.arrayType == TrackerArrayTypes.UINT_ARRAY);
    }

    function testRulesEngine_Unit_TestTrackerArrayValue_Bytes_MappedTracker() public ifDeploymentTestsEnabled endWithStopPrank {
        // create policy and tracker array type

        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        // create tracker value arrays
        /// create tracker value arrays
        bytes[] memory trackerValues1 = new bytes[](2);
        trackerValues1[0] = abi.encode(bytes("hello"));
        trackerValues1[1] = abi.encode(bytes("world"));

        /// create tracker value arrays
        bytes[] memory trackerValues2 = new bytes[](2);
        trackerValues2[0] = abi.encode(bytes("foo"));
        trackerValues2[1] = abi.encode(bytes("bar"));
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.trackerKeyType = ParamTypes.UINT;
        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(trackerValues); // value 1
        trackerValues[1] = abi.encode(trackerValues2); // value

        /// create tracker name
        string memory trackerName = "tracker1";

        /// build the members of the struct:
        tracker.pType = ParamTypes.DYNAMIC_TYPE_ARRAY;
        tracker.trackerValue = abi.encode(trackerValues);
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createMappedTracker(
            policyID,
            tracker,
            trackerName,
            trackerKeys,
            trackerValues,
            TrackerArrayTypes.BYTES_ARRAY
        );

        // ensure metadata is correct
        TrackerMetadataStruct memory metaData = RulesEngineComponentFacet(address(red)).getTrackerMetadata(policyID, trackerId);
        assertTrue(metaData.arrayType == TrackerArrayTypes.BYTES_ARRAY);
    }

    function testRulesEngine_Unit_TestTrackerArrayValue_Address_MappedTracker() public ifDeploymentTestsEnabled endWithStopPrank {
        // create policy and tracker array type

        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        // create tracker value arrays
        /// create tracker value arrays
        address[] memory trackerValues1 = new address[](2);
        trackerValues1[0] = address(0x001);
        trackerValues1[1] = address(0x002);

        /// create tracker value arrays
        address[] memory trackerValues2 = new address[](2);
        trackerValues2[0] = address(0x003);
        trackerValues2[1] = address(0x004);
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.trackerKeyType = ParamTypes.UINT;
        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(trackerValues); // value 1
        trackerValues[1] = abi.encode(trackerValues2); // value

        /// create tracker name
        string memory trackerName = "tracker1";

        /// build the members of the struct:
        tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
        tracker.trackerValue = abi.encode(trackerValues);
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createMappedTracker(
            policyID,
            tracker,
            trackerName,
            trackerKeys,
            trackerValues,
            TrackerArrayTypes.ADDR_ARRAY
        );

        // ensure metadata is correct
        TrackerMetadataStruct memory metaData = RulesEngineComponentFacet(address(red)).getTrackerMetadata(policyID, trackerId);
        assertTrue(metaData.arrayType == TrackerArrayTypes.ADDR_ARRAY);
    }

    function testRulesEngine_Unit_TestTrackerArrayValue_Address_MappedTracker_InvalidType()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create policy and tracker array type

        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        // create tracker value arrays
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.ADDR; // set the ParamType for the tracker value to be decoded as
        tracker.trackerKeyType = ParamTypes.ADDR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x7654321)); // value 1 - allowed recipient
        trackerValues[1] = abi.encode(address(0x7654321)); // value 2 - allowed recipient

        /// create tracker name
        string memory trackerName = "tracker1";

        /// build the members of the struct:
        tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
        tracker.trackerValue = abi.encode(trackerValues);
        vm.expectRevert("Invalid type");
        RulesEngineComponentFacet(address(red)).createMappedTracker(
            policyID,
            tracker,
            trackerName,
            trackerKeys,
            trackerValues,
            TrackerArrayTypes.VOID
        );
    }

    function testRulesEngine_Unit_ValidateDiamondMineDeploymentBytecode() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // deploy standalone facets for comparison
        RulesEngineProcessorFacet standaloneProcessor = new RulesEngineProcessorFacet();
        RulesEnginePolicyFacet standalonePolicy = new RulesEnginePolicyFacet();
        RulesEngineComponentFacet standaloneComponent = new RulesEngineComponentFacet();
        RulesEngineForeignCallFacet standaloneForeignCall = new RulesEngineForeignCallFacet();
        RulesEngineAdminRolesFacet standaloneAdminRoles = new RulesEngineAdminRolesFacet();
        RulesEngineInitialFacet standaloneInitial = new RulesEngineInitialFacet();
        RulesEngineRuleFacet standaloneRule = new RulesEngineRuleFacet();
        NativeFacet standaloneNative = new NativeFacet();

        address[] memory standaloneFacets = new address[](8);
        standaloneFacets[0] = address(standaloneProcessor);
        standaloneFacets[1] = address(standalonePolicy);
        standaloneFacets[2] = address(standaloneComponent);
        standaloneFacets[3] = address(standaloneForeignCall);
        standaloneFacets[4] = address(standaloneAdminRoles);
        standaloneFacets[5] = address(standaloneInitial);
        standaloneFacets[6] = address(standaloneRule);
        standaloneFacets[7] = address(standaloneNative);

        string[] memory facetNames = new string[](8);
        facetNames[0] = "RulesEngineProcessorFacet";
        facetNames[1] = "RulesEnginePolicyFacet";
        facetNames[2] = "RulesEngineComponentFacet";
        facetNames[3] = "RulesEngineForeignCallFacet";
        facetNames[4] = "RulesEngineAdminRolesFacet";
        facetNames[5] = "RulesEngineInitialFacet";
        facetNames[6] = "RulesEngineRuleFacet";
        facetNames[7] = "NativeFacet";

        // get all deployed facet addresses from the diamond
        address[] memory deployedFacetAddresses = DiamondLoupeFacet(address(red)).facetAddresses();

        // for each standalone facet find its corresponding deployed facet and compare bytecode
        for (uint256 i = 0; i < standaloneFacets.length; i++) {
            address standaloneFacetAddress = standaloneFacets[i];
            string memory facetName = facetNames[i];

            // verify standalone facet has bytecode
            uint256 standaloneCodeSize;
            assembly {
                standaloneCodeSize := extcodesize(standaloneFacetAddress)
            }
            assertTrue(standaloneCodeSize > 0, string(abi.encodePacked("Standalone facet has no bytecode: ", facetName)));

            // find the corresponding deployed facet address by checking if any deployed address has matching bytecode
            bool matchingFacetFound = false;

            for (uint256 j = 0; j < deployedFacetAddresses.length; j++) {
                address deployedFacetAddress = deployedFacetAddresses[j];

                // get bytecode for both facets
                bytes memory standaloneCode;
                bytes memory deployedCode;

                assembly {
                    // get standalone facet bytecode
                    let standaloneSize := extcodesize(standaloneFacetAddress)
                    standaloneCode := mload(0x40)
                    mstore(0x40, add(standaloneCode, and(add(add(standaloneSize, 0x20), 0x1f), not(0x1f))))
                    mstore(standaloneCode, standaloneSize)
                    extcodecopy(standaloneFacetAddress, add(standaloneCode, 0x20), 0, standaloneSize)

                    // get deployed facet bytecode
                    let deployedSize := extcodesize(deployedFacetAddress)
                    deployedCode := mload(0x40)
                    mstore(0x40, add(deployedCode, and(add(add(deployedSize, 0x20), 0x1f), not(0x1f))))
                    mstore(deployedCode, deployedSize)
                    extcodecopy(deployedFacetAddress, add(deployedCode, 0x20), 0, deployedSize)
                }

                // compare bytecode
                if (keccak256(standaloneCode) == keccak256(deployedCode)) {
                    matchingFacetFound = true;
                    break;
                }
            }

            assertTrue(matchingFacetFound, string(abi.encodePacked("No matching deployed facet found for standalone: ", facetName)));
        }

        // validate that all expected facets are deployed
        assertEq(deployedFacetAddresses.length, 8, "Unexpected number of deployed facets");
    }
}
