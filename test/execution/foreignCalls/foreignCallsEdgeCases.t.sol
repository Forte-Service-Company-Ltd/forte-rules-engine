/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/execution/rulesEngineInternalFunctions/rulesEngineInternalFunctions.t.sol";

/**
 * Edge case tests for foreign calls within the rules engine
 * These tests hit the boundaries of what the EVM can handle
 * to ensure the rules engine doesn't impose artificial limits
 */
abstract contract foreignCallsEdgeCases is rulesEngineInternalFunctions {
    uint256 gasLeftBefore;
    uint256 gasLeftAfter;
    uint256 gasDelta;
    uint256 constant GAS_LIMIT = 75_000_000; // Well above Eth mainnet max gas limit per block

    /**
     * Test extremely large array - 5,000 elements
     * This should definitely hit gas limits and demonstrate EVM boundaries
     */
    function testRulesEngine_Unit_ForeignCall_ExtremelyLargeUintArray() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithArray(uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        // Create array with 5,000 elements
        uint256[] memory extremeArray = new uint256[](5000);
        for (uint256 i = 0; i < 5000; i++) {
            extremeArray[i] = i + 1;
        }

        bytes memory vals = abi.encode(extremeArray);
        bytes[] memory retVals = new bytes[](0);

        gasLeftBefore = gasleft();

        // check gas before and after this call, determine what the gas used in this tx is,
        // compare to a block limit to see if this is above gas limit per block on mainnet
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        gasLeftAfter = gasleft();
        gasDelta = gasLeftBefore - gasLeftAfter;

        uint256[] memory storedArray = foreignCall.getInternalArrayUint();
        assertEq(storedArray[0], 1);
        assertEq(storedArray[4999], 5000);
        assertEq(storedArray.length, 5000);
        assertTrue(gasDelta > GAS_LIMIT);
    }

    /**
     * Test large string array
     */
    function testRulesEngine_Unit_ForeignCall_LargeStringArray_1000_Elements() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithArray(string[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.DYNAMIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        // Create string array with 500 elements
        string[] memory largeStringArray = new string[](500);
        for (uint256 i = 0; i < 500; i++) {
            largeStringArray[i] = string(abi.encodePacked("Element_", vm.toString(i)));
        }

        bytes memory vals = abi.encode(largeStringArray);
        bytes[] memory retVals = new bytes[](0);

        gasLeftBefore = gasleft();

        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        gasLeftAfter = gasleft();
        gasDelta = gasLeftBefore - gasLeftAfter;

        string[] memory storedArray = foreignCall.getInternalArrayStr();
        assertEq(storedArray[0], "Element_0");
        assertEq(storedArray[499], "Element_499");
        assertEq(storedArray.length, 500);
        assertTrue(gasDelta > GAS_LIMIT);
    }

    /**
     * Test multiple arrays
     */
    function testRulesEngine_Unit_ForeignCall_MultipleArrayParameters() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithArray(uint256[],uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](2);
        fc.parameterTypes[0] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.parameterTypes[1] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;

        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](2);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[1].index = 1;
        typeSpecificIndices[1].eType = EncodedIndexType.ENCODED_VALUES;

        // Create two large arrays
        uint256[] memory array1 = new uint256[](5000);
        uint256[] memory array2 = new uint256[](5000);

        for (uint256 i = 0; i < 5000; i++) {
            array1[i] = i;
            array2[i] = i + 5000;
        }

        bytes memory vals = abi.encode(array1, array2);
        bytes[] memory retVals = new bytes[](0);

        gasLeftBefore = gasleft();

        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        gasLeftAfter = gasleft();
        gasDelta = gasLeftBefore - gasLeftAfter;

        uint256[] memory storedArray = foreignCall.getInternalArrayUint();
        assertEq(storedArray.length, 10000); // 5000 + 5000
        assertEq(storedArray[0], 0);
        assertEq(storedArray[5000], 5000); // First element of second array
        assertTrue(gasDelta > GAS_LIMIT);
    }

    /**
     * Test empty array edge case
     */
    function testRulesEngine_Unit_ForeignCall_EmptyArray() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithEmptyArray(uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        // Create empty array
        uint256[] memory emptyArray = new uint256[](0);
        bytes memory vals = abi.encode(emptyArray);
        bytes[] memory retVals = new bytes[](0);

        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);

        uint256[] memory storedArray = foreignCall.getInternalArrayUint();
        assertEq(storedArray.length, 0);
    }

    /**
     * Test maximum uint256 values in array to test value bounds
     */
    function testRulesEngine_Unit_ForeignCall_MaxUintValues() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithArray(uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        // Create array with maximum uint256 values
        uint256[] memory maxValueArray = new uint256[](5000);
        for (uint256 i = 0; i < 5000; i++) {
            maxValueArray[i] = type(uint256).max;
        }

        bytes memory vals = abi.encode(maxValueArray);
        bytes[] memory retVals = new bytes[](0);

        gasLeftBefore = gasleft();

        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        gasLeftAfter = gasleft();
        gasDelta = gasLeftBefore - gasLeftAfter;

        uint256[] memory storedArray = foreignCall.getInternalArrayUint();
        assertEq(storedArray[0], type(uint256).max);
        assertEq(storedArray[4999], type(uint256).max);
        assertEq(storedArray.length, 5000);
        assertTrue(gasDelta > GAS_LIMIT);
    }

    /**
     * Test calling a foreign call function that doesn't exist through rule evaluation
     * This reverts the entire transaction when triggered through a calling function showing proper error handling for non-existent functions
     */
    function testRulesEngine_Unit_ForeignCall_NonExistentFunction() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory nonExistentFunctionSig = "dummyFunction(uint256)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        // Direct evaluation test - EvmError: Revert silently
        {
            ForeignCall memory fc;
            fc.foreignCallAddress = address(foreignCall);
            fc.signature = bytes4(keccak256(bytes(nonExistentFunctionSig)));
            fc.parameterTypes = new ParamTypes[](1);
            fc.parameterTypes[0] = ParamTypes.UINT;
            fc.returnType = ParamTypes.BOOL;
            fc.encodedIndices = new ForeignCallEncodedIndex[](1);
            fc.encodedIndices[0].index = 0;
            fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

            ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
            typeSpecificIndices[0].index = 0;
            typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

            uint256 testValue = 1337;
            bytes memory vals = abi.encode(testValue);
            bytes[] memory retVals = new bytes[](0);

            // This does NOT revert - it will execute but the foreign call will fail gracefully
            RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        }

        // Calling function invocation evaluation test - reverts with EvmError: Revert
        {
            vm.startPrank(policyAdmin);
            uint256 policyId = _createBlankPolicy();
            _setupEffectProcessor();

            ForeignCall memory fc;
            fc.foreignCallAddress = address(foreignCall);
            fc.signature = bytes4(keccak256(bytes(nonExistentFunctionSig)));
            fc.parameterTypes = new ParamTypes[](1);
            fc.parameterTypes[0] = ParamTypes.UINT;
            fc.returnType = ParamTypes.BOOL;
            fc.encodedIndices = new ForeignCallEncodedIndex[](1);
            fc.encodedIndices[0].index = 1; // Use the amount parameter from transfer function
            fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

            uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, nonExistentFunctionSig);

            Rule memory rule;
            rule.instructionSet = new uint256[](2);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 0;
            rule.placeHolders = new Placeholder[](1);
            rule.placeHolders[0].pType = ParamTypes.BOOL;
            rule.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
            rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects = new Effect[](1);
            rule.posEffects[0] = effectId_event;

            uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

            ParamTypes[] memory pTypes = new ParamTypes[](2);
            pTypes[0] = ParamTypes.ADDR;
            pTypes[1] = ParamTypes.UINT;

            uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                policyId,
                bytes4(keccak256(bytes(callingFunction))),
                pTypes,
                callingFunction,
                ""
            );

            bytes4[] memory selectors = new bytes4[](1);
            selectors[0] = bytes4(keccak256(bytes(callingFunction)));
            uint256[] memory functionIds = new uint256[](1);
            functionIds[0] = callingFunctionId;
            uint256[][] memory ruleIdsArray = new uint256[][](1);
            ruleIdsArray[0] = new uint256[](1);
            ruleIdsArray[0][0] = ruleId;

            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                selectors,
                functionIds,
                ruleIdsArray,
                PolicyType.CLOSED_POLICY,
                policyName,
                policyDescription
            );

            vm.stopPrank();
            vm.startPrank(callingContractAdmin);

            uint256[] memory policyIds = new uint256[](1);
            policyIds[0] = policyId;
            RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

            vm.stopPrank();
            vm.startPrank(address(userContract));

            // This reverts because the foreign call function doesn't exist - EvmError: Revert
            vm.expectRevert();
            userContract.transfer(address(0x1234), 100);

            vm.stopPrank();
        }
    }

    /**
     * Test foreign call that deploys a contract which self-destructs in its constructor
     */
    function testRulesEngine_Unit_ForeignCall_SelfDestructedContract() public ifDeploymentTestsEnabled endWithStopPrank {
        SelfDestructFactory factory = new SelfDestructFactory();
        address deployedAddress;

        //Direct evaluation test
        {
            string memory functionSig = "deployAndDestruct(uint256)";

            ForeignCall memory fc;
            fc.foreignCallAddress = address(factory);
            fc.signature = bytes4(keccak256(bytes(functionSig)));
            fc.parameterTypes = new ParamTypes[](1);
            fc.parameterTypes[0] = ParamTypes.UINT;
            fc.returnType = ParamTypes.ADDR;
            fc.encodedIndices = new ForeignCallEncodedIndex[](1);
            fc.encodedIndices[0].index = 0;
            fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

            ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
            typeSpecificIndices[0].index = 0;
            typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

            uint256 testValue = 123;
            bytes memory vals = abi.encode(testValue);
            bytes[] memory retVals = new bytes[](0);

            console2.log("Testing deployment of self-destructing contract with value:", testValue);

            // Direct evaluation test
            ForeignCallReturnValue memory result = RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(
                fc,
                vals,
                retVals,
                typeSpecificIndices,
                1
            );

            // Extract the deployed contract address from the result
            deployedAddress = abi.decode(result.value, (address));
            console2.log("Deployed contract address:", deployedAddress);

            // Check if the contract has any code (should be 0 since it self-destructed)
            uint256 codeSize;
            assembly {
                codeSize := extcodesize(deployedAddress)
            }

            // After EIP-6780/Cancun, only contracts that self-destruct in the same transaction
            // as their creation will have code size 0. Our contract self-destructs in constructor.
            assertEq(codeSize, 0, "Contract should have no code after self-destruct in constructor");

            // Verify factory recorded the deployment
            (address lastAddr, uint256 lastResult) = factory.getLastDeployment();
            assertEq(lastAddr, deployedAddress, "Factory should record deployed address");
            assertEq(lastResult, testValue * 2 + 100, "Factory should record calculated result");
        }

        // Calling function evaluation setup
        uint256 policyId;
        uint256 foreignCallId;
        {
            vm.startPrank(policyAdmin);

            policyId = _createBlankPolicy();
            _setupEffectProcessor();

            string memory functionSig = "deployAndDestruct(uint256)";
            ForeignCall memory fc;
            fc.foreignCallAddress = address(factory);
            fc.signature = bytes4(keccak256(bytes(functionSig)));
            fc.parameterTypes = new ParamTypes[](1);
            fc.parameterTypes[0] = ParamTypes.UINT;
            fc.returnType = ParamTypes.ADDR;
            fc.encodedIndices = new ForeignCallEncodedIndex[](1);
            fc.encodedIndices[0].index = 1;
            fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

            foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, functionSig);
        }

        uint256 ruleId;
        {
            Rule memory rule;
            rule.instructionSet = new uint256[](2);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 0;

            rule.placeHolders = new Placeholder[](1);
            rule.placeHolders[0].pType = ParamTypes.ADDR;
            rule.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
            rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects = new Effect[](1);
            rule.posEffects[0] = effectId_event;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);
        }
        {
            ParamTypes[] memory pTypes = new ParamTypes[](2);
            pTypes[0] = ParamTypes.ADDR;
            pTypes[1] = ParamTypes.UINT;

            uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                policyId,
                bytes4(keccak256(bytes(callingFunction))),
                pTypes,
                callingFunction,
                ""
            );

            bytes4[] memory selectors = new bytes4[](1);
            selectors[0] = bytes4(keccak256(bytes(callingFunction)));
            uint256[] memory functionIds = new uint256[](1);
            functionIds[0] = callingFunctionId;
            uint256[][] memory ruleIdsArray = new uint256[][](1);
            ruleIdsArray[0] = new uint256[](1);
            ruleIdsArray[0][0] = ruleId;

            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                selectors,
                functionIds,
                ruleIdsArray,
                PolicyType.CLOSED_POLICY,
                policyName,
                policyDescription
            );

            vm.stopPrank();
            vm.startPrank(callingContractAdmin);

            uint256[] memory policyIds = new uint256[](1);
            policyIds[0] = policyId;
            RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

            vm.stopPrank();
        }

        // Calling function execution test
        {
            vm.startPrank(address(userContract));

            // This should successfully deploy and self-destruct contract through rule evaluation
            uint256 transferAmount = 456;

            bool success = userContract.transfer(address(0x1234), transferAmount);
            assertTrue(success, "Transfer should succeed");

            // Verify another contract was deployed and self-destructed
            (, uint256 ruleResult) = factory.getLastDeployment();
            assertEq(ruleResult, transferAmount * 2 + 100, "Rule should use transfer amount");
        }
    }

    /**
     * Test foreign call that attempts recursive calls to showcase
     * how the rules engine cannot handle recursion directly
     * This hits gas limits and demonstrate EVM boundaries
     */
    function testRulesEngine_Unit_ForeignCall_RecursiveCall() public ifDeploymentTestsEnabled endWithStopPrank {
        RecursiveCallContract recursiveContract = new RecursiveCallContract();
        recursiveContract.setRulesEngineAddress(address(red));

        // Direct evaluation test
        {
            string memory functionSig = "aggressiveRecursiveCall(uint256)";
            ForeignCall memory fc;
            fc.foreignCallAddress = address(recursiveContract);
            fc.signature = bytes4(keccak256(bytes(functionSig)));
            fc.parameterTypes = new ParamTypes[](1);
            fc.parameterTypes[0] = ParamTypes.UINT;
            fc.returnType = ParamTypes.UINT;
            fc.encodedIndices = new ForeignCallEncodedIndex[](1);
            fc.encodedIndices[0].index = 0;
            fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

            ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
            typeSpecificIndices[0].index = 0;
            typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

            uint256 testValue = 1;
            bytes memory vals = abi.encode(testValue);
            bytes[] memory retVals = new bytes[](0);

            gasLeftBefore = gasleft();
            RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
            gasLeftAfter = gasleft();
            gasDelta = gasLeftBefore - gasLeftAfter;

            console2.log("Gas used in direct recursive foreign call evaluation:", gasDelta);

            assertTrue(gasDelta > GAS_LIMIT);

            recursiveContract.resetDepth();
        }

        // Calling function evaluation test
        {
            vm.startPrank(policyAdmin);

            uint256 policyId = _createBlankPolicy();
            _setupEffectProcessor();

            string memory functionSig = "aggressiveRecursiveCall(uint256)";
            ForeignCall memory fc;
            fc.foreignCallAddress = address(recursiveContract);
            fc.signature = bytes4(keccak256(bytes(functionSig)));
            fc.parameterTypes = new ParamTypes[](1);
            fc.parameterTypes[0] = ParamTypes.UINT;
            fc.returnType = ParamTypes.UINT;
            fc.encodedIndices = new ForeignCallEncodedIndex[](1);
            fc.encodedIndices[0].index = 1;
            fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

            uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, functionSig);

            Rule memory rule;
            rule.instructionSet = new uint256[](2);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 0;
            rule.placeHolders = new Placeholder[](1);
            rule.placeHolders[0].pType = ParamTypes.UINT;
            rule.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
            rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects = new Effect[](1);
            rule.posEffects[0] = effectId_event;

            uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

            ParamTypes[] memory pTypes = new ParamTypes[](2);
            pTypes[0] = ParamTypes.ADDR;
            pTypes[1] = ParamTypes.UINT;

            uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                policyId,
                bytes4(keccak256(bytes(callingFunction))),
                pTypes,
                callingFunction,
                ""
            );

            bytes4[] memory selectors = new bytes4[](1);
            selectors[0] = bytes4(keccak256(bytes(callingFunction)));
            uint256[] memory functionIds = new uint256[](1);
            functionIds[0] = callingFunctionId;
            uint256[][] memory ruleIdsArray = new uint256[][](1);
            ruleIdsArray[0] = new uint256[](1);
            ruleIdsArray[0][0] = ruleId;

            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                selectors,
                functionIds,
                ruleIdsArray,
                PolicyType.CLOSED_POLICY,
                policyName,
                policyDescription
            );

            vm.stopPrank();
            vm.startPrank(callingContractAdmin);

            uint256[] memory policyIds = new uint256[](1);
            policyIds[0] = policyId;
            RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

            vm.stopPrank();
            vm.startPrank(address(userContract));

            gasLeftBefore = gasleft();

            userContract.transfer(address(0x1234), 1);
            gasLeftAfter = gasleft();
            gasDelta = gasLeftBefore - gasLeftAfter;
            assertTrue(gasDelta > GAS_LIMIT);
        }
    }

    /**
     * Test calling a function that returns nothing when expecting return data
     */
    function testRulesEngine_Unit_ForeignCall_NoReturnData() public ifDeploymentTestsEnabled endWithStopPrank {
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes("testSig(uint256)"))); // This returns bool
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.returnType = ParamTypes.VOID; // Expecting no return data
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        uint256 testValue = 99;
        bytes memory vals = abi.encode(testValue);
        bytes[] memory retVals = new bytes[](0);

        // Direct evaluation test
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);

        // Verify the function actually executed
        assertEq(foreignCall.getDecodedIntOne(), 99);

        // Now test through rule evaluation
        vm.startPrank(policyAdmin);

        uint256 policyId = _createBlankPolicy();
        _setupEffectProcessor();

        // Modify foreign call to use transfer amount parameter
        fc.encodedIndices[0].index = 1;
        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "testSig(uint256)");

        Rule memory rule;
        rule.instructionSet = new uint256[](2);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.VOID;
        rule.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes,
            callingFunction,
            ""
        );

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256(bytes(callingFunction)));
        uint256[] memory functionIds = new uint256[](1);
        functionIds[0] = callingFunctionId;
        uint256[][] memory ruleIdsArray = new uint256[][](1);
        ruleIdsArray[0] = new uint256[](1);
        ruleIdsArray[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            selectors,
            functionIds,
            ruleIdsArray,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        vm.stopPrank();
        vm.startPrank(address(userContract));

        // Expect revert because rule placeholder expects void but function returns data
        vm.expectRevert("Rules Engine Revert");
        userContract.transfer(address(0x1234), 99);
    }

    /**
     * Test function that returns data not matching expected type
     */
    function testRulesEngine_Unit_ForeignCall_MalformedReturnData() public ifDeploymentTestsEnabled endWithStopPrank {
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        string memory functionSig = "testSig(string)"; // Returns bool

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.STR;
        fc.returnType = ParamTypes.UINT; // Expecting uint256 but function returns bool
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        string memory testString = "malformed_test";
        bytes memory vals = abi.encode(testString);
        bytes[] memory retVals = new bytes[](0);

        // Direct evaluation test - handles type mismatch gracefully with silent revert
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);

        // Now test through rule evaluation
        vm.startPrank(policyAdmin);

        uint256 policyId = _createBlankPolicy();
        _setupEffectProcessor();

        // Create a rule that doesn't rely on transfer parameters since we need string input
        Rule memory rule;
        rule.instructionSet = new uint256[](2);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT; // Expecting uint but will get bool
        rule.placeHolders[0].typeSpecificIndex = uint128(
            RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, functionSig)
        );
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        // Add raw data for the string parameter since transfer doesn't have string params
        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.STR;
        rule.rawData.dataValues[0] = abi.encode(testString);
        rule.rawData.instructionSetIndex[0] = 0; // Use in first placeholder

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes,
            callingFunction,
            ""
        );

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256(bytes(callingFunction)));
        uint256[] memory functionIds = new uint256[](1);
        functionIds[0] = callingFunctionId;
        uint256[][] memory ruleIdsArray = new uint256[][](1);
        ruleIdsArray[0] = new uint256[](1);
        ruleIdsArray[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            selectors,
            functionIds,
            ruleIdsArray,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        vm.stopPrank();
        vm.startPrank(address(userContract));

        vm.expectRevert("Invalid dynamic data offset");
        userContract.transfer(address(0x1234), 100);
    }

    /**
     * Test foreign calls when already at significant call stack depth
     */
    function testRulesEngine_Unit_ForeignCall_DeepCallStack() public ifDeploymentTestsEnabled endWithStopPrank {
        // Create a contract that makes deep recursive calls before calling our foreign call
        DeepCallStackContract deepContract = new DeepCallStackContract();

        string memory functionSig = "deepRecursiveCall(uint256)";

        ForeignCall memory fc;
        fc.foreignCallAddress = address(deepContract);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.returnType = ParamTypes.UINT;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        // Use a depth that approaches but doesn't exceed EVM limits
        uint256 depth = 500; // Should be safe but deep
        bytes memory vals = abi.encode(depth);
        bytes[] memory retVals = new bytes[](0);

        // Direct evaluation test - handles deep call stacks appropriately
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);

        // Now test through rule evaluation
        vm.startPrank(policyAdmin);

        uint256 policyId = _createBlankPolicy();
        _setupEffectProcessor();

        // Modify foreign call to use transfer amount parameter
        fc.encodedIndices[0].index = 1; // Use amount parameter from transfer
        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, functionSig);

        Rule memory rule;
        rule.instructionSet = new uint256[](2);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes,
            callingFunction,
            ""
        );

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256(bytes(callingFunction)));
        uint256[] memory functionIds = new uint256[](1);
        functionIds[0] = callingFunctionId;
        uint256[][] memory ruleIdsArray = new uint256[][](1);
        ruleIdsArray[0] = new uint256[](1);
        ruleIdsArray[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            selectors,
            functionIds,
            ruleIdsArray,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        vm.stopPrank();
        vm.startPrank(address(userContract));

        // handles deep call stacks through rule evaluation
        userContract.transfer(address(0x1234), 500);
    }

    /**
     * Test passing wrong parameter types to foreign call
     */
    function testRulesEngine_Unit_ForeignCall_ParameterTypeMismatch() public ifDeploymentTestsEnabled endWithStopPrank {
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        string memory functionSig = "testSig(uint256)";

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.STR; // Function expects UINT
        fc.returnType = ParamTypes.BOOL;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        // Pass string data
        string memory wrongTypeData = "this_should_be_uint256";
        bytes memory vals = abi.encode(wrongTypeData);
        bytes[] memory retVals = new bytes[](0);

        // Direct evaluation test - handles parameter type mismatches gracefully with silent revert
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);

        // test through rule evaluation
        vm.startPrank(policyAdmin);

        uint256 policyId = _createBlankPolicy();
        _setupEffectProcessor();

        // Create rule with raw data for string parameter
        Rule memory rule;
        rule.instructionSet = new uint256[](2);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.BOOL;
        rule.placeHolders[0].typeSpecificIndex = uint128(
            RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, functionSig)
        );
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        // Add raw data for the string parameter
        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.STR;
        rule.rawData.dataValues[0] = abi.encode(wrongTypeData);
        rule.rawData.instructionSetIndex[0] = 0;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes,
            callingFunction,
            ""
        );

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256(bytes(callingFunction)));
        uint256[] memory functionIds = new uint256[](1);
        functionIds[0] = callingFunctionId;
        uint256[][] memory ruleIdsArray = new uint256[][](1);
        ruleIdsArray[0] = new uint256[](1);
        ruleIdsArray[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            selectors,
            functionIds,
            ruleIdsArray,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        vm.stopPrank();
        vm.startPrank(address(userContract));

        // Expect revert because we passed wrong type to foreign call
        vm.expectRevert("Invalid dynamic data offset");
        userContract.transfer(address(0x1234), 100);

        vm.stopPrank();
    }
}

// Helper contracts for edge case testing

/**
 * Contract that self-destructs in its constructor
 */
contract SelfDestructInConstructor {
    uint256 public result;

    constructor(uint256 inputValue) {
        // Run some logic in constructor
        result = inputValue * 2 + 100;

        // Self-destruct immediately after logic
        selfdestruct(payable(tx.origin));
    }
}

/**
 * Factory contract that deploys self-destructing contracts
 */
contract SelfDestructFactory {
    event ContractDeployed(address contractAddress, uint256 inputValue, uint256 result);

    uint256 public lastDeployedResult;
    address public lastDeployedAddress;

    function deployAndDestruct(uint256 inputValue) external returns (address) {
        // Deploy contract that will self-destruct in constructor
        bytes memory bytecode = abi.encodePacked(type(SelfDestructInConstructor).creationCode, abi.encode(inputValue));

        address contractAddr;
        assembly {
            contractAddr := create2(0, add(bytecode, 0x20), mload(bytecode), inputValue)
        }

        // Verify deployment succeeded even if contract self-destructed
        require(contractAddr != address(0), "Contract deployment failed");

        // The contract is already self-destructed at this point
        lastDeployedAddress = contractAddr;

        // Calculate what the result would have been (since contract is gone)
        uint256 calculatedResult = inputValue * 2 + 100;
        lastDeployedResult = calculatedResult;

        emit ContractDeployed(contractAddr, inputValue, calculatedResult);

        return contractAddr;
    }

    function getLastDeployment() external view returns (address, uint256) {
        return (lastDeployedAddress, lastDeployedResult);
    }
}

/**
 * Contract that attempts recursive calls back to rules engine
 */
contract RecursiveCallContract {
    address public rulesEngineAddress;
    uint256 public recursionDepth;

    function setRulesEngineAddress(address _rulesEngine) external {
        rulesEngineAddress = _rulesEngine;
    }

    function resetDepth() external {
        recursionDepth = 0;
    }

    /**
     * Aggressive recursive call designed to burn through gas
     */
    function aggressiveRecursiveCall(uint256 value) external returns (uint256) {
        recursionDepth++;

        // Burn gas with expensive operations
        uint256 gasWaster = 0;
        for (uint256 i = 0; i < 2000; i++) {
            gasWaster = uint256(keccak256(abi.encode(gasWaster, i, value, recursionDepth)));
        }

        // Continue recursion if we have gas and haven't hit depth limit
        if (gasleft() > 100000 && recursionDepth < 1000 && rulesEngineAddress != address(0)) {
            // Create foreign call that calls ourselves again
            ForeignCall memory recursiveFc;
            recursiveFc.foreignCallAddress = address(this);
            recursiveFc.signature = this.aggressiveRecursiveCall.selector;
            recursiveFc.parameterTypes = new ParamTypes[](1);
            recursiveFc.parameterTypes[0] = ParamTypes.UINT;
            recursiveFc.returnType = ParamTypes.UINT;
            recursiveFc.encodedIndices = new ForeignCallEncodedIndex[](1);
            recursiveFc.encodedIndices[0].index = 0;
            recursiveFc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

            ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
            typeSpecificIndices[0].index = 0;
            typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

            bytes memory vals = abi.encode(value + 1);
            bytes[] memory retVals = new bytes[](0);

            // Recursive call through rules engine
            RulesEngineProcessorFacet(rulesEngineAddress).evaluateForeignCallForRule(recursiveFc, vals, retVals, typeSpecificIndices, 1);
        }

        return value + (gasWaster % 1000) + recursionDepth;
    }
}

/**
 * Contract that creates deep call stacks for testing
 */
contract DeepCallStackContract {
    function deepRecursiveCall(uint256 depth) external returns (uint256) {
        if (depth == 0) {
            return 1;
        }

        // Make a recursive call to increase stack depth
        try this.deepRecursiveCall(depth - 1) returns (uint256 result) {
            return result + 1;
        } catch {
            // If we hit stack limit, return current depth
            return depth;
        }
    }
}
