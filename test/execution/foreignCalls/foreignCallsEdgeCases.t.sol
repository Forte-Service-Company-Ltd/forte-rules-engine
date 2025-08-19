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
        string memory arrayCallingFunction = "func(uint[])";
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

        _setUpForeignCallWithAlwaysTrueRuleDynamicArrayArg(fc, arrayCallingFunction, functionSig, 1);
        // Create array with 5,000 elements
        uint256[] memory extremeArray = new uint256[](5000);
        for (uint256 i = 0; i < 5000; i++) {
            extremeArray[i] = i + 1;
        }

        bytes[] memory retVals = new bytes[](0);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(arrayCallingFunction))), extremeArray);

        // check gas before and after this call, determine what the gas used in this tx is,
        // compare to a block limit to see if this is above gas limit per block on mainnet
        vm.startPrank(address(userContract));
        gasLeftBefore = gasleft();
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        string memory arrayCallingFunction = "func(string[])";
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

        _setUpForeignCallWithAlwaysTrueRuleDynamicArrayArg(fc, arrayCallingFunction, functionSig, 1);
        bytes[] memory retVals = new bytes[](0);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(arrayCallingFunction))), largeStringArray);

        // check gas before and after this call, determine what the gas used in this tx is,
        // compare to a block limit to see if this is above gas limit per block on mainnet
        vm.startPrank(address(userContract));
        gasLeftBefore = gasleft();
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

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
        string memory arrayCallingFunction = "func(uint256[],uint256[])";
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

        _setUpForeignCallWithAlwaysTrueRuleDynamicArrayArg(fc, arrayCallingFunction, functionSig, 2);
        bytes[] memory retVals = new bytes[](0);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(arrayCallingFunction))), array1, array2);

        // check gas before and after this call, determine what the gas used in this tx is,
        // compare to a block limit to see if this is above gas limit per block on mainnet
        vm.startPrank(address(userContract));
        gasLeftBefore = gasleft();
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

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
        string memory arrayCallingFunction = "func(uint256[])";
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

        _setUpForeignCallWithAlwaysTrueRuleDynamicArrayArg(fc, arrayCallingFunction, functionSig, 1);
        bytes[] memory retVals = new bytes[](0);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(arrayCallingFunction))), emptyArray);

        // check gas before and after this call, determine what the gas used in this tx is,
        // compare to a block limit to see if this is above gas limit per block on mainnet
        vm.startPrank(address(userContract));
        gasLeftBefore = gasleft();
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        uint256[] memory storedArray = foreignCall.getInternalArrayUint();
        assertEq(storedArray.length, 0);
    }

    /**
     * Test maximum uint256 values in array to test value bounds
     */
    function testRulesEngine_Unit_ForeignCall_MaxUintValues() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory arrayCallingFunction = "func(uint256[])";
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

        _setUpForeignCallWithAlwaysTrueRuleDynamicArrayArg(fc, arrayCallingFunction, functionSig, 1);
        bytes[] memory retVals = new bytes[](0);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(arrayCallingFunction))), maxValueArray);

        // check gas before and after this call, determine what the gas used in this tx is,
        // compare to a block limit to see if this is above gas limit per block on mainnet
        vm.startPrank(address(userContract));
        gasLeftBefore = gasleft();
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        string memory arrayCallingFunction = "func(uint256)";
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
            _setUpForeignCallWithAlwaysTrueRuleValueTypeArg(fc, arrayCallingFunction, nonExistentFunctionSig, ParamTypes.UINT);
            bytes[] memory retVals = new bytes[](0);
            bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(arrayCallingFunction))), testValue);

            // This does NOT revert - it will execute but the foreign call will fail gracefully
            vm.startPrank(address(userContract));
            gasLeftBefore = gasleft();
            RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
    function testRulesEngine_Fuzz_ForeignCall_SelfDestructedContract(
        uint8 _transferAmount
    ) public ifDeploymentTestsEnabled endWithStopPrank {
        uint transferAmount = uint(_transferAmount);
        string memory callingFunc = "func(uint256)";
        SelfDestructFactory factory = new SelfDestructFactory();
        address deployedAddress;
        string memory functionSig = "deployAndDestruct(uint256)";

        vm.startPrank(policyAdmin);

        ForeignCall memory fc;
        fc.foreignCallAddress = address(factory);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.returnType = ParamTypes.ADDR;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        // Calling function evaluation setup
        _setUpForeignCallWithAlwaysTrueRuleValueTypeArg(fc, callingFunc, functionSig, ParamTypes.UINT);

        // Calling function execution test
        vm.startPrank(address(userContract));

        // This should successfully deploy and self-destruct contract through rule evaluation
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunc))), transferAmount);

        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopPrank();
        // Verify another contract was deployed and self-destructed
        (address ruleAddr, uint256 ruleResult) = factory.getLastDeployment();
        assertEq(ruleResult, transferAmount * 2 + 100, "Rule should use transfer amount");
    }

    /**
     * Test foreign call that attempts recursive calls to showcase
     * how the rules engine cannot handle recursion directly
     * This hits gas limits and demonstrate EVM boundaries
     */
    function testRulesEngine_Unit_ForeignCall_RecursiveCall() public ifDeploymentTestsEnabled endWithStopPrank {
        RecursiveCallContract recursiveContract = new RecursiveCallContract();

        recursiveContract.setRulesEngineAddress(address(red));
        recursiveContract.setUserContractAddress(address(userContract));
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

        string memory testString = "malformed_test";

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

        // Use a depth that approaches but doesn't exceed EVM limits
        uint256 depth = 500; // Should be safe but deep

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
        userContract.transfer(address(0x1234), depth);
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

        // Pass string data
        string memory wrongTypeData = "this_should_be_uint256";

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
    address public userContractAddress;
    bytes32 public _hash;
    uint256 variable;
    uint public gasLeft;

    function setRulesEngineAddress(address _rulesEngine) external {
        rulesEngineAddress = _rulesEngine;
    }

    function setUserContractAddress(address _userContractAddress) external {
        userContractAddress = _userContractAddress;
    }

    function resetDepth() external {
        recursionDepth = 0;
    }

    /**
     * Aggressive recursive call designed to burn through gas
     */
    function aggressiveRecursiveCall(uint256 value) external returns (uint256) {
        recursionDepth++;

        assembly {
            sstore(variable.slot, mload(0x7fffff)) // very expensive memory read
        }

        userContractAddress.call(abi.encodeWithSignature("transfer(address,uint256)", address(0x1234), value));
        gasLeft = gasleft();
        return gasleft();
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
