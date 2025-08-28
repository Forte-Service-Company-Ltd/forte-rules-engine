/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import {FacetUtils} from "src/engine/facets/FacetUtils.sol";

/**
 * @dev this is a test facet contract that uses the internal _isThereDuplicatesInCalldataValueTypeArray function
 * from the FacetUtils. Since the function is not meant to be used directly, some example functions were created.
 */
contract TestFacetUtils is FacetUtils {
    function checkDuplicatesBytes4(bytes4[] calldata sigs) public {
        uint start;
        assembly {
            start := sigs.offset
        }
        if (_isThereDuplicatesInCalldataValueTypeArray(sigs.length, start)) revert(DUPLICATES_NOT_ALLOWED);
    }

    function checkDuplicatesBytes32(bytes32[] calldata hashes) public {
        uint start;
        assembly {
            start := hashes.offset
        }
        if (_isThereDuplicatesInCalldataValueTypeArray(hashes.length, start)) revert(DUPLICATES_NOT_ALLOWED);
    }

    function checkDuplicatesUint256(uint256[] calldata ids) public {
        uint start;
        assembly {
            start := ids.offset
        }
        if (_isThereDuplicatesInCalldataValueTypeArray(ids.length, start)) revert(DUPLICATES_NOT_ALLOWED);
    }
}

abstract contract PolicyCRUDFuzzTest is RulesEngineCommon {
    /**
     *
     *
     * Execution tests for policies within the rules engine
     *
     *
     */

    function testPolicy_createPolicy(uint8 _policyType) public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint8 policyTypes = 2;
        _policyType = _policyType % (policyTypes * 2); // makes sure we have some valid and some invalid types
        vm.startPrank(user1);
        if (_policyType > policyTypes) vm.expectRevert("PolicyType is invalid");
        // a low-level call is necessary for the test not to fail on a policyType negative-path test-building phase
        (bool success, bytes memory data) = address(red).call(
            abi.encodeWithSelector(
                RulesEnginePolicyFacet(address(red)).createPolicy.selector,
                _policyType,
                "Test Policy",
                "This is a test policy"
            )
        );
        uint id = abi.decode(data, (uint));
        /// we check if the policy id is handled correctly
        if (_policyType <= policyTypes) require(id == 1, "Policy ID should be 1");
        else require(success == false, "Policy ID should be 0");
    }

    function testPolicy_openClosePolicy(uint8 _initialState, uint8 _toState) public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint8 states = 3;
        PolicyType initialState = PolicyType(_initialState % states);
        PolicyType toState = PolicyType(_toState % states);
        vm.startPrank(user1);
        uint policyId = RulesEnginePolicyFacet(address(red)).createPolicy(initialState, "Test Policy", "This is a test policy");
        if (initialState == PolicyType.CLOSED_POLICY) assertTrue(RulesEnginePolicyFacet(address(red)).isClosedPolicy(policyId));
        else if (initialState == PolicyType.OPEN_POLICY) assertFalse(RulesEnginePolicyFacet(address(red)).isClosedPolicy(policyId));
        else assertTrue(RulesEnginePolicyFacet(address(red)).isDisabledPolicy(policyId));

        if (toState == PolicyType.CLOSED_POLICY) {
            RulesEnginePolicyFacet(address(red)).closePolicy(policyId);
            assertTrue(RulesEnginePolicyFacet(address(red)).isClosedPolicy(policyId));
        } else if (toState == PolicyType.OPEN_POLICY) {
            RulesEnginePolicyFacet(address(red)).openPolicy(policyId);
            assertFalse(RulesEnginePolicyFacet(address(red)).isClosedPolicy(policyId));
        } else {
            RulesEnginePolicyFacet(address(red)).disablePolicy(policyId);
            assertTrue(RulesEnginePolicyFacet(address(red)).isDisabledPolicy(policyId));
        }
    }

    function testPolicy_updatePolicy_policyType(uint8 _policyType) public {
        uint8 policyTypes = 2;
        _policyType = _policyType % (policyTypes * 2); // makes sure we have some valid and some invalid types
        vm.startPrank(user1);
        uint policyId = _createBlankPolicy();
        bytes4[] memory selectors = new bytes4[](0);
        uint256[] memory functionIds = new uint256[](0);
        uint256[][] memory _ruleIds = new uint256[][](0);
        if (_policyType > policyTypes) vm.expectRevert("PolicyType is invalid");
        // a low-level call is necessary for the test not to fail on a policyType negative-path test-building phase
        (bool success, ) = address(red).call(
            abi.encodeWithSelector(
                RulesEnginePolicyFacet(address(red)).updatePolicy.selector,
                policyId,
                selectors,
                _ruleIds,
                _policyType,
                "Test Policy",
                "This is a test policy"
            )
        );
        if (_policyType <= policyTypes) {
            require(success, "Policy update should succeed");
        } else {
            require(!success, "Policy update should fail");
        }
        if (!(_policyType > policyTypes)) {
            assertEq(RulesEnginePolicyFacet(address(red)).isClosedPolicy(policyId), _policyType == 0 ? true : false);
        }
    }

    function testPolicy_updatePolicy_notAuthorizedToPolicy(uint randomPolicyId) public {
        randomPolicyId = randomPolicyId % 10;
        vm.startPrank(user1);
        uint policyId = _createBlankPolicy();
        bytes4[] memory selectors = new bytes4[](0);
        uint256[][] memory _ruleIds = new uint256[][](0);
        if (policyId != randomPolicyId) vm.expectRevert("Not Authorized To Policy");
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            randomPolicyId,
            selectors,
            _ruleIds,
            PolicyType.OPEN_POLICY,
            "Test Policy",
            "This is a test policy"
        );
        if (policyId == randomPolicyId) {
            (bytes4[] memory callingFunctions_, uint256[][] memory ruleIds_) = RulesEnginePolicyFacet(address(red)).getPolicy(policyId);
            assertEq(callingFunctions_.length, selectors.length);
            assertEq(ruleIds_.length, _ruleIds.length);
        }
    }

    function testPolicy_updatePolicy_invalidSignature(uint selectorAmount) public {
        uint maxSizeArray = 7;
        selectorAmount = (selectorAmount % maxSizeArray) + 1;
        vm.startPrank(user1);
        uint policyId = _createBlankPolicy();
        bytes4 sigCallingFunction = bytes4(keccak256(bytes(callingFunction)));
        // we skip the creation of the function to provoke the error
        uint functionId = 1;
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        bytes4[] memory selectors = new bytes4[](selectorAmount);
        if (selectorAmount > 0)
            // bytes4 grabs the 4 most significant bytes of a 32-byte word. We XOR against "i" shifted to the left 28 bytes so it can align with the
            // selector's bytes4 which allows us to produce a different selector for each iteration after the first one (since i = 0 the first iteration)
            for (uint i; i < selectorAmount; i++) selectors[i] = bytes4(sigCallingFunction ^ ((bytes32(i) << (256 - 4 * 8)))); // sigCallingFunction XOR i
        uint256[][] memory _ruleIds = new uint256[][](0);
        // TODO make this test better by fuzzing some more vars
        vm.expectRevert("Invalid Signature");
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            selectors,
            _ruleIds,
            PolicyType.OPEN_POLICY,
            "Test Policy",
            "This is a test policy"
        );
    }

    function testPolicy_updatePolicy_InvalidRule(uint functionAmount) public {
        uint maxSizeArray = 7;
        functionAmount = (functionAmount % maxSizeArray) + 1;
        vm.startPrank(user1);
        uint policyId = _createBlankPolicy();

        // we skip the rule creation to provoke the error
        uint ruleId = 1;

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        bytes4 sigCallingFunction = bytes4(keccak256(bytes(callingFunction)));
        RulesEngineComponentFacet(address(red)).createCallingFunction(policyId, sigCallingFunction, pTypes, callingFunction, "");
        bytes4[] memory selectors = new bytes4[](functionAmount);
        if (functionAmount > 0)
            for (uint i; i < functionAmount; i++) selectors[i] = bytes4(sigCallingFunction ^ (bytes32(i) << (256 - 8 * 4)));
        uint256[][] memory _ruleIds = new uint256[][](functionAmount);
        uint256[] memory _ids = new uint256[](functionAmount);
        _ids[0] = ruleId;
        if (functionAmount > 0) for (uint i; i < functionAmount; i++) _ruleIds[i] = _ids;
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

    function testPolicy_updatePolicy_arrayLengthWithRules(uint functionAmount, uint ruleAmounts) public {
        {
            uint maxSizeArray = 7;
            functionAmount = (functionAmount % maxSizeArray) + 1;
            console2.log("functionAmount", functionAmount);
            ruleAmounts = ruleAmounts % maxSizeArray;
        }
        vm.startPrank(user1);
        uint policyId = _createBlankPolicy();

        uint ruleId;
        Rule memory rule;
        {
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

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, "My rule", "My way or the highway");

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

            // Save the rule
            RulesEngineRuleFacet(address(red)).updateRule(policyId, ruleId, rule, "My rule", "My way or the highway");
        }
        bytes4 sigCallingFunction = bytes4(keccak256(bytes(callingFunction)));
        {
            ParamTypes[] memory pTypes = new ParamTypes[](2);
            pTypes[0] = ParamTypes.ADDR;
            pTypes[1] = ParamTypes.UINT;
            bytes4[] memory selectors = new bytes4[](functionAmount);
            if (functionAmount > 0)
                // bytes4 grabs the 4 most significant bytes of a 32-byte word. We XOR against "i" shifted to the left 28 bytes so it can align with the
                // selector's bytes4 which allows us to produce a different selector for each iteration after the first one (since i = 0 the first iteration)
                for (uint i; i < functionAmount; i++) {
                    selectors[i] = bytes4(sigCallingFunction ^ ((bytes32(i) << (256 - 4 * 8)))); // sigCallingFunction XOR i
                    RulesEngineComponentFacet(address(red)).createCallingFunction(policyId, selectors[i], pTypes, callingFunction, "");
                }
            uint256[][] memory _ruleIds = new uint256[][](ruleAmounts);
            uint256[] memory _ids = new uint256[](1);
            console2.log("ruleId", ruleId);
            _ids[0] = ruleId;
            console2.log("_ids[0]", _ids[0]);
            if (ruleAmounts > 0) for (uint i; i < ruleAmounts; i++) _ruleIds[i] = _ids;
            // console2.log("_ruleIds[0][0]", _ruleIds[0][0]);
            if (functionAmount != ruleAmounts && ruleAmounts > 0 && functionAmount > 0) vm.expectRevert("Invalid rule array length");
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                selectors,
                _ruleIds,
                PolicyType.OPEN_POLICY,
                "Test Policy",
                "This is a test policy"
            );
        }
        if (functionAmount == ruleAmounts && ruleAmounts > 0 && functionAmount > 0) {
            (bytes4[] memory callingFunctions_, uint256[][] memory ruleIds_) = RulesEnginePolicyFacet(address(red)).getPolicy(policyId);
            assertEq(callingFunctions_.length, functionAmount, "selector length mismatch");
            assertEq(ruleIds_.length, ruleAmounts, "rule id length mismatch");
            for (uint i; i < ruleIds_.length; i++) {
                console2.log("i", i);
                console2.log("ruleIds_[0][0]", ruleIds_[0][0]);
                assertEq(ruleIds_.length, functionAmount, "rule id length mismatch");
                assertEq(ruleIds_[i].length, 1, "rule id length mismatch");
                RuleStorageSet memory ruleStorage = RulesEngineRuleFacet(address(red)).getRule(policyId, ruleIds_[i][0]);
                assertEq(ruleStorage.rule.instructionSet.length, 7, "instruction set length mismatch");
            }
        }
    }

    function testPolicy_updatePolicy_identicalSigs(
        uint functionAmount,
        uint copiedElementIndex,
        uint identicalElementIndex,
        bool shouldRevert
    ) public {
        {
            uint maxSizeArray = 7;
            functionAmount = (functionAmount % maxSizeArray) + 2; // will be between 2 and 9
            identicalElementIndex = (identicalElementIndex % (functionAmount - 1)) + 1; // will be between 1 and functionAmount - 1
            copiedElementIndex = (copiedElementIndex % (functionAmount)); // could be any index inside the array
            if (copiedElementIndex == identicalElementIndex) {
                identicalElementIndex = copiedElementIndex == 0 ? 1 : copiedElementIndex - 1;
            }
        }
        vm.startPrank(user1);
        uint policyId = _createBlankPolicy();

        uint ruleId;
        Rule memory rule;
        {
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

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, "My rule", "My way or the highway");

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

            // Save the rule
            RulesEngineRuleFacet(address(red)).updateRule(policyId, ruleId, rule, "My rule", "My way or the highway");
        }
        bytes4 sigCallingFunction = bytes4(keccak256(bytes(callingFunction)));
        {
            ParamTypes[] memory pTypes = new ParamTypes[](2);
            pTypes[0] = ParamTypes.ADDR;
            pTypes[1] = ParamTypes.UINT;
            bytes4[] memory selectors = new bytes4[](functionAmount);
            if (functionAmount > 0)
                // bytes4 grabs the 4 most significant bytes of a 32-byte word. We XOR against "i" shifted to the left 28 bytes so it can align with the
                // selector's bytes4 which allows us to produce a different selector for each iteration after the first one (since i = 0 the first iteration)
                for (uint i; i < functionAmount; i++) {
                    selectors[i] = bytes4(sigCallingFunction ^ ((bytes32(i) << (256 - 4 * 8)))); // sigCallingFunction XOR i
                    RulesEngineComponentFacet(address(red)).createCallingFunction(policyId, selectors[i], pTypes, callingFunction, "");
                }
            if (shouldRevert) selectors[identicalElementIndex] = selectors[copiedElementIndex]; // we duplicate a random element in a random position

            uint256[][] memory _ruleIds = new uint256[][](functionAmount);
            uint256[] memory _ids = new uint256[](1);
            _ids[0] = ruleId;
            for (uint i; i < functionAmount; i++) _ruleIds[i] = _ids;
            if (shouldRevert) vm.expectRevert("Duplicates not allowed");
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                selectors,
                _ruleIds,
                PolicyType.OPEN_POLICY,
                "Test Policy",
                "This is a test policy"
            );
        }
        if (!shouldRevert) {
            (bytes4[] memory callingFunctions_, uint256[][] memory ruleIds_) = RulesEnginePolicyFacet(address(red)).getPolicy(policyId);
            assertEq(callingFunctions_.length, functionAmount, "selector length mismatch");
            assertEq(ruleIds_.length, functionAmount, "rule id length mismatch");
            for (uint i; i < ruleIds_.length; i++) {
                console2.log("i", i);
                console2.log("ruleIds_[0][0]", ruleIds_[0][0]);
                assertEq(ruleIds_.length, functionAmount, "rule id length mismatch");
                assertEq(ruleIds_[i].length, 1, "rule id length mismatch");
                RuleStorageSet memory ruleStorage = RulesEngineRuleFacet(address(red)).getRule(policyId, ruleIds_[i][0]);
                assertEq(ruleStorage.rule.instructionSet.length, 7, "instruction set length mismatch");
            }
        }
    }

    function testPolicy_updatePolicy_identicalElementsInCalldataArrayBytes4(uint seedSig, uint multiplier) public {
        uint sigAmount = 4;
        TestFacetUtils facet = new TestFacetUtils();
        bytes4[] memory sigs = new bytes4[](sigAmount);
        for (uint i; i < sigAmount; i++) {
            unchecked {
                sigs[i] = bytes4(bytes32(seedSig * multiplier * (i + 1)));
            }
        }
        /// the following condition is basically a representation of what the algorithm does
        if (
            (sigs[0] == sigs[1] || sigs[0] == sigs[2] || sigs[0] == sigs[3]) ||
            (sigs[1] == sigs[2] || sigs[1] == sigs[3]) ||
            sigs[2] == sigs[3]
        ) vm.expectRevert("Duplicates not allowed");
        facet.checkDuplicatesBytes4(sigs);
    }

    function testPolicy_updatePolicy_identicalElementsInCalldataArrayBytes32(uint seedSig, uint multiplier) public {
        uint sigAmount = 4;
        TestFacetUtils facet = new TestFacetUtils();
        bytes32[] memory sigs = new bytes32[](sigAmount);
        for (uint i; i < sigAmount; i++) {
            unchecked {
                sigs[i] = bytes32(seedSig * multiplier * (i + 1));
            }
        }
        /// the following condition is basically a representation of what the algorithm does
        if (
            (sigs[0] == sigs[1] || sigs[0] == sigs[2] || sigs[0] == sigs[3]) ||
            (sigs[1] == sigs[2] || sigs[1] == sigs[3]) ||
            sigs[2] == sigs[3]
        ) vm.expectRevert("Duplicates not allowed");
        facet.checkDuplicatesBytes32(sigs);
    }

    function testPolicy_updatePolicy_identicalElementsInCalldataArrayUint(uint seedSig, uint multiplier) public {
        uint sigAmount = 4;
        TestFacetUtils facet = new TestFacetUtils();
        uint[] memory sigs = new uint[](sigAmount);
        for (uint i; i < sigAmount; i++) {
            unchecked {
                sigs[i] = seedSig * multiplier * (i + 1);
            }
        }
        /// the following condition is basically a representation of what the algorithm does
        if (
            (sigs[0] == sigs[1] || sigs[0] == sigs[2] || sigs[0] == sigs[3]) ||
            (sigs[1] == sigs[2] || sigs[1] == sigs[3]) ||
            sigs[2] == sigs[3]
        ) vm.expectRevert("Duplicates not allowed");
        facet.checkDuplicatesUint256(sigs);
    }
}
// NOTE for my self

// 1. create test exclusively for the algorithm that checks for no identical items in array (done)
// 2. create negative path test for identical elements in an array (done)
// 3. create test to demonstrate that identical signatures can have different Ids
// 4. fix the identical functioins with different ids by checking for the set flag at creation time
// 5. Create test that proves that there is no check updating policy with rules without function sigs and ids
// 6. Fix this
// 7. create test that proves that we can fool the system by giving the wrong id to a sig by giving identica ids in the sig id array
// 8. Fix this by checking for identical ids in the array

// 9. Add test for CALLING_FUNCTION_ALREADY_EXISTS
// 10. add test for foreign call already exists
// 11. add test for foreign call not set
// 12. can I update an inexistent policy?
// 13. Check if calling function is set when creating so we don't override a function. Add test
// 13. Check if foreign call is set when creating so we don't override a foreign call. Add test

// Proposed change:
// Main idea is to delete the id for callingFunctions since the selector MUST be the id. For this we neet to:

// 1.
// 2. delete the functionIdCounter.
// 3. callingFunctionStorageSets MUST be ` mapping(uint256 policyId => mapping(bytes4 selector => CallingFunctionStorageSet))`.
// 4. CallingFunctionStorageSet MUST not have the signature field.
// 5. Policy MUST keep the callingFunctions array.
// 6. delete callingFunctionIdMap from Policy

// Same goes for foreign calls
