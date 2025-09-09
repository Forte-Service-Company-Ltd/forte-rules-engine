/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract trackers is RulesEngineCommon {
    /**
     *
     *
     * Execution tests for trackers within the rules engine
     *
     *
     */

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectAddress() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.ADDR;
        tracker.set = true;
        tracker.trackerValue = abi.encode(0xD00D);
        setupRuleWithTrackerAddr(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            address(0x7654321)
        );
        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        vm.startSnapshotGas("CheckRules_Explicit_WithTrackerUpdateEffectAddress");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        assertEq(tracker.trackerValue, abi.encode(0x7654321));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectBool() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.BOOL;
        tracker.set = true;
        tracker.trackerValue = abi.encode(bool(false));
        setupRuleWithTrackerBool(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5, bool(true));
        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        vm.startSnapshotGas("CheckRules_Explicit_WithTrackerUpdateEffectBool");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        assertEq(tracker.trackerValue, abi.encode(bool(true)));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectUint() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.UINT;
        tracker.set = true;
        tracker.trackerValue = abi.encode(uint256(13));
        setupRuleWithTrackerUint(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5, 99);
        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        vm.startSnapshotGas("CheckRules_Explicit_WithTrackerUpdateEffectUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        assertEq(tracker.trackerValue, abi.encode(uint256(99)));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectBytes() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.BYTES;
        tracker.set = true;
        tracker.trackerValue = bytes("initial");
        setupRuleWithTracker2(policyId, tracker, TrackerArrayTypes.VOID);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5, bytes("post"));
        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        vm.startSnapshotGas("CheckRules_Explicit_WithTrackerUpdateEffectBytes");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory comparison = abi.encode("post");
        assertEq(tracker.trackerValue, abi.encode(keccak256(comparison)));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectString() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.BYTES;
        tracker.set = true;
        tracker.trackerValue = "initial";
        setupRuleWithTracker2(policyId, tracker, TrackerArrayTypes.VOID);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5, "post");
        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        vm.startSnapshotGas("CheckRules_Explicit_WithTrackerUpdateEffectString");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory comparison = abi.encode("post");
        assertEq(tracker.trackerValue, abi.encode(keccak256(comparison)));
    }

    function testRulesEngine_Unit_CheckRules_WithTrackerValue() public ifDeploymentTestsEnabled endWithStopPrank {
        // positive path: tracker value 2, transfer value 3 (3 > 2, should succeed)
        setupRuleWithTracker(2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        vm.startSnapshotGas("CheckRules_WithTrackerValue_Positive");
        bool retVal = userContract.transfer(address(0x7654321), 3);
        vm.stopSnapshotGas();
        assertTrue(retVal);

        // Negative path: tracker value 2, transfer value 1 (1 > 2, should revert)
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 1);
    }

    function testRulesEngine_Unit_CheckRules_ManualUpdateToTracker() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = setupRuleWithTracker(4);
        bool retVal = userContract.transfer(address(0x7654321), 5);
        assertTrue(retVal);
        // expect failure here
        vm.expectRevert(abi.encodePacked(revert_text));
        retVal = userContract.transfer(address(0x7654321), 3);
        /// manually update the tracker here to higher value so that rule fails
        //                  calling contract,  updated uint, empty address, empty string, bool, empty bytes
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(7);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEngineComponentFacet(address(red)).updateTracker(policyId, 1, tracker);

        vm.expectRevert(abi.encodePacked(revert_text));
        retVal = userContract.transfer(address(0x7654321), 4);

        retVal = userContract.transfer(address(0x7654321), 9);
        assertTrue(retVal);
        for (uint i; i < 9_998; i++) {
            vm.pauseGasMetering();
            RulesEngineComponentFacet(address(red)).createTracker(policyId, tracker, "name", TrackerArrayTypes.VOID);
        }
        // Expect to revert when _trackerIndex >= MAX_LOOP
        vm.expectRevert("Max trackers reached");
        RulesEngineComponentFacet(address(red)).createTracker(policyId, tracker, "name", TrackerArrayTypes.VOID);
    }

    function testRuleEngine_Unit_createTrackerInvalidMappedFlag() public {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();
        Trackers memory tracker;
        tracker.mapped = true;

        /// build the members of the struct:
        tracker.pType = ParamTypes.UINT;
        tracker.trackerValue = abi.encode(666);
        vm.expectRevert("Invalid type");
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName", TrackerArrayTypes.VOID);
    }

    function testRuleEngine_Unit_MappedTrackerCreateTrackerInvalidMappedFlag() public {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT;
        tracker.trackerKeyType = ParamTypes.UINT;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000000000); // value 1
        trackerValues[1] = abi.encode(2000000000); // value

        /// create tracker name
        string memory trackerName = "tracker1";

        /// build the members of the struct:
        tracker.pType = ParamTypes.UINT;
        tracker.trackerValue = abi.encode(666);
        vm.expectRevert("Invalid type");
        RulesEngineComponentFacet(address(red)).createMappedTracker(
            policyIds[0],
            tracker,
            trackerName,
            trackerKeys,
            trackerValues,
            TrackerArrayTypes.VOID
        );
    }

    //// Mapped Trackers
    /// trackers as a rule conditional
    /// uint to uint trackers
    function testRulesEngine_Unit_MappedTrackerAsConditional_Uint() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.UINT;
        tracker.trackerKeyType = ParamTypes.UINT;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000000000); // value 1
        trackerValues[1] = abi.encode(2000000000); // value

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule for positive test
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.UINT, // value type
            ParamTypes.UINT, // tracker type
            2, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(value, abi.encode(1000000000));
        assertEq(trackerIndex, 1);

        /// positive path: value matches tracker condition
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, 1);
        vm.startSnapshotGas("MappedTrackerAsConditional_Uint_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        /// negative path: value doesn't match tracker condition
        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 2000000000, 1);
        vm.expectRevert(abi.encodePacked(revert_text));
        vm.startSnapshotGas("MappedTrackerAsConditional_Uint_Negative");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    /// uint to address
    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToAddress() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.ADDR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x7654321)); // value 1
        trackerValues[1] = abi.encode(address(0x1234567)); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.ADDR, // value type
            ParamTypes.ADDR, // tracker type
            1, // key type specific index
            0, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(value, abi.encode(address(0x7654321)));
        assertEq(trackerIndex, 1);

        /// Test positive path: value matches tracker condition
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1);
        vm.startSnapshotGas("MappedTrackerAsConditional_UintToAddress_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        /// Test negative path: value doesn't match tracker condition (should revert)
        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// address to uint - Combined positive and negative test
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToUint() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.UINT; // set the ParamType for the tracker value to be decoded as
        tracker.trackerKeyType = ParamTypes.ADDR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1); // value 1
        trackerValues[1] = abi.encode(2); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.ADDR, // key type
            ParamTypes.UINT, // value type
            ParamTypes.UINT, // tracker type
            0, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode(1));
        assertEq(trackerIndex, 1);

        vm.startPrank(userContractAddress);

        /// POSITIVE PATH: Test that valid address-to-uint mapping passes
        // address to uint mapped tracker (is the amount allowed for address)
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1);
        vm.startSnapshotGas("MappedTrackerAsConditional_AddressToUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        /// NEGATIVE PATH: Test that invalid amount for address causes revert
        // Using an amount (2000000000) that exceeds the tracked value (2) for address 0x1234567
        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// address to Address
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToAddress() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
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

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.ADDR, // key type
            ParamTypes.ADDR, // value type
            ParamTypes.ADDR, // tracker type
            0, // key type specific index
            0, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode(address(0x7654321)));
        assertEq(trackerIndex, 1);

        vm.startPrank(userContractAddress);

        /// POSITIVE PATH: Test that valid address-to-address mapping passes
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1);
        vm.startSnapshotGas("MappedTrackerAsConditional_AddressToAddress");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        /// NEGATIVE PATH: Test that trying to transfer to an untracked/invalid address causes revert
        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x9999999), 1);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    // Uint to Bool
    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToBool() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
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

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.BOOL, // value type
            ParamTypes.BOOL, // tracker type
            1, // key type specific index
            2, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(value, abi.encode(true));
        assertEq(trackerIndex, 1);

        /// positive path: value matches tracker condition
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, true);
        vm.startSnapshotGas("MappedTrackerAsConditional_UintToBool_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        /// negative path: value doesn't match tracker condition (should revert)
        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, true);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// bool to uint
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToUint() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.BOOL;
        tracker.trackerKeyType = ParamTypes.UINT;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(true); // key 1
        trackerKeys[1] = abi.encode(false); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1); // value 1
        trackerValues[1] = abi.encode(2); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BOOL, // key type
            ParamTypes.UINT, // value type
            ParamTypes.UINT, // tracker type
            2, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(value, abi.encode(true));
        assertEq(trackerIndex, 1);

        /// positive path: validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, true);
        vm.startSnapshotGas("MappedTrackerAsConditional_BoolToUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        /// negative path: use a bool key that causes rule failure
        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2, true);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// Address to Bool
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToBool() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.ADDR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(true); // value 1
        trackerValues[1] = abi.encode(false); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.BOOL, // value type
            ParamTypes.BOOL, // tracker type
            0, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode(true));
        assertEq(trackerIndex, 1);
        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, false);
        vm.startSnapshotGas("MappedTrackerAsConditional_AddressToBool");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, true);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    // Bool To Address
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToAddress() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct for bool→address mapping
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.ADDR; // tracker stores address values
        tracker.trackerKeyType = ParamTypes.BOOL; // keys are booleans

        /// create tracker key arrays (bool keys)
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(true); // key 1
        trackerKeys[1] = abi.encode(false); // key 2

        /// create tracker value arrays (address values)
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x7654321)); // value for true
        trackerValues[1] = abi.encode(address(0x1234567)); // value for false

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BOOL, // key type (bool)
            ParamTypes.ADDR, // value type (address)
            ParamTypes.ADDR, // tracker type (address)
            2, // key type specific index (bool parameter index)
            0, // value type specific index (address parameter index)
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        // Verify mapping: true → 0x7654321
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(true));
        assertEq(value, abi.encode(address(0x7654321)));

        // Verify mapping: false → 0x1234567
        value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(false));
        assertEq(value, abi.encode(address(0x1234567)));

        assertEq(trackerIndex, 1);

        /// positive path: bool key true maps to address 0x7654321, condition should pass
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, true);
        vm.startSnapshotGas("MappedTrackerAsConditional_BoolToAddress_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        /// negative path: bool key false maps to address 0x1234567, but we pass 0x7654321, should revert
        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 2000000000, false);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    // Address to String
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToString() public ifDeploymentTestsEnabled resetsGlobalVariables {
        string memory val1 = "trackerValue1";
        string memory val2 = "trackerValue2";
        address addy1 = address(0x7654321);
        address addy2 = address(0x1234567);

        uint256 policyId = _createBlankPolicy();
        /// create tracker struct for address→string mapping
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.STR; // tracker stores string values
        tracker.trackerKeyType = ParamTypes.ADDR; // keys are addresses

        /// create tracker key arrays (address keys)
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(addy1); // key 1
        trackerKeys[1] = abi.encode(addy2); // key 2

        /// create tracker value arrays (string values)
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(val1); // value for 0x7654321
        trackerValues[1] = abi.encode(val2); // value for 0x1234567

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.ADDR, // key type (address)
            ParamTypes.STR, // value type (string)
            ParamTypes.STR, // tracker type (string)
            0, // key type specific index (address parameter index)
            2, // value type specific index (string parameter index)
            trackerKeys,
            trackerValues,
            trackerName
        );
        {
            // validate tracker
            Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
            assertTrue(returnedTracker.mapped);
        }
        {
            // Verify mapping: 0x7654321 → "trackerValue1"
            bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, trackerIndex, abi.encode(addy1));
            assertEq(value, abi.encodePacked(keccak256(abi.encode(val1))), "not val1");

            // Verify mapping: 0x1234567 → "trackerValue2"
            value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, trackerIndex, abi.encode(addy2));
            assertEq(value, abi.encodePacked(keccak256(abi.encode(val2))), "not val2");

            assertEq(trackerIndex, 1, "not trackerIndex");
        }

        /// positive path: address 0x7654321 maps to "trackerValue1", condition should pass
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), addy1, 1, "trackerValue1");
        vm.startSnapshotGas("MappedTrackerAsConditional_AddressToString_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        {
            /// negative path: address 0x1234567 maps to "trackerValue2", but we pass "trackerValue1", should revert
            arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), addy2, 2000000000, val1);
            vm.expectRevert(abi.encodePacked(revert_text));
            RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        }

        // Rule execution
        // setup
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        // _addCallingFunctionToPolicy(policyIds[0]);
        vm.startPrank(policyAdmin);
        Rule memory rule;
        uint256 ruleId;
        {
            rule.placeHolders = new Placeholder[](2);
            // placeholder zero is the address of the receipient
            rule.placeHolders[0].pType = ParamTypes.ADDR;
            rule.placeHolders[0].typeSpecificIndex = 0; // _to_ address
            // placeholder 1 is the mapped tracker value of the _to_ address
            rule.placeHolders[1].pType = ParamTypes.STR;
            rule.placeHolders[1].typeSpecificIndex = uint128(trackerIndex);
            rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;

            // compare tracker value of the _to_ address in an ERC20 transfer against val1. True if they are the same. False otherwise
            rule.instructionSet = new uint256[](10);
            rule.instructionSet[0] = uint256(LogicalOp.PLH); // we place the key at mem[0] (the address of the receipient)
            rule.instructionSet[1] = 0; // placeholder[0]
            rule.instructionSet[2] = uint256(LogicalOp.PLHM); // we get the value of the mapped tracker, and place it in mem[1]
            rule.instructionSet[3] = uint128(trackerIndex);
            rule.instructionSet[4] = 0; // get the key from mem[0]
            rule.instructionSet[5] = uint256(LogicalOp.NUM); // we place the hashed value of what we know is val1 in mem[2]
            rule.instructionSet[6] = uint256(keccak256(abi.encode(val1)));
            rule.instructionSet[7] = uint256(LogicalOp.EQ); // we compare mem[1] agains mem[2]
            rule.instructionSet[8] = 1;
            rule.instructionSet[9] = 2;

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        }
        {
            uint[][] memory _ruleIds = new uint[][](1);
            _ruleIds[0] = new uint[](1);
            _ruleIds[0][0] = ruleId;
            bytes4[] memory _callingFunctions = new bytes4[](1);
            _callingFunctions[0] = bytes4(keccak256(bytes(callingFunction)));
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                _callingFunctions,
                _ruleIds,
                PolicyType.CLOSED_POLICY,
                policyName,
                policyDescription
            );
        }
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        vm.stopPrank();

        // positive case: we check that the tracker value for addy1 is val1 (it should)
        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), addy1, 1000); // 1000 is a random value completely irrelevant for the test
        vm.startPrank(userContractAddress);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // negative case: we check that the tracker value for addy2 is val1 (it shouldn't. We expect a revert in this case)
        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), addy2, 1000); // 1000 is a random value completely irrelevant for the test
        vm.startPrank(userContractAddress);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    // string to address
    function testRulesEngine_Unit_MappedTrackerAsConditional_StringToAddress() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct for string→address mapping
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.ADDR; // tracker stores address values
        tracker.trackerKeyType = ParamTypes.STR; // keys are strings

        /// create tracker key arrays (string keys)
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(string("trackerValue1")); // key 1
        trackerKeys[1] = abi.encode(string("trackerValue2")); // key 2

        /// create tracker value arrays (address values)
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x7654321)); // value for "trackerValue1"
        trackerValues[1] = abi.encode(address(0x1234567)); // value for "trackerValue2"

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.STR, // key type (string)
            ParamTypes.ADDR, // value type (address)
            ParamTypes.ADDR, // tracker type (address)
            2, // key type specific index (string parameter index)
            0, // value type specific index (address parameter index)
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        // Verify mapping: "trackerValue1" → 0x7654321
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(string("trackerValue1"))
        );
        assertEq(value, abi.encode(address(0x7654321)));

        // Verify mapping: "trackerValue2" → 0x1234567
        value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(string("trackerValue2")));
        assertEq(value, abi.encode(address(0x1234567)));

        assertEq(trackerIndex, 1);

        /// positive path: string "trackerValue1" maps to address 0x7654321, condition should pass
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            string("trackerValue1")
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_StringToAddress_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        /// negative path: string "trackerValue1" maps to address 0x7654321, but we pass 0x1234567, should revert
        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, "trackerValue1");
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    // String to Uint
    function testRulesEngine_Unit_MappedTrackerAsConditional_StringToUint() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.UINT;
        tracker.trackerKeyType = ParamTypes.STR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(string("key1")); // key 1
        trackerKeys[1] = abi.encode(string("key2")); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000); // value 1
        trackerValues[1] = abi.encode(2000); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.STR, // key type
            ParamTypes.UINT, // value type
            ParamTypes.UINT, // tracker type
            2, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(string("key1")));
        assertEq(value, abi.encode(1000));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1000,
            string("key1")
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_StringToUint_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            2000,
            string("key1")
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // Uint to String
    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToString() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.STR;
        tracker.trackerKeyType = ParamTypes.UINT;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(string("value1")); // value 1
        trackerValues[1] = abi.encode(string("value2")); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.STR, // value type
            ParamTypes.STR, // tracker type
            1, // key type specific index
            2, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(value, abi.encode(keccak256(abi.encode(string("value1")))));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, string("value1"));
        vm.startSnapshotGas("MappedTrackerAsConditional_UintToString_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            string("wrongValue")
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // String to Bool
    function testRulesEngine_Unit_MappedTrackerAsConditional_StringToBool() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.BOOL;
        tracker.trackerKeyType = ParamTypes.STR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(string("active")); // key 1
        trackerKeys[1] = abi.encode(string("inactive")); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(true); // value 1
        trackerValues[1] = abi.encode(false); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.STR, // key type
            ParamTypes.BOOL, // value type
            ParamTypes.BOOL, // tracker type
            4, // key type specific index (STR at position 4)
            3, // value type specific index (BOOL at position 3)
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(string("active")));
        assertEq(value, abi.encode(true));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321), // index 0 (ADDR)
            1, // index 1 (UINT)
            bytes(""), // index 2 (BYTES) - placeholder
            true, // index 3 (BOOL) - value
            string("active") // index 4 (STR) - key
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_StringToBool_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321), // index 0 (ADDR)
            1, // index 1 (UINT)
            bytes(""), // index 2 (BYTES) - placeholder
            false, // index 3 (BOOL) - value (wrong value)
            string("active") // index 4 (STR) - key
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // Bool to String
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToString() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.STR;
        tracker.trackerKeyType = ParamTypes.BOOL;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(true); // key 1
        trackerKeys[1] = abi.encode(false); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(string("enabled")); // value 1
        trackerValues[1] = abi.encode(string("disabled")); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BOOL, // key type
            ParamTypes.STR, // value type
            ParamTypes.STR, // tracker type
            3, // key type specific index
            4, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(true));
        assertEq(value, abi.encode(keccak256(abi.encode(string("enabled")))));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            bytes(""),
            true,
            string("enabled")
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_BoolToString_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            bytes(""),
            true,
            string("disabled")
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // String to String
    function testRulesEngine_Unit_MappedTrackerAsConditional_StringToString() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.STR;
        tracker.trackerKeyType = ParamTypes.STR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(string("user1")); // key 1
        trackerKeys[1] = abi.encode(string("user2")); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(string("admin")); // value 1
        trackerValues[1] = abi.encode(string("user")); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BYTES, // key type (use BYTES slot for string data)
            ParamTypes.STR, // value type
            ParamTypes.STR, // tracker type
            2, // key type specific index (BYTES slot at position 2)
            4, // value type specific index (STR at position 4)
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(string("user1")));
        assertEq(value, abi.encode(keccak256(abi.encode(string("admin")))));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321), // index 0 (ADDR)
            1, // index 1 (UINT)
            bytes("user1"), // index 2 (BYTES) - key as bytes
            false, // index 3 (BOOL) - placeholder
            string("admin") // index 4 (STR) - value
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_StringToString_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321), // index 0 (ADDR)
            1, // index 1 (UINT)
            bytes("user1"), // index 2 (BYTES) - key as bytes
            false, // index 3 (BOOL) - placeholder
            string("user") // index 4 (STR) - value
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // Bytes to Uint
    function testRulesEngine_Unit_MappedTrackerAsConditional_BytesToUint() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.UINT;
        tracker.trackerKeyType = ParamTypes.BYTES;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(bytes("data1")); // key 1
        trackerKeys[1] = abi.encode(bytes("data2")); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000); // value 1
        trackerValues[1] = abi.encode(2000); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BYTES, // key type
            ParamTypes.UINT, // value type
            ParamTypes.UINT, // tracker type
            2, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(bytes("data1")));
        assertEq(value, abi.encode(1000));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1000,
            bytes("data1")
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_BytesToUint_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            2000,
            bytes("data1")
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // Uint to Bytes
    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToBytes() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.BYTES;
        tracker.trackerKeyType = ParamTypes.UINT;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(bytes("response1")); // value 1
        trackerValues[1] = abi.encode(bytes("response2")); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.BYTES, // value type
            ParamTypes.BYTES, // tracker type
            1, // key type specific index
            2, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(value, abi.encode(keccak256(abi.encode(bytes("response1")))));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            bytes("response1")
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_UintToBytes_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            bytes("wrongResponse")
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // Bytes to Address
    function testRulesEngine_Unit_MappedTrackerAsConditional_BytesToAddress() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.BYTES;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(bytes("token1")); // key 1
        trackerKeys[1] = abi.encode(bytes("token2")); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x7654321)); // value 1
        trackerValues[1] = abi.encode(address(0x1234567)); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BYTES, // key type
            ParamTypes.ADDR, // value type
            ParamTypes.ADDR, // tracker type
            2, // key type specific index
            0, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(bytes("token1")));
        assertEq(value, abi.encode(address(0x7654321)));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, bytes("token1"));
        vm.startSnapshotGas("MappedTrackerAsConditional_BytesToAddress_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 1, bytes("token1"));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // Address to Bytes
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToBytes() public ifDeploymentTestsEnabled resetsGlobalVariables {
        bytes memory val1 = "metadata1";
        bytes memory val2 = "metadata2";
        address addy1 = address(0x7654321);
        address addy2 = address(0x1234567);

        uint256 trackerIndex;

        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        {
            Trackers memory tracker;
            tracker.mapped = true;
            tracker.pType = ParamTypes.BYTES;
            tracker.trackerKeyType = ParamTypes.ADDR;

            /// create tracker key arrays
            bytes[] memory trackerKeys = new bytes[](2);
            trackerKeys[0] = abi.encode(addy1); // key 1
            trackerKeys[1] = abi.encode(addy2); // key 2

            /// create tracker value arrays
            bytes[] memory trackerValues = new bytes[](2);
            trackerValues[0] = abi.encode(val1); // value 1
            trackerValues[1] = abi.encode(val2); // value 2

            /// create tracker name
            string memory trackerName = "tracker1";

            /// set up rule
            trackerIndex = _setupRuleWithMappedTracker(
                policyId,
                tracker,
                ParamTypes.ADDR, // key type
                ParamTypes.BYTES, // value type
                ParamTypes.BYTES, // tracker type
                0, // key type specific index
                2, // value type specific index
                trackerKeys,
                trackerValues,
                trackerName
            );
        }
        // validate tracker
        {
            Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
            assertTrue(returnedTracker.mapped);

            bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(addy1));
            assertEq(value, abi.encodePacked(keccak256(abi.encode(val1))), "not val1");
            assertEq(trackerIndex, 1);

            /// validate tracker is checked as conditional - positive path
            vm.startPrank(userContractAddress);
            bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), addy1, 1, val1);
            vm.startSnapshotGas("MappedTrackerAsConditional_AddressToBytes_Positive");
            RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
            vm.stopSnapshotGas();

            // negative path
            bytes memory arguments2 = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), addy1, 1, bytes("wrongMetadata"));
            vm.expectRevert(abi.encodePacked(revert_text));
            RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
        }
        // Rule execution
        // setup
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        // _addCallingFunctionToPolicy(policyIds[0]);
        vm.startPrank(policyAdmin);
        Rule memory rule;
        uint256 ruleId;
        {
            rule.placeHolders = new Placeholder[](2);
            // placeholder zero is the address of the receipient
            rule.placeHolders[0].pType = ParamTypes.ADDR;
            rule.placeHolders[0].typeSpecificIndex = 0; // _to_ address
            // placeholder 1 is the mapped tracker value of the _to_ address
            rule.placeHolders[1].pType = ParamTypes.BYTES;
            rule.placeHolders[1].typeSpecificIndex = uint128(trackerIndex);
            rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;

            // compare tracker value of the _to_ address in an ERC20 transfer against val1. True if they are the same. False otherwise
            rule.instructionSet = new uint256[](10);
            rule.instructionSet[0] = uint256(LogicalOp.PLH); // we place the key at mem[0] (the address of the receipient)
            rule.instructionSet[1] = 0; // placeholder[0]
            rule.instructionSet[2] = uint256(LogicalOp.PLHM); // we get the value of the mapped tracker, and place it in mem[1]
            rule.instructionSet[3] = uint128(trackerIndex);
            rule.instructionSet[4] = 0; // get the key from mem[0]
            rule.instructionSet[5] = uint256(LogicalOp.NUM); // we place the hashed value of what we know is val1 in mem[2]
            rule.instructionSet[6] = uint256(keccak256(abi.encode(val1)));
            rule.instructionSet[7] = uint256(LogicalOp.EQ); // we compare mem[1] agains mem[2]
            rule.instructionSet[8] = 1;
            rule.instructionSet[9] = 2;

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        }
        {
            uint[][] memory _ruleIds = new uint[][](1);
            _ruleIds[0] = new uint[](1);
            _ruleIds[0][0] = ruleId;
            bytes4[] memory _callingFunctions = new bytes4[](1);
            _callingFunctions[0] = bytes4(keccak256(bytes(callingFunction)));
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                _callingFunctions,
                _ruleIds,
                PolicyType.CLOSED_POLICY,
                policyName,
                policyDescription
            );
        }
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        vm.stopPrank();

        // positive case: we check that the tracker value for addy1 is val1 (it should)
        bytes memory _arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), addy1, 1000); // 1000 is a random value completely irrelevant for the test
        vm.startPrank(userContractAddress);
        RulesEngineProcessorFacet(address(red)).checkPolicies(_arguments);

        // negative case: we check that the tracker value for addy2 is val1 (it shouldn't. We expect a revert in this case)
        _arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), addy2, 1000); // 1000 is a random value completely irrelevant for the test
        vm.startPrank(userContractAddress);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(_arguments);
    }

    // Bytes to Bool
    function testRulesEngine_Unit_MappedTrackerAsConditional_BytesToBool() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.BOOL;
        tracker.trackerKeyType = ParamTypes.BYTES;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(bytes("allowed")); // key 1
        trackerKeys[1] = abi.encode(bytes("denied")); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(true); // value 1
        trackerValues[1] = abi.encode(false); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BYTES, // key type
            ParamTypes.BOOL, // value type
            ParamTypes.BOOL, // tracker type
            3, // key type specific index
            2, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(bytes("allowed")));
        assertEq(value, abi.encode(true));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            true,
            bytes("allowed")
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_BytesToBool_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            false,
            bytes("allowed")
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // Bool to Bytes
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToBytes() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.BYTES;
        tracker.trackerKeyType = ParamTypes.BOOL;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(true); // key 1
        trackerKeys[1] = abi.encode(false); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(bytes("success")); // value 1
        trackerValues[1] = abi.encode(bytes("failure")); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BOOL, // key type
            ParamTypes.BYTES, // value type
            ParamTypes.BYTES, // tracker type
            3, // key type specific index
            2, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(true));
        assertEq(value, abi.encode(keccak256(abi.encode(bytes("success")))));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            bytes("success"),
            true
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_BoolToBytes_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            bytes("failure"),
            true
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // Bytes to String
    function testRulesEngine_Unit_MappedTrackerAsConditional_BytesToString() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.STR;
        tracker.trackerKeyType = ParamTypes.BYTES;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(bytes("key1")); // key 1
        trackerKeys[1] = abi.encode(bytes("key2")); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(string("name1")); // value 1
        trackerValues[1] = abi.encode(string("name2")); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BYTES, // key type
            ParamTypes.STR, // value type
            ParamTypes.STR, // tracker type
            2, // key type specific index (BYTES at position 2)
            4, // value type specific index (STR at position 4)
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(bytes("key1")));
        assertEq(value, abi.encode(keccak256(abi.encode(string("name1")))));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321), // index 0 (ADDR)
            1, // index 1 (UINT)
            bytes("key1"), // index 2 (BYTES) - key
            false, // index 3 (BOOL) - placeholder
            string("name1") // index 4 (STR) - value
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_BytesToString_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321), // index 0 (ADDR)
            1, // index 1 (UINT)
            bytes("key1"), // index 2 (BYTES) - key
            false, // index 3 (BOOL) - placeholder
            string("wrongName") // index 4 (STR) - value
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // String to Bytes
    function testRulesEngine_Unit_MappedTrackerAsConditional_StringToBytes() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.BYTES;
        tracker.trackerKeyType = ParamTypes.STR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(string("config1")); // key 1
        trackerKeys[1] = abi.encode(string("config2")); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(bytes("data1")); // value 1
        trackerValues[1] = abi.encode(bytes("data2")); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.STR, // key type
            ParamTypes.BYTES, // value type
            ParamTypes.BYTES, // tracker type
            4, // key type specific index (STR at position 4)
            2, // value type specific index (BYTES at position 2)
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(string("config1")));
        assertEq(value, abi.encode(keccak256(abi.encode(bytes("data1")))));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321), // index 0 (ADDR)
            1, // index 1 (UINT)
            bytes("data1"), // index 2 (BYTES) - value
            false, // index 3 (BOOL) - placeholder
            string("config1") // index 4 (STR) - key
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_StringToBytes_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321), // index 0 (ADDR)
            1, // index 1 (UINT)
            bytes("wrongData"), // index 2 (BYTES) - value
            false, // index 3 (BOOL) - placeholder
            string("config1") // index 4 (STR) - key
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // Bytes to Bytes
    function testRulesEngine_Unit_MappedTrackerAsConditional_BytesToBytes() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.BYTES;
        tracker.trackerKeyType = ParamTypes.BYTES;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(bytes("hash1")); // key 1
        trackerKeys[1] = abi.encode(bytes("hash2")); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(bytes("signature1")); // value 1
        trackerValues[1] = abi.encode(bytes("signature2")); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BYTES, // key type
            ParamTypes.BYTES, // value type
            ParamTypes.BYTES, // tracker type
            2, // key type specific index (BYTES at position 2)
            4, // value type specific index (STR at position 4, but we'll pass BYTES)
            trackerKeys,
            trackerValues,
            trackerName
        );

        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(bytes("hash1")));
        assertEq(value, abi.encode(keccak256(abi.encode(bytes("signature1")))));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321), // index 0 (ADDR)
            1, // index 1 (UINT)
            bytes("hash1"), // index 2 (BYTES) - key
            false, // index 3 (BOOL) - placeholder
            bytes("signature1") // index 4 (BYTES) - value
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_BytesToBytes_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321), // index 0 (ADDR)
            1, // index 1 (UINT)
            bytes("hash1"), // index 2 (BYTES) - key
            false, // index 3 (BOOL) - placeholder
            bytes("wrongSignature") // index 4 (BYTES) - value
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // Bool to Bool
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToBool() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.BOOL;
        tracker.trackerKeyType = ParamTypes.BOOL;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(true); // key 1
        trackerKeys[1] = abi.encode(false); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(false); // value 1 (inverted)
        trackerValues[1] = abi.encode(true); // value 2 (inverted)

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BOOL, // key type
            ParamTypes.BOOL, // value type
            ParamTypes.BOOL, // tracker type
            2, // key type specific index
            3, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(true));
        assertEq(value, abi.encode(false));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, true, false);
        vm.startSnapshotGas("MappedTrackerAsConditional_BoolToBool_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, true, true);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    /// tracker updated from effects
    // uint to uint tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToUint() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.UINT;
        tracker.trackerKeyType = ParamTypes.UINT;
        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2
        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000000000); // value 1
        trackerValues[1] = abi.encode(2000000000); // value 2
        /// create tracker name
        string memory trackerName = "tracker1";

        ParamTypes trackerKeyTypes = ParamTypes.UINT;

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker,
            trackerKeys,
            trackerValues,
            trackerKeyTypes,
            trackerName
        );

        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(value, abi.encode(1000000000));
        assertEq(trackerIndex, 1);

        /// Test positive path: tracker should be updated from effect
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, 100);
        vm.startSnapshotGas("MappedTrackerUpdatedFromEffects_UintToUint_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // check that the tracker was updated from the effect to expected value
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(updatedValue, abi.encode(100));
    }

    // uint to address tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToAddress() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct for uint→address mapping
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.ADDR; // tracker stores address values
        tracker.trackerKeyType = ParamTypes.UINT; // keys are uints

        /// create tracker key arrays (uint keys)
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays (address values)
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x1234567)); // initial value for key 1
        trackerValues[1] = abi.encode(address(0x7654321)); // value for key 2

        /// create tracker name
        string memory trackerName = "tracker1";

        ParamTypes trackerKeyTypes = ParamTypes.UINT;

        /// set up rule that will update tracker from effect
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker,
            trackerKeys,
            trackerValues,
            trackerKeyTypes,
            trackerName
        );

        // validate tracker setup
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        // verify initial mapping: key 1 → 0x1234567
        bytes memory initialValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(initialValue, abi.encode(address(0x1234567)));
        assertEq(trackerIndex, 1);

        /// Test positive path: execute rule which should succeed and update tracker via effect
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1000000000,
            address(0x7654321)
        );
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // verify tracker was updated to expected value
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(updatedValue, abi.encode(address(0x7654321)));

        /// Test second execution: execute rule again with different parameters
        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, address(0x1234567));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // verify tracker was updated again (since rule always passes due to 1==1 logic)
        bytes memory secondUpdatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(secondUpdatedValue, abi.encode(address(0x1234567))); // should now be the new address
    }

    // address to Uint tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToUint() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct for address→uint mapping
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.UINT; // tracker stores uint values
        tracker.trackerKeyType = ParamTypes.ADDR; // keys are addresses

        /// create tracker key arrays (address keys)
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays (uint values)
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000); // initial value for 0x7654321
        trackerValues[1] = abi.encode(2000); // value for 0x1234567

        /// create tracker name
        string memory trackerName = "tracker1";

        ParamTypes trackerKeyTypes = ParamTypes.ADDR;

        /// set up rule that will update tracker from effect
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker,
            trackerKeys,
            trackerValues,
            trackerKeyTypes,
            trackerName
        );

        // validate tracker setup
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        // verify initial mapping: 0x7654321 → 1000
        bytes memory initialValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(initialValue, abi.encode(1000));
        assertEq(trackerIndex, 1);

        /// Test first execution: execute rule which should update tracker via effect
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, 20000);
        vm.startSnapshotGas("MappedTrackerUpdatedFromEffects_AddressToUint_First");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // verify tracker was updated to expected value
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(updatedValue, abi.encode(20000));
    }

    // address to Address tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToAddress() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct for address→address mapping
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.ADDR; // tracker stores address values
        tracker.trackerKeyType = ParamTypes.ADDR; // keys are addresses

        /// create tracker key arrays (address keys)
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x1234567)); // key 1
        trackerKeys[1] = abi.encode(address(0x7654321)); // key 2

        /// create tracker value arrays (address values)
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x9999999)); // initial value for 0x1234567
        trackerValues[1] = abi.encode(address(0x8888888)); // initial value for 0x7654321

        /// create tracker name
        string memory trackerName = "tracker1";

        ParamTypes trackerKeyTypes = ParamTypes.ADDR;

        /// set up rule that will update tracker from effect
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker,
            trackerKeys,
            trackerValues,
            trackerKeyTypes,
            trackerName
        );

        // validate tracker setup
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);
        assertEq(uint256(returnedTracker.trackerKeyType), uint256(ParamTypes.ADDR));

        // verify initial mapping: 0x7654321 → 0x8888888
        bytes memory initialValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(initialValue, abi.encode(address(0x8888888)));
        assertEq(trackerIndex, 1);

        /// Test first execution: execute rule which should update tracker via effect
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1000000000,
            address(0x7777)
        );
        vm.startSnapshotGas("MappedTrackerUpdatedFromEffects_AddressToAddress_First");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // verify tracker was updated to expected value
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(updatedValue, abi.encode(address(0x7777)));

        /// Test second execution: execute rule again with same key but different effect value
        arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321), // same key as first execution
            2000000000,
            address(0x6666) // different effect value
        );
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // verify tracker was updated again with the new value
        bytes memory secondUpdatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(secondUpdatedValue, abi.encode(address(0x6666))); // should now be the newest value
    }

    // address to bool tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToBool() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct for address→bool mapping
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.BOOL; // tracker stores bool values
        tracker.trackerKeyType = ParamTypes.ADDR; // keys are addresses

        /// create tracker key arrays (address keys)
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x1234567)); // key 1
        trackerKeys[1] = abi.encode(address(0x7654321)); // key 2

        /// create tracker value arrays (bool values)
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(false); // initial value for 0x1234567
        trackerValues[1] = abi.encode(false); // initial value for 0x7654321

        /// create tracker name
        string memory trackerName = "tracker1";

        ParamTypes trackerKeyTypes = ParamTypes.ADDR;

        /// set up rule that will update tracker from effect
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker,
            trackerKeys,
            trackerValues,
            trackerKeyTypes,
            trackerName
        );

        // validate tracker setup
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);
        assertEq(uint256(returnedTracker.trackerKeyType), uint256(ParamTypes.ADDR));

        // verify initial mapping: 0x7654321 → false
        bytes memory initialValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(initialValue, abi.encode(false));
        assertEq(trackerIndex, 1);

        /// Test first execution: execute rule which should update tracker via effect
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, true);
        vm.startSnapshotGas("MappedTrackerUpdatedFromEffects_AddressToBool_First");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // verify tracker was updated to expected value
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(updatedValue, abi.encode(true));

        /// Test second execution: execute rule again with same key but different effect value
        arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321), // same key as first execution
            2000000000,
            false // different effect value
        );
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // verify tracker was updated again with the new value
        bytes memory secondUpdatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(secondUpdatedValue, abi.encode(false)); // should now be false again

        // verify we can toggle the boolean value through effects
        assertTrue(abi.decode(updatedValue, (bool)) != abi.decode(secondUpdatedValue, (bool)));
    }

    function testRulesEngine_Unit_MappedTrackerInstructionSetCompare_AddressToUint() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.UINT;
        tracker.trackerKeyType = ParamTypes.ADDR;
        tracker.mapped = true;
        string memory trackerName = "tracker1";

        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x1234567)); // key 1
        trackerKeys[1] = abi.encode(address(0x7654321)); // key 2

        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000); // value 1
        trackerValues[1] = abi.encode(2000); // value 2

        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // placeHolderValueType
            ParamTypes.ADDR, // placeHolderValueType2
            ParamTypes.UINT, // trackerValueType
            0, // typespecific index 1
            1, // typespecific index 2
            trackerKeys,
            trackerValues,
            trackerName
        );

        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);
        assertEq(uint256(returnedTracker.trackerKeyType), uint256(ParamTypes.ADDR));

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x1234567)));
        assertEq(value, abi.encode(1000));
        assertEq(trackerIndex, 1);

        bytes memory trackerValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(trackerValue, abi.encode(2000));

        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 1000);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        bytes memory arguments2 = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 2000);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);

        bytes memory arguments3 = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments3);
    }

    function testRulesEngine_Unit_MappedTrackerInstructionSetCompare_Bytes() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.BYTES;
        tracker.mapped = true;
        string memory trackerName = "king of the hill";

        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(bytes("king of the hill")); // key 1
        trackerKeys[1] = abi.encode(bytes("regular player")); // key 2

        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x1234567)); // value 1
        trackerValues[1] = abi.encode(address(0x7654321)); // value 2

        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BYTES, // placeHolderValueType
            ParamTypes.ADDR, // placeHolderValueType2
            ParamTypes.ADDR, // trackerValueType
            2, // typespecific index 1
            0, // typespecific index 2
            trackerKeys,
            trackerValues,
            trackerName
        );

        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);
        assertEq(uint256(returnedTracker.trackerKeyType), uint256(ParamTypes.BYTES));

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(bytes("king of the hill"))
        );
        assertEq(value, abi.encode(address(0x1234567)));
        assertEq(trackerIndex, 1);

        bytes memory trackerValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(bytes("regular player"))
        );
        assertEq(trackerValue, abi.encode(address(0x7654321)));

        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x1234567),
            2000,
            bytes("king of the hill")
        );
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            2000,
            bytes("regular player")
        );
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);

        bytes memory arguments3 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            2000,
            bytes("king of the hill")
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments3);

        bytes memory arguments4 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x1234567),
            2000,
            bytes("regular player")
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments4);
    }

    function testRulesEngine_Integration_TrackerUpdate() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT;
        tracker.trackerValue = abi.encode(1);
        string memory trackerName = "tracker1";

        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, trackerName, TrackerArrayTypes.VOID);
        Trackers memory tracker2;
        tracker2.pType = ParamTypes.UINT;
        tracker2.trackerValue = abi.encode(2);
        string memory trackerName2 = "tracker2";
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker2, trackerName2, TrackerArrayTypes.VOID);

        ForeignCallTestContract foreignCallTestContract = new ForeignCallTestContract();
        ForeignCall memory foreignCall;
        foreignCall.signature = bytes4(keccak256(bytes("testSig(uint256,uint256)")));
        foreignCall.foreignCallAddress = address(foreignCallTestContract);
        foreignCall.returnType = ParamTypes.UINT;
        foreignCall.parameterTypes = new ParamTypes[](2);
        foreignCall.parameterTypes[0] = ParamTypes.UINT;
        foreignCall.parameterTypes[1] = ParamTypes.UINT;
        foreignCall.encodedIndices = new ForeignCallEncodedIndex[](2);
        foreignCall.encodedIndices[0].eType = EncodedIndexType.TRACKER;
        foreignCall.encodedIndices[0].index = 1;
        foreignCall.encodedIndices[1].eType = EncodedIndexType.TRACKER;
        foreignCall.encodedIndices[1].index = 2;

        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], foreignCall, "testSig");

        ForeignCall memory foreignCall2;
        foreignCall2.signature = bytes4(keccak256(bytes("testSig(uint256,uint256)")));
        foreignCall2.foreignCallAddress = address(foreignCallTestContract);
        foreignCall2.returnType = ParamTypes.UINT;
        foreignCall2.parameterTypes = new ParamTypes[](2);
        foreignCall2.parameterTypes[0] = ParamTypes.UINT;
        foreignCall2.parameterTypes[1] = ParamTypes.UINT;
        foreignCall2.encodedIndices = new ForeignCallEncodedIndex[](2);
        foreignCall2.encodedIndices[0].eType = EncodedIndexType.TRACKER;
        foreignCall2.encodedIndices[0].index = 1;
        foreignCall2.encodedIndices[1].eType = EncodedIndexType.TRACKER;
        foreignCall2.encodedIndices[1].index = 2;

        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], foreignCall2, "testSig2");

        Rule memory rule;
        // PLH 2, NUM 1234, EQ 0, 1, PLH 3, NUM 1234, EQ 4, 5, AND 3, 6
        rule.instructionSet = new uint256[](17);
        rule.instructionSet[0] = uint256(LogicalOp.PLH);
        rule.instructionSet[1] = uint256(2);
        rule.instructionSet[2] = uint256(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(1234);
        rule.instructionSet[4] = uint256(LogicalOp.EQ);
        rule.instructionSet[5] = uint256(0);
        rule.instructionSet[6] = uint256(1);
        rule.instructionSet[7] = uint256(LogicalOp.PLH);
        rule.instructionSet[8] = uint256(3);
        rule.instructionSet[9] = uint256(LogicalOp.NUM);
        rule.instructionSet[10] = uint256(1234);
        rule.instructionSet[11] = uint256(LogicalOp.EQ);
        rule.instructionSet[12] = uint256(4);
        rule.instructionSet[13] = uint256(5);
        rule.instructionSet[14] = uint256(LogicalOp.AND);
        rule.instructionSet[15] = uint256(3);
        rule.instructionSet[16] = uint256(6);

        rule.placeHolders = new Placeholder[](4);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[0].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 2;
        rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[2].pType = ParamTypes.UINT;
        rule.placeHolders[2].typeSpecificIndex = 1;
        rule.placeHolders[2].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[3].pType = ParamTypes.UINT;
        rule.placeHolders[3].typeSpecificIndex = 2;
        rule.placeHolders[3].flags = FLAG_FOREIGN_CALL;

        rule.positiveEffectPlaceHolders = new Placeholder[](4);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 1;
        rule.positiveEffectPlaceHolders[0].flags = FLAG_TRACKER_VALUE;
        rule.positiveEffectPlaceHolders[1].pType = ParamTypes.UINT;
        rule.positiveEffectPlaceHolders[1].typeSpecificIndex = 2;
        rule.positiveEffectPlaceHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.positiveEffectPlaceHolders[2].pType = ParamTypes.UINT;
        rule.positiveEffectPlaceHolders[2].typeSpecificIndex = 1;
        rule.positiveEffectPlaceHolders[2].flags = FLAG_FOREIGN_CALL;
        rule.positiveEffectPlaceHolders[3].pType = ParamTypes.UINT;
        rule.positiveEffectPlaceHolders[3].typeSpecificIndex = 2;
        rule.positiveEffectPlaceHolders[3].flags = FLAG_FOREIGN_CALL;

        rule.negativeEffectPlaceHolders = new Placeholder[](4);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 1;
        rule.negativeEffectPlaceHolders[0].flags = FLAG_TRACKER_VALUE;
        rule.negativeEffectPlaceHolders[1].pType = ParamTypes.UINT;
        rule.negativeEffectPlaceHolders[1].typeSpecificIndex = 2;
        rule.negativeEffectPlaceHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.negativeEffectPlaceHolders[2].pType = ParamTypes.UINT;
        rule.negativeEffectPlaceHolders[2].typeSpecificIndex = 1;
        rule.negativeEffectPlaceHolders[2].flags = FLAG_FOREIGN_CALL;
        rule.negativeEffectPlaceHolders[3].pType = ParamTypes.UINT;
        rule.negativeEffectPlaceHolders[3].typeSpecificIndex = 2;
        rule.negativeEffectPlaceHolders[3].flags = FLAG_FOREIGN_CALL;

        uint256[] memory negInstructionSet = new uint256[](14);
        negInstructionSet[0] = uint256(LogicalOp.NUM);
        negInstructionSet[1] = uint256(0);
        negInstructionSet[2] = uint256(LogicalOp.TRU);
        negInstructionSet[3] = uint256(1);
        negInstructionSet[4] = uint256(0);
        negInstructionSet[5] = uint256(TrackerTypes.MEMORY);
        negInstructionSet[6] = uint256(LogicalOp.NUM);
        negInstructionSet[7] = uint256(47);
        negInstructionSet[8] = uint256(LogicalOp.TRU);
        negInstructionSet[9] = uint256(2);
        negInstructionSet[10] = uint256(2);
        negInstructionSet[11] = uint256(TrackerTypes.MEMORY);
        negInstructionSet[12] = uint256(LogicalOp.PLH);
        negInstructionSet[13] = uint256(0);

        rule.negEffects = new Effect[](1);
        rule.negEffects[0].instructionSet = negInstructionSet;
        rule.negEffects[0].effectType = EffectTypes.EXPRESSION;
        rule.negEffects[0].valid = true;

        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_revert;
        rule.posEffects[0].valid = true;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        vm.stopPrank();

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 1000);
        vm.startPrank(userContractAddress);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        bytes memory trackerValue = RulesEngineComponentFacet(address(red)).getTracker(policyIds[0], 1).trackerValue;
        assertEq(trackerValue, abi.encode(0));
        trackerValue = RulesEngineComponentFacet(address(red)).getTracker(policyIds[0], 2).trackerValue;
        assertEq(trackerValue, abi.encode(47));
    }

    // STATIC ARRAY TESTS

    function testRulesEngine_Unit_StaticArrayTracker_UintArray() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();

        // build tracker for static uint array
        Trackers memory tracker;
        tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
        tracker.set = true;

        // Create initial array
        uint256[] memory initialArray = new uint256[](2);
        initialArray[0] = 100;
        initialArray[1] = 200;
        tracker.trackerValue = abi.encode(initialArray);

        setupRuleWithTracker2(policyId, tracker, TrackerArrayTypes.UINT_ARRAY);

        // Create updated array for the function call
        uint256[] memory updatedArray = new uint256[](3);
        updatedArray[0] = 300;
        updatedArray[1] = 400;
        updatedArray[2] = 500;

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(updatedArray)
        );

        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        vm.startSnapshotGas("StaticArrayTracker_UintArray");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory trackerBytes = abi.decode(tracker.trackerValue, (bytes));
        uint256[] memory resultArray = abi.decode(trackerBytes, (uint256[]));
        assertEq(resultArray.length, 3);
        assertEq(resultArray[0], 300);
        assertEq(resultArray[1], 400);
        assertEq(resultArray[2], 500);

        // Test with empty array
        uint256[] memory emptyArray = new uint256[](0);

        bytes memory emptyArguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(emptyArray)
        );

        RulesEngineProcessorFacet(address(red)).checkPolicies(emptyArguments);

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory emptyTrackerBytes = abi.decode(tracker.trackerValue, (bytes));
        uint256[] memory emptyResultArray = abi.decode(emptyTrackerBytes, (uint256[]));
        assertEq(emptyResultArray.length, 0);
    }

    function testRulesEngine_Unit_StaticArrayTracker_EmptyArray() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();

        // build tracker for static uint array
        Trackers memory tracker;
        tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
        tracker.set = true;

        // Create empty array
        uint256[] memory emptyArray = new uint256[](0);
        tracker.trackerValue = abi.encode(emptyArray);

        setupRuleWithTracker2(policyId, tracker, TrackerArrayTypes.UINT_ARRAY);

        // Create another empty array for the function call
        uint256[] memory updatedEmptyArray = new uint256[](0);

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(updatedEmptyArray)
        );

        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        vm.startSnapshotGas("StaticArrayTracker_EmptyArray");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory trackerBytes = abi.decode(tracker.trackerValue, (bytes));
        uint256[] memory resultArray = abi.decode(trackerBytes, (uint256[]));
        assertEq(resultArray.length, 0);

        // Test with non-empty array update (should work but replace the empty array)
        uint256[] memory nonEmptyArray = new uint256[](2);
        nonEmptyArray[0] = 1;
        nonEmptyArray[1] = 2;

        bytes memory nonEmptyArguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(nonEmptyArray)
        );

        RulesEngineProcessorFacet(address(red)).checkPolicies(nonEmptyArguments);

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory nonEmptyTrackerBytes = abi.decode(tracker.trackerValue, (bytes));
        uint256[] memory nonEmptyResultArray = abi.decode(nonEmptyTrackerBytes, (uint256[]));
        assertEq(nonEmptyResultArray.length, 2);
        assertEq(nonEmptyResultArray[0], 1);
        assertEq(nonEmptyResultArray[1], 2);
    }

    function testRulesEngine_Unit_TrackerAsConditional_String() public ifDeploymentTestsEnabled resetsGlobalVariables {
        /// create tracker value (string value)
        string memory val1 = "trackerValue1";
        string memory badVal = "trackerValueWrong";
        bytes memory trackerValue = abi.encode(val1); // value for 0x7654321

        uint256 policyId = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyId);
        /// create tracker struct for address→string mapping
        Trackers memory tracker;
        tracker.pType = ParamTypes.STR; // tracker stores string values
        tracker.trackerValue = trackerValue;

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = RulesEngineComponentFacet(address(red)).createTracker(
            policyId,
            tracker,
            trackerName,
            TrackerArrayTypes.VOID
        );
        {
            // validate tracker
            Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
            assertFalse(returnedTracker.mapped);
            assertEq(returnedTracker.trackerValue, abi.encodePacked(keccak256(abi.encode(val1))), "not val1");
            assertEq(trackerIndex, 1);
        }

        // Rule execution
        // setup
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        Rule memory rule;
        uint256 ruleId;
        {
            rule.placeHolders = new Placeholder[](2);
            // placeholder zero is the address of the receipient
            rule.placeHolders[0].pType = ParamTypes.STR;
            rule.placeHolders[0].typeSpecificIndex = 2; // data
            // placeholder 1 is the mapped tracker value of the _to_ address
            rule.placeHolders[1].pType = ParamTypes.STR;
            rule.placeHolders[1].typeSpecificIndex = uint128(trackerIndex);
            rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;

            // compare string value passed as data in an ERC20 transfer against the tracker value. True if they are the same. False otherwise
            rule.instructionSet = new uint256[](7);
            rule.instructionSet[0] = uint256(LogicalOp.PLH); // we place the value to check against at mem[0] (the data of transfer)
            rule.instructionSet[1] = 0; // placeholder[0]
            rule.instructionSet[2] = uint256(LogicalOp.PLH); // we get the value of the mapped tracker, and place it in mem[1]
            rule.instructionSet[3] = 1; // get the key from mem[0]
            rule.instructionSet[4] = uint256(LogicalOp.EQ); // we compare mem[1] agains mem[0]
            rule.instructionSet[5] = 1;
            rule.instructionSet[6] = 0;

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        }
        {
            uint[][] memory _ruleIds = new uint[][](1);
            _ruleIds[0] = new uint[](1);
            _ruleIds[0][0] = ruleId;
            bytes4[] memory _callingFunctions = new bytes4[](1);
            _callingFunctions[0] = bytes4(keccak256(bytes(callingFunction)));
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                _callingFunctions,
                _ruleIds,
                PolicyType.CLOSED_POLICY,
                policyName,
                policyDescription
            );
        }
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        vm.stopPrank();

        // positive case: we check that the tracker value is val1 (it should)
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0xbabe), 1000, val1); // 1000 is a random value completely irrelevant for the test
        vm.startPrank(userContractAddress);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // negative case: we check that the tracker value is badVal (it shouldn't. We expect a revert in this case)
        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0xbabe), 1000, badVal); // 1000 is a random value completely irrelevant for the test
        vm.startPrank(userContractAddress);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_TrackerAsConditional_Bytes() public ifDeploymentTestsEnabled resetsGlobalVariables {
        /// create tracker value (string value)
        bytes memory val1 = "trackerValue1";
        bytes memory badVal = "trackerValueWrong";
        bytes memory trackerValue = abi.encode(val1); // value for 0x7654321

        uint256 policyId = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyId);
        /// create tracker struct for address→string mapping
        Trackers memory tracker;
        tracker.pType = ParamTypes.STR; // tracker stores string values
        tracker.trackerValue = trackerValue;

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = RulesEngineComponentFacet(address(red)).createTracker(
            policyId,
            tracker,
            trackerName,
            TrackerArrayTypes.VOID
        );
        {
            // validate tracker
            Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
            assertFalse(returnedTracker.mapped);
            assertEq(returnedTracker.trackerValue, abi.encodePacked(keccak256(abi.encode(val1))), "not val1");
            assertEq(trackerIndex, 1);
        }

        // Rule execution
        // setup
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        Rule memory rule;
        uint256 ruleId;
        {
            rule.placeHolders = new Placeholder[](2);
            // placeholder zero is the address of the receipient
            rule.placeHolders[0].pType = ParamTypes.BYTES;
            rule.placeHolders[0].typeSpecificIndex = 2; // data
            // placeholder 1 is the mapped tracker value of the _to_ address
            rule.placeHolders[1].pType = ParamTypes.BYTES;
            rule.placeHolders[1].typeSpecificIndex = uint128(trackerIndex);
            rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;

            // compare string value passed as data in an ERC20 transfer against the tracker value. True if they are the same. False otherwise
            rule.instructionSet = new uint256[](7);
            rule.instructionSet[0] = uint256(LogicalOp.PLH); // we place the value to check against at mem[0] (the data of transfer)
            rule.instructionSet[1] = 0; // placeholder[0]
            rule.instructionSet[2] = uint256(LogicalOp.PLH); // we get the value of the mapped tracker, and place it in mem[1]
            rule.instructionSet[3] = 1; // get the key from mem[0]
            rule.instructionSet[4] = uint256(LogicalOp.EQ); // we compare mem[1] agains mem[0]
            rule.instructionSet[5] = 1;
            rule.instructionSet[6] = 0;

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        }
        {
            uint[][] memory _ruleIds = new uint[][](1);
            _ruleIds[0] = new uint[](1);
            _ruleIds[0][0] = ruleId;
            bytes4[] memory _callingFunctions = new bytes4[](1);
            _callingFunctions[0] = bytes4(keccak256(bytes(callingFunction)));
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                _callingFunctions,
                _ruleIds,
                PolicyType.CLOSED_POLICY,
                policyName,
                policyDescription
            );
        }
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        vm.stopPrank();

        // positive case: we check that the tracker value is val1 (it should)
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0xbabe), 1000, val1); // 1000 is a random value completely irrelevant for the test
        vm.startPrank(userContractAddress);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // negative case: we check that the tracker value is badVal (it shouldn't. We expect a revert in this case)
        arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0xbabe), 1000, badVal); // 1000 is a random value completely irrelevant for the test
        vm.startPrank(userContractAddress);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_StaticArrayTracker_LargeArray() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();

        // build tracker for static uint array
        Trackers memory tracker;
        tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
        tracker.set = true;

        // Create large uint array (100 elements)
        uint256[] memory initialArray = new uint256[](100);
        for (uint256 i = 0; i < 100; i++) {
            initialArray[i] = i * 10;
        }
        tracker.trackerValue = abi.encode(initialArray);

        setupRuleWithTracker2(policyId, tracker, TrackerArrayTypes.UINT_ARRAY);

        // Create updated large array for the function call
        uint256[] memory updatedArray = new uint256[](50);
        for (uint256 i = 0; i < 50; i++) {
            updatedArray[i] = i * 20;
        }

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(updatedArray)
        );

        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        vm.startSnapshotGas("StaticArrayTracker_LargeArray");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory trackerBytes = abi.decode(tracker.trackerValue, (bytes));
        uint256[] memory resultArray = abi.decode(trackerBytes, (uint256[]));
        assertEq(resultArray.length, 50);
        assertEq(resultArray[0], 0);
        assertEq(resultArray[25], 500);
        assertEq(resultArray[49], 980);

        // Test with very large array (might hit gas limits)
        uint256[] memory veryLargeArray = new uint256[](1000);
        for (uint256 i = 0; i < 1000; i++) {
            veryLargeArray[i] = i;
        }

        bytes memory veryLargeArguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(veryLargeArray)
        );

        RulesEngineProcessorFacet(address(red)).checkPolicies(veryLargeArguments);
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory largeTrackerBytes = abi.decode(tracker.trackerValue, (bytes));
        uint256[] memory largeResultArray = abi.decode(largeTrackerBytes, (uint256[]));
        assertEq(largeResultArray.length, 1000);
        assertEq(largeResultArray[0], 0);
        assertEq(largeResultArray[999], 999);
    }

    function testRulesEngine_Unit_StaticArrayTracker_AddressArray() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();

        // build tracker for static address array
        Trackers memory tracker;
        tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
        tracker.set = true;

        // Create initial address array
        address[] memory initialArray = new address[](2);
        initialArray[0] = address(0x1234567890123456789012345678901234567890);
        initialArray[1] = address(0x0987654321098765432109876543210987654321);
        tracker.trackerValue = abi.encode(initialArray);

        setupRuleWithTracker2(policyId, tracker, TrackerArrayTypes.ADDR_ARRAY);

        // Create updated address array for the function call
        address[] memory updatedArray = new address[](3);
        updatedArray[0] = address(0xaBcDef1234567890123456789012345678901234);
        updatedArray[1] = address(0xFedCba0987654321098765432109876543210987);
        updatedArray[2] = address(0x1111111111111111111111111111111111111111);

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(updatedArray)
        );

        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        vm.startSnapshotGas("StaticArrayTracker_AddressArray");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory trackerBytes = abi.decode(tracker.trackerValue, (bytes));
        address[] memory resultArray = abi.decode(trackerBytes, (address[]));
        assertEq(resultArray.length, 3);
        assertEq(resultArray[0], address(0xaBcDef1234567890123456789012345678901234));
        assertEq(resultArray[1], address(0xFedCba0987654321098765432109876543210987));
        assertEq(resultArray[2], address(0x1111111111111111111111111111111111111111));

        // Test with array containing zero addresses (should be valid)
        address[] memory zeroArray = new address[](2);
        zeroArray[0] = address(0);
        zeroArray[1] = address(0);

        bytes memory zeroArguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(zeroArray)
        );

        RulesEngineProcessorFacet(address(red)).checkPolicies(zeroArguments);

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory zeroTrackerBytes = abi.decode(tracker.trackerValue, (bytes));
        address[] memory zeroResultArray = abi.decode(zeroTrackerBytes, (address[]));
        assertEq(zeroResultArray.length, 2);
        assertEq(zeroResultArray[0], address(0));
        assertEq(zeroResultArray[1], address(0));
    }

    function testRulesEngine_Unit_StaticArrayTracker_BoolArray() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();

        // build tracker for static bool array
        Trackers memory tracker;
        tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
        tracker.set = true;

        // Create initial bool array
        bool[] memory initialArray = new bool[](4);
        initialArray[0] = true;
        initialArray[1] = false;
        initialArray[2] = true;
        initialArray[3] = false;
        tracker.trackerValue = abi.encode(initialArray);

        setupRuleWithTracker2(policyId, tracker, TrackerArrayTypes.BOOL_ARRAY);

        // Create updated bool array for the function call
        bool[] memory updatedArray = new bool[](3);
        updatedArray[0] = false;
        updatedArray[1] = true;
        updatedArray[2] = false;

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(updatedArray)
        );

        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        vm.startSnapshotGas("StaticArrayTracker_BoolArray");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory trackerBytes = abi.decode(tracker.trackerValue, (bytes));
        bool[] memory resultArray = abi.decode(trackerBytes, (bool[]));
        assertEq(resultArray.length, 3);
        assertFalse(resultArray[0]);
        assertTrue(resultArray[1]);
        assertFalse(resultArray[2]);

        // Test with all-false array (edge case)
        bool[] memory allFalseArray = new bool[](3);
        // All elements are false by default

        bytes memory allFalseArguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(allFalseArray)
        );

        RulesEngineProcessorFacet(address(red)).checkPolicies(allFalseArguments);

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory allFalseTrackerBytes = abi.decode(tracker.trackerValue, (bytes));
        bool[] memory allFalseResultArray = abi.decode(allFalseTrackerBytes, (bool[]));
        assertEq(allFalseResultArray.length, 3);
        assertFalse(allFalseResultArray[0]);
        assertFalse(allFalseResultArray[1]);
        assertFalse(allFalseResultArray[2]);
    }

    // DYNAMIC ARRAY TESTS

    function testRulesEngine_Unit_DynamicArrayTracker_StringArray() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();

        // build tracker for dynamic string array
        Trackers memory tracker;
        tracker.pType = ParamTypes.DYNAMIC_TYPE_ARRAY;
        tracker.set = true;

        // Create initial string array
        string[] memory initialArray = new string[](3);
        initialArray[0] = "hello";
        initialArray[1] = "world";
        initialArray[2] = "test";
        tracker.trackerValue = abi.encode(initialArray);

        setupRuleWithTracker2(policyId, tracker, TrackerArrayTypes.STR_ARRAY);

        // Create updated string array for the function call
        string[] memory updatedArray = new string[](2);
        updatedArray[0] = "updated";
        updatedArray[1] = "strings";

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(updatedArray)
        );

        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        vm.startSnapshotGas("DynamicArrayTracker_StringArray");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory trackerBytes = abi.decode(tracker.trackerValue, (bytes));
        string[] memory resultArray = abi.decode(trackerBytes, (string[]));
        assertEq(resultArray.length, 2);
        assertEq(resultArray[0], "updated");
        assertEq(resultArray[1], "strings");

        // Test with array containing empty strings
        string[] memory emptyStringArray = new string[](2);
        emptyStringArray[0] = "";
        emptyStringArray[1] = "";

        bytes memory emptyStringArguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(emptyStringArray)
        );

        RulesEngineProcessorFacet(address(red)).checkPolicies(emptyStringArguments);

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory emptyStringTrackerBytes = abi.decode(tracker.trackerValue, (bytes));
        string[] memory emptyStringResultArray = abi.decode(emptyStringTrackerBytes, (string[]));
        assertEq(emptyStringResultArray.length, 2);
        assertEq(emptyStringResultArray[0], "");
        assertEq(emptyStringResultArray[1], "");
    }

    function testRulesEngine_Unit_DynamicArrayTracker_EmptyStringArray() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();

        // build tracker for dynamic string array
        Trackers memory tracker;
        tracker.pType = ParamTypes.DYNAMIC_TYPE_ARRAY;
        tracker.set = true;

        // Create empty string array
        string[] memory emptyArray = new string[](0);
        tracker.trackerValue = abi.encode(emptyArray);

        setupRuleWithTracker2(policyId, tracker, TrackerArrayTypes.STR_ARRAY);

        // Create another empty string array for the function call
        string[] memory updatedEmptyArray = new string[](0);

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(updatedEmptyArray)
        );

        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        vm.startSnapshotGas("DynamicArrayTracker_EmptyStringArray");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory trackerBytes = abi.decode(tracker.trackerValue, (bytes));
        string[] memory resultArray = abi.decode(trackerBytes, (string[]));
        assertEq(resultArray.length, 0);

        // Test with non-empty array update (should work but replace the empty array)
        string[] memory nonEmptyArray = new string[](2);
        nonEmptyArray[0] = "first";
        nonEmptyArray[1] = "second";

        bytes memory nonEmptyArguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(nonEmptyArray)
        );

        RulesEngineProcessorFacet(address(red)).checkPolicies(nonEmptyArguments);

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory nonEmptyTrackerBytes = abi.decode(tracker.trackerValue, (bytes));
        string[] memory nonEmptyResultArray = abi.decode(nonEmptyTrackerBytes, (string[]));
        assertEq(nonEmptyResultArray.length, 2);
        assertEq(nonEmptyResultArray[0], "first");
        assertEq(nonEmptyResultArray[1], "second");
    }

    function testRulesEngine_Unit_DynamicArrayTracker_LargeStringArray() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();

        // build tracker for dynamic string array
        Trackers memory tracker;
        tracker.pType = ParamTypes.DYNAMIC_TYPE_ARRAY;
        tracker.set = true;

        // Create large string array (50 elements)
        string[] memory initialArray = new string[](50);
        for (uint256 i = 0; i < 50; i++) {
            initialArray[i] = string(abi.encodePacked("item_", vm.toString(i)));
        }
        tracker.trackerValue = abi.encode(initialArray);

        setupRuleWithTracker2(policyId, tracker, TrackerArrayTypes.STR_ARRAY);

        // Create updated string array for the function call
        string[] memory updatedArray = new string[](25);
        for (uint256 i = 0; i < 25; i++) {
            updatedArray[i] = string(abi.encodePacked("updated_", vm.toString(i)));
        }

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(updatedArray)
        );

        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        vm.startSnapshotGas("DynamicArrayTracker_LargeStringArray");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory trackerBytes = abi.decode(tracker.trackerValue, (bytes));
        string[] memory resultArray = abi.decode(trackerBytes, (string[]));
        assertEq(resultArray.length, 25);
        assertEq(resultArray[0], "updated_0");
        assertEq(resultArray[12], "updated_12");
        assertEq(resultArray[24], "updated_24");

        // Create extremely large string array with very long strings
        string[] memory extremeArray = new string[](5);
        for (uint256 i = 0; i < 5; i++) {
            // Create very long strings
            string memory longString = "";
            for (uint256 j = 0; j < 100; j++) {
                longString = string(abi.encodePacked(longString, "verylongstringcontent"));
            }
            extremeArray[i] = longString;
        }

        bytes memory extremeArguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(extremeArray)
        );

        RulesEngineProcessorFacet(address(red)).checkPolicies(extremeArguments);
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory extremeTrackerBytes = abi.decode(tracker.trackerValue, (bytes));
        string[] memory extremeResultArray = abi.decode(extremeTrackerBytes, (string[]));
        assertEq(extremeResultArray.length, 5);
        assertTrue(bytes(extremeResultArray[0]).length > 1000); // Very long string
    }

    function testRulesEngine_Unit_DynamicArrayTracker_BytesArray() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();

        // build tracker for dynamic bytes array
        Trackers memory tracker;
        tracker.pType = ParamTypes.DYNAMIC_TYPE_ARRAY;
        tracker.set = true;

        // Create initial bytes array
        bytes[] memory initialArray = new bytes[](3);
        initialArray[0] = hex"deadbeef";
        initialArray[1] = hex"cafebabe";
        initialArray[2] = hex"0123456789abcdef";
        tracker.trackerValue = abi.encode(initialArray);

        setupRuleWithTracker2(policyId, tracker, TrackerArrayTypes.BYTES_ARRAY);

        // Create updated bytes array for the function call
        bytes[] memory updatedArray = new bytes[](2);
        updatedArray[0] = hex"fedcba9876543210";
        updatedArray[1] = hex"1122334455667788";

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(updatedArray)
        );

        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        vm.startSnapshotGas("DynamicArrayTracker_BytesArray");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory trackerBytes = abi.decode(tracker.trackerValue, (bytes));
        bytes[] memory resultArray = abi.decode(trackerBytes, (bytes[]));
        assertEq(resultArray.length, 2);
        assertEq(resultArray[0], hex"fedcba9876543210");
        assertEq(resultArray[1], hex"1122334455667788");

        // Test with bytes array containing empty bytes elements
        bytes[] memory emptyBytesArray = new bytes[](2);
        emptyBytesArray[0] = hex"";
        emptyBytesArray[1] = hex"";

        bytes memory emptyBytesArguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            abi.encode(emptyBytesArray)
        );

        RulesEngineProcessorFacet(address(red)).checkPolicies(emptyBytesArguments);

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory emptyBytesTrackerBytes = abi.decode(tracker.trackerValue, (bytes));
        bytes[] memory emptyBytesResultArray = abi.decode(emptyBytesTrackerBytes, (bytes[]));
        assertEq(emptyBytesResultArray.length, 2);
        assertEq(emptyBytesResultArray[0].length, 0);
        assertEq(emptyBytesResultArray[1].length, 0);
    }

    function testRulesEngine_Unit_StaticArrayTracker_MaliciousActor() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        {
            Trackers memory tracker;
            tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
            tracker.set = true;
            uint256[] memory emptyArray = new uint256[](0);
            tracker.trackerValue = abi.encode(emptyArray);
            setupRuleWithTracker2(policyId, tracker, TrackerArrayTypes.UINT_ARRAY);
        }

        // Normal operation: Update tracker legitimately
        {
            uint256[] memory updatedArray = new uint256[](2);
            updatedArray[0] = 1;
            updatedArray[1] = 2;
            bytes memory arguments = abi.encodeWithSelector(
                bytes4(keccak256(bytes(callingFunction))),
                address(0x7654321),
                5,
                abi.encode(updatedArray)
            );
            vm.startPrank(address(userContract));
            RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
            vm.stopPrank();
        }

        // Verify normal operation worked
        {
            Trackers memory normalTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
            uint256[] memory resultArray = abi.decode(abi.decode(normalTracker.trackerValue, (bytes)), (uint256[]));
            assertEq(resultArray.length, 2);
            assertEq(resultArray[0], 1);
            assertEq(resultArray[1], 2);
        }

        // Direct tracker manipulation
        address maliciousActor = address(0xBAD);
        {
            vm.startPrank(maliciousActor);
            Trackers memory maliciousTracker;
            maliciousTracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
            maliciousTracker.set = true;
            uint256[] memory maliciousArray = new uint256[](1);
            maliciousArray[0] = 999;
            maliciousTracker.trackerValue = abi.encode(maliciousArray);

            vm.expectRevert("Not Authorized To Policy");
            RulesEngineComponentFacet(address(red)).updateTracker(policyId, 1, maliciousTracker);
            vm.stopPrank();
        }

        // Tracker values should remain unchanged
        {
            Trackers memory finalTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
            uint256[] memory finalArray = abi.decode(abi.decode(finalTracker.trackerValue, (bytes)), (uint256[]));
            assertEq(finalArray.length, 2);
            assertEq(finalArray[0], 1);
            assertEq(finalArray[1], 2);
        }
    }

    function testRulesEngine_Unit_StaticArrayTracker_MaliciousContract() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();

        // Build tracker for static uint array
        Trackers memory tracker;
        tracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
        tracker.set = true;
        uint256[] memory emptyArray = new uint256[](0);
        tracker.trackerValue = abi.encode(emptyArray);

        // Set up rule with tracker
        setupRuleWithTracker2(policyId, tracker, TrackerArrayTypes.UINT_ARRAY);
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        // Legitimate contract performs normal operation to populate tracker
        {
            uint256[] memory normalArray = new uint256[](2);
            normalArray[0] = 100;
            normalArray[1] = 200;

            bytes memory legitimateArguments = abi.encodeWithSelector(
                bytes4(keccak256(bytes(callingFunction))),
                address(0x1234567),
                10,
                abi.encode(normalArray)
            );

            vm.startPrank(address(userContract));
            RulesEngineProcessorFacet(address(red)).checkPolicies(legitimateArguments);
            vm.stopPrank();
        }

        // Verify tracker was set correctly by legitimate contract
        {
            Trackers memory currentTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
            uint256[] memory currentArray = abi.decode(abi.decode(currentTracker.trackerValue, (bytes)), (uint256[]));
            assertEq(currentArray.length, 2);
            assertEq(currentArray[0], 100);
            assertEq(currentArray[1], 200);
        }

        // Deploy a second contract to act as potential malicious contract
        ExampleUserContract maliciousContract = new ExampleUserContract();
        maliciousContract.setRulesEngineAddress(address(red));
        maliciousContract.setCallingContractAdmin(address(maliciousContract));

        // malicious actor tries to directly update tracker
        vm.startPrank(address(maliciousContract));
        {
            Trackers memory maliciousTracker;
            maliciousTracker.pType = ParamTypes.STATIC_TYPE_ARRAY;
            maliciousTracker.set = true;
            uint256[] memory maliciousArray = new uint256[](1);
            maliciousArray[0] = 999;
            maliciousTracker.trackerValue = abi.encode(maliciousArray);

            vm.expectRevert("Not Authorized To Policy");
            RulesEngineComponentFacet(address(red)).updateTracker(policyId, 1, maliciousTracker);
        }
        vm.stopPrank();

        //  Malicious contract tries to apply policy to itself
        vm.startPrank(address(maliciousContract));
        vm.expectRevert("Only verified policy subscriber can apply closed policies");
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(maliciousContract), policyIds);
        vm.stopPrank();

        // tracker values should remain completely unchanged
        {
            Trackers memory finalTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
            uint256[] memory finalArray = abi.decode(abi.decode(finalTracker.trackerValue, (bytes)), (uint256[]));
            assertEq(finalArray.length, 2, "Tracker length should remain unchanged");
            assertEq(finalArray[0], 100, "First tracker value should remain unchanged");
            assertEq(finalArray[1], 200, "Second tracker value should remain unchanged");
        }
    }

    function testRulesEngine_Unit_MappedTracker_MsgData_Storage() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();

        // Crate and setup mapped tracker for msg.data storage
        uint256 trackerIndex = _createMsgDataMappedTracker(policyId);

        // Create and setup rule with TRUM opcode
        uint256 ruleId = _createMsgDataStorageRule(policyId, trackerIndex);

        // Setup policy with calling function and rule
        _setupPolicyWithMsgDataRule(policyId, ruleId);

        // Execute test and verify results
        _executeMsgDataTest(policyId, trackerIndex);
    }

    function _createMsgDataMappedTracker(uint256 policyId) internal returns (uint256) {
        Trackers memory tracker;
        tracker.set = true;
        tracker.mapped = true;
        tracker.pType = ParamTypes.BYTES; // Value type: bytes (for msg.data)
        tracker.trackerKeyType = ParamTypes.ADDR; // Key type: address (for msg.sender)

        // Need to provide at least one key-value pair to ensure tracker is properly stored
        bytes[] memory trackerKeys = new bytes[](1);
        trackerKeys[0] = abi.encode(address(0x0123)); // dummy key

        bytes[] memory trackerValues = new bytes[](1);
        trackerValues[0] = abi.encode(bytes("dummy")); // dummy value

        return
            RulesEngineComponentFacet(address(red)).createMappedTracker(
                policyId,
                tracker,
                "msgDataTracker",
                trackerKeys,
                trackerValues,
                TrackerArrayTypes.VOID
            );
    }

    function _createMsgDataStorageRule(uint256 policyId, uint256 trackerIndex) internal returns (uint256) {
        Rule memory rule;

        // Simple condition that always passes (1 == 1)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        // Set up effect placeholders for storing data
        rule.positiveEffectPlaceHolders = new Placeholder[](2);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.BYTES;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 0;
        rule.positiveEffectPlaceHolders[0].flags = uint8(GLOBAL_MSG_DATA << SHIFT_GLOBAL_VAR);
        rule.positiveEffectPlaceHolders[1].pType = ParamTypes.ADDR;
        rule.positiveEffectPlaceHolders[1].typeSpecificIndex = 0;
        rule.positiveEffectPlaceHolders[1].flags = uint8(GLOBAL_MSG_SENDER << SHIFT_GLOBAL_VAR);

        // Create positive effect: Store msg.data in mapped tracker using TRUM
        rule.posEffects = new Effect[](1);
        rule.posEffects[0].valid = true;
        rule.posEffects[0].effectType = EffectTypes.EXPRESSION;
        rule.posEffects[0].text = "";
        rule.posEffects[0].errorMessage = "";

        // TRUM instruction to store msg.data with sender key
        // PLH(value) PLH(key) TRUM trackerIndex valueIndex keyIndex PLACE_HOLDER
        rule.posEffects[0].instructionSet = new uint256[](9);
        rule.posEffects[0].instructionSet[0] = uint(LogicalOp.PLH);
        rule.posEffects[0].instructionSet[1] = 0; // msg.data placeholder index
        rule.posEffects[0].instructionSet[2] = uint(LogicalOp.PLH);
        rule.posEffects[0].instructionSet[3] = 1; // msg.sender placeholder index
        rule.posEffects[0].instructionSet[4] = uint(LogicalOp.TRUM);
        rule.posEffects[0].instructionSet[5] = trackerIndex;
        rule.posEffects[0].instructionSet[6] = 0; // value (msg.data) from placeholder 0
        rule.posEffects[0].instructionSet[7] = 1; // key (msg.sender) from placeholder 1
        rule.posEffects[0].instructionSet[8] = uint(TrackerTypes.PLACE_HOLDER);

        rule.negEffects = new Effect[](0);

        return RulesEngineRuleFacet(address(red)).createRule(policyId, rule, "msgDataStorageRule", "Stores msg.data in mapped tracker");
    }

    function _setupPolicyWithMsgDataRule(uint256 policyId, uint256 ruleId) internal {
        // Set up calling function
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

        // Update policy
        bytes4[] memory callingFunctions = new bytes4[](1);
        callingFunctions[0] = callingFunctionId;
        uint256[][] memory ruleIds = new uint256[][](1);
        ruleIds[0] = new uint256[](1);
        ruleIds[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            ruleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );

        // Apply policy to user contract
        vm.startPrank(callingContractAdmin);
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContract), policyIds);
        vm.stopPrank();
    }

    function _executeMsgDataTest(uint256 policyId, uint256 trackerIndex) internal {
        // Execute the policy with specific calldata to store msg.data
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), uint256(100));

        // Execute policy - this should store msg.data in the mapped tracker
        vm.prank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // Check that data was stored using the correct key format (abi.encoded address)
        bytes memory keyAsBytes = abi.encode(address(userContract));
        bytes memory storedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, trackerIndex, keyAsBytes);

        // Verify that some data was stored (non-empty)
        assertTrue(storedValue.length > 0, "No data stored in mapped tracker");

        // Decode the stored hash
        bytes32 storedHash = abi.decode(storedValue, (bytes32));

        // Calculate the expected hash of the msg.data
        bytes memory actualMsgData = abi.encodeWithSelector(RulesEngineProcessorFacet.checkPolicies.selector, arguments);

        // Replicate the exact _handleGlobalVar implementation
        bytes memory encodedData = new bytes(actualMsgData.length + 64);

        // Replicate the exact assembly from _handleGlobalVar
        assembly {
            mstore(add(encodedData, 32), 0x20)
            mstore(add(encodedData, 64), mload(actualMsgData))
        }

        // Copy the actual data starting at position 64
        // This overwrites the length that was stored at position 64
        for (uint256 i = 0; i < actualMsgData.length; i++) {
            encodedData[i + 64] = actualMsgData[i];
        }

        bytes32 expectedHash = keccak256(encodedData);

        // Verify that the stored hash matches the expected hash
        assertEq(storedHash, expectedHash, "Stored hash should match expected hash of msg.data");
    }
}
