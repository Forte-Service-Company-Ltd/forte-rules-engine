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
        setupRuleWithTracker2(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5, bytes("post"));
        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        vm.startSnapshotGas("CheckRules_Explicit_WithTrackerUpdateEffectBytes");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory comparison = abi.encode("post");
        assertEq(tracker.trackerValue, comparison);
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
        setupRuleWithTracker2(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5, "post");
        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        vm.startSnapshotGas("CheckRules_Explicit_WithTrackerUpdateEffectString");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory comparison = abi.encode("post");
        assertEq(tracker.trackerValue, comparison);
    }

    function testRulesEngine_Unit_CheckRules_WithTrackerValue() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithTracker(2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        vm.startSnapshotGas("CheckRules_WithTrackerValue");
        bool retVal = userContract.transfer(address(0x7654321), 3);
        vm.stopSnapshotGas();
        assertTrue(retVal);
    }

    function testRulesEngine_Unit_CheckRules_WithTrackerValue_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithTracker(7);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 6);
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
    }

    //// Mapped Trackers
    /// trackers as a rule conditional
    /// uint to uint trackers
    function testRulesEngine_Unit_MappedTrackerAsConditional_Uint_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
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

        /// set up rule
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

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, 1);
        vm.startSnapshotGas("MappedTrackerAsConditional_Uint_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_MappedTrackerAsConditional_Uint_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
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

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
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

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(value, abi.encode(1000000000));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 2000000000);
        vm.expectRevert(abi.encodePacked(revert_text));
        vm.startSnapshotGas("MappedTrackerAsConditional_UintToUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    /// uint to address
    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToAddress_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
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

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1);
        vm.startSnapshotGas("MappedTrackerAsConditional_UintToAddress");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToAddress_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.UINT;

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
            0, // key type specific index
            1, // value type specific index
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

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// address to uint
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToUint_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
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

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        // address to uint mapped tracker (is the amount to allowed for address)
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1);
        vm.startSnapshotGas("MappedTrackerAsConditional_AddressToUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToUint_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
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
            ParamTypes.UINT, // key type
            ParamTypes.ADDR, // value type
            ParamTypes.ADDR, // tracker type
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

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// address to Address
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToAddress_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; // set the ParamType for the tracker value to be decoded as
        tracker.trackerKeyType = ParamTypes.ADDR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x7654321)); // value 1
        trackerValues[1] = abi.encode(address(0x7654321)); // value 2

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

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        // address to Address mapped tracker (Tracked addresses can only transfer to address(0x7654321));
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1);
        vm.startSnapshotGas("MappedTrackerAsConditional_AddressToAddress");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToAddress_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; // set the ParamType for the tracker value to be decoded as
        tracker.trackerKeyType = ParamTypes.ADDR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x7654321)); // value 1
        trackerValues[1] = abi.encode(address(0x7654321)); // value 2

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
        assertEq(value, abi.encode(address(0x7654321)));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        // address to Address mapped tracker (Tracked addresses can only transfer to address(0x7654321));
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    // Uint to Bool
    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToBool_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
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
            0, // key type specific index
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

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, false);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// uint to bool
    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToBool_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
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

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, true);
        vm.startSnapshotGas("MappedTrackerAsConditional_UintToBool");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    // Bool to Uint
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToUint_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT;
        tracker.trackerKeyType = ParamTypes.BOOL;

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
            0, // key type specific index
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

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, false);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// bool to uint
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToUint_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
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
        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, true);
        vm.startSnapshotGas("MappedTrackerAsConditional_BoolToUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    // address to bool
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToBool_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
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
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, true);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// Address to Bool
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToBool_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
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
    }

    // Bool To Address
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToAddress_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.BOOL;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(true); // key 1
        trackerKeys[1] = abi.encode(false); // key 2

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

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(true));
        assertEq(value, abi.encode(address(0x7654321)));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, false);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// Bool To Address
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToAddress_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
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
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, true);
        vm.startSnapshotGas("MappedTrackerAsConditional_BoolToAddress");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    // Address to String
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToString_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.STR;
        tracker.trackerKeyType = ParamTypes.ADDR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode("trackerValue1"); // value 1
        trackerValues[1] = abi.encode("trackerValue2"); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.ADDR, // key type
            ParamTypes.STR, // value type
            ParamTypes.STR, // tracker type
            0, // key type specific index
            2, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode("trackerValue1"));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x1234567),
            2000000000,
            "trackerValue1"
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// Address to String
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToString_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.STR;
        tracker.trackerKeyType = ParamTypes.ADDR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode("trackerValue1"); // value 1
        trackerValues[1] = abi.encode("trackerValue2"); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.ADDR, // key type
            ParamTypes.STR, // value type
            ParamTypes.STR, // tracker type
            0, // key type specific index
            2, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode("trackerValue1"));
        assertEq(trackerIndex, 1);
        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, "trackerValue1");
        vm.startSnapshotGas("MappedTrackerAsConditional_AddressToString");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    // string to address
    // Address to String
    function testRulesEngine_Unit_MappedTrackerAsConditional_StringToAddress_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.STR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(string("trackerValue1")); // key 1
        trackerKeys[1] = abi.encode(string("trackerValue2")); // key 2

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
            ParamTypes.STR, // key type
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

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(string("trackerValue1"))
        );
        assertEq(value, abi.encode(address(0x7654321)));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x1234567),
            2000000000,
            "trackerValue1"
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// String to Address
    function testRulesEngine_Unit_MappedTrackerAsConditional_StringToAddress_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.STR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(string("trackerValue1")); // key 1
        trackerKeys[1] = abi.encode(string("trackerValue2")); // key 2

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
            ParamTypes.STR, // key type
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

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(string("trackerValue1"))
        );
        assertEq(value, abi.encode(address(0x7654321)));
        assertEq(trackerIndex, 1);
        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            string("trackerValue1")
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_StringToAddress");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    // String to Uint
    function testRulesEngine_Unit_MappedTrackerAsConditional_StringToUint() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
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
        assertEq(value, abi.encode(string("value1")));
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
        assertEq(value, abi.encode(string("enabled")));
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
        assertEq(value, abi.encode(string("admin")));
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
        assertEq(value, abi.encode(bytes("response1")));
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
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.BYTES;
        tracker.trackerKeyType = ParamTypes.ADDR;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(bytes("metadata1")); // value 1
        trackerValues[1] = abi.encode(bytes("metadata2")); // value 2

        /// create tracker name
        string memory trackerName = "tracker1";

        /// set up rule
        uint256 trackerIndex = _setupRuleWithMappedTracker(
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
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode(bytes("metadata1")));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional - positive path
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            bytes("metadata1")
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_AddressToBytes_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // negative path
        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            bytes("wrongMetadata")
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);
    }

    // Bytes to Bool
    function testRulesEngine_Unit_MappedTrackerAsConditional_BytesToBool() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
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
        assertEq(value, abi.encode(bytes("success")));
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
        assertEq(value, abi.encode(string("name1")));
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
        assertEq(value, abi.encode(bytes("data1")));
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
        assertEq(value, abi.encode(bytes("signature1")));
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
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToUint_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
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

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, 100);
        vm.startSnapshotGas("MappedTrackerUpdatedFromEffects_UintToUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(updatedValue, abi.encode(100));
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToUint_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
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

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, 100);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertNotEq(updatedValue, abi.encode(200));
    }

    // uint to address tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToAddress_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.UINT;
        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2
        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x1234567)); // value 1
        trackerValues[1] = abi.encode(address(0x7654321)); // value 2
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
        assertEq(value, abi.encode(address(0x1234567)));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1000000000,
            address(0x7654321)
        );
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(updatedValue, abi.encode(address(0x7654321)));
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToAddress_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.UINT;
        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2
        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x1234567)); // value 1
        trackerValues[1] = abi.encode(address(0x7654321)); // value 2
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
        assertEq(value, abi.encode(address(0x1234567)));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1000000000,
            address(0x7654321)
        );
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertNotEq(updatedValue, abi.encode(address(0x1234567)));
    }

    // address to Uint tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToUint_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT;
        tracker.trackerKeyType = ParamTypes.ADDR;
        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2
        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000); // value 1
        trackerValues[1] = abi.encode(2000); // value 2
        /// create tracker name
        string memory trackerName = "tracker1";
        /// set up rule
        ParamTypes trackerKeyTypes = ParamTypes.ADDR;

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

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode(1000));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, 20000);
        vm.startSnapshotGas("MappedTrackerUpdatedFromEffects_AddressToUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(updatedValue, abi.encode(20000));
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToUint_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT;
        tracker.trackerKeyType = ParamTypes.ADDR;
        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2
        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000); // value 1
        trackerValues[1] = abi.encode(2000); // value 2
        /// create tracker name
        string memory trackerName = "tracker1";
        /// set up rule
        ParamTypes trackerKeyTypes = ParamTypes.ADDR;

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

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode(1000));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, 20000);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertNotEq(updatedValue, abi.encode(1000));
    }

    // address to Address tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToAddress_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.ADDR;
        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x1234567)); // key 1
        trackerKeys[1] = abi.encode(address(0x7654321)); // key 2
        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x9999999)); // value 1
        trackerValues[1] = abi.encode(address(0x8888888)); // value 2
        /// create tracker name
        string memory trackerName = "tracker1";

        ParamTypes trackerKeyTypes = ParamTypes.ADDR;

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
        assertEq(uint256(returnedTracker.trackerKeyType), uint256(ParamTypes.ADDR));

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode(address(0x8888888)));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1000000000,
            address(0x7777)
        );
        vm.startSnapshotGas("MappedTrackerUpdatedFromEffects_AddressToAddress");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(updatedValue, abi.encode(address(0x7777)));
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToAddress_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.ADDR;
        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x1234567)); // key 1
        trackerKeys[1] = abi.encode(address(0x7654321)); // key 2
        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x9999999)); // value 1
        trackerValues[1] = abi.encode(address(0x8888888)); // value 2
        /// create tracker name
        string memory trackerName = "tracker1";

        ParamTypes trackerKeyTypes = ParamTypes.ADDR;
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

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode(address(0x8888888)));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1000000000,
            address(0x7777)
        );
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertNotEq(updatedValue, abi.encode(address(0x8888888)));
    }

    // address to bool tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToBool_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.BOOL;
        tracker.trackerKeyType = ParamTypes.ADDR;
        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x1234567)); // key 1
        trackerKeys[1] = abi.encode(address(0x7654321)); // key 2
        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(false); // value 1
        trackerValues[1] = abi.encode(false); // value 2
        /// create tracker name
        string memory trackerName = "tracker1";

        ParamTypes trackerKeyTypes = ParamTypes.ADDR;
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
        assertEq(uint256(returnedTracker.trackerKeyType), uint256(ParamTypes.ADDR));

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode(false));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, true);
        vm.startSnapshotGas("MappedTrackerUpdatedFromEffects_AddressToBool");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(updatedValue, abi.encode(true));
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToBool_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.BOOL;
        tracker.trackerKeyType = ParamTypes.ADDR;
        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x1234567)); // key 1
        trackerKeys[1] = abi.encode(address(0x7654321)); // key 2
        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(false); // value 1
        trackerValues[1] = abi.encode(false); // value 2
        /// create tracker name
        string memory trackerName = "tracker1";

        ParamTypes trackerKeyTypes = ParamTypes.ADDR;
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
        assertEq(uint256(returnedTracker.trackerKeyType), uint256(ParamTypes.ADDR));

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode(false));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, true);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertNotEq(updatedValue, abi.encode(false));
    }

    function testRulesEngine_Unit_MappedTrackerInstructionSetCompare_AddressToUint() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
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

        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, trackerName);
        Trackers memory tracker2;
        tracker2.pType = ParamTypes.UINT;
        tracker2.trackerValue = abi.encode(2);
        string memory trackerName2 = "tracker2";
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker2, trackerName2);

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

        rule.effectPlaceHolders = new Placeholder[](4);
        rule.effectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[0].typeSpecificIndex = 1;
        rule.effectPlaceHolders[0].flags = FLAG_TRACKER_VALUE;
        rule.effectPlaceHolders[1].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[1].typeSpecificIndex = 2;
        rule.effectPlaceHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.effectPlaceHolders[2].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[2].typeSpecificIndex = 1;
        rule.effectPlaceHolders[2].flags = FLAG_FOREIGN_CALL;
        rule.effectPlaceHolders[3].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[3].typeSpecificIndex = 2;
        rule.effectPlaceHolders[3].flags = FLAG_FOREIGN_CALL;

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

        setupRuleWithTracker2(policyId, tracker);

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

        setupRuleWithTracker2(policyId, tracker);

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

        setupRuleWithTracker2(policyId, tracker);

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

        setupRuleWithTracker2(policyId, tracker);

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

        setupRuleWithTracker2(policyId, tracker);

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

        setupRuleWithTracker2(policyId, tracker);

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

        setupRuleWithTracker2(policyId, tracker);

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

        setupRuleWithTracker2(policyId, tracker);

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

        setupRuleWithTracker2(policyId, tracker);

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

    // tracker update from malicious actor

    // setup policy tracker

    /* 
    Contract A
    Contract B
    Policy A

    CA -> PA
    CB -> PA
    */
}
