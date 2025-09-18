/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "test/utils/DiamondMineNoCheatcodes.sol";
import "test/utils/TestProcessorFacet.sol";
import "test/clientContractExamples/ExampleUserContract.sol";

enum TestType {
    STRING_FROM_TRACKER,
    BYTES_FROM_TRACKER,
    STRING_FROM_PLACEHOLDER,
    BYTES_FROM_PLACEHOLDER,
    STRING_FROM_MAPPED_TRACKER,
    BYTES_FROM_MAPPED_TRACKER
}

contract trackersStringFuzz is DiamondMineNoCheatcodes, RulesEngineCommon {
    function setUp() public {
        red = createRulesEngineDiamondWithTestProcessorFacet(address(this));
        userContractAddress = address(new ExampleUserContract());
        ExampleUserContract(userContractAddress).setRulesEngineAddress(address(red));
        ExampleUserContract(userContractAddress).setCallingContractAdmin(callingContractAdmin);
    }

    function SetupPlaceholdersAndRule(
        bytes memory _input,
        TestType _testType
    )
        internal
        ifDeploymentTestsEnabled
        endWithStopPrank
        returns (uint256[] memory instructionSet, Placeholder[] memory placeHolders, uint256 policyId)
    {
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        vm.startPrank(callingContractAdmin);
        policyIds[0] = _createBlankPolicy();
        vm.stopPrank();
        // Rule: info == "Bad Info" -> revert -> updateInfo(address _to, string info) returns (bool)"
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, *uint256 representation of Bad Info*, LogicalOp.EQ, 0, 1
        // Build the instruction set for the rule (including placeholders)
        if (_testType == TestType.STRING_FROM_MAPPED_TRACKER || _testType == TestType.BYTES_FROM_MAPPED_TRACKER) {
            rule.instructionSet = new uint256[](10);
            // PLHM, 1, NUM, *uint256 representation of Bad Info*, EQ, 0, 1
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 0;
            rule.instructionSet[2] = uint(LogicalOp.PLHM);
            rule.instructionSet[3] = 1;
            rule.instructionSet[4] = 0;
            rule.instructionSet[5] = uint(LogicalOp.NUM);
            rule.instructionSet[6] = uint256(keccak256(_input));
            rule.instructionSet[7] = uint(LogicalOp.EQ);
            rule.instructionSet[8] = 1;
            rule.instructionSet[9] = 2;
        } else {
            rule.instructionSet = new uint256[](7);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 0;
            rule.instructionSet[2] = uint(LogicalOp.NUM);
            rule.instructionSet[3] = uint256(keccak256(abi.encode(_input)));
            rule.instructionSet[4] = uint(LogicalOp.EQ);
            rule.instructionSet[5] = 0;
            rule.instructionSet[6] = 1;
        }

        // Build the calling function argument placeholder
        if (_testType == TestType.STRING_FROM_PLACEHOLDER) {
            rule.placeHolders = new Placeholder[](1);
            rule.placeHolders[0].pType = ParamTypes.STR;
            // We're using the type specific index of the calldata that's pointed to by the string in calling function 2
            rule.placeHolders[0].typeSpecificIndex = 1;
        } else if (_testType == TestType.BYTES_FROM_PLACEHOLDER) {
            rule.placeHolders = new Placeholder[](1);
            rule.placeHolders[0].pType = ParamTypes.BYTES;
            rule.placeHolders[0].typeSpecificIndex = 1;
        } else if (_testType == TestType.STRING_FROM_MAPPED_TRACKER) {
            bytes[] memory trackerKeys = new bytes[](1);
            bytes[] memory trackerValues = new bytes[](1);
            trackerKeys[0] = abi.encode(1);
            trackerValues[0] = _input;
            Trackers memory tracker = Trackers({
                mapped: true,
                pType: ParamTypes.STR,
                trackerKeyType: ParamTypes.UINT,
                trackerValue: abi.encode(0),
                set: false,
                trackerIndex: 0
            });

            rule.placeHolders = new Placeholder[](2);
            rule.placeHolders[0].pType = ParamTypes.UINT;
            rule.placeHolders[0].typeSpecificIndex = 0;
            rule.placeHolders[0].flags = 0;
            rule.placeHolders[1].pType = ParamTypes.STR;
            rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
            vm.startPrank(callingContractAdmin);
            rule.placeHolders[1].typeSpecificIndex = uint128(
                RulesEngineComponentFacet(address(red)).createMappedTracker(
                    policyIds[0],
                    tracker,
                    "test",
                    trackerKeys,
                    trackerValues,
                    TrackerArrayTypes.VOID
                )
            );
            vm.stopPrank();
        } else if (_testType == TestType.BYTES_FROM_MAPPED_TRACKER) {
            bytes[] memory trackerKeys = new bytes[](1);
            bytes[] memory trackerValues = new bytes[](1);
            trackerKeys[0] = abi.encode(1);
            trackerValues[0] = _input;
            Trackers memory tracker = Trackers({
                mapped: true,
                pType: ParamTypes.BYTES,
                trackerKeyType: ParamTypes.UINT,
                trackerValue: abi.encode(0),
                set: false,
                trackerIndex: 0
            });

            rule.placeHolders = new Placeholder[](2);
            rule.placeHolders[0].pType = ParamTypes.UINT;
            rule.placeHolders[0].typeSpecificIndex = 0;
            rule.placeHolders[0].flags = 0;
            rule.placeHolders[1].pType = ParamTypes.BYTES;
            rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
            vm.startPrank(callingContractAdmin);
            rule.placeHolders[1].typeSpecificIndex = uint128(
                RulesEngineComponentFacet(address(red)).createMappedTracker(
                    policyIds[0],
                    tracker,
                    "test",
                    trackerKeys,
                    trackerValues,
                    TrackerArrayTypes.VOID
                )
            );
            vm.stopPrank();
        } else if (_testType == TestType.STRING_FROM_TRACKER) {
            Trackers memory tracker = Trackers({
                set: false,
                trackerIndex: 0,
                trackerKeyType: ParamTypes.VOID,
                mapped: false,
                pType: ParamTypes.STR,
                trackerValue: abi.encode(_input)
            });

            rule.placeHolders = new Placeholder[](1);
            rule.placeHolders[0].pType = ParamTypes.STR;
            vm.startPrank(callingContractAdmin);
            rule.placeHolders[0].typeSpecificIndex = uint128(
                RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "test", TrackerArrayTypes.VOID)
            );
            vm.stopPrank();
            rule.placeHolders[0].flags = FLAG_TRACKER_VALUE;
        } else if (_testType == TestType.BYTES_FROM_TRACKER) {
            Trackers memory tracker = Trackers({
                set: false,
                trackerIndex: 0,
                trackerKeyType: ParamTypes.VOID,
                mapped: false,
                pType: ParamTypes.BYTES,
                trackerValue: abi.encode(_input)
            });

            rule.placeHolders = new Placeholder[](1);
            rule.placeHolders[0].pType = ParamTypes.BYTES;
            vm.startPrank(callingContractAdmin);
            rule.placeHolders[0].typeSpecificIndex = uint128(
                RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "test", TrackerArrayTypes.VOID)
            );
            vm.stopPrank();
            rule.placeHolders[0].flags = FLAG_TRACKER_VALUE;
        }

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        vm.startPrank(callingContractAdmin);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, "test", "test");

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.STR;
        // Save the calling function
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(keccak256(bytes(callingFunction2))),
            pTypes,
            callingFunction2,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction2))));
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContractAddress), policyIds);

        instructionSet = rule.instructionSet;
        placeHolders = rule.placeHolders;
        policyId = policyIds[0];
    }

    function test_stringFromTracker(string memory _input) public {
        (uint256[] memory instructionSet, Placeholder[] memory placeHolders, uint256 policyId) = SetupPlaceholdersAndRule(
            bytes(_input),
            TestType.STRING_FROM_TRACKER
        );
        bytes[] memory arguments = new bytes[](1);
        arguments[0] = abi.encode(_input);
        bool result = TestProcessorFacet(address(red)).run(instructionSet, placeHolders, policyId, arguments);
        assertTrue(result);
    }

    /// forge-config: default.fuzz.runs = 20
    function test_bytesFromTracker(bytes memory _input) public {
        (uint256[] memory instructionSet, Placeholder[] memory placeHolders, uint256 policyId) = SetupPlaceholdersAndRule(
            _input,
            TestType.BYTES_FROM_TRACKER
        );
        bytes[] memory arguments = new bytes[](1);
        arguments[0] = abi.encode(_input);
        bool result = TestProcessorFacet(address(red)).run(instructionSet, placeHolders, policyId, arguments);
        assertTrue(result);
    }

    /// forge-config: default.fuzz.runs = 20
    function test_stringFromPlaceholder(string memory _input) public {
        (uint256[] memory instructionSet, Placeholder[] memory placeHolders, uint256 policyId) = SetupPlaceholdersAndRule(
            bytes(_input),
            TestType.STRING_FROM_PLACEHOLDER
        );
        bytes[] memory arguments = new bytes[](1);
        arguments[0] = abi.encode(_input);
        bool result = TestProcessorFacet(address(red)).run(instructionSet, placeHolders, policyId, arguments);
        assertTrue(result);
    }

    /// forge-config: default.fuzz.runs = 20
    function test_bytesFromPlaceholder(bytes memory _input) public {
        (uint256[] memory instructionSet, Placeholder[] memory placeHolders, uint256 policyId) = SetupPlaceholdersAndRule(
            _input,
            TestType.BYTES_FROM_PLACEHOLDER
        );
        bytes[] memory arguments = new bytes[](1);
        arguments[0] = abi.encode(_input);
        bool result = TestProcessorFacet(address(red)).run(instructionSet, placeHolders, policyId, arguments);
        assertTrue(result);
    }

    /// forge-config: default.fuzz.runs = 20
    function test_stringFromMappedTracker(string memory _input) public {
        (uint256[] memory instructionSet, Placeholder[] memory placeHolders, uint256 policyId) = SetupPlaceholdersAndRule(
            abi.encode(_input),
            TestType.STRING_FROM_MAPPED_TRACKER
        );
        RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, placeHolders[1].typeSpecificIndex, abi.encode(1));
        bytes[] memory arguments = new bytes[](2);
        arguments[0] = abi.encode(1);
        arguments[1] = abi.encode(0);
        bool result = TestProcessorFacet(address(red)).run(instructionSet, placeHolders, policyId, arguments);
        assertTrue(result);
    }

    /// forge-config: default.fuzz.runs = 20
    function test_bytesFromMappedTracker(bytes memory _input) public {
        (uint256[] memory instructionSet, Placeholder[] memory placeHolders, uint256 policyId) = SetupPlaceholdersAndRule(
            _input,
            TestType.BYTES_FROM_MAPPED_TRACKER
        );
        RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, placeHolders[1].typeSpecificIndex, abi.encode(1));
        bytes[] memory arguments = new bytes[](2);
        arguments[0] = abi.encode(1);
        arguments[1] = abi.encode(0);
        bool result = TestProcessorFacet(address(red)).run(instructionSet, placeHolders, policyId, arguments);
        assertTrue(result);
    }
}
