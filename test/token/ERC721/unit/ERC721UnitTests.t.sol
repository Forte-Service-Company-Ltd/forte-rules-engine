/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/token/ERC721/unit/ERC721UnitTestsCommon.t.sol";

contract ERC721UnitTests is ERC721UnitTestsCommon {
    string constant ERC721_SAFEMINT_SIGNATURE = "safeMint(address)";
    string constant ERC721_SAFETRANSFERFROM_SIGNATURE = "safeTransferFrom(address,address,uint256,bytes)";
    string constant ERC721_TRANSFERFROM_SIGNATURE = "transferFrom(address,address,uint256)";

    function setUp() public {
        red = createRulesEngineDiamond(address(0xB0b));
        vm.startPrank(callingContractAdmin);
        userContract721 = new ExampleERC721("Token Name", "SYMB");
        userContract721Address = address(userContract721);
        userContract721.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        _setupEffectProcessor();
        vm.stopPrank();
    }

    function _setCallingContractAdmin() internal {
        vm.startPrank(callingContractAdmin);
        userContract721.setCallingContractAdmin(address(callingContractAdmin));
        vm.stopPrank();
    }

    function _doSomeMinting(address to) internal {
        vm.startPrank(callingContractAdmin);
        userContract721.safeMint(to);
        vm.stopPrank();
    }

    function testERC721_SafeMint_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        _setupRuleWithRevertSafeMint(ERC721_SAFEMINT_SIGNATURE, pTypes);
        vm.expectRevert(abi.encodePacked(revert_text));
        _doSomeMinting(address(55));
    }

    function testERC721_SafeMint_Unit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        _setupRuleWithRevertSafeMint(ERC721_SAFEMINT_SIGNATURE, pTypes);
        vm.startPrank(callingContractAdmin);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        userContract721.safeMint(USER_ADDRESS);
    }

    function testERC721_SafeTransferFrom_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        _doSomeMinting(USER_ADDRESS);
        ParamTypes[] memory pTypes = new ParamTypes[](5);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;
        pTypes[3] = ParamTypes.BYTES;
        pTypes[4] = ParamTypes.ADDR;
        _setupRuleWithRevertSafeTransferFrom(ERC721_SAFETRANSFERFROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract721.safeTransferFrom(USER_ADDRESS, USER_ADDRESS_2, 0, "");
    }

    function testERC721_SafeTransferFrom_Unit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        _doSomeMinting(USER_ADDRESS_2);
        ParamTypes[] memory pTypes = new ParamTypes[](5);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;
        pTypes[3] = ParamTypes.BYTES;
        pTypes[4] = ParamTypes.ADDR;
        _setupRuleWithRevertSafeTransferFrom(ERC721_SAFETRANSFERFROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS_2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        userContract721.safeTransferFrom(USER_ADDRESS_2, USER_ADDRESS, 0, "");
    }

    function testERC721_TransferFrom_Unit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        _doSomeMinting(USER_ADDRESS_2);
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;
        pTypes[3] = ParamTypes.ADDR;
        _setupRuleWithRevertTransferFrom(ERC721_TRANSFERFROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS_2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        userContract721.transferFrom(USER_ADDRESS_2, USER_ADDRESS, 0);
    }

    function testERC721_TransferFrom_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        _doSomeMinting(USER_ADDRESS);
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;
        pTypes[3] = ParamTypes.ADDR;
        _setupRuleWithRevertTransferFrom(ERC721_TRANSFERFROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract721.transferFrom(USER_ADDRESS, USER_ADDRESS_2, 0);
    }

    function testERC721_Unit_Disabled_Policy() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        _doSomeMinting(USER_ADDRESS);
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;
        pTypes[3] = ParamTypes.ADDR;
        // Expect revert while rule is enabled
        uint256 _policyId = _setupRuleWithRevertTransferFrom(ERC721_TRANSFERFROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract721.transferFrom(USER_ADDRESS, USER_ADDRESS_2, 0);

        // Disable the policy and expect it to go through
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).disablePolicy(_policyId);
        assertTrue(RulesEnginePolicyFacet(address(red)).isDisabledPolicy(_policyId));
        vm.startPrank(USER_ADDRESS);
        userContract721.transferFrom(USER_ADDRESS, USER_ADDRESS_2, 0);
    }

    function _setupRuleWithRevertSafeMint(
        string memory _callingFunction,
        ParamTypes[] memory pTypes
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        vm.startPrank(policyAdmin);
        // if the address equals the mint to address, then emit event, else revert
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicyOpen();

        _addCallingFunctionToPolicy(policyIds[0], bytes4(keccak256(bytes(_callingFunction))), pTypes, _callingFunction);

        Rule memory rule = _createEQRuleSafeMint(USER_ADDRESS);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContract721Address, policyIds);
    }

    function testERC721_setCallingContractAdmin_FailsForNonOwner() public ifDeploymentTestsEnabled endWithStopPrank {
        // Try setting the calling contract admin with a random account
        vm.startPrank(address(0x7654321));
        vm.expectRevert(abi.encodePacked("OwnableUnauthorizedAccount(0x0000000000000000000000000000000007654321)"));
        userContract721.setCallingContractAdmin(address(0x7654321));
    }

    function testERC721_setCallingContractAdmin_OwnerCanTransfer() public ifDeploymentTestsEnabled endWithStopPrank {
        RulesEngineAdminRolesFacet rearf = RulesEngineAdminRolesFacet(address(red));

        // Pre-condition: (no calling contract admin set)
        assertEq(rearf.isCallingContractAdmin(address(userContract721), address(USER_ADDRESS_2)), false);
        assertEq(rearf.isCallingContractAdmin(address(userContract721), address(callingContractAdmin)), false);

        // Test that the calling contract admin can be set by the contract owner
        vm.startPrank(callingContractAdmin);
        userContract721.setCallingContractAdmin(address(USER_ADDRESS_2));
        assertEq(
            rearf.isCallingContractAdmin(address(userContract721), address(USER_ADDRESS_2)),
            true,
            "Calling contract admin was not set to address 2"
        );
        assertEq(
            rearf.isCallingContractAdmin(address(userContract721), address(callingContractAdmin)),
            false,
            "Deployer set to calling contract admin without explicitly being granted role"
        );
        vm.stopPrank();
        vm.startPrank(address(USER_ADDRESS_2));

        // Transfer it to the contract owner
        RulesEngineAdminRolesFacet(address(red)).proposeNewCallingContractAdmin(address(userContract721), address(callingContractAdmin));
        vm.stopPrank();
        vm.startPrank(address(callingContractAdmin));
        RulesEngineAdminRolesFacet(address(red)).confirmNewCallingContractAdmin(address(userContract721));
        assertEq(
            rearf.isCallingContractAdmin(address(userContract721), address(callingContractAdmin)),
            true,
            "Calling contract admin role not given to new address"
        );
        assertEq(
            rearf.isCallingContractAdmin(address(userContract721), address(USER_ADDRESS_2)),
            false,
            "Previous calling contract admin role not removed on new set"
        );
        vm.stopPrank();
    }
}
