/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/token/ERC20/unit/ERC20UnitTestsCommon.t.sol";

contract ERC20UnitTests is ERC20UnitTestsCommon {
    string constant ERC20_TRANSFER_SIGNATURE = "transfer(address,uint256)";
    string constant ERC20_TRANSFER_FROM_SIGNATURE = "transferFrom(address,address,uint256)";
    string constant ERC20_MINT_SIGNATURE = "mint(address,uint256)";

    function setUp() public {
        red = createRulesEngineDiamond(address(0xB0b));
        vm.startPrank(callingContractAdmin);
        userContractERC20 = new ExampleERC20("Token Name", "SYMB");
        userContractERC20Address = address(userContractERC20);
        userContractERC20.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        _setupEffectProcessor();
        //vm.startPrank(policyAdmin);
    }

    function _setCallingContractAdmin() internal {
        vm.startPrank(callingContractAdmin);
        userContractERC20.setCallingContractAdmin(address(callingContractAdmin));
        vm.stopPrank();
    }

    function _doSomeMinting(address to, uint256 amount) internal {
        vm.startPrank(callingContractAdmin);
        userContractERC20.mint(to, amount);
        vm.stopPrank();
    }

    function testERC20_Transfer_Before_Unit_checkRule_ForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        // set up the ERC20

        _doSomeMinting(USER_ADDRESS, 1_000_000 * ATTO);
        _setup_checkRule_ForeignCall_Positive(ruleValue, userContractERC20Address);

        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.startPrank(USER_ADDRESS);
        bool response = userContractERC20.transfer(address(0x7654321), transferValue);
        assertTrue(response);
    }

    function testERC20_Transfer_Before_Unit_checkRule_ForeignCall_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        // set up the ERC20
        _doSomeMinting(USER_ADDRESS, 1_000_000 * ATTO);
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        ruleValue = 15;
        transferValue = 10;
        _setup_checkRule_ForeignCall_Negative(ruleValue, userContractERC20Address);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContractERC20.transfer(address(0x7654321), transferValue);
    }

    function testERC20_TransferFrom_Before_Unit_checkRule_ForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        // set up the ERC20
        _doSomeMinting(USER_ADDRESS, 1_000_000 * ATTO);
        _setup_checkRule_TransferFrom_ForeignCall_Positive(ruleValue, userContractERC20Address);

        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.startPrank(USER_ADDRESS);
        userContractERC20.approve(USER_ADDRESS, transferValue);
        bool response = userContractERC20.transferFrom(USER_ADDRESS, address(0x7654321), transferValue);
        assertTrue(response);
    }

    function testERC20_Transfer_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        // set up the ERC20
        _doSomeMinting(USER_ADDRESS, 1_000_000 * ATTO);
        _setupRuleWithRevert(address(userContractERC20));
        vm.startPrank(callingContractAdmin);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContractERC20.transfer(address(0x7654321), 5);
    }

    function testERC20_TransferFrom_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        // set up the ERC20
        _doSomeMinting(USER_ADDRESS, 1_000_000 * ATTO);
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;
        pTypes[3] = ParamTypes.ADDR;
        _setupRuleWithRevertTransferFrom(ERC20_TRANSFER_FROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        userContractERC20.approve(USER_ADDRESS, 3);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContractERC20.transferFrom(USER_ADDRESS, address(0x7654321), 3);
    }

    function testERC20_TransferFrom_Unit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        // set up the ERC20
        _doSomeMinting(USER_ADDRESS, 1_000_000 * ATTO);
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;
        pTypes[3] = ParamTypes.ADDR;
        _setupRuleWithRevertTransferFrom(ERC20_TRANSFER_FROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        userContractERC20.approve(USER_ADDRESS, 5);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        bool response = userContractERC20.transferFrom(USER_ADDRESS, address(0x7654321), 5);
        assertTrue(response);
    }

    function testERC20_TransferFrom_Unit_BalanceFromLessThan100() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        // set up the ERC20 with a balance that will test both positive and negative paths
        _doSomeMinting(USER_ADDRESS, 110);
        ParamTypes[] memory pTypes = new ParamTypes[](7);
        pTypes[0] = ParamTypes.ADDR; // _from
        pTypes[1] = ParamTypes.ADDR; // _to
        pTypes[2] = ParamTypes.UINT; // _value (amount)
        pTypes[3] = ParamTypes.ADDR; // msg.sender
        pTypes[4] = ParamTypes.UINT; // _balanceFrom - THIS is what we want to check
        pTypes[5] = ParamTypes.UINT; // _balanceTo
        pTypes[6] = ParamTypes.UINT; // _blockTime
        _setupRuleWithRevertTransferFromBalanceCheck(ERC20_TRANSFER_FROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        userContractERC20.approve(USER_ADDRESS, 50);

        // Positive path: First transferFrom should succeed (balanceFrom 110 >= 100)
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        bool response = userContractERC20.transferFrom(USER_ADDRESS, address(0x7654321), 20);
        assertTrue(response);

        // Negative path: Second transferFrom should revert (balanceFrom 90 < 100)
        vm.expectRevert(abi.encodePacked(revert_text));
        userContractERC20.transferFrom(USER_ADDRESS, address(0x7654321), 10);
    }

    function testERC20_Mint_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();

        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        _setupRuleWithRevertMint(ERC20_MINT_SIGNATURE, pTypes);
        vm.startPrank(callingContractAdmin);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContractERC20.mint(USER_ADDRESS, 3);
    }

    function testERC20_Mint_Unit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();

        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        _setupRuleWithRevertMint(ERC20_MINT_SIGNATURE, pTypes);
        vm.startPrank(callingContractAdmin);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        userContractERC20.mint(USER_ADDRESS, 5);
    }

    function testERC20_Unit_Disabled_Policy() public ifDeploymentTestsEnabled endWithStopPrank {
        _setCallingContractAdmin();
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        // Expect revert while rule is enabled
        uint256 _policyId = _setupRuleWithRevertMint(ERC20_MINT_SIGNATURE, pTypes);

        vm.expectRevert(abi.encodePacked(revert_text));
        _doSomeMinting(USER_ADDRESS, 3);

        // Disable the policy and expect it to go through
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).disablePolicy(_policyId);
        assertTrue(RulesEnginePolicyFacet(address(red)).isDisabledPolicy(_policyId));
        _doSomeMinting(USER_ADDRESS, 3);
    }

    function testERC20_setCallingContractAdmin_FailsForNonOwner() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(address(0x7654321));
        vm.expectRevert(abi.encodePacked("OwnableUnauthorizedAccount(0x0000000000000000000000000000000007654321)"));
        userContractERC20.setCallingContractAdmin(address(0x7654321));
    }

    function testERC20_setCallingContractAdmin_OwnerCanTransfer() public ifDeploymentTestsEnabled endWithStopPrank {
        RulesEngineAdminRolesFacet rearf = RulesEngineAdminRolesFacet(address(red));

        // Pre-condition: (no calling contract admin set)
        assertEq(rearf.isCallingContractAdmin(address(userContractERC20), address(USER_ADDRESS_2)), false);
        assertEq(rearf.isCallingContractAdmin(address(userContractERC20), address(callingContractAdmin)), false);

        // Test that the calling contract admin can be set by the contract owner
        vm.startPrank(callingContractAdmin);
        userContractERC20.setCallingContractAdmin(address(USER_ADDRESS_2));
        assertEq(
            rearf.isCallingContractAdmin(address(userContractERC20), address(USER_ADDRESS_2)),
            true,
            "Calling contract admin was not set to address 2"
        );
        assertEq(
            rearf.isCallingContractAdmin(address(userContractERC20), address(callingContractAdmin)),
            false,
            "Deployer set to calling contract admin without explicitly being granted role"
        );
        vm.stopPrank();
        vm.startPrank(address(USER_ADDRESS_2));

        // Transfer it to the contract owner
        RulesEngineAdminRolesFacet(address(red)).proposeNewCallingContractAdmin(address(userContractERC20), address(callingContractAdmin));
        vm.stopPrank();
        vm.startPrank(address(callingContractAdmin));
        RulesEngineAdminRolesFacet(address(red)).confirmNewCallingContractAdmin(address(userContractERC20));
        assertEq(
            rearf.isCallingContractAdmin(address(userContractERC20), address(callingContractAdmin)),
            true,
            "Calling contract admin role not given to new address"
        );
        assertEq(
            rearf.isCallingContractAdmin(address(userContractERC20), address(USER_ADDRESS_2)),
            false,
            "Previous calling contract admin role not removed on new set"
        );
        vm.stopPrank();
    }
}
