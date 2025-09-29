/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "test/utils/ExampleProxy.sol";
import "test/utils/ExampleERC20Upgradeable.sol";
import "src/example/ExampleERC20.sol";

contract ProxyTest is RulesEngineCommon {

    ExampleERC20Upgradeable logic;
    ExampleProxy proxy;

    function setUp() public {
        // Start test as the policyAdmin account
        vm.startPrank(policyAdmin);
        // Deploy Rules Engine Diamond
        red = createRulesEngineDiamond(address(0xB0b));
        // Create and connect user contract to Rules Engine

        _setupEffectProcessor();

        vm.startPrank(policyAdmin);
        logic = new ExampleERC20Upgradeable();
        proxy = new ExampleProxy(address(logic),"");
        ExampleERC20Upgradeable(address(proxy)).initialize("Test Coin", "TSC", address(0));
        ExampleERC20Upgradeable(address(proxy)).setRulesEngineAddress(address(red));
        ExampleERC20Upgradeable(address(proxy)).setCallingContractAdmin(callingContractAdmin);
        
    }
    /**
     *
     *
     * Execution tests for rules invoked through proxy contracts
     *
     *
     */
    function testRulesEngine_Unit_Proxy_Call_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        _setupRuleWithRevertForProxy(address(proxy));
        vm.startPrank(callingContractAdmin);
        ExampleERC20Upgradeable(address(proxy)).mint(callingContractAdmin, 5);
        vm.expectRevert(abi.encodePacked(revert_text));
        ExampleERC20Upgradeable(address(proxy)).transfer(address(0x7654321), 5);
    }

    function testRulesEngine_Unit_Proxy_Call_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        _setupRuleWithRevertForProxy(address(proxy));
        vm.startPrank(callingContractAdmin);
        ExampleERC20Upgradeable(address(proxy)).mint(callingContractAdmin, 1);
        ExampleERC20Upgradeable(address(proxy)).transfer(address(0x7654321), 1);
        assertEq(ExampleERC20Upgradeable(address(proxy)).balanceOf(address(0x7654321)), 1);
    }

    function testRulesEngine_Unit_Proxy_Contract_Call_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        _setupRuleWithRevertForProxyTransferFrom(address(proxy));
        vm.startPrank(callingContractAdmin);
        ExampleERC20Upgradeable(address(proxy)).mint(callingContractAdmin, 50);

        // Set up an approved transfer for a calling contract.
        DummyTrade trader = new DummyTrade();
        ExampleERC20Upgradeable(address(proxy)).approve(address(trader), 5);

        vm.expectRevert(abi.encodePacked(revert_text));
        trader.dummyTrade(address(proxy), callingContractAdmin, address(22), 5);
    }

    /// Ensure that a contract call to a FRE enabled function still invokes the policies.
    function testRulesEngine_Unit_Contract_Call_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(callingContractAdmin);
        userContractERC20 = new ExampleERC20("Token Name", "SYMB");
        userContractERC20Address = address(userContractERC20);
        userContractERC20.setRulesEngineAddress(address(red));
        vm.startPrank(callingContractAdmin);
        userContractERC20.setCallingContractAdmin(address(callingContractAdmin));
        vm.stopPrank();
        _setupRuleWithRevertTransferFrom(userContractERC20Address);
        vm.startPrank(callingContractAdmin);
        ExampleERC20(userContractERC20Address).mint(callingContractAdmin, 50);

        // Set up an approved transfer for a calling contract.
        DummyTrade trader = new DummyTrade();
        IERC20(userContractERC20Address).approve(address(trader), 1);

        vm.expectRevert(abi.encodePacked(revert_text));
        trader.dummyTrade(userContractERC20Address, callingContractAdmin, address(22), 1);
    }


    function _setupRuleWithRevertForProxy(address userContractMinTransferAddress) public ifDeploymentTestsEnabled resetsGlobalVariables {
        vm.startPrank(policyAdmin);
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicyOpen();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule memory rule = _createGTRule(policyIds[0], 4);
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 4;
        rule.instructionSet[4] = uint(LogicalOp.GT); // register 2
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        rule.posEffects[0] = effectId_revert;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractMinTransferAddress, policyIds);
    }

    function _setupRuleWithRevertForProxyTransferFrom(address userContractMinTransferAddress) public ifDeploymentTestsEnabled resetsGlobalVariables {
        vm.startPrank(policyAdmin);
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicyOpen();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicyForTransferFrom(policyIds[0]);

        // Rule: amount > 4 -> revert -> transferFrom(address _to, uint256 amount) returns (bool)"
        // Rule memory rule = _createGTRule(policyIds[0], 4);
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 4;
        rule.instructionSet[4] = uint(LogicalOp.GT); // register 2
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        rule.posEffects[0] = effectId_revert;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractMinTransferAddress, policyIds);
    }

    function _setupRuleWithRevertTransferFrom(address userContractMinTransferAddress) public ifDeploymentTestsEnabled resetsGlobalVariables {
        vm.startPrank(policyAdmin);
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicyOpen();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicyForTransferFrom(policyIds[0]);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule memory rule = _createGTRule(policyIds[0], 4);
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 4;
        rule.instructionSet[4] = uint(LogicalOp.GT); // register 2
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        rule.posEffects[0] = effectId_revert;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractMinTransferAddress, policyIds);
    }

    function _setCallingContractAdmin() internal {
        vm.startPrank(callingContractAdmin);
        userContractERC20.setCallingContractAdmin(address(callingContractAdmin));
        vm.stopPrank();
    }

    function _addCallingFunctionToPolicyForTransferFrom(uint256 policyId) internal returns (bytes4) {
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;
        // Save the calling function
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(bytes4(keccak256(bytes("transferFrom(address,address,uint256)")))),
            pTypes,
            "transferFrom(address,address,uint256)",
            "",
            "transferFrom(address,address,uint256)"
        );
        // Save the Policy
        if (callingFunctions.length == 0) callingFunctions.push(bytes4(keccak256(bytes("transferFrom(address,address,uint256)"))));
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        return bytes4(bytes4(keccak256(bytes(callingFunction))));
    }
}

import "@openzeppelin/token/ERC20/IERC20.sol";

contract DummyTrade{
    function dummyTrade(address token, address sender, address receiver, uint256 amountIn) public {
            IERC20(token).transferFrom(sender, receiver, amountIn);
    }
}
 
