/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract ERC20UnitTestsCommon is RulesEngineCommon {
    function _setupRuleWithRevertTransferFrom(
        string memory _callingFunction,
        ParamTypes[] memory pTypes
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        vm.startPrank(policyAdmin);
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicyOpen();

        _addCallingFunctionToPolicyOpen(policyIds[0], bytes4(keccak256(bytes(_callingFunction))), pTypes, _callingFunction);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRuleTransferFrom(4);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractERC20Address, policyIds);
    }

    function _setupRuleWithRevertMint(
        string memory _callingFunction,
        ParamTypes[] memory pTypes
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 _policyId) {
        vm.startPrank(policyAdmin);
        uint256[] memory policyIds = new uint256[](1);

        _policyId = policyIds[0] = _createBlankPolicyOpen();

        _addCallingFunctionToPolicyOpen(policyIds[0], bytes4(keccak256(bytes(_callingFunction))), pTypes, _callingFunction);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRuleMint(4);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractERC20Address, policyIds);
        return _policyId;
    }

    function _setupRuleWithRevertTransferFromBalanceCheck(
        string memory _callingFunction,
        ParamTypes[] memory pTypes
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        vm.startPrank(policyAdmin);
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicyOpen();

        _addCallingFunctionToPolicyOpen(policyIds[0], bytes4(keccak256(bytes(_callingFunction))), pTypes, _callingFunction);

        // Rule: balanceFrom >= 100 -> allow (positive), balanceFrom < 100 -> revert (negative)
        Rule memory rule = _createGTEQRuleTransferFromBalanceCheck(100);
        rule.posEffects[0] = effectId_event; // TRUE condition (balance >= 100) → allow with event
        rule.negEffects[0] = effectId_revert; // FALSE condition (balance < 100) → revert
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractERC20Address, policyIds);
    }

    function _createGTRuleTransferFrom(uint256 _amount) public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = _amount;
        instructionSet[4] = uint(LogicalOp.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 2;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createGTEQRuleTransferFromBalanceCheck(uint256 _balanceThreshold) public returns (Rule memory) {
        // Rule: balanceFrom >= _balanceThreshold -> allow (positive effect), else revert (negative effect)
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _balanceThreshold, LogicalOp.GTEQL, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = _balanceThreshold;
        instructionSet[4] = uint(LogicalOp.GTEQL);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 4; // balanceFrom is the second UINT parameter
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createGTRuleMint(uint256 _amount) public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = _amount;
        instructionSet[4] = uint(LogicalOp.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }
}
