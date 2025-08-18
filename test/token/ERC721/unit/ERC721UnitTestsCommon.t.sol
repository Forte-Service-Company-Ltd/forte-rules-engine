/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract ERC721UnitTestsCommon is RulesEngineCommon {
    function _setupRuleWithRevertSafeTransferFrom(
        string memory _callingFunction,
        ParamTypes[] memory pTypes
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        vm.startPrank(policyAdmin);
        // if the address equals the mint to address, then emit event, else revert
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicyOpen();

        _addCallingFunctionToPolicy(policyIds[0], bytes4(keccak256(bytes(_callingFunction))), pTypes, _callingFunction);

        Rule memory rule = _createEQRuleSafeTransferFrom(USER_ADDRESS);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContract721Address, policyIds);
    }

    function _setupRuleWithRevertTransferFrom(
        string memory _callingFunction,
        ParamTypes[] memory pTypes
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 _policyId) {
        vm.startPrank(policyAdmin);
        // if the address equals the mint to address, then emit event, else revert
        uint256[] memory policyIds = new uint256[](1);

        _policyId = policyIds[0] = _createBlankPolicyOpen();

        _addCallingFunctionToPolicy(policyIds[0], bytes4(keccak256(bytes(_callingFunction))), pTypes, _callingFunction);

        Rule memory rule = _createEQRuleTransferFrom(USER_ADDRESS);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContract721Address, policyIds);
        return _policyId;
    }

    function _createEQRuleSafeMint(address _address) public returns (Rule memory) {
        // Rule: _to == _address -> revert -> safeMint(address _to)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = uint256(uint160(_address));
        instructionSet[4] = uint(LogicalOp.EQ);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createEQRuleSafeTransferFrom(address _address) public returns (Rule memory) {
        // Rule: _to == _address -> revert -> safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = uint256(uint160(_address));
        instructionSet[4] = uint(LogicalOp.EQ);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createEQRuleTransferFrom(address _address) public returns (Rule memory) {
        // Rule: _to == _address -> revert -> TransferFrom(address from, address to, uint256 tokenId)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = uint256(uint160(_address));
        instructionSet[4] = uint(LogicalOp.EQ);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }
}
