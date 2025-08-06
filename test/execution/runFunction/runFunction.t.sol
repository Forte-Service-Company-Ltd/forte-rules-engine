/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract runFunction is RulesEngineCommon {
    ExampleERC20 _exampleERC20;
    uint constant memorySize = 90;
    /**
     *
     *
     * Execution tests for the run function within the rules engine
     *
     *
     */
    /**
     * @dev this test proves inderectly the correct utilization of the _mem_ array during instructionSet execution
     *     in the RuleEngineProcessorFacet's _run function. It does so by running a size-fuzzed instruction set
     *     that can overflow the _mem_ array by 1. An ERC20 token is used as the callingContract. The rule simply
     *     puts numbers into _mem_ since the goal is to check that the array overflows exactly when expected.
     */
    function testRun_memArrayOverflow(bool toOverflow) public {
        // we set the ERC20 calling contract
        _exampleERC20 = new ExampleERC20("Token Name", "SYMB");
        _exampleERC20.mint(callingContractAdmin, 1_000_000 * ATTO);
        _exampleERC20.setRulesEngineAddress(address(red));
        _exampleERC20.setCallingContractAdmin(callingContractAdmin);

        // we define the calling function
        vm.startPrank(user1);
        ParamTypes[] memory pTypes = new ParamTypes[](6);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.UINT;
        pTypes[4] = ParamTypes.UINT;
        pTypes[5] = ParamTypes.UINT;
        uint policyId = _createBlankPolicy();
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(bytes4(keccak256(bytes("transfer(address,uint256)")))),
            pTypes,
            "transfer(address,uint256)",
            "address,uint256"
        );

        // We set the rule. We only create an overflowing condition if that's what we want (toOverflow flag)
        // This way, we can make sure that it is overflowing exactly where it is supoosed to. This proves
        // indirectly that the _mem_ array is being iterated and used as expected.
        Rule memory rule;
        uint size = memorySize + (toOverflow ? 1 : 0);
        // the instruction set has to have double the size of the instructions we want since the opcode NUM
        // requires 2 slots
        rule.instructionSet = new uint256[](size * 2);
        // we fill up the instruction set with the instruction "Put number _i_ at _i_th position in _mem_"
        for (uint i; i < size; i++) {
            rule.instructionSet[i * 2] = uint(LogicalOp.NUM);
            rule.instructionSet[i * 2 + 1] = i;
        }
        // we need at least one effect
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // we save the rule
        uint ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule, "My rule", "My way or the highway");
        // we update the policy
        uint256[][] memory _ruleIds = new uint256[][](1);
        uint256[] memory _ids = new uint256[](1);
        _ids[0] = ruleId;
        _ruleIds[0] = _ids;
        callingFunctions.push(bytes4(keccak256(bytes("transfer(address,uint256)"))));
        callingFunctionIds.push(callingFunctionId);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            callingFunctionIds,
            _ruleIds,
            PolicyType.OPEN_POLICY,
            "Test Policy",
            "This is a test policy"
        );
        // now we apply the policy to the ERC20
        vm.startPrank(callingContractAdmin);
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(_exampleERC20), policyIds);
        // the transfer reverts when the size of the instruction set is greater than _memorySize_ (toOverflow flag)
        if (toOverflow) vm.expectRevert("panic: array out-of-bounds access (0x32)");
        _exampleERC20.transfer(address(0x7654321), 3);
    }
}
