/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract PolicyCRUDTest is RulesEngineCommon {
    /**
     *
     *
     * Execution tests for policies within the rules engine
     *
     *
     */

    function testPolicyCreatePolicy(uint8 _policyType) public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint8 policyTypes = 2;
        _policyType = _policyType % (policyTypes * 2); // makes sure we have some valid and some invalid types
        vm.startPrank(user1);
        // a low-level call is necessary for the test not to fail on a policyType negative-path test-building phase
        if (_policyType > policyTypes) vm.expectRevert();
        (, bytes memory data) = address(red).call(
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
        else require(id == 0, "Policy ID should be 0");
    }
}
