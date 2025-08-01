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

    function testPolicyCreatePolicyType(uint8 _policyType) public ifDeploymentTestsEnabled resetsGlobalVariables {
        _policyType = _policyType % 6;
        vm.startPrank(user1);
        // a low-level call is necessary for the test not to fail on an invalid policyType before hand
        (bool success, ) = address(red).call(
            abi.encodeWithSelector(
                RulesEnginePolicyFacet(address(red)).createPolicy.selector,
                _policyType,
                "Test Policy",
                "This is a test policy"
            )
        );
        if (_policyType > 2 && success) revert("Policy type should not be created");
        else if (_policyType <= 2 && !success) revert("Policy should've been created");
    }
}
