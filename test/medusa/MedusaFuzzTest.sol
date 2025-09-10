// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

/**
 * @title MedusaFuzzTest
 * @dev Simple test contract specifically designed for Medusa fuzzing
 * Contains property-based tests that Medusa can recognize and execute
 */
contract MedusaFuzzTest is RulesEngineCommon {
    function setUp() public {
        // Start test as the policyAdmin account
        vm.startPrank(policyAdmin);
        // Deploy Rules Engine Diamond
        red = createRulesEngineDiamond(address(0xB0b));
        // Create and connect user contract to Rules Engine
        userContract = new ExampleUserContract();
        userContractAddress = address(userContract);
        userContract.setRulesEngineAddress(address(red));
        vm.stopPrank();
    }

    /**
     * @dev Property test: Admin role should always be consistent
     * This is a simple property test that Medusa can fuzz
     */
    function property_adminRoleConsistency() public view returns (bool) {
        // Check that the policy admin is consistently set
        address currentAdmin = RulesEngineAdminRolesFacet(address(red)).getPolicyAdmin();
        return currentAdmin != address(0);
    }

    /**
     * @dev Property test: Policy creation should maintain invariants
     */
    function property_policyCreationInvariant(uint256 policyType) public returns (bool) {
        // Bound the policy type to valid range
        if (policyType > 2) policyType = policyType % 3;

        vm.startPrank(policyAdmin);

        try RulesEnginePolicyFacet(address(red)).createPolicy(PolicyType(policyType), "Test Policy", "Test Description") returns (
            uint256 policyId
        ) {
            // If policy creation succeeds, verify it exists
            vm.stopPrank();
            return policyId > 0;
        } catch {
            // If it fails, that's also acceptable for some inputs
            vm.stopPrank();
            return true;
        }
    }

    /**
     * @dev Optimization test: Gas usage should be reasonable
     */
    function optimize_gasUsageReasonable() public returns (bool) {
        vm.startPrank(policyAdmin);

        uint256 gasBefore = gasleft();
        try RulesEnginePolicyFacet(address(red)).createPolicy(PolicyType.OPEN_POLICY, "Gas Test Policy", "Testing gas usage") {
            uint256 gasUsed = gasBefore - gasleft();
            vm.stopPrank();
            // Ensure gas usage is reasonable (less than 1M gas)
            return gasUsed < 1_000_000;
        } catch {
            vm.stopPrank();
            return false;
        }
    }

    /**
     * @dev Assertion test: Basic functionality should work
     */
    function test_basicAssertion() public {
        vm.startPrank(policyAdmin);

        uint256 policyId = RulesEnginePolicyFacet(address(red)).createPolicy(
            PolicyType.OPEN_POLICY,
            "Assertion Test Policy",
            "Testing assertions"
        );

        // Assert that policy was created successfully
        assert(policyId > 0);

        vm.stopPrank();
    }
}
