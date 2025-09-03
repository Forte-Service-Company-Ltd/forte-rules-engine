/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/ForteRulesEngine.sol";
import "forge-std/src/Script.sol";
import "src/engine/facets/NativeFacet.sol";
import "src/engine/facets/RulesEngineProcessorFacet.sol";
import "src/engine/facets/RulesEnginePolicyFacet.sol";
import "src/engine/facets/RulesEngineRuleFacet.sol";
import "src/engine/facets/RulesEngineComponentFacet.sol";
import "src/engine/facets/RulesEngineForeignCallFacet.sol";
import "src/engine/facets/RulesEngineAdminRolesFacet.sol";
import "src/engine/facets/RulesEngineInitialFacet.sol";
import "test/utils/TestProcessorFacet.sol";
import {IDiamondInit} from "diamond-std/initializers/IDiamondInit.sol";
import {DiamondInit} from "diamond-std/initializers/DiamondInit.sol";
import {FacetCut, FacetCutAction} from "diamond-std/core/DiamondCut/DiamondCutLib.sol";

/**
 * @title DiamondMine
 * @dev This contract is an abstract template for deploying and configuring a Rules Engine Diamond for testing purposes.
 * @notice This contract is intended specifically for testing purposes and should not be used in production.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract DiamondMineNoCheatcodes is Script {
    FacetCut[] _ruleProcessorFacetCutsNoCheatcodes;
    FacetCut[] _ruleProcessorFacetCutsWithTestProcessorFacet;

    /****************************** Non-cheatcode Diamond Deployment Methods ********************************************/
    function createSelectorArrayNoCheatcodes(string memory facet) internal pure returns (bytes4[] memory) {
        if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEnginePolicyFacet"))) {
            bytes4[] memory selectors = new bytes4[](15);
            selectors[0] = RulesEnginePolicyFacet.createPolicy.selector;
            selectors[1] = RulesEnginePolicyFacet.updatePolicy.selector;
            selectors[2] = RulesEnginePolicyFacet.getPolicy.selector;
            selectors[3] = RulesEnginePolicyFacet.applyPolicy.selector;
            selectors[4] = RulesEnginePolicyFacet.unapplyPolicy.selector;
            selectors[5] = RulesEnginePolicyFacet.getAppliedPolicyIds.selector;
            selectors[6] = RulesEnginePolicyFacet.cementPolicy.selector;
            selectors[7] = RulesEnginePolicyFacet.isCementedPolicy.selector;
            selectors[8] = RulesEnginePolicyFacet.isClosedPolicy.selector;
            selectors[9] = RulesEnginePolicyFacet.isDisabledPolicy.selector;
            selectors[10] = RulesEnginePolicyFacet.disablePolicy.selector;
            selectors[11] = RulesEnginePolicyFacet.openPolicy.selector;
            selectors[12] = RulesEnginePolicyFacet.closePolicy.selector;
            selectors[13] = RulesEnginePolicyFacet.deletePolicy.selector;
            selectors[14] = RulesEnginePolicyFacet.getPolicyMetadata.selector;
            return selectors;
        } else if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEngineComponentFacet"))) {
            bytes4[] memory selectors = new bytes4[](17);
            selectors[0] = RulesEngineComponentFacet.createCallingFunction.selector;
            selectors[1] = RulesEngineComponentFacet.updateCallingFunction.selector;
            selectors[2] = RulesEngineComponentFacet.getCallingFunction.selector;
            selectors[3] = RulesEngineComponentFacet.deleteCallingFunction.selector;
            selectors[4] = RulesEngineComponentFacet.getAllCallingFunctions.selector;
            selectors[5] = RulesEngineComponentFacet.getTracker.selector;
            selectors[6] = RulesEngineComponentFacet.deleteTracker.selector;
            selectors[7] = RulesEngineComponentFacet.getAllTrackers.selector;
            selectors[8] = RulesEngineComponentFacet.createTracker.selector;
            selectors[9] = RulesEngineComponentFacet.getTrackerMetadata.selector;
            selectors[10] = RulesEngineComponentFacet.getMappedTrackerValue.selector;
            // Handle overloaded updateTracker functions with explicit signatures
            selectors[11] = bytes4(keccak256("updateTracker(uint256,uint256,(bool,uint8,bool,uint8,bytes,uint256))"));
            selectors[12] = bytes4(keccak256("updateTracker(uint256,uint256,(bool,uint8,bool,uint8,bytes,uint256),bytes,bytes)"));
            selectors[13] = RulesEngineComponentFacet.getCallingFunctionMetadata.selector;
            selectors[14] = RulesEngineComponentFacet.addClosedPolicySubscriber.selector;
            selectors[15] = RulesEngineComponentFacet.removeClosedPolicySubscriber.selector;
            selectors[16] = RulesEngineComponentFacet.isClosedPolicySubscriber.selector;
            return selectors;
        } else if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEngineForeignCallFacet"))) {
            bytes4[] memory selectors = new bytes4[](13); // Only create enough slots for actual selectors
            selectors[0] = RulesEngineForeignCallFacet.createForeignCall.selector;
            selectors[1] = RulesEngineForeignCallFacet.updateForeignCall.selector;
            selectors[2] = RulesEngineForeignCallFacet.getForeignCall.selector;
            selectors[3] = RulesEngineForeignCallFacet.deleteForeignCall.selector;
            selectors[4] = RulesEngineForeignCallFacet.getAllForeignCalls.selector;
            selectors[5] = RulesEngineForeignCallFacet.getForeignCallMetadata.selector;
            selectors[6] = RulesEngineForeignCallFacet.addAdminToPermissionList.selector;
            selectors[7] = RulesEngineForeignCallFacet.updatePermissionList.selector;
            selectors[8] = RulesEngineForeignCallFacet.getForeignCallPermissionList.selector;
            selectors[9] = RulesEngineForeignCallFacet.removeAllFromPermissionList.selector;
            selectors[10] = RulesEngineForeignCallFacet.removeFromPermissionList.selector;
            selectors[11] = RulesEngineForeignCallFacet.removeForeignCallPermissions.selector;
            selectors[12] = RulesEngineForeignCallFacet.getAllPermissionedFCs.selector;
            return selectors;
        } else if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEngineAdminRolesFacet"))) {
            bytes4[] memory selectors = new bytes4[](18); // Only create enough slots for actual selectors
            selectors[0] = RulesEngineAdminRolesFacet.proposeNewPolicyAdmin.selector;
            selectors[1] = RulesEngineAdminRolesFacet.confirmNewPolicyAdmin.selector;
            selectors[2] = RulesEngineAdminRolesFacet.isPolicyAdmin.selector;
            selectors[3] = RulesEngineAdminRolesFacet.generatePolicyAdminRole.selector;
            selectors[4] = RulesEngineAdminRolesFacet.proposeNewCallingContractAdmin.selector;
            selectors[5] = RulesEngineAdminRolesFacet.confirmNewCallingContractAdmin.selector;
            selectors[6] = RulesEngineAdminRolesFacet.isCallingContractAdmin.selector;
            selectors[7] = RulesEngineAdminRolesFacet.grantCallingContractRole.selector;
            selectors[8] = RulesEngineAdminRolesFacet.grantCallingContractRoleAccessControl.selector;
            selectors[9] = RulesEngineAdminRolesFacet.grantCallingContractRoleOwnable.selector;
            selectors[10] = RulesEngineAdminRolesFacet.grantForeignCallAdminRole.selector;
            selectors[11] = RulesEngineAdminRolesFacet.isForeignCallAdmin.selector;
            selectors[12] = RulesEngineAdminRolesFacet.proposeNewForeignCallAdmin.selector;
            selectors[13] = RulesEngineAdminRolesFacet.confirmNewForeignCallAdmin.selector;
            selectors[14] = AccessControlEnumerable.getRoleMemberCount.selector;
            selectors[15] = AccessControl.hasRole.selector;
            selectors[16] = AccessControl.renounceRole.selector;
            selectors[17] = AccessControl.revokeRole.selector;
            return selectors;
        } else if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEngineInitialFacet"))) {
            bytes4[] memory selectors = new bytes4[](3);
            selectors[0] = RulesEngineInitialFacet.initialize.selector;
            selectors[1] = RulesEngineInitialFacet.retrieveRawStringFromInstructionSet.selector;
            selectors[2] = RulesEngineInitialFacet.retrieveRawAddressFromInstructionSet.selector;
            return selectors;
        } else if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEngineProcessorFacet"))) {
            bytes4[] memory selectors = new bytes4[](1);
            selectors[0] = RulesEngineProcessorFacet.checkPolicies.selector;
            return selectors;
        } else if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEngineRuleFacet"))) {
            bytes4[] memory selectors = new bytes4[](6);
            selectors[0] = RulesEngineRuleFacet.createRule.selector;
            selectors[1] = RulesEngineRuleFacet.updateRule.selector;
            selectors[2] = RulesEngineRuleFacet.getRule.selector;
            selectors[3] = RulesEngineRuleFacet.deleteRule.selector;
            selectors[4] = RulesEngineRuleFacet.getAllRules.selector;
            selectors[5] = RulesEngineRuleFacet.getRuleMetadata.selector;
            return selectors;
        } else if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("NativeFacet"))) {
            bytes4[] memory selectors = new bytes4[](2);
            selectors[0] = ERC173Facet.owner.selector;
            selectors[1] = ERC173Facet.transferOwnership.selector;
            return selectors;
        }
        // Default return for unknown facets - empty array
        return new bytes4[](0);
    }

    // Implementation of createRulesEngineDiamond without cheatcodes
    function createRulesEngineDiamondNoCheatcodes(address owner) internal returns (ForteRulesEngine diamond) {
        delete _ruleProcessorFacetCutsNoCheatcodes;
        // Start by deploying the DiamonInit contract.
        DiamondInit diamondInit = new DiamondInit();

        // Build the DiamondArgs.
        RulesEngineDiamondArgs memory diamondArgs = RulesEngineDiamondArgs({
            init: address(diamondInit),
            // NOTE: "interfaceId" can be used since "init" is the only function in IDiamondInit.
            initCalldata: abi.encode(type(IDiamondInit).interfaceId)
        });

        _ruleProcessorFacetCutsNoCheatcodes.push(
            FacetCut({
                facetAddress: address(new RulesEngineProcessorFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("RulesEngineProcessorFacet")
            })
        );

        _ruleProcessorFacetCutsNoCheatcodes.push(
            FacetCut({
                facetAddress: address(new RulesEnginePolicyFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("RulesEnginePolicyFacet")
            })
        );

        _ruleProcessorFacetCutsNoCheatcodes.push(
            FacetCut({
                facetAddress: address(new RulesEngineComponentFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("RulesEngineComponentFacet")
            })
        );

        // Data
        _ruleProcessorFacetCutsNoCheatcodes.push(
            FacetCut({
                facetAddress: address(new RulesEngineForeignCallFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("RulesEngineForeignCallFacet")
            })
        );

        _ruleProcessorFacetCutsNoCheatcodes.push(
            FacetCut({
                facetAddress: address(new RulesEngineAdminRolesFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("RulesEngineAdminRolesFacet")
            })
        );

        _ruleProcessorFacetCutsNoCheatcodes.push(
            FacetCut({
                facetAddress: address(new RulesEngineInitialFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("RulesEngineInitialFacet")
            })
        );

        _ruleProcessorFacetCutsNoCheatcodes.push(
            FacetCut({
                facetAddress: address(new RulesEngineRuleFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("RulesEngineRuleFacet")
            })
        );

        _ruleProcessorFacetCutsNoCheatcodes.push(
            FacetCut({
                facetAddress: address(new NativeFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("NativeFacet")
            })
        );

        // Deploy the diamond and initialize
        ForteRulesEngine rulesEngineInternal = new ForteRulesEngine(_ruleProcessorFacetCutsNoCheatcodes, diamondArgs);

        RulesEngineInitialFacet(address(rulesEngineInternal)).initialize(owner);
        return rulesEngineInternal;
    }

    function createRulesEngineDiamondWithTestProcessorFacet(address owner) internal returns (ForteRulesEngine diamond) {
        delete _ruleProcessorFacetCutsWithTestProcessorFacet;
        // Start by deploying the DiamonInit contract.
        DiamondInit diamondInit = new DiamondInit();

        // Build the DiamondArgs.
         RulesEngineDiamondArgs memory diamondArgs = RulesEngineDiamondArgs({
            init: address(diamondInit),
            // NOTE: "interfaceId" can be used since "init" is the only function in IDiamondInit.
            initCalldata: abi.encode(type(IDiamondInit).interfaceId)
        });

        // Protocol Facets

        // Native
        _ruleProcessorFacetCutsWithTestProcessorFacet.push(
            FacetCut({
                facetAddress: address(new NativeFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayTestProcessorFacet("NativeFacet")
            })
        );

        // Main
        _ruleProcessorFacetCutsWithTestProcessorFacet.push(
            FacetCut({
                facetAddress: address(new TestProcessorFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayTestProcessorFacet("TestProcessorFacet")
            })
        );

        // Data
        _ruleProcessorFacetCutsWithTestProcessorFacet.push(
            FacetCut({
                facetAddress: address(new RulesEnginePolicyFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayTestProcessorFacet("RulesEnginePolicyFacet")
            })
        );

        // Data
        _ruleProcessorFacetCutsWithTestProcessorFacet.push(
            FacetCut({
                facetAddress: address(new RulesEngineComponentFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayTestProcessorFacet("RulesEngineComponentFacet")
            })
        );

        // Data
        _ruleProcessorFacetCutsWithTestProcessorFacet.push(
            FacetCut({
                facetAddress: address(new RulesEngineForeignCallFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayTestProcessorFacet("RulesEngineForeignCallFacet")
            })
        );

        // Data
        _ruleProcessorFacetCutsWithTestProcessorFacet.push(
            FacetCut({
                facetAddress: address(new RulesEngineAdminRolesFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayTestProcessorFacet("RulesEngineAdminRolesFacet")
            })
        );

        // Data
        _ruleProcessorFacetCutsWithTestProcessorFacet.push(
            FacetCut({
                facetAddress: address(new RulesEngineInitialFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayTestProcessorFacet("RulesEngineInitialFacet")
            })
        );

        // Data
        _ruleProcessorFacetCutsWithTestProcessorFacet.push(
            FacetCut({
                facetAddress: address(new RulesEngineRuleFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayTestProcessorFacet("RulesEngineRuleFacet")
            })
        );

        /// Build the diamond
        // Deploy the diamond.
        ForteRulesEngine rulesEngineInternal = new ForteRulesEngine(_ruleProcessorFacetCutsWithTestProcessorFacet, diamondArgs);
        RulesEngineInitialFacet(address(rulesEngineInternal)).initialize(owner);
        return rulesEngineInternal;
    }

    function createSelectorArrayTestProcessorFacet(string memory facet) internal returns (bytes4[] memory selectors) {
        string[] memory _inputs = new string[](3);
        _inputs[0] = "python3";
        _inputs[1] = "script/python/get_selectors.py";
        _inputs[2] = facet;
        bytes memory res = vm.ffi(_inputs);
        return abi.decode(res, (bytes4[]));
    }
}
