/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {RulesEngineProcessorFacet as ProcessorFacet} from "src/engine/facets/RulesEngineProcessorFacet.sol";
import {ForeignCall, ForeignCallReturnValue, ForeignCallEncodedIndex, Placeholder} from "src/engine/RulesEngineStorageStructure.sol";

/**
 * @dev this is a test facet contract that exposes the internal evaluateForeignCallForRuleExternal function
 * from the RulesEngineProcessorFacet since this function can be tested as a stand-alone function/contract
 */
contract TestProcessorFacet is ProcessorFacet {
    function evaluateForeignCallForRuleExternal(
        ForeignCall memory fc,
        bytes calldata functionArguments,
        bytes[] memory retVals,
        ForeignCallEncodedIndex[] memory metadata,
        uint256 policyId
    ) public returns (ForeignCallReturnValue memory retVal) {
        return super.evaluateForeignCallForRule(fc, functionArguments, retVals, metadata, policyId);
    }

    function run(
        uint256[] memory _prog,
        Placeholder[] memory _placeHolders,
        uint256 _policyId,
        bytes[] memory _arguments
    ) public returns (bool) {
        return super._run(_prog, _placeHolders, _policyId, _arguments);
    }
}