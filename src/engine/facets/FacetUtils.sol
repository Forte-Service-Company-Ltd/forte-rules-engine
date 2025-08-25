// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {RulesEngineDiamondLib, RulesEngineDiamondStorage} from "src/engine/RulesEngineDiamondLib.sol";
import {Placeholder} from "src/engine/RulesEngineStorageStructure.sol";

/**
 * @title Facet Utilities
 * @dev This contract provides utility functions for interacting with other facets in the Rules Engine.
 *      It includes functionality for performing delegate calls to other facets using their function selectors.
 * @notice This contract is intended to be used internally by facets in the Rules Engine to streamline cross-facet interactions.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract FacetUtils {
    // Constants for bit flags and masks
    uint8 constant FLAG_FOREIGN_CALL = 0x01; // 00000001
    uint8 constant FLAG_TRACKER_VALUE = 0x02; // 00000010
    uint8 constant MASK_GLOBAL_VAR = 0x1C; // 00011100
    uint8 constant SHIFT_GLOBAL_VAR = 2;

    /**
     * @notice Performs a delegate call to another facet in the Rules Engine.
     * @dev Uses the function selector to locate the target facet and executes the provided call data.
     *      Reverts with the returned error message if the delegate call fails.
     * @param _functionSelector The function selector of the target function in the other facet.
     * @param _callData The encoded call data to pass to the target function.
     * @return _success A boolean indicating whether the delegate call was successful.
     * @return _res The returned data from the delegate call.
     */
    function _callAnotherFacet(bytes4 _functionSelector, bytes memory _callData) internal returns (bool _success, bytes memory _res) {
        RulesEngineDiamondStorage storage ds = RulesEngineDiamondLib.s();
        address facet = ds.facetAddressAndSelectorPosition[_functionSelector].facetAddress;
        (_success, _res) = address(facet).delegatecall(_callData);
        if (!_success)
            assembly {
                revert(add(_res, 0x20), mload(_res))
            }
    }

    /**
     * @notice Checks if the foreign call flag is set in a Placeholder using assembly
     * @dev Uses optimized assembly to extract the flag bit directly from memory
     * @param placeholder The Placeholder struct to check
     * @return result True if the foreign call flag is set, false otherwise
     */
    function _isForeignCall(Placeholder memory placeholder) internal pure returns (bool result) {
        assembly {
            // Load the flags byte from memory (offset 0x40 from placeholder pointer)
            let flags := and(mload(add(placeholder, 0x40)), 0xFF)

            // Check if FLAG_FOREIGN_CALL bit is set
            // FLAG_FOREIGN_CALL = 0x01 (00000001 in binary)
            result := and(flags, 0x01)
        }
    }

    /**
     * @notice Checks if the tracker value flag is set in a Placeholder using assembly
     * @dev Uses optimized assembly to extract the flag bit directly from memory
     * @param placeholder The Placeholder struct to check
     * @return result True if the tracker value flag is set, false otherwise
     */
    function _isTrackerValue(Placeholder memory placeholder) internal pure returns (bool result) {
        assembly {
            // Load the flags byte from memory (offset 0x40 from placeholder pointer)
            let flags := and(mload(add(placeholder, 0x40)), 0xFF)

            // Check if FLAG_TRACKER_VALUE bit is set
            // FLAG_TRACKER_VALUE = 0x02 (00000010 in binary)
            result := and(flags, 0x02)
        }
    }

    /**
     * @dev Helper function to extract flags from a placeholder
     * @param placeholder The placeholder to extract flags from
     * @return isTrackerValue Whether the tracker value flag is set
     * @return isForeignCall Whether the foreign call flag is set
     * @return globalVarType The global variable type
     */
    function _extractFlags(
        Placeholder memory placeholder
    ) internal pure returns (bool isTrackerValue, bool isForeignCall, uint8 globalVarType) {
        assembly {
            // Load the flags byte from memory (offset 0x40 from placeholder pointer)
            let flags := and(mload(add(placeholder, 0x40)), 0xFF)

            // Check if foreign call bit is set (bit 0)
            isForeignCall := and(flags, 0x01) // FLAG_FOREIGN_CALL = 0x01

            // Check if tracker bit is set (bit 1)
            isTrackerValue := and(flags, 0x02) // FLAG_TRACKER_VALUE = 0x02

            // Extract global var type (bits 2-4)
            // First AND with mask 0x1C (00011100), then shift right by 2 bits
            globalVarType := shr(2, flags) // MASK_GLOBAL_VAR = 0x1C, SHIFT_GLOBAL_VAR = 2
        }
    }

    /**
     * @dev this is a type-agnostic solution for determining if an array of value types from calldata contains duplicates in it
     * @param len the length of the array. Can be easily retrieved in _Solidity_ by using array.length;
     * @param start the location in the calldata of the first element of the array. Can be retrieved with _Yul_ by doing array.offset
     * @return duplicatesFound true if at least one element is repeated in the array. False otherwise
     * @notice this is only useful for an array passed as an argument to an external/public function and the function explicitely uses
     *      the calldata keyword. This won't work if the array is stored in memory.
     */
    function _isThereDuplicatesInCalldataValueTypeArray(uint len, uint start) internal pure returns (bool duplicatesFound) {
        assembly {
            // loop for element (a) can only go until length - 1 (last one must be (b))
            for {
                let i := 0
            } lt(i, sub(len, 1)) {
                i := add(i, 1)
            } {
                let element := calldataload(add(start, mul(i, 32))) // we load the element from calldata to later compare it against all others
                // loop for element (b) must start from i + 1 item (i must be (a))
                for {
                    let j := add(i, 1)
                } lt(j, len) {
                    j := add(j, 1)
                } {
                    let other := calldataload(add(start, mul(j, 32))) // we store the other element (b)
                    // now we compare element a with b
                    if eq(element, other) {
                        duplicatesFound := 1 // if they are equal we set the result to true
                        break // we are done now
                    }
                }
                if gt(duplicatesFound, 0) {
                    break
                }
            }
        }
    }
}
