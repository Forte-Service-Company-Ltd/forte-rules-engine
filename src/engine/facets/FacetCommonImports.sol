// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {RulesEngineStoragePositionLib as lib} from "src/engine/RulesEngineStoragePositionLib.sol";
import "src/engine/AccessModifiers.sol";
import "src/engine/RulesEngineStorageStructure.sol";
import "src/engine/facets/FacetUtils.sol";
import "src/engine/RulesEngineEvents.sol";
import "src/engine/RulesEngineErrors.sol";

/**
 * @title Facet Common Imports
 * @dev This abstract contract consolidates common imports and dependencies for facets in the Rules Engine.
 *      It ensures consistent access to shared libraries, modifiers, storage structures, utilities, events, and errors.
 * @notice This contract is intended to be inherited by other facet contracts to streamline their implementation.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
abstract contract FacetCommonImports is AccessModifiers {
    uint256 constant MAX_LOOP = 10_000;
    uint8 constant MAX_PTYPES = 8;
    bytes32 constant EMPTY_STRING_HASH = keccak256(bytes(""));
    bytes4 constant EMPTY_SIG = bytes4(keccak256(bytes("")));
    uint constant memorySize = 90; // size of the mem array
    uint constant opsSize1 = 3; // the first 3 opcodes use only one argument
    uint constant opsSizeUpTo2 = 17; // the 4th through 16th opcodes use up to two arguments
    uint constant opsSizeUpTo3 = 18; // the 17th through the end opcodes use up to three arguments
    uint constant opsTotalSize = 19; // there are a total of 18 opcodes in the set LogicalOp
}
