// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import {RulesEngineStorageLib as StorageLib} from "src/engine/facets/RulesEngineStorageLib.sol";

/**
 * @title Rules Engine Foreign Call Facet
 * @dev This contract serves as the data facet for the Rules Engine Foreign Call Components. It provides functionality for managing
 *      foreign calls. It enforces role-based access control
 *      and ensures that only authorized users can modify or retrieve data. The contract also supports policy cementing
 *      to prevent further modifications.
 * @notice This contract is a critical component of the Rules Engine, enabling secure and flexible data management.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract RulesEngineForeignCallFacet is FacetCommonImports {
    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Foreign Call Management
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Creates a foreign call and stores it in the contract's storage.
     * @dev Builds a foreign call structure and maps it to the associated policy ID.
     * @param _policyId The policy ID the foreign call will be mapped to.
     * @param _foreignCall The definition of the foreign call to create.
     * @param foreignCallName The name of the foreign call
     * @param foreignCallAddress address to make the external to
     * @param foreignCallSelector the selector of the function to call in the contract at the foreignCallAddress
     * @return foreignCallId The index of the created foreign call.
     */
    function createForeignCall(
        uint256 _policyId,
        ForeignCall calldata _foreignCall,
        string calldata foreignCallName,
        address foreignCallAddress,
        bytes4 foreignCallSelector
    ) external returns (uint256 foreignCallId) {
        _policyAdminOnly(_policyId, msg.sender);
        _notCemented(_policyId);
        assembly {
            foreignCallId := or(foreignCallSelector, foreignCallAddress)
        }
        _isForeignCallPermissioned(foreignCallId);
        if (StorageLib._isForeignCallSet(_policyId, foreignCallId)) revert(FOREIGN_CALL_ALREADY_SET);

        // Step 1: Generate the foreign call index
        //uint256 foreignCallIndex = _incrementForeignCallIndex(_policyId);

        // Step 2: Store the foreign call
        _storeForeignCallData(_policyId, _foreignCall, foreignCallId);

        // Step 3: Store metadata
        _storeForeignCallMetadata(_policyId, foreignCallId, foreignCallName);

        emit ForeignCallCreated(_policyId, foreignCallId);
    }

    /**
     * @notice Updates a foreign call in the contract's storage.
     * @param policyId The policy ID the foreign call is associated with.
     * @param foreignCallId The ID of the foreign call to update.
     * @param foreignCall The updated foreign call structure.
     * @return fc The updated foreign call structure.
     */
    function updateForeignCall(
        uint256 policyId,
        uint256 foreignCallId,
        ForeignCall calldata foreignCall
    ) external returns (ForeignCall memory fc) {
        _policyAdminOnly(policyId, msg.sender);
        _notCemented(policyId);
        if (!StorageLib._isForeignCallSet(policyId, foreignCallId)) revert(FOREIGN_CALL_NOT_SET);
        _isForeignCallPermissioned(foreignCallId);
        fc = foreignCall;
        _storeForeignCall(policyId, foreignCall, foreignCallId);
        emit ForeignCallUpdated(policyId, foreignCallId);
    }

    /**
     * @notice Deletes a foreign call from the contract's storage.
     * @param policyId The policy ID the foreign call is associated with.
     * @param foreignCallId The ID of the foreign call to delete.
     */
    function deleteForeignCall(uint256 policyId, uint256 foreignCallId) external {
        _policyAdminOnly(policyId, msg.sender);
        _notCemented(policyId);
        delete lib._getForeignCallStorage().foreignCalls[policyId][foreignCallId];
        emit ForeignCallDeleted(policyId, foreignCallId);
    }

    /**
     * @dev Retrieve Foreign Call Set from storage
     * @param policyId the policy Id of the foreign call to retrieve
     * @return the foreign call set structure
     */
    function getAllForeignCalls(uint256 policyId) external view returns (ForeignCall[] memory) {
        // Return the Foreign Call Set data from storage
        uint256[] memory foreignCallIds = lib._getForeignCallStorage().foreignCallIds[policyId];
        ForeignCall[] memory foreignCalls = new ForeignCall[](foreignCallIds.length);
        uint256 j = 0;
        for (uint256 i = 0; i < foreignCallIds.length; i++) {
            if (lib._getForeignCallStorage().foreignCalls[policyId][foreignCallIds[i]].set) {
                foreignCalls[j] = lib._getForeignCallStorage().foreignCalls[policyId][foreignCallIds[i]];
                j++;
            }
        }
        return foreignCalls;
    }

    /**
     * @notice Retrieves a foreign call from the contract's storage.
     * @param policyId The policy ID of the foreign call to retrieve.
     * @param foreignCallId The ID of the foreign call to retrieve.
     * @return The foreign call structure.
     */
    function getForeignCall(uint256 policyId, uint256 foreignCallId) public view returns (ForeignCall memory) {
        // Load the Foreign Call data from storage
        return lib._getForeignCallStorage().foreignCalls[policyId][foreignCallId];
    }

    /**
     * @notice retrieves the foreign call metadata
     * @param policyId The policy ID the foreign call is associated with.
     * @param foreignCallId The identifier for the foreign call
     * @return the metadata for the foreign call
     */
    function getForeignCallMetadata(uint256 policyId, uint256 foreignCallId) public view returns (string memory) {
        return lib._getForeignCallMetadataStorage().foreignCallMetadata[policyId][foreignCallId];
    }

    /**
     * @notice Stores a foreign call in the contract's storage.
     * @dev Ensures the foreign call is properly set before storing it.
     * @param _policyId The policy ID the foreign call is associated with.
     * @param _foreignCall The foreign call to store.
     */
    function _storeForeignCall(uint256 _policyId, ForeignCall calldata _foreignCall, uint256 _foreignCallId) internal {
        assert(_foreignCall.parameterTypes.length == _foreignCall.encodedIndices.length);
        address foreignCallAddress = address(uint160(_foreignCallId));
        bytes4 foreignCallSelector = bytes4(bytes32(_foreignCallId));
        if (foreignCallAddress == address(0)) revert(ZERO_ADDRESS_NOT_ALLOWED);
        if (foreignCallAddress == address(this)) revert(ADDRESS_NOT_ALLOWED);
        if (foreignCallSelector == EMPTY_SIG) revert(SIG_REQ);
        require(_foreignCall.parameterTypes.length < MAX_LOOP, MAX_FC_PT);
        uint mappedTrackerKeyIndexCounter = 0;
        for (uint256 i = 0; i < _foreignCall.encodedIndices.length; i++) {
            if (_foreignCall.encodedIndices[i].eType == EncodedIndexType.MAPPED_TRACKER_KEY) {
                require(
                    mappedTrackerKeyIndexCounter < _foreignCall.mappedTrackerKeyIndices.length,
                    MAPPED_TRACKER_KEY_INDICES_LENGTH_MISMATCH
                );
                require(
                    _foreignCall.mappedTrackerKeyIndices[mappedTrackerKeyIndexCounter].eType != EncodedIndexType.MAPPED_TRACKER_KEY,
                    MAPPED_TRACKER_KEY_CANNOT_BE_DOUBLE_NESTED
                );
                mappedTrackerKeyIndexCounter++;
            }
        }
        require(mappedTrackerKeyIndexCounter == _foreignCall.mappedTrackerKeyIndices.length, MAPPED_TRACKER_KEY_INDICES_LENGTH_MISMATCH);
        uint256 id;
        assembly {
            id := or(foreignCallSelector, foreignCallAddress)
        }
        lib._getForeignCallStorage().foreignCalls[_policyId][id] = _foreignCall;
        lib._getForeignCallStorage().foreignCalls[_policyId][id].set = true;
        lib._getForeignCallStorage().foreignCallIds[_policyId].push(id);
    }

    /**
     * @dev Helper function to increment the foreign call index
     * @dev Ensures the foreign call is properly set before storing it.
     * @param _policyId The policy ID the foreign call is associated with.
     */
    /*function _incrementForeignCallIndex(uint256 _policyId) private returns (uint256) {
        ForeignCallStorage storage data = lib._getForeignCallStorage();
        return ++data.foreignCallIdxCounter[_policyId];
    }*/

    /**
     * @dev Helper function to store the foreign call data
     * @dev Ensures the foreign call is properly set before storing it.
     * @param _policyId The policy ID the foreign call is associated with.
     * @param _foreignCall The foreign call to store.
     */
    function _storeForeignCallData(uint256 _policyId, ForeignCall calldata _foreignCall, uint256 _foreignCallId) private {
        ForeignCallStorage storage data = lib._getForeignCallStorage();
        _storeForeignCall(_policyId, _foreignCall, _foreignCallId);
    }

    /**
     * @dev Helper function to store the foreign call metadata
     * @param _policyId The policy ID the foreign call is associated with.
     * @param _foreignCallId The ID of the foreign call.
     * @param _foreignCallName The name of the foreign call.
     */
    function _storeForeignCallMetadata(uint256 _policyId, uint256 _foreignCallId, string calldata _foreignCallName) private {
        require(keccak256(bytes(_foreignCallName)) != EMPTY_STRING_HASH, NAME_REQ);
        lib._getForeignCallMetadataStorage().foreignCallMetadata[_policyId][_foreignCallId] = _foreignCallName;
    }

    /**
     * @notice Checks if the foreign call is permissioned and if the caller is authorized.
     * @param _foreignCallId The ID of the foreign call.
     */
    function _isForeignCallPermissioned(uint256 _foreignCallId) internal view {
        // look up the foreign call in the permissioned foreign call storage to see if it is permissioned
        if (
            lib._getForeignCallStorage().isPermissionedForeignCall[_foreignCallId] &&
            !lib._getForeignCallStorage().permissionedForeignCallAdmins[_foreignCallId][msg.sender]
        ) revert(NOT_PERMISSIONED_FOR_FOREIGN_CALL);
    }

    /**
     * @notice Adds an admin to the permission list for a foreign call.
     * @dev This function can only be called by an existing foreign call admin.
     * @param foreignCallId The ID of the foreign call.
     * @param policyAdminsToAdd The address of the admin to add to the permission list.
     */
    function addAdminToPermissionList(uint256 foreignCallId, address policyAdminsToAdd) external {
        _foreignCallAdminOnly(address(uint160(foreignCallId)), msg.sender, bytes4(bytes32(foreignCallId)));
        // add single address to the permission list for the foreign call
        lib._getForeignCallStorage().permissionedForeignCallAdminsList[foreignCallId].push(policyAdminsToAdd);
        // add single address to the permission mapping
        lib._getForeignCallStorage().permissionedForeignCallAdmins[foreignCallId][policyAdminsToAdd] = true;
        // emit event
        emit AdminAddedToForeignCallPermissions(foreignCallId, policyAdminsToAdd);
    }

    /**
     * @notice Updates the permission list for a foreign call.
     * @dev This function can only be called by an existing foreign call admin.
     * @param foreignCallId The ID of the foreign call.
     * @param policyAdminsToAdd The addresses of the admins to add to the permission list.
     */
    function updatePermissionList(uint256 foreignCallId, address[] memory policyAdminsToAdd) external {
        _foreignCallAdminOnly(address(uint160(foreignCallId)), msg.sender, bytes4(bytes32(foreignCallId)));
        // retreive current list and set all addresses in the current list to false (remove them from the permission list)
        address[] memory oldAdminList = getForeignCallPermissionList(foreignCallId);
        // reset mappings and arrays to empty
        delete lib._getForeignCallStorage().permissionedForeignCallAdminsList[foreignCallId];
        for (uint256 i = 0; i < oldAdminList.length; i++) {
            lib._getForeignCallStorage().permissionedForeignCallAdmins[foreignCallId][oldAdminList[i]] = false;
        }

        // add all addresses to the permission list for the foreign call
        for (uint256 i = 0; i < policyAdminsToAdd.length; i++) {
            lib._getForeignCallStorage().permissionedForeignCallAdminsList[foreignCallId].push(policyAdminsToAdd[i]);
            lib._getForeignCallStorage().permissionedForeignCallAdmins[foreignCallId][policyAdminsToAdd[i]] = true;
            // emit event
            emit AdminAddedToForeignCallPermissions(foreignCallId, policyAdminsToAdd[i]);
        }
        // emit list of addresses added to the permission list
        emit ForeignCallPermissionsListUpdate(foreignCallId, policyAdminsToAdd);
    }

    /**
     * @notice Retrieves the permission list for a foreign call.
     * @param foreignCallId The ID of the foreign call to retrieve the permission list for.
     * @return An array of addresses that are permissioned for the foreign call.
     */
    function getForeignCallPermissionList(uint256 foreignCallId) public view returns (address[] memory) {
        // return the permissioned foreign call admins for the foreign call address and selector
        return lib._getForeignCallStorage().permissionedForeignCallAdminsList[foreignCallId];
    }

    /**
     * @notice Removes all addresses from the permission list for a foreign call.
     * @notice This function resets the permission list to only include the foreign call admin.
     * @dev This function can only be called by an existing foreign call admin.
     * @param foreignCallId The ID of the foreign call to remove all permissions from.
     */
    function removeAllFromPermissionList(uint256 foreignCallId) external {
        _foreignCallAdminOnly(address(uint160(foreignCallId)), msg.sender, bytes4(bytes32(foreignCallId)));
        // retreive current list and set all addresses in the current list to false (remove them from the permission list)
        address[] memory oldAdminList = getForeignCallPermissionList(foreignCallId);
        // reset mappings and arrays to empty
        delete lib._getForeignCallStorage().permissionedForeignCallAdminsList[foreignCallId];
        for (uint256 i = 1; i < oldAdminList.length; i++) {
            // index starts at one to skip the foreign call admin address
            lib._getForeignCallStorage().permissionedForeignCallAdmins[foreignCallId][oldAdminList[i]] = false;
        }
        // emit event
        emit ForeignCallPermissionsListReset(foreignCallId);
    }

    /**
     * @notice Removes a specific address from the permission list for a foreign call.
     * @dev This function can only be called by an existing foreign call admin.
     * @param foreignCallId The ID of the foreign call to remove the address from.
     * @param policyAdminToRemove The address of the admin to remove from the permission list.
     */
    function removeFromPermissionList(uint256 foreignCallId, address policyAdminToRemove) external {
        _foreignCallAdminOnly(address(uint160(foreignCallId)), msg.sender, bytes4(bytes32(foreignCallId)));
        // remove the address from the permission list for the foreign call
        lib._getForeignCallStorage().permissionedForeignCallAdmins[foreignCallId][policyAdminToRemove] = false;
        // remove the address from the permissioned foreign call admins list
        address[] storage adminList = lib._getForeignCallStorage().permissionedForeignCallAdminsList[foreignCallId];
        for (uint256 i = 0; i < adminList.length; i++) {
            if (adminList[i] == policyAdminToRemove) {
                adminList[i] = adminList[adminList.length - 1]; // Move last element to current position
                adminList.pop(); // Remove last element
                break;
            }
        }
        // emit event
        emit ForeignCallPermissionsListUpdate(foreignCallId, adminList);
    }

    /**
     * @notice Removes foreign call permissions from the contract address and selector pair.
     * @dev This function can only be called by an existing foreign call admin.
     * @param foreignCallId The ID of the foreign call to remove permissions for.
     */
    function removeForeignCallPermissions(uint256 foreignCallId) external {
        _foreignCallAdminOnly(address(uint160(foreignCallId)), msg.sender, bytes4(bytes32(foreignCallId)));
        // retreive current list and set all addresses in the current list to false (remove them from the permission list)
        address[] memory oldAdminList = getForeignCallPermissionList(foreignCallId);
        // reset mappings and arrays to empty
        delete lib._getForeignCallStorage().permissionedForeignCallAdminsList[foreignCallId];
        for (uint256 i = 0; i < oldAdminList.length; i++) {
            lib._getForeignCallStorage().permissionedForeignCallAdmins[foreignCallId][oldAdminList[i]] = false;
        }

        // remove from permissioned foreign call master list and map
        lib._getForeignCallStorage().isPermissionedForeignCall[foreignCallId] = false;
        //address[] storage pfcAddressList = lib._getPermissionedForeignCallStorage().permissionedForeignCallAddresses;
        //bytes4[] storage pfcSelectorsList = lib._getPermissionedForeignCallStorage().permissionedForeignCallSignatures;
        uint256[] storage pfcIds = lib._getPermissionedForeignCallStorage().permissionedForeignCallIds;
        for (uint256 i = 0; i < pfcIds.length; i++) {
            if (pfcIds[i] == foreignCallId) {
                // Move last element to current position
                pfcIds[i] = pfcIds[pfcIds.length - 1];
                // Remove last element
                pfcIds.pop();
                break;
            }
        }

        // emit event
        emit ForeignCallPermissionsRemoved(foreignCallId);
    }

    /**
     * @notice Retrieves all permissioned foreign calls.
     * @return The PermissionedForeignCallStorage structure containing all permissioned foreign calls.
     */
    function getAllPermissionedFCs() external pure returns (PermissionedForeignCallStorage memory) {
        return lib._getPermissionedForeignCallStorage();
    }

    /**
     * @notice Checks that a policy is not cemented.
     * @param _policyId The ID of the policy.
     */
    function _notCemented(uint256 _policyId) internal view {
        if (lib._getPolicyStorage().policyStorageSets[_policyId].policy.cemented) revert(NOT_ALLOWED_CEMENTED_POLICY);
    }

    /**
     * @notice Checks that the caller is a policy admin
     * @param _policyId The ID of the policy.
     * @param _address The address to check for policy admin status.
     */
    function _policyAdminOnly(uint256 _policyId, address _address) internal {
        // 0x901cee11 = isPolicyAdmin(uint256,address)
        (bool success, bytes memory res) = _callAnotherFacet(
            0x901cee11,
            abi.encodeWithSignature("isPolicyAdmin(uint256,address)", _policyId, _address)
        );
        bool returnBool;
        if (success) {
            if (res.length >= 4) {
                assembly {
                    returnBool := mload(add(res, 32))
                }
            } else {
                returnBool = false;
            }
            // returned false so revert with error
            if (!returnBool) revert(NOT_AUTH_POLICY);
        }
    }

    /**
     * @notice Checks that the caller is a policy admin
     * @param _foreignCallAddr The ID of the foreign call.
     * @param _address The address to check for policy admin status.
     * @param _functionSelector The function selector to check for policy admin status.
     */
    function _foreignCallAdminOnly(address _foreignCallAddr, address _address, bytes4 _functionSelector) internal {
        // 0x41a2b7ae = isForeignCallAdmin(address,address,bytes4)
        (bool success, bytes memory res) = _callAnotherFacet(
            0x41a2b7ae,
            abi.encodeWithSignature("isForeignCallAdmin(address,address,bytes4)", _foreignCallAddr, _address, _functionSelector)
        );
        bool returnBool;
        if (success) {
            if (res.length >= 4) {
                assembly {
                    returnBool := mload(add(res, 32))
                }
            } else {
                returnBool = false;
            }
            // returned false so revert with error
            if (!returnBool) revert(NOT_AUTH_FC);
        }
    }

    /**
     * @notice Validates a foreign call.
     * @param _foreignCall The foreign call to validate.
     */
    function _validateForeignCall(ForeignCall memory _foreignCall, address _foreignCallAddress) internal pure {
        _validateParamType(_foreignCall.returnType);
        for (uint256 i = 0; i < _foreignCall.parameterTypes.length; i++) {
            _validateParamType(_foreignCall.parameterTypes[i]);
        }
        require(_foreignCallAddress != address(0), ZERO_ADDRESS_NOT_ALLOWED);
    }

    /**
     * @notice Validates a paramType.
     * @param paramType The paramType to validate.
     */
    function _validateParamType(ParamTypes paramType) internal pure {
        uint paramTypesSize = 8;
        if (uint(paramType) >= paramTypesSize) revert(INVALID_PARAM_TYPE);
    }
}
