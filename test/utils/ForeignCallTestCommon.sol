/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {console} from "forge-std/src/console.sol";
/**
 * @title Example contract for testing the Foreign Call Encoding
 * @author @mpetersoCode55
 */
contract ForeignCallTestContract {
    uint256 decodedIntOne;
    uint256 decondedIntTwo;
    string decodedStrOne;
    string decodedStrTwo;
    bytes decodedBytes;
    address decodedAddr;
    address decodedAddrTwo;
    uint256 internalValue;
    uint256[] internalArrayUint;
    address[] internalArrayAddr;
    string[] internalArrayStr;
    bytes[] internalArrayBytes;
    bool public decodedBool;
    uint128 public decodedUint128;
    uint64 public decodedUint64;

    function testSig(
        uint256 encodedIntOne,
        string memory encodedStrOne,
        uint256 encodedIntTwo,
        string memory encodedStrTwo,
        address encodedAddr
    ) public returns (bool) {
        decodedIntOne = encodedIntOne;
        decondedIntTwo = encodedIntTwo;
        decodedStrOne = encodedStrOne;
        decodedStrTwo = encodedStrTwo;
        decodedAddr = encodedAddr;
        if (encodedIntOne == 1 && encodedIntTwo == 3 && keccak256(bytes(encodedStrOne)) == keccak256("two")) {
            return true;
        } else {
            return false;
        }
    }

    function testSig(uint256 encodedIntOne, uint256 encodedIntTwo) public returns (bool) {
        decodedIntOne = encodedIntOne;
        decondedIntTwo = encodedIntTwo;
        return true;
    }

    function testSig(address encodedAddr, address encodedAddrTwo) public returns (bool) {
        decodedAddr = encodedAddr;
        decodedAddrTwo = encodedAddrTwo;
        return true;
    }

    function testSig(string memory encodedStrOne, string memory encodedStrTwo) public returns (bool) {
        decodedStrOne = encodedStrOne;
        decodedStrTwo = encodedStrTwo;
        return true;
    }

    function testSig(uint256 encodedIntOne) public returns (bool) {
        decodedIntOne = encodedIntOne;
        return true;
    }

    function testSig(address encodedAddr) public returns (bool) {
        decodedAddr = encodedAddr;
        return true;
    }

    function testSig(address encodedAddr, uint256 encodedInt) public returns (bool) {
        decodedAddr = encodedAddr;
        decodedIntOne = encodedInt;
        return true;
    }

    function testSig(string memory encodedStr) public returns (bool) {
        decodedStrOne = encodedStr;
        return true;
    }

    function testSigWithArray(uint256[] memory encodedArray) public returns (bool) {
        for (uint256 i = 0; i < encodedArray.length; i++) {
            internalArrayUint.push(encodedArray[i]);
        }
        return true;
    }

    function testSigWithArray(uint256[] memory encodedArray, uint256[] memory encodedArrayTwo) public returns (bool) {
        for (uint256 i = 0; i < encodedArray.length; i++) {
            internalArrayUint.push(encodedArray[i]);
        }
        for (uint256 i = 0; i < encodedArrayTwo.length; i++) {
            internalArrayUint.push(encodedArrayTwo[i]);
        }
        return true;
    }

    function testSigWithArray(address[] memory encodedArray) public returns (bool) {
        for (uint256 i = 0; i < encodedArray.length; i++) {
            internalArrayAddr.push(encodedArray[i]);
        }
        return true;
    }

    function testSigWithArray(string[] memory encodedArray) public returns (bool) {
        for (uint256 i = 0; i < encodedArray.length; i++) {
            internalArrayStr.push(encodedArray[i]);
        }
        return true;
    }

    function testSigWithArrayPassthrough(string[] memory encodedArray) public pure returns (string[] memory) {
        return encodedArray;
    }

    function testSigWithArraySetInternally(string[] memory encodedArray) public pure returns (string[] memory) {
        encodedArray = new string[](5);
        encodedArray[0] = ("super");
        encodedArray[1] = ("superduper");
        encodedArray[2] = ("superduperduper");
        encodedArray[3] = ("superduperduperduper");
        encodedArray[4] = ("superduperduperduperduper");
        return encodedArray;
    }

    function testSigWithArraySetInternallyOneArg(uint256 x) public pure returns (string[] memory) {
        x;
        string[] memory array = new string[](5);
        array[0] = ("super");
        array[1] = ("superduper");
        array[2] = ("superduperduper");
        array[3] = ("superduperduperduper");
        array[4] = ("superduperduperduperduper");
        return array;
    }

    function testSigWithArraySetInternallyNoArg() public pure returns (string[] memory) {
        string[] memory array = new string[](5);
        array[0] = ("super");
        array[1] = ("superduper");
        array[2] = ("superduperduper");
        array[3] = ("superduperduperduper");
        array[4] = ("superduperduperduperduper");
        return array;
    }

    function testSigWithArray(string[] memory encodedArray, string[] memory encodedArrayTwo) public returns (bool) {
        for (uint256 i = 0; i < encodedArray.length; i++) {
            internalArrayStr.push(encodedArray[i]);
        }
        for (uint256 i = 0; i < encodedArrayTwo.length; i++) {
            internalArrayStr.push(encodedArrayTwo[i]);
        }
        return true;
    }

    function testSigWithArray(bytes[] memory encodedArray) public returns (bool) {
        for (uint256 i = 0; i < encodedArray.length; i++) {
            internalArrayBytes.push(encodedArray[i]);
        }
        return true;
    }

    function testSigWithBytes(bytes memory encodedBytes) public returns (bool) {
        decodedBytes = encodedBytes;
        return true;
    }

    function testSig(bytes memory msgData, string memory str) public returns (bool) {
        decodedBytes = msgData;
        decodedStrOne = str;
        return true;
    }

    function testSigWithMultiArrays(string memory str, uint256[] memory uintArray, string[] memory strArray) public returns (bool) {
        decodedStrOne = str;
        for (uint256 i = 0; i < uintArray.length; i++) {
            internalArrayUint.push(uintArray[i]);
        }
        for (uint256 i = 0; i < strArray.length; i++) {
            internalArrayStr.push(strArray[i]);
        }
        return true;
    }

    function testSigWithMultiArrays(
        uint256[] memory encodedArrayUint,
        address[] memory encodedArrayAddr,
        string[] memory encodedArrayStr,
        bytes[] memory encodedArrayBytes
    ) public returns (bool) {
        for (uint256 i = 0; i < encodedArrayUint.length; i++) {
            internalArrayUint.push(encodedArrayUint[i]);
        }
        for (uint256 i = 0; i < encodedArrayAddr.length; i++) {
            internalArrayAddr.push(encodedArrayAddr[i]);
        }
        for (uint256 i = 0; i < encodedArrayStr.length; i++) {
            internalArrayStr.push(encodedArrayStr[i]);
        }
        for (uint256 i = 0; i < encodedArrayBytes.length; i++) {
            internalArrayBytes.push(encodedArrayBytes[i]);
        }
        return true;
    }

    function testSigWithMultiArrays(uint256[] memory encodedArrayUint, string[] memory encodedArrayStr) public returns (bool) {
        for (uint i = 0; i < encodedArrayUint.length; i++) {
            internalArrayUint.push(encodedArrayUint[i]);
        }
        for (uint i = 0; i < encodedArrayStr.length; i++) {
            internalArrayStr.push(encodedArrayStr[i]);
        }
        return true;
    }

    function testSigWithMultiArrays(string[] memory encodedArrayStr, uint256[] memory encodedArrayUint) public returns (bool) {
        for (uint i = 0; i < encodedArrayUint.length; i++) {
            internalArrayUint.push(encodedArrayUint[i]);
        }
        for (uint i = 0; i < encodedArrayStr.length; i++) {
            internalArrayStr.push(encodedArrayStr[i]);
        }
        return true;
    }

    function testSigWithBool(bool encodedBool) public returns (bool) {
        decodedBool = encodedBool;
        return true;
    }

    function testSigWithUint128(uint128 encodedUint128) public returns (uint128) {
        decodedUint128 = encodedUint128;
        return encodedUint128;
    }

    function testSigWithUint64(uint64 encodedUint64) public returns (uint64) {
        decodedUint64 = encodedUint64;
        return encodedUint64;
    }

    function simpleCheck(uint256 value) public returns (uint256) {
        internalValue = value;
        return value;
    }

    function square(uint256 value) public pure returns (uint256) {
        return value * value;
    }

    function getInternalValue() public view returns (uint256) {
        return internalValue;
    }

    function getDecodedIntOne() public view returns (uint256) {
        return decodedIntOne;
    }

    function getDecodedIntTwo() public view returns (uint256) {
        return decondedIntTwo;
    }

    function getDecodedStrOne() public view returns (string memory) {
        return decodedStrOne;
    }

    function getDecodedStrTwo() public view returns (string memory) {
        return decodedStrTwo;
    }

    function getDecodedBytes() public view returns (bytes memory) {
        return decodedBytes;
    }

    function getDecodedAddr() public view returns (address) {
        return decodedAddr;
    }

    function getInternalArrayUint() public view returns (uint256[] memory) {
        return internalArrayUint;
    }

    function getInternalArrayAddr() public view returns (address[] memory) {
        return internalArrayAddr;
    }

    function getInternalArrayStr() public view returns (string[] memory) {
        return internalArrayStr;
    }

    function getInternalArrayBytes() public view returns (bytes[] memory) {
        return internalArrayBytes;
    }

    function getDecodedAddrTwo() public view returns (address) {
        return decodedAddrTwo;
    }

    function getDecodedBool() public view returns (bool) {
        return decodedBool;
    }

    function getDecodedUint128() public view returns (uint128) {
        return decodedUint128;
    }

    function getDecodedUint64() public view returns (uint64) {
        return decodedUint64;
    }

    function testSigWithEmptyArray(uint256[] memory emptyArray) public returns (bool) {
        // Clear existing array and add empty array elements (should be none)
        delete internalArrayUint;
        for (uint256 i = 0; i < emptyArray.length; i++) {
            internalArrayUint.push(emptyArray[i]);
        }
        return true;
    }

    function testSigReturningString(uint256 input) public pure returns (string memory) {
        if (input == 44) {
            return "forty-four";
        } else if (input == 0) {
            return "zero";
        } else {
            return "other";
        }
    }

    function willRevert(uint256 input) public pure returns (bool) {
        input;
        revert();
    }
}

contract ForeignCallTestContractOFAC {
    mapping(address => bool) public onTheNaughtyList;
    mapping(uint => bool) public onTheNaughtyIdList;
    mapping(address => bool) public approvedList;
    mapping(uint => bool) public approvedIdList;

    function addToNaughtyList(address addr) public {
        onTheNaughtyList[addr] = true;
    }

    function addToNaughtyIdList(uint tokenId) public {
        onTheNaughtyIdList[tokenId] = true;
    }

    function getNaughty(address addr) public view returns (bool) {
        return onTheNaughtyList[addr];
    }

    function addToApprovedList(address addr) public {
        approvedList[addr] = true;
    }

    function addToApprovedIdList(uint tokenId) public {
        approvedIdList[tokenId] = true;
    }

    function getApproved(address addr) public view returns (bool) {
        return approvedList[addr];
    }
}
