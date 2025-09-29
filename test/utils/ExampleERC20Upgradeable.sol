// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "@openzeppelin-contracts-upgradeable-5.4.0/token/ERC20/ERC20Upgradeable.sol";
import "src/client/RulesEngineClientERC20.sol";

contract ExampleERC20Upgradeable is ERC20Upgradeable, RulesEngineClientERC20 {

    address freAddress;

    /**
     * @dev Initializer sets the the App Manager
     * @param _name Name of the token
     * @param _symbol Symbol of the token
     * @param _freAddress Address of Rules Engine
     */
    function initialize(string memory _name, string memory _symbol, address _freAddress) public {
        _name = _name;
        _symbol = _symbol;
        freAddress = _freAddress;
    }

    function doStuff(uint256 amount) public pure returns(bool) {
        amount;
        return true;
    }

    /**
     * @notice Transfers tokens to a specified address.
     * @dev This function overrides the {IERC20-transfer} function and interacts with the Rules Engine to ensure compliance
     *      with transfer policies. It includes a reentrancy guard to prevent reentrancy attacks.
     * @param to The recipient address.
     * @param amount The number of tokens to transfer.
     * @return bool True if the transfer is successful, false otherwise.
     */
    // Disabling this finding, it is a false positive. A reentrancy lock modifier has been
    // applied to this function
    // slither-disable-start reentrancy-events
    // slither-disable-start reentrancy-no-eth
    function transfer(
        address to,
        uint256 amount
    )
        public
        virtual
        override        
        checksPoliciesERC20TransferBefore(to, amount, balanceOf(msg.sender), balanceOf(to), block.timestamp)
        returns (bool)
    {
        address owner = _msgSender();
        _transfer(owner, to, amount);
        return true;
    }

    /**
     * @notice Transfers tokens on behalf of another address.
     * @dev This function overrides the {IERC20-transferFrom} function and interacts with the Rules Engine to ensure compliance
     *      with transfer policies. It includes a reentrancy guard to prevent reentrancy attacks.
     * @param from The address to transfer tokens from.
     * @param to The recipient address.
     * @param amount The number of tokens to transfer.
     * @return bool True if the transfer is successful, false otherwise.
     */
    function transferFrom(
        address from,
        address to,
        uint256 amount
    )
        public
        virtual
        override
        checksPoliciesERC20TransferFromBefore(from, to, amount, balanceOf(from), balanceOf(to), block.timestamp)
        returns (bool)
    {
        address spender = _msgSender();
        _spendAllowance(from, spender, amount);
        _transfer(from, to, amount);
        return true;
    }

    function setCallingContractAdmin(address callingContractAdmin) public override {
        super.setCallingContractAdmin(callingContractAdmin);
    }

     /**
     * @notice Override the default setRulesEngineAddress and add onlyOwner modifier to prevent unauthorized access
     */
    function setRulesEngineAddress(address rulesEngine) public override {
        super.setRulesEngineAddress(rulesEngine);
    }

    /**
     * @notice Mints new tokens to a specified address.
     * @dev This function interacts with the Rules Engine to ensure compliance with minting policies.
     * @param to The recipient address.
     * @param amount The number of tokens to mint.
     */
    function mint(
        address to,
        uint256 amount
    ) public virtual {
        _mint(to, amount);
    }

}
