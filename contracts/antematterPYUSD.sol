// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract AntematterPYUSD is ERC20, ERC20Burnable, Pausable, AccessControl {
    bytes32 public constant assetProtectionRole = keccak256("assetProtectionRole");
    bytes32 public constant owner = keccak256("owner");
    bytes32 public constant supplyController = keccak256("supplyController");
    bytes32 public constant betaDelegateWhitelister = keccak256("betaDelegateWhitelister");

    // EIP191 header for EIP712 prefix
    string constant internal EIP191_HEADER = "\x19\x01";
    // Hash of the EIP712 Domain Separator Schema
    bytes32 constant internal EIP712_DOMAIN_SEPARATOR_SCHEMA_HASH = keccak256(
    "EIP712Domain(string name,address verifyingContract)"
    );
    bytes32 constant internal EIP712_DELEGATED_TRANSFER_SCHEMA_HASH = keccak256(
    "BetaDelegatedTransfer(address to,uint256 value,uint256 fee,uint256 seq,uint256 deadline)"
    );
    // Hash of the EIP712 Domain Separator data
    // solhint-disable-next-line var-name-mixedcase
    bytes32 public EIP712_DOMAIN_HASH;

    mapping(address => bool) internal frozen;

    // DELEGATED TRANSFER DATA
    mapping(address => bool) internal betaDelegateWhitelist;
    mapping(address => uint256) internal nextSeqs;

    struct DelegatedTransfer {
        bytes32 r;
        bytes32 s;
        uint8 v;
        address to;
        uint256 value;
        uint256 fee;
        uint256 seq;
        uint256 deadline;
    }


    /**
     * EVENTS
     */

    // OWNABLE EVENTS
    event OwnershipTransferred(
        address indexed newOwner
    );

    // ASSET PROTECTION EVENTS
    event AddressFrozen(address indexed addr);
    event AddressUnfrozen(address indexed addr);
    event FrozenAddressWiped(address indexed addr);
    event AssetProtectionRoleSet (
        address indexed newAssetProtectionRole
    );

    // SUPPLY CONTROL EVENTS
    event SupplyControllerSet(
        address indexed newSupplyController
    );

    // DELEGATED TRANSFER EVENTS
    event BetaDelegatedTransfer(
        address indexed from, address indexed to, uint256 value, uint256 seq, uint256 fee
    );
    event BetaDelegateWhitelisterSet(
        address indexed newWhitelister
    );
    event BetaDelegateWhitelisted(address indexed newDelegate);
    event BetaDelegateUnwhitelisted(address indexed oldDelegate);

    constructor() ERC20("AntematterPYUSD", "AMTPYUSD") {
        _grantRole(owner, msg.sender);
        _grantRole(supplyController, msg.sender);
        frozen[address(this)] = true;

         EIP712_DOMAIN_HASH = keccak256(abi.encodePacked(// solium-disable-line
                EIP712_DOMAIN_SEPARATOR_SCHEMA_HASH,
                keccak256(bytes(name())),
                bytes32(bytes(abi.encodePacked(address(this))))
            ));
    }

    function decimals() override public pure returns(uint8) {
        return 6;
    }  

    // OWNER FUNCTIONALITY

    function changeOwner(address _proposedOwner) public onlyRole(owner) {
        require(_proposedOwner != address(0), "cannot transfer ownership to address zero");
        require(msg.sender != _proposedOwner, "caller already is owner");
        _revokeRole(owner, msg.sender);
        _grantRole(owner, _proposedOwner);
        emit OwnershipTransferred(_proposedOwner);
    }

    function pause() public onlyRole(owner) {
        _pause();
    }

    function unpause() public onlyRole(owner) {
        _unpause();
    }

      // ASSET PROTECTION FUNCTIONALITY

    /**
     * @dev Sets a new asset protection role address.
     * @param _newAssetProtectionRole The new address allowed to freeze/unfreeze addresses and seize their tokens.
     */
    function setAssetProtectionRole(address _newAssetProtectionRole) public {
        require(hasRole(assetProtectionRole, msg.sender) || hasRole(owner, msg.sender), "only assetProtectionRole or Owner");
        _revokeRole(assetProtectionRole, msg.sender);
        _grantRole(assetProtectionRole,msg.sender);
        emit AssetProtectionRoleSet(_newAssetProtectionRole);
    }

    /**
     * @dev Freezes an address balance from being transferred.
     * @param _addr The new address to freeze.
     */
    function freeze(address _addr) public onlyRole(assetProtectionRole) {
        require(!frozen[_addr], "address already frozen");
        frozen[_addr] = true;
        emit AddressFrozen(_addr);
    }

    /**
     * @dev Unfreezes an address balance allowing transfer.
     * @param _addr The new address to unfreeze.
     */
    function unfreeze(address _addr) public onlyRole(assetProtectionRole) {
        require(frozen[_addr], "address already unfrozen");
        frozen[_addr] = false;
        emit AddressUnfrozen(_addr);
    }

    /**
     * @dev Wipes the balance of a frozen address, and burns the tokens.
     * @param _addr The new frozen address to wipe.
     */
    function wipeFrozenAddress(address _addr) public onlyRole(assetProtectionRole) {
        require(frozen[_addr], "address is not frozen");
        _burn(_addr, balanceOf(_addr));
        emit FrozenAddressWiped(_addr);
    }

    /**
    * @dev Gets whether the address is currently frozen.
    * @param _addr The address to check if frozen.
    * @return A bool representing whether the given address is frozen.
    */
    function isFrozen(address _addr) public view returns (bool) {
        return frozen[_addr];
    }

    // SUPPLY CONTROL FUNCTIONALITY

    /**
     * @dev Sets a new supply controller address.
     * @param _newSupplyController The address allowed to burn/mint tokens to control supply.
     */
    function setSupplyController(address _newSupplyController) public {
        require(hasRole(supplyController, msg.sender) || hasRole(owner, msg.sender), "only SupplyController or Owner");
        require(_newSupplyController != address(0), "cannot set supply controller to address zero");
        _revokeRole(supplyController, msg.sender);
        _grantRole(supplyController, _newSupplyController);
        emit SupplyControllerSet(_newSupplyController);
    }

    /**
     * @dev Increases the total supply by minting the specified number of tokens to the supply controller account.
     * @param _value The number of tokens to add.
     */
    function increaseSupply(uint256 _value) public onlyRole(supplyController)  {
        _mint(msg.sender,_value);
    }

    /**
     * @dev Decreases the total supply by burning the specified number of tokens from the supply controller account.
     * @param _value The number of tokens to remove.
     */
    function decreaseSupply(uint256 _value) public onlyRole(supplyController) {
       _burn(msg.sender,_value);
    }

        // DELEGATED TRANSFER FUNCTIONALITY

    /**
     * @dev returns the next seq for a target address.
     * The transactor must submit nextSeqOf(transactor) in the next transaction for it to be valid.
     * Note: that the seq context is specific to this smart contract.
     * @param target The target address.
     * @return the seq.
     */
    //
    function nextSeqOf(address target) public view returns (uint256) {
        return nextSeqs[target];
    }

    /**
     * @dev Performs a transfer on behalf of the from address, identified by its signature on the delegatedTransfer msg.
     * Splits a signature byte array into r,s,v for convenience.
     * @param sig the signature of the delgatedTransfer msg.
     * @param to The address to transfer to.
     * @param value The amount to be transferred.
     * @param fee an optional ERC20 fee paid to the executor of betaDelegatedTransfer by the from address.
     * @param seq a sequencing number included by the from address specific to this contract to protect from replays.
     * @param deadline a block number after which the pre-signed transaction has expired.
     */
    function betaDelegatedTransfer(
        bytes memory sig, address to, uint256 value, uint256 fee, uint256 seq, uint256 deadline
    ) public {
        require(sig.length == 65, "signature should have length 65");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        _betaDelegatedTransfer(r, s, v, to, value, fee, seq, deadline);
    }

    /**
     * @dev Performs a transfer on behalf of the from address, identified by its signature on the betaDelegatedTransfer msg.
     * Note: both the delegate and transactor sign in the fees. The transactor, however,
     * has no control over the gas price, and therefore no control over the transaction time.
     * Beta prefix chosen to avoid a name clash with an emerging standard in ERC865 or elsewhere.
     * Internal to the contract - see betaDelegatedTransfer and betaDelegatedTransferBatch.
     * @param r the r signature of the delgatedTransfer msg.
     * @param s the s signature of the delgatedTransfer msg.
     * @param v the v signature of the delgatedTransfer msg.
     * @param to The address to transfer to.
     * @param value The amount to be transferred.
     * @param fee an optional ERC20 fee paid to the delegate of betaDelegatedTransfer by the from address.
     * @param seq a sequencing number included by the from address specific to this contract to protect from replays.
     * @param deadline a block number after which the pre-signed transaction has expired.
     */
    function _betaDelegatedTransfer(
        bytes32 r, bytes32 s, uint8 v, address to, uint256 value, uint256 fee, uint256 seq, uint256 deadline
    ) internal whenNotPaused {
        require(betaDelegateWhitelist[msg.sender], "Beta feature only accepts whitelisted delegates");
        require(value > 0 || fee > 0, "cannot transfer zero tokens with zero fee");
        require(block.number <= deadline, "transaction expired");
        // prevent sig malleability from ecrecover()
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "signature incorrect");
        require(v == 27 || v == 28, "signature incorrect");

        // EIP712 scheme: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md
        bytes32 delegatedTransferHash = keccak256(abi.encodePacked(// solium-disable-line
                EIP712_DELEGATED_TRANSFER_SCHEMA_HASH, bytes32(bytes(abi.encodePacked(to))), value, fee, seq, deadline
            ));
        bytes32 hash = keccak256(abi.encodePacked(EIP191_HEADER, EIP712_DOMAIN_HASH, delegatedTransferHash));
        address _from = ecrecover(hash, v, r, s);

        require(!frozen[to] && !frozen[_from] && !frozen[msg.sender], "address frozen");
        require((value+fee) <= balanceOf(_from), "insufficient fund");
        require(nextSeqs[_from] == seq, "incorrect seq");

        _transfer(_from,msg.sender,fee);
        _transfer(_from,to,value);

        emit BetaDelegatedTransfer(_from, to, value, seq, fee);
    }

    function betaDelegatedTransferBatch(DelegatedTransfer[] calldata transfers) public {
            for (uint8 i = 0; i < transfers.length; i++) {
            DelegatedTransfer memory transfer = transfers[i];
            _betaDelegatedTransfer(
                transfer.r,
                transfer.s,
                transfer.v,
                transfer.to,
                transfer.value,
                transfer.fee,
                transfer.seq,
                transfer.deadline
            );
        }
    }

    /**
    * @dev Gets whether the address is currently whitelisted for betaDelegateTransfer.
    * @param _addr The address to check if whitelisted.
    * @return A bool representing whether the given address is whitelisted.
    */
    function isWhitelistedBetaDelegate(address _addr) public view returns (bool) {
        return betaDelegateWhitelist[_addr];
    }

    /**
     * @dev Sets a new betaDelegate whitelister.
     * @param _newWhitelister The address allowed to whitelist betaDelegates.
     */
    function setBetaDelegateWhitelister(address _newWhitelister) public {
        require(hasRole(betaDelegateWhitelister, msg.sender) || hasRole(owner, msg.sender), "only Whitelister or Owner");
        _revokeRole(betaDelegateWhitelister,msg.sender);
        emit BetaDelegateWhitelisterSet(_newWhitelister);
    }

    /**
     * @dev Whitelists an address to allow calling BetaDelegatedTransfer.
     * @param _addr The new address to whitelist.
     */
    function whitelistBetaDelegate(address _addr) public onlyRole(betaDelegateWhitelister) {
        require(!betaDelegateWhitelist[_addr], "delegate already whitelisted");
        betaDelegateWhitelist[_addr] = true;
        emit BetaDelegateWhitelisted(_addr);
    }

    /**
     * @dev Unwhitelists an address to disallow calling BetaDelegatedTransfer.
     * @param _addr The new address to whitelist.
     */
    function unwhitelistBetaDelegate(address _addr) public onlyRole(betaDelegateWhitelister) {
        require(betaDelegateWhitelist[_addr], "delegate not whitelisted");
        betaDelegateWhitelist[_addr] = false;
        emit BetaDelegateUnwhitelisted(_addr);
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount)
        internal
        whenNotPaused
        override
    {
        require(!frozen[to] && !frozen[msg.sender], "address frozen");
        super._beforeTokenTransfer(from, to, amount);
    }
}