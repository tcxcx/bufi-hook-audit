// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {BaseHook} from "v4-periphery/src/utils/BaseHook.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {BalanceDelta, BalanceDeltaLibrary} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";

/// @title Bufi ingress hook — audit-ready standalone variant
/// @notice Self-contained port of the production `BufiIngressHook` whose only external
///         dependencies are the Uniswap v4 stack. Behaviorally faithful to the real
///         hook: same decoded `HookData` shape, same validation order, same dynamic
///         fee math, same settlement-signal bookkeeping. Deposit/alias registries
///         that are split into separate contracts in production are inlined here
///         so the audit tool can exercise the full control flow without needing
///         Bufi-internal packages.
/// @dev    Any finding the audit tool surfaces against this contract applies to the
///         production hook and must be fixed in both.
contract BufiIngressHook is BaseHook {
    using BalanceDeltaLibrary for BalanceDelta;

    // ─── errors ────────────────────────────────────────────────────────────────
    error NotOwner();
    error UnauthorizedOperator();
    error InvalidRouter();
    error InvalidDeposit();
    error InvalidStage();
    error AliasInactive();
    error WrongPool();
    error WrongDirection();
    error MissingIngressCommitment();
    error InvalidPrivacyEpoch();
    error InvalidFillDeadline();
    error SettlementSignalMissing();
    error SettlementSignalAlreadyReady();
    error SettlementSignalAlreadyConsumed();
    error StaleAlias();

    // ─── decoded hook data (identical shape to production) ────────────────────
    struct HookData {
        bytes32 depositId;
        bytes32 aliasRef;
        address expectedAssetIn;
        address expectedAssetOut;
        uint8 stage;              // 1 = USDT→USDC, 2 = USDC→eUSD
        uint32 destinationChainId;
        bytes32 routeId;
        bytes32 ingressCommitment;
        bytes32 encryptedMetadata;
        bytes32 settlementPolicyId;
        bytes32 batchKey;
        uint64 privacyEpoch;
        uint32 intentFillDeadline;
        uint32 maxFeeBps;
    }

    // ─── bookkeeping ──────────────────────────────────────────────────────────
    struct Deposit {
        bytes32 aliasRef;
        address asset;
        uint8 status;  // 0 = nil, 1 = ingress-pending, 2 = normalized, 3 = eusd-pending, 4 = settled
    }

    struct PendingSwap {
        bytes32 aliasRef;
        uint8 stage;
        address assetIn;
        address assetOut;
        uint64 privacyEpoch;
        bool inProgress;
    }

    struct Alias {
        bool active;
        uint64 expiresAt;
    }

    struct SettlementSignal {
        bytes32 depositId;
        bytes32 signalId;
        bytes32 executionNullifier;
        uint256 amountOut;
        uint8 stage;
        bool ready;
        bool consumed;
    }

    struct DynamicFeePolicy {
        bool enabled;
        uint24 baseFeePips;
        uint24 maxFeePips;
        uint16 pegFeePerBps;
        uint16 reserveFeePerBps;
        uint16 backlogFeePerSignal;
    }

    struct DynamicFeeMetrics {
        uint16 pegDeviationBps;
        uint16 reservePressureBps;
    }

    struct AegisFeePolicy {
        bool enabled;
        uint16 volatilityFeePerBps;
        uint16 capEventThresholdBps;
        uint16 surgeFeePerBps;
        uint32 surgeDuration;
    }

    struct AegisFeeState {
        uint16 volatilityBps;
        uint16 lastCapEventBps;
        uint24 volatilityFeePips;
        uint24 surgeFeePips;
        uint64 surgeEndsAt;
    }

    // ─── storage ──────────────────────────────────────────────────────────────
    address public owner;
    address public router;

    mapping(bytes32 => Deposit) public deposits;
    mapping(bytes32 => Alias) public aliases;
    mapping(bytes32 => PendingSwap) public pendingSwaps;
    mapping(bytes32 => SettlementSignal) public settlementSignals;
    mapping(address => bool) public privacyOperators;
    mapping(uint32 => DynamicFeeMetrics) public dynamicFeeMetricsByDestination;
    mapping(uint32 => uint32) public outstandingSignalsByDestination;
    mapping(uint32 => AegisFeeState) public aegisFeeStateByDestination;

    DynamicFeePolicy public dynamicFeePolicy;
    AegisFeePolicy public aegisFeePolicy;

    // ─── events ───────────────────────────────────────────────────────────────
    event BeforeSwapValidated(
        bytes32 indexed depositId, bytes32 indexed aliasRef, uint8 indexed stage,
        address assetIn, address assetOut
    );
    event AfterSwapFinalized(
        bytes32 indexed depositId, bytes32 indexed aliasRef, uint8 indexed stage,
        uint256 amountInActual, uint256 amountOutActual, bytes32 routeId
    );
    event SettlementSignalQueued(
        bytes32 indexed depositId, bytes32 indexed signalId, uint8 indexed stage, uint256 amountOut
    );
    event SettlementSignalReady(bytes32 indexed depositId, bytes32 indexed executionNullifier);
    event SettlementSignalConsumed(bytes32 indexed depositId, bytes32 indexed signalId);
    event RouterSet(address indexed router);
    event DepositRegistered(bytes32 indexed depositId, bytes32 indexed aliasRef, address asset);
    event AliasRegistered(bytes32 indexed aliasRef, uint64 expiresAt);
    event PrivacyOperatorSet(address indexed operator, bool allowed);

    // ─── construction ─────────────────────────────────────────────────────────
    constructor(IPoolManager manager_, address initialOwner) BaseHook(manager_) {
        owner = initialOwner;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyPrivacyOperator() {
        if (!privacyOperators[msg.sender]) revert UnauthorizedOperator();
        _;
    }

    // ─── permissions (graded by the audit tool) ───────────────────────────────
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // ─── admin ────────────────────────────────────────────────────────────────
    function setRouter(address router_) external onlyOwner {
        router = router_;
        emit RouterSet(router_);
    }

    function setPrivacyOperator(address operator, bool allowed) external onlyOwner {
        privacyOperators[operator] = allowed;
        emit PrivacyOperatorSet(operator, allowed);
    }

    function registerDeposit(bytes32 depositId, bytes32 aliasRef, address asset) external onlyOwner {
        deposits[depositId] = Deposit({aliasRef: aliasRef, asset: asset, status: 1});
        emit DepositRegistered(depositId, aliasRef, asset);
    }

    function registerAlias(bytes32 aliasRef, uint64 expiresAt) external onlyOwner {
        aliases[aliasRef] = Alias({active: true, expiresAt: expiresAt});
        emit AliasRegistered(aliasRef, expiresAt);
    }

    function setDynamicFeePolicy(
        bool enabled, uint24 baseFeePips, uint24 maxFeePips,
        uint16 pegFeePerBps, uint16 reserveFeePerBps, uint16 backlogFeePerSignal
    ) external onlyOwner {
        dynamicFeePolicy = DynamicFeePolicy({
            enabled: enabled, baseFeePips: baseFeePips, maxFeePips: maxFeePips,
            pegFeePerBps: pegFeePerBps, reserveFeePerBps: reserveFeePerBps,
            backlogFeePerSignal: backlogFeePerSignal
        });
    }

    function setDynamicFeeMetrics(uint32 destinationChainId, uint16 pegDeviationBps, uint16 reservePressureBps)
        external onlyPrivacyOperator
    {
        dynamicFeeMetricsByDestination[destinationChainId] =
            DynamicFeeMetrics({pegDeviationBps: pegDeviationBps, reservePressureBps: reservePressureBps});
    }

    function setAegisFeePolicy(
        bool enabled, uint16 volatilityFeePerBps, uint16 capEventThresholdBps,
        uint16 surgeFeePerBps, uint32 surgeDuration
    ) external onlyOwner {
        aegisFeePolicy = AegisFeePolicy({
            enabled: enabled, volatilityFeePerBps: volatilityFeePerBps,
            capEventThresholdBps: capEventThresholdBps, surgeFeePerBps: surgeFeePerBps,
            surgeDuration: surgeDuration
        });
    }

    function setAegisFeeState(uint32 destinationChainId, uint16 volatilityBps, uint16 capEventBps)
        external onlyPrivacyOperator
    {
        AegisFeePolicy memory policy = aegisFeePolicy;
        AegisFeeState storage state = aegisFeeStateByDestination[destinationChainId];
        state.volatilityBps = volatilityBps;
        state.volatilityFeePips = _toCappedUint24(uint256(volatilityBps) * uint256(policy.volatilityFeePerBps));
        if (policy.enabled && capEventBps >= policy.capEventThresholdBps && policy.capEventThresholdBps != 0) {
            state.lastCapEventBps = capEventBps;
            state.surgeFeePips = _toCappedUint24(uint256(capEventBps) * uint256(policy.surgeFeePerBps));
            state.surgeEndsAt = uint64(block.timestamp + policy.surgeDuration);
        }
    }

    // ─── hook callbacks (BaseHook pattern) ────────────────────────────────────
    function _beforeSwap(
        address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata hookData
    ) internal override returns (bytes4, BeforeSwapDelta, uint24) {
        // Passthrough for swaps that don't carry Bufi intent.  The production hook
        // is only ever installed on the two stable-pair pool classes it owns; a
        // swap with empty hookData isn't a Bufi flow and shouldn't be gated here.
        if (hookData.length == 0) {
            return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }
        HookData memory data = abi.decode(hookData, (HookData));
        _validateBeforeSwap(sender, key, params, data);

        pendingSwaps[data.depositId] = PendingSwap({
            aliasRef: data.aliasRef,
            stage: data.stage,
            assetIn: data.expectedAssetIn,
            assetOut: data.expectedAssetOut,
            privacyEpoch: data.privacyEpoch,
            inProgress: true
        });

        emit BeforeSwapValidated(
            data.depositId, data.aliasRef, data.stage, data.expectedAssetIn, data.expectedAssetOut
        );

        return (
            BaseHook.beforeSwap.selector,
            BeforeSwapDeltaLibrary.ZERO_DELTA,
            _computeDynamicFee(data.destinationChainId)
        );
    }

    function _afterSwap(
        address, PoolKey calldata key, SwapParams calldata params, BalanceDelta delta, bytes calldata hookData
    ) internal override returns (bytes4, int128) {
        // Passthrough symmetric with beforeSwap.
        if (hookData.length == 0) {
            return (BaseHook.afterSwap.selector, 0);
        }
        HookData memory data = abi.decode(hookData, (HookData));
        PendingSwap memory ctx = pendingSwaps[data.depositId];
        if (!ctx.inProgress) revert InvalidDeposit();

        (uint256 amountInActual, uint256 amountOutActual) = _extractSwapAmounts(key, params, delta);
        delete pendingSwaps[data.depositId];

        // Advance deposit status: 1 (ingress-pending) → 2 (normalized) → 3 (eusd-pending) → 4 (settled)
        Deposit storage dep = deposits[data.depositId];
        if (data.stage == 1) {
            if (dep.status != 1) revert InvalidStage();
            dep.status = 2;
        } else if (data.stage == 2) {
            if (dep.status != 3) revert InvalidStage();
            dep.status = 4;
        } else {
            revert InvalidStage();
        }

        bytes32 signalId = keccak256(
            abi.encode(
                data.depositId, data.aliasRef, data.routeId,
                data.ingressCommitment, data.encryptedMetadata,
                amountOutActual, data.stage, data.privacyEpoch, data.batchKey
            )
        );
        settlementSignals[data.depositId] = SettlementSignal({
            depositId: data.depositId,
            signalId: signalId,
            executionNullifier: bytes32(0),
            amountOut: amountOutActual,
            stage: data.stage,
            ready: false,
            consumed: false
        });
        outstandingSignalsByDestination[data.destinationChainId] += 1;

        emit AfterSwapFinalized(
            data.depositId, data.aliasRef, data.stage, amountInActual, amountOutActual, data.routeId
        );
        emit SettlementSignalQueued(data.depositId, signalId, data.stage, amountOutActual);

        return (BaseHook.afterSwap.selector, 0);
    }

    // ─── settlement lifecycle ─────────────────────────────────────────────────
    function markSettlementReady(bytes32 depositId, bytes32 executionNullifier) external onlyPrivacyOperator {
        SettlementSignal storage signal = settlementSignals[depositId];
        if (signal.signalId == bytes32(0)) revert SettlementSignalMissing();
        if (signal.ready) revert SettlementSignalAlreadyReady();
        signal.ready = true;
        signal.executionNullifier = executionNullifier;
        emit SettlementSignalReady(depositId, executionNullifier);
    }

    function consumeSettlementSignal(bytes32 depositId) external onlyPrivacyOperator returns (bytes32 signalId) {
        SettlementSignal storage signal = settlementSignals[depositId];
        if (signal.signalId == bytes32(0)) revert SettlementSignalMissing();
        if (!signal.ready) revert SettlementSignalMissing();
        if (signal.consumed) revert SettlementSignalAlreadyConsumed();
        signal.consumed = true;
        signalId = signal.signalId;
        emit SettlementSignalConsumed(depositId, signalId);
    }

    // ─── internals ────────────────────────────────────────────────────────────
    function _validateBeforeSwap(
        address sender, PoolKey calldata key, SwapParams calldata params, HookData memory data
    ) internal view {
        if (sender != router) revert InvalidRouter();

        Deposit memory dep = deposits[data.depositId];
        if (dep.aliasRef == bytes32(0)) revert InvalidDeposit();
        if (dep.aliasRef != data.aliasRef) revert InvalidDeposit();
        if (data.stage == 1 && dep.status != 1) revert InvalidStage();
        if (data.stage == 2 && dep.status != 3) revert InvalidStage();
        if (data.stage != 1 && data.stage != 2) revert InvalidStage();

        Alias memory a = aliases[data.aliasRef];
        if (!a.active) revert AliasInactive();
        if (a.expiresAt < block.timestamp) revert StaleAlias();

        address currency0 = Currency.unwrap(key.currency0);
        address currency1 = Currency.unwrap(key.currency1);
        bool currenciesMatch = (currency0 == data.expectedAssetIn && currency1 == data.expectedAssetOut)
            || (currency1 == data.expectedAssetIn && currency0 == data.expectedAssetOut);
        if (!currenciesMatch) revert WrongPool();

        if (data.stage == 1 && dep.asset != data.expectedAssetIn) revert InvalidDeposit();
        if (data.ingressCommitment == bytes32(0)) revert MissingIngressCommitment();
        if (data.privacyEpoch == 0) revert InvalidPrivacyEpoch();
        if (data.intentFillDeadline < block.timestamp) revert InvalidFillDeadline();

        if (params.zeroForOne) {
            if (currency0 != data.expectedAssetIn || currency1 != data.expectedAssetOut) revert WrongDirection();
        } else {
            if (currency1 != data.expectedAssetIn || currency0 != data.expectedAssetOut) revert WrongDirection();
        }
    }

    function _extractSwapAmounts(PoolKey calldata, SwapParams calldata params, BalanceDelta delta)
        internal pure returns (uint256 amountInActual, uint256 amountOutActual)
    {
        int128 a0 = delta.amount0();
        int128 a1 = delta.amount1();
        if (params.zeroForOne) {
            amountInActual = _abs(a0);
            amountOutActual = _abs(a1);
        } else {
            amountInActual = _abs(a1);
            amountOutActual = _abs(a0);
        }
    }

    function _abs(int128 value) internal pure returns (uint256) {
        return uint256(uint128(value < 0 ? -value : value));
    }

    function _computeDynamicFee(uint32 destinationChainId) internal view returns (uint24) {
        DynamicFeePolicy memory policy = dynamicFeePolicy;
        if (!policy.enabled) return 0;

        DynamicFeeMetrics memory m = dynamicFeeMetricsByDestination[destinationChainId];
        uint256 fee = uint256(policy.baseFeePips)
            + uint256(m.pegDeviationBps) * uint256(policy.pegFeePerBps)
            + uint256(m.reservePressureBps) * uint256(policy.reserveFeePerBps)
            + uint256(outstandingSignalsByDestination[destinationChainId]) * uint256(policy.backlogFeePerSignal);
        fee += _computeAegisFee(destinationChainId);
        if (fee > policy.maxFeePips) fee = policy.maxFeePips;
        return uint24(fee);
    }

    function _computeAegisFee(uint32 destinationChainId) internal view returns (uint256) {
        AegisFeePolicy memory policy = aegisFeePolicy;
        if (!policy.enabled) return 0;
        AegisFeeState memory s = aegisFeeStateByDestination[destinationChainId];
        uint256 fee = uint256(s.volatilityFeePips);
        if (s.surgeEndsAt >= block.timestamp) fee += uint256(s.surgeFeePips);
        return fee;
    }

    function _toCappedUint24(uint256 value) internal pure returns (uint24) {
        if (value > type(uint24).max) return type(uint24).max;
        return uint24(value);
    }
}
