import { Keypair } from "@stellar/stellar-sdk";
import type { LogHandler } from "./logger.js";

/**
 * Progress stages reported during proof generation and/or on-chain
 * submission (zksoroban#29). `generateProof` emits `witness_*`/`proof_*`
 * around the two real, separately-timed stages `snarkjs.groth16.fullProve`
 * normally combines into one opaque call; `verifyOnChain` emits `submit_*`
 * around its own transaction build/submit/confirm cycle. Neither function
 * emits stages it doesn't itself perform — an application that wants all
 * six, in order, calls `generateProof` then `verifyOnChain` with the same
 * `onProgress`, since generating a proof and submitting one are already two
 * separate calls in this SDK, not one combined operation.
 */
export type ProofStage =
  | "witness_start"
  | "witness_done"
  | "proof_start"
  | "proof_done"
  | "submit_start"
  | "submit_done";

export type OnProofProgress = (stage: ProofStage) => void;

/**
 * Invokes `onProgress` for `stage`, catching and discarding anything it
 * throws — a progress callback's own bug or failure must never abort the
 * operation it's just reporting on (an explicit zksoroban#29 requirement).
 * A no-op if `onProgress` wasn't supplied.
 */
export function emitProofStage(onProgress: OnProofProgress | undefined, stage: ProofStage): void {
  if (!onProgress) {
    return;
  }

  try {
    onProgress(stage);
  } catch {
    // Deliberately ignored — see this function's own doc comment.
  }
}

/**
 * Typed error codes mirroring `contracts/verifier`'s `VerifierError`
 * `#[contracterror]` enum. The numeric values are stable and match the
 * contract exactly; see `docs/architecture.md` for the full table.
 */
export enum VerifierErrorCode {
  AlreadyInitialized = 1,
  NotInitialized = 2,
  Unauthorized = 3,
  InvalidProof = 4,
  InvalidPublicInputs = 5,
  ProofExpired = 6,
  RateLimited = 7,
  NotAllowlisted = 8,
  BatchTooLarge = 9,
  EmptyBatch = 10,
  VerificationKeyMissing = 11,
  MalformedCalldata = 12,
  ArithmeticOverflow = 13,
}

/**
 * Typed SDK error thrown when the contract returns a `VerifierError`.
 * Maps the numeric contract error code to a named `code` field.
 */
export class VerifierContractError extends Error {
  readonly code: VerifierErrorCode;
  readonly contractCode: number;

  constructor(contractCode: number, message?: string) {
    const name = VerifierErrorCode[contractCode] ?? `Unknown(${contractCode})`;
    super(message ?? `Verifier contract error: ${name} (${contractCode})`);
    this.name = "VerifierContractError";
    this.code = contractCode as VerifierErrorCode;
    this.contractCode = contractCode;
  }
}

/**
 * Maps a raw numeric contract error code to a {@link VerifierContractError}.
 */
export function toVerifierContractError(contractCode: number): VerifierContractError {
  return new VerifierContractError(contractCode);
}

export interface SnarkjsProof {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
  protocol: "groth16";
}

export interface SorobanProofCalldata {
  proofA: Buffer;
  proofB: Buffer;
  proofC: Buffer;
  publicInputs: Buffer[];
}

/**
 * A Groth16 verifying key encoded into the raw-bytes layout
 * `contracts/registry`'s `register_circuit(id, vk)` expects — the same
 * BN254 G1/G2 point encoding {@link SorobanProofCalldata} uses for a proof,
 * applied to a verifying key's `alpha`/`beta`/`gamma`/`delta`/`IC` instead.
 */
export interface RegistryVerifyingKey {
  alpha: Buffer;
  beta: Buffer;
  gamma: Buffer;
  delta: Buffer;
  ic: Buffer[];
}

export interface VerificationKey {
  protocol: string;
  curve: string;
  nPublic: number;
  vk_alpha_1: string[];
  vk_beta_2: string[][];
  vk_gamma_2: string[][];
  vk_delta_2: string[][];
  vk_alphabeta_12: string[][][];
  IC: string[][];
}

export interface ProofBundle {
  proof: SnarkjsProof;
  publicSignals: string[];
  circuit: string;
  generatedAt: string;
  networkPassphrase: string;
}

/**
 * Options for the SDK's opt-in retry behavior.
 *
 * Passing a `retry` object to any RPC-touching call (`verifyOnChain`,
 * `verifyBatchOnChain`, `verifyViaRegistry`, `verifyBatchViaRegistry`,
 * `estimateVerifyFee`, `getContractConfig`) turns on per-request retries
 * with exponential backoff for transient failures. Omitting it keeps the
 * previous behavior — a single attempt, no retries.
 *
 * See `docs/architecture.md` ("Retry & Exponential Backoff") for exactly
 * which requests are retried and which are deliberately not.
 */
export interface RetryOptions {
  /**
   * How many times to retry after the initial attempt fails. Defaults to
   * `3`; `0` disables retries explicitly.
   */
  maxRetries?: number;
  /**
   * Base of the exponential backoff curve in milliseconds: the delay after
   * the first failed attempt, doubling each time. Defaults to `500`.
   */
  baseDelayMs?: number;
  /**
   * Ceiling for any single backoff delay in milliseconds. Defaults to
   * `8000`.
   */
  maxDelayMs?: number;
  /**
   * Full jitter — spread each delay uniformly over `[0, delay]` so many
   * concurrent callers don't retry in lockstep. Defaults to `true`.
   */
  jitter?: boolean;
  /**
   * Called once per scheduled retry, just before the backoff sleep.
   * Never called for a failure that exhausts the retries or isn't
   * transient — those throw to the caller instead.
   */
  onRetry?: (info: RetryAttemptInfo) => void;
}

/**
 * Details of one scheduled retry, passed to {@link RetryOptions.onRetry}.
 */
export interface RetryAttemptInfo {
  /** Human-readable label for the request that failed (e.g. `"getAccount"`). */
  label: string;
  /** 1-based attempt number of the attempt that just failed. */
  attempt: number;
  /** Milliseconds the SDK will wait before the next attempt. */
  delayMs: number;
  /** The error that triggered this retry. */
  error: unknown;
}

/**
 * A network endpoint plus the one contract a call targets on it — the
 * `rpcUrl`, `networkPassphrase`, and `contractId` that, before
 * zksoroban#40, were scattered across separate string parameters on
 * every SDK function and had to be kept in sync by hand across every
 * call site. Every RPC-touching SDK function now takes a single
 * `network: NetworkConfig` instead.
 *
 * `networkPassphrase` isn't just documentation — every function that
 * takes a `NetworkConfig` still asks the RPC server for its own
 * passphrase (`getNetwork()`, as it always has) and now also checks it
 * against `network.networkPassphrase`, throwing {@link NetworkMismatchError}
 * on a mismatch. This is exactly the class of mistake centralizing
 * network config is meant to prevent — an `rpcUrl` pointed at one
 * network with a `networkPassphrase`/`contractId` left over from
 * another — caught before a transaction is ever built, not after it
 * fails in some less obvious way downstream.
 *
 * Use {@link TESTNET}/{@link MAINNET}/{@link LOCAL} directly, or spread
 * one with a different `contractId` when a call targets a different
 * contract on the same network (e.g. `contracts/registry` instead of
 * `contracts/verifier`): `{ ...TESTNET, contractId: REGISTRY_ID }`.
 */
export interface NetworkConfig {
  rpcUrl: string;
  networkPassphrase: string;
  contractId: string;
}

/**
 * `contracts/verifier`'s current Testnet deployment — see the root
 * README's "Testnet Deployment" section. `soroban-testnet.stellar.org`
 * is Stellar's own free, public Testnet RPC endpoint.
 */
export const TESTNET: NetworkConfig = {
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: "Test SDF Network ; September 2015",
  contractId: "CBL6MAWJALQP25LYKUUOC34K464XPSF6BLKUW6MXZDEXEDXMQUSP7HNN"
};

/**
 * Mainnet's network passphrase, for completeness — `rpcUrl` and
 * `contractId` are deliberately left empty. Stellar does not operate a
 * single free public Mainnet Soroban RPC endpoint the way it does for
 * Testnet (real deployments use a self-hosted or third-party RPC
 * provider), and no `zksoroban` contract is deployed to Mainnet: the
 * reference circuit's trusted setup is explicitly testnet-only (see
 * `docs/security-model.md`'s Trust Assumptions) and was never meant to
 * secure anything of real value. Fill in both before use:
 * `{ ...MAINNET, rpcUrl: "<your RPC provider>", contractId: "<your deployment>" }`.
 */
export const MAINNET: NetworkConfig = {
  rpcUrl: "",
  networkPassphrase: "Public Global Stellar Network ; September 2015",
  contractId: ""
};

/**
 * A local `stellar container start local` quickstart node — see
 * `docs/performance.md`'s reproduction steps for the exact commands.
 * `contractId` is deliberately empty: a local deployment's contract ID
 * is generated fresh by `stellar contract deploy` and has no universal
 * default. Fill it in after deploying:
 * `{ ...LOCAL, contractId: "<your local deployment>" }`.
 */
export const LOCAL: NetworkConfig = {
  rpcUrl: "http://localhost:8000/rpc",
  networkPassphrase: "Standalone Network ; February 2017",
  contractId: ""
};

export interface VerifyOptions {
  network: NetworkConfig;
  keypair: Keypair;
  calldata?: SorobanProofCalldata;
  bundle?: ProofBundle;
  /**
   * Optional retry policy for transient RPC failures. Omit for the
   * previous single-attempt behavior — see {@link RetryOptions}.
   */
  retry?: RetryOptions;
  /**
   * Optional logger for structured logging. Omit to use the default
   * logger (WARN level, console output) — see {@link LogHandler}.
   */
  logger?: LogHandler;
  /**
   * Optional progress callback (zksoroban#29). `verifyOnChain` emits
   * `submit_start` right before building the transaction and
   * `submit_done` once a final `verified`/`txHash`/`ledger`/`fee` result
   * is ready to return — the two stages this function actually performs.
   * It does not emit `witness_*`/`proof_*`; those belong to
   * {@link generateProof}, a separate call. Pass the same `onProgress` to
   * both if an application wants all six stages, in order, across the
   * two calls.
   */
  onProgress?: OnProofProgress;
}

export interface VerifyResult {
  verified: boolean;
  txHash: string;
  ledger: number;
  fee: string;
}

/**
 * Options accepted by {@link verifyViaRegistry}.
 *
 * Unlike {@link VerifyOptions}, no `keypair` is needed: `contracts/registry`'s
 * `verify_proof(id, ...)` requires no auth and mutates no storage, so this
 * call is simulation-only, exactly like {@link GetContractConfigOptions}.
 */
export interface VerifyViaRegistryOptions {
  /** `network.contractId` here is `contracts/registry`'s address, not `contracts/verifier`'s. */
  network: NetworkConfig;
  /** The `id` a circuit was registered under via `register_circuit`. */
  circuitId: number;
  calldata?: SorobanProofCalldata;
  bundle?: ProofBundle;
  /**
   * Optional retry policy for transient RPC failures. Omit for the
   * previous single-attempt behavior — see {@link RetryOptions}.
   */
  retry?: RetryOptions;
  /**
   * Optional logger for structured logging. Omit to use the default
   * logger (WARN level, console output) — see {@link LogHandler}.
   */
  logger?: LogHandler;
}

/**
 * One proof in a {@link verifyBatchOnChain} call, targeting
 * `contracts/verifier`'s `verify_batch`. Same shape as a single
 * {@link VerifyOptions}'s proof inputs, minus the fields that are shared
 * across the whole batch (`network`, `keypair`).
 */
export interface VerifierBatchItem {
  proof: SnarkjsProof;
  publicSignals: string[];
  expiryLedger?: number;
}

/**
 * Options accepted by {@link verifyBatchOnChain}.
 *
 * Like {@link VerifyOptions}, this targets `contracts/verifier`, which
 * requires the caller's own Soroban auth and mutates rate-limit state — so a
 * `keypair` is required and this submits a real transaction. All items in
 * `items` are verified in one transaction under that single `keypair`'s
 * identity, and are each still subject to their own allowlist/rate-limit/
 * expiry check.
 */
export interface VerifyBatchOptions {
  network: NetworkConfig;
  keypair: Keypair;
  items: VerifierBatchItem[];
  /**
   * Optional retry policy for transient RPC failures. Omit for the
   * previous single-attempt behavior — see {@link RetryOptions}.
   */
  retry?: RetryOptions;
  /**
   * Optional logger for structured logging. Omit to use the default
   * logger (WARN level, console output) — see {@link LogHandler}.
   */
  logger?: LogHandler;
}
