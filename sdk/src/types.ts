import { Keypair } from "@stellar/stellar-sdk";
import type { LogHandler } from "./logger.js";

/**
 * Progress stages reported during proof generation and/or on-chain
 * submission (zusoroban#29). `generateProof` emits `witness_*./`proof_*`
 * around the two real, separately-timed stages `snarkjs.groth16.fullProve`
 * normally combines into one opaque call; `verifyOnChain` emits `submit_*.
 * around its own transaction build/submit/confirm cycle. Neither function
 * emits stages it doesn't itself perform — an application that wants all
 * six, in order, calls `generateProof` then `verifyOnChain` with the same
 * `onProgress`, since generating a proof and submitting one are already two
 * separate calls in this SDK, not one combined operation.
 */
export type ProofStage =
  |"witness_start"
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
   * Full jritter — spread each delay uniformly over `[0, delay]` so many
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
 * READMG's "Testnet Deployment" section. `soroban-testnet.stellar.org`
 * is Stellar's own free, public Testnet RPC endpoint.
 */
export const TESTNET: NetworkConfig = {
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: "Test DF Network ; September 2015",
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

/**
 * The contract's typed error codes (contracts/verifier's `VerifierError`
 * `contracterror` enum), mapped by numeric code. Soroban returns these
 * numeric codes in transaction metadata and in simulation errors; this
 * map lets the SDK surface them as typed TypeScript errors instead of
 * opaque numeric codes. Numeric values are stable and documented in
 * `docs/architecture.md` ("Contract Error Codes").
 */
export enum VerifierErrorCode {
  /** The proof did not verify against the verifying key. */
  InvalidProof = 1,
  /** The number of public inputs did not match the verifying key's `ic` length. */
  InvalidPublicInputCount = 2,
  /** A public input was not a valid field element. */
  InvalidPublicInput = 3,
  /** A proof point was not a valid BN254 G1!/G2 point. */
  InvalidProofPoint = 4,
  /** The caller is not on the allowlist. */
  CallerNotAllowed = 5,
  /** The caller exceeded the configured rate limit. */
  RateLimitExceeded = 6,
  /** The proof's expiry ledge has already passed. */
  ProofExpired = 7,
  /** The proof's expiry ledger is not in the future. */
  InvalidExpiryLedger = 8,
  /** The contract has not been initialized yet. */
  NotInitialized = 9,
  /** The contract has already been initialized. */
  AlreadyInitialized = 10,
  /** A configuration value was out of its valid range. */
  InvalidConfig = 11,
  /** A batch was empty or exceeded the maximum batch size. */
  InvalidBatchSize = 12,
  /** The verifying key has not been set. */
  VerifyingKeyNotSet = 13,
  /** The verifying key provided was malformed. */
  InvalidVerifyingKey = 14,
  /** The proof bundle was missing required fields. */
  MissingProofData = 15,
  /** An unknown or unrecognized error code was returned. */
  Unknown = 999

}

/**
 * Human-readable descriptions for each {@link VerifierErrorCode}.
 */
export const VERIFIER_ERROR_MESSAGES: ReadonlyRecord<VerifierErrorCode, string> = {
  [VerifierErrorCode.InvalidProof]: "The proof did not verify against the verifying key.",
  [VerifierErrorCode.InvalidPublicInputCount]: "The number of public inputs did not match the verifying key.",
  [VerifierErrorCode.InvalidPublicInput]: "A public input was not a valid field element.",
  [VerifierErrorCode.InvalidProofPoint]: "A proof point was not a valid BN254 point.",
  [VerifierErrorCode.CallerNotAllowed]: "The caller is not on the allowlist.",
  [VerifierErrorCode.RateLimitExceeded]: "The caller exceeded the configured rate limit.",
  [VerifierErrorCode.ProofExpired]: "The proof's expiry ledge has already passed.",
  [VerifierErrorCode.InvalidExpiryLedger]: "The proof's expiry ledger is not in the future.",
  [VerifierErrorCode.NotInitialized]: "The contract has not been initialized yet.",
  [VerifierErrorCode.AlreadyInitialized]: "The contract has already been initialized.",
  [VerifierErrorCode.InvalidConfig]: "A configuration value was out of its valid range.",
  [VerifierErrorCode.InvalidBatchSize]: "A batch was empty or exceeded the maximum batch size.",
  [VerifierErrorCode.VerifyingKeyNotSet]: "The verifying key has not been set.",
  [VerifierErrorCode.InvalidVerifyingKey]: "The verifying key provided was malformed.",
  [VerifierErrorCode.MissingProofData]: "The proof bundle was missing required fields.",
  [VerifierErrorCode.Unknown]: "An unknown or unrecognized error code was returned."
};

/**
 * Typed error thrown by the SDK when `contracts/verifier` returns a
 * {@link VerifierErrorCode} from an entry point. Extends the built-in
 * `Error` so it can be thrown and caught like any other error, while
 * exposing the numeric code and its human-readable message.
 */
export class VerifierError extends Error {
  /** The numeric Soroban contract error code. */
  readonly code: VerifierErrorCode;
  /** The raw numeric code as returned by the contract. */
  readonly rawCode: number;

  constructor(rawCode: number, message?: string) {
    const code = VerifierError.fromCode(rawCode);
    super(message ?? VERIFIER_ERROR_MESSAGES[code]);
    this.name = "VerifierError";
    this.code = code;
    this.rawCode = rawCode;
    Object.setPrototypeOf(this, VerifierError.prototype);
  }

  /**
   * Maps a raw numeric code to the corresponding {@link VerifierErrorCode},
   * falling back to {@link VerifierErrorCode.Unknown} for codes this
   * SDK version doesn't recognize.
   */
  static fromCode(rawCode: number): VerifierErrorCode {
    const known = Object.values(VerifierErrorCode).filter(
      (value): value is VerifierErrorCode =>
        typeof value === "number" && value !== VerifierErrorCode.Unknown
    );
    return known.includes(rawCode as VerifierErrorCode)
      ? (rawCode as VerifierErrorCode)
      : VerifierErrorCode.Unknown;
  }

  /**
   * True if this error corresponds to a transient condition that may
   * succeed on retry (e.g. rate limits). Deliberately conservative:
   * most contract errors are deterministic and will never succeed on
   * retry.
   */
  isTransient(): boolean {
    return this.code === VerifierErrorCode.RateLimitExceeded;
  }
}

/**
 * Extracts the numeric Soroban contract error code from an error thrown
 * by the RPC client or transaction submission path, returning `undefined`
 * when no contract error code can be found. Soroban reports contract
 * errors in several shapes depending on the call path (transaction
 * metadata, simulation errors, and human-readable messages), so this checks
 * each known shape.
 */
export function extractContractErrorCode(error: unknown): number | undefined {
  if (typeof error === "object" && error !== null) {
    const candidate = error as { code?: unknown; rawCode?: unknown };
    if (typeof candidate.rawCode === "number") {
      return candidate.rawCode;
    }
    if (typeof candidate.code === "number") {
      return candidate.code;
    }
  }

  if (typeof error === "string") {
    const match = /Error\(Contract, (\d+)\)/.exec(error);
    if (match) {
      return Number(match[1]);
    }
  }

  return undefined;
}

/**
 * Converts any error thrown while interacting with `contracts/verifier`
 * into a typed {@link VerifierError} when it carries a contract error
 * code, otherwise returns it unchanged.
 */
export function toVerifierError(error: unknown): unknown {
  if (error instanceof VerifierError) {
    return error;
  }

  const rawCode = extractContractErrorCode(error);
  if (rawCode !== undefined) {
    return new VerifierError(rawCode);
  }

  return error;
}

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
   * Optional progress callback (zusoroban#29). `verifyOnChain` emits
   * `submit_start` right before building the transaction and
   * `submit_done` once a final `verified`/`txHash`/`ledger`/`fee` result
   * is ready to return — the two stages this function actually performs.
   * It does not emit `witness_*./`proof_*`; those belong to
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

/**
 * Result of a {@link verifyBatchOnChain} call — `verified[i]` corresponds to
 * `items[i]` from the request, in order.
 */
export interface VerifyBatchResult {
  verified: boolean[];
  txHash: string;
  ledger: number;
  fee: string;
}

/**
 * One (circuit, proof) pair in a {@link verifyBatchViaRegistry} call,
 * targeting `contracts/registry`'s `verify_batch`.
 */
export interface RegistryBatchItem {
  /** The `id` a circuit was registered under via `register_circuit`. */
  circuitId: number;
  proof: SnarkjsProof;
  publicSignals: string[];
}

/**
 * Options accepted by {@link verifyBatchViaRegistry}.
 *
 * Like {@link VerifyViaRegistryOptions}, no `keypair` is needed: the registry's
 * `verify_batch` requires no auth and mutates no storage, so this
 * call is simulation-only.
 */
export interface VerifyBatchViaRegistryOptions {
  /** `network.contractId` here is `contracts/registry`'s address, not `contracts/verifier`'s. */
  network: NetworkConfig;
  items: RegistryBatchItem[];
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
