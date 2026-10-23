import {
  Account,
  Address,
  BASE_FEE,
  Contract,
  Keypair,
  nativeToScVal,
  TransactionBuilder,
  rpc,
  scValToNative,
  xdr
} from "@stellar/stellar-sdk";

import { withRetry } from "./retry.js";
import { formatProof } from "./proof.js";
import { createLogger, defaultLogger, Logger, LogHandler } from "./logger.js";
import {
  ContractConfig,
  emitProofStage,
  NetworkConfig,
  NetworkMismatchError,
  ProofBundle,
  RetryOptions,
  RegistryBatchItem,
  SorobanProofCalldata,
  SorobanZkError,
  SorobanZkErrorCode,
  VerifierBatchItem,
  VerifyBatchOptions,
  VerifyBatchResult,
  VerifyBatchViaRegistryOptions,
  VerifyOptions,
  VerifyResult,
  VerifyViaRegistryOptions
} from "./types.js";
import { validateCalldata } from "./validate.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const POLL_INTERVAL_MS = 1_000;

function makeBytesScVal(bytes: Buffer): xdr.ScVal {
  return xdr.ScVal.scvBytes(bytes);
}

function makePublicInputsScVal(publicInputs: Buffer[]): xdr.ScVal {
  return xdr.ScVal.scvVec(publicInputs.map((item) => xdr.ScVal.scvBytes(item)));
}

// contracts/verifier's `ProofItem` and contracts/registry's `BatchItem` are
// both `#[contracttype] struct`s, which Soroban encodes as a Map keyed by
// Symbol (not String) — `nativeToScVal`'s default object handling produces
// String keys, so every field needs an explicit `'symbol'` key-type hint to
// match what the contract's derived struct decoder expects.
function makeProofItemScVal(calldata: SorobanProofCalldata): xdr.ScVal {
  return nativeToScVal(
    {
      proof_a: calldata.proofA,
      proof_b: calldata.proofB,
      proof_c: calldata.proofC,
      public_inputs: calldata.publicInputs
    },
    {
      type: {
        proof_a: ["symbol", "bytes"],
        proof_b: ["symbol", "bytes"],
        proof_c: ["symbol", "bytes"],
        public_inputs: ["symbol", null]
      }
    }
  );
}

function makeRegistryBatchItemScVal(circuitId: number, calldata: SorobanProofCalldata): xdr.ScVal {
  return nativeToScVal(
    {
      id: circuitId,
      proof_a: calldata.proofA,
      proof_b: calldata.proofB,
      proof_c: calldata.proofC,
      public_inputs: calldata.publicInputs
    },
    {
      type: {
        id: ["symbol", "u32"],
        proof_a: ["symbol", "bytes"],
        proof_b: ["symbol", "bytes"],
        proof_c: ["symbol", "bytes"],
        public_inputs: ["symbol", null]
      }
    }
  );
}

function feeFromResult(result: xdr.TransactionResult): string {
  return result.feeCharged.toString();
}

// Maps contracts/verifier's `VerifierError` enum (#[contracterror], repr(u32))
// to a typed SorobanZkErrorCode. Error code numbers are stable and documented
// in docs/architecture.md. Soroban tooling (simulation errors, stellar-cli)
// renders a contract error as the literal substring `Error(Contract, #N)`,
// so that's what we match against rather than parsing raw XDR.
const CONTRACT_ERROR_CODES: Record<number, SorobanZkErrorCode> = {
  1: SorobanZkErrorCode.CONTRACT_NOT_INITIALIZED,
  2: SorobanZkErrorCode.RATE_LIMIT_EXCEEDED,
  3: SorobanZkErrorCode.INVALID_WINDOW_SIZE,
  4: SorobanZkErrorCode.PROOF_EXPIRED,
  5: SorobanZkErrorCode.CALLER_NOT_ALLOWED,
  11: SorobanZkErrorCode.ALREADY_USED
};

function extractContractErrorCode(message: string): SorobanZkErrorCode | undefined {
  const match = message.match(/Error\(Contract,\s*#(\d+)\)/);
  if (!match) {
    return undefined;
  }
  return CONTRACT_ERROR_CODES[Number(match[1])];
}

function classifyError(error: unknown): SorobanZkError {
  const message = error instanceof Error ? error.message : String(error);

  const contractErrorCode = extractContractErrorCode(message);
  if (contractErrorCode) {
    return new SorobanZkError(message, contractErrorCode);
  }

  const lowered = message.toLowerCase();

  if (lowered.includes("resource") || lowered.includes("instruction") || lowered.includes("limit")) {
    return new SorobanZkError(message, SorobanZkErrorCode.RESOURCE_LIMIT_EXCEEDED);
  }

  if (lowered.includes("network") || lowered.includes("fetch") || lowered.includes("timeout")) {
    return new SorobanZkError(message, SorobanZkErrorCode.NETWORK_ERROR);
  }

  return new SorobanZkError(message, SorobanZkErrorCode.CONTRACT_INVOCATION_FAILED);
}

function decodeReturnValueFromDiagnostics(
  diagnosticEventsXdr: xdr.DiagnosticEvent[] | undefined
): boolean | undefined {
  if (!diagnosticEventsXdr) {
    return undefined;
  }

  for (const event of diagnosticEventsXdr) {
    const contractEvent = event.event;
    const topics = contractEvent.body.v0.topics;
    if (topics.length < 2) {
      continue;
    }

    const marker = scValToNative(topics[0]);
    if (marker === "fn_return") {
      return Boolean(scValToNative(contractEvent.body.v0.data));
    }
  }

  return undefined;
}

/**
 * Decode `verify_proof`'s return value from a successful transaction.
 *
 * Prefers `returnValue`, which soroban-rpc derives from the transaction's
 * result meta and is present on every successful invocation. Falls back to
 * scanning diagnostic events for the legacy `fn_return` marker, since some
 * RPC providers disable diagnostics. Returns `undefined` when neither source
 * carries a decodable value — the caller must treat that as an error rather
 * than coercing it to `false`, which would be indistinguishable from a real
 * on-chain rejection.
 */
function decodeVerifyReturnValue(result: {
  returnValue?: xdr.ScVal;
  diagnosticEventsXdr?: xdr.DiagnosticEvent[];
}): boolean | undefined {
  if (result.returnValue) {
    return Boolean(scValToNative(result.returnValue));
  }
  return decodeReturnValueFromDiagnostics(result.diagnosticEventsXdr);
}

function decodeBoolArrayFromDiagnostics(
  diagnosticEventsXdr: string[] | undefined
): boolean[] | undefined {
  if (!diagnosticEventsXdr) {
    return undefined;
  }

  for (const encoded of diagnosticEventsXdr) {
    const event = xdr.DiagnosticEvent.fromXDR(encoded, "base64");
    const contractEvent = event.event;
    const topics = contractEvent.body.v0.topics;
    if (topics.length < 2) {
      continue;
    }

    const marker = scValToNative(topics[0]);
    if (marker === "fn_return") {
      const native = scValToNative(contractEvent.body.v0.data);
      return Array.isArray(native) ? native.map(Boolean) : undefined;
    }
  }

  return undefined;
}

export function assertBundleNetwork(bundle: ProofBundle, networkPassphrase: string): void {
  if (bundle.networkPassphrase !== networkPassphrase) {
    throw new NetworkMismatchError(bundle.networkPassphrase, networkPassphrase);
  }
}

// Shared by every RPC-touching function below (zksoroban#40): build the
// retry-wrapped rpc.Server for a NetworkConfig, and confirm the RPC server's
// own reported passphrase actually matches what the NetworkConfig declared
// -- exactly the class of rpcUrl/networkPassphrase/contractId mix-up
// centralizing this config is meant to prevent, caught before a
// transaction is ever built rather than failing less obviously downstream.
function makeServer(network: NetworkConfig, retry?: RetryOptions) {
  return withRetry(
    new rpc.Server(network.rpcUrl, { allowHttp: network.rpcUrl.startsWith("http://") }),
    retry
  );
}

function assertNetworkPassphrase(network: NetworkConfig, actualPassphrase: string): void {
  if (network.networkPassphrase !== actualPassphrase) {
    throw new NetworkMismatchError(
      network.networkPassphrase,
      actualPassphrase,
      "The supplied NetworkConfig declares"
    );
  }
}

function resolveCalldata(opts: VerifyOptions): SorobanProofCalldata {
  if (opts.calldata) {
    return opts.calldata;
  }

  if (opts.bundle) {
    return formatProof(opts.bundle.proof, opts.bundle.publicSignals);
  }

  throw new SorobanZkError(
    "verifyOnChain requires either calldata or a bundle",
    SorobanZkErrorCode.INVALID_PROOF_FORMAT
  );
}

export async function verifyOnChain(opts: VerifyOptions): Promise<VerifyResult> {
  const logger: Logger = opts.logger ? createLogger("DEBUG", opts.logger) : defaultLogger;
  const calldata = resolveCalldata(opts);
  validateCalldata(calldata);

  logger.debug("verifyOnChain", "resolving calldata", { hasBundle: !!opts.bundle, hasCalldata: !!opts.calldata });

  try {
    emitProofStage(opts.onProgress, "submit_start");
    const server = makeServer(opts.network, opts.retry);
    logger.debug("verifyOnChain", "getting network info");
    const network = await server.getNetwork();
    assertNetworkPassphrase(opts.network, network.passphrase);

    if (opts.bundle) {
      assertBundleNetwork(opts.bundle, network.passphrase);
    }

    logger.debug("verifyOnChain", "getting account", { publicKey: opts.keypair.publicKey() });
    const account = await server.getAccount(opts.keypair.publicKey());
    const contract = new Contract(opts.network.contractId);
    const callerScVal = new Address(opts.keypair.publicKey()).toScVal();

    const transaction = new TransactionBuilder(account, {
      fee: BASE_FEE,
      networkPassphrase: network.passphrase
    })
      .addOperation(
        contract.call(
          "verify_proof",
          callerScVal,
          makeBytesScVal(calldata.proofA),
          makeBytesScVal(calldata.proofB),
          makeBytesScVal(calldata.proofC),
          makePublicInputsScVal(calldata.publicInputs)
        )
      )
      .setTimeout(30)
      .build();

    logger.debug("verifyOnChain", "preparing transaction");
    const prepared = await server.prepareTransaction(transaction);
    prepared.sign(opts.keypair);

    logger.info("verifyOnChain", "submitting transaction", { contractId: opts.network.contractId });
    const sendResult = await server.sendTransaction(prepared);
    if (sendResult.status !== "PENDING" && sendResult.status !== "DUPLICATE") {
      throw new SorobanZkError(
        `Transaction submission failed with status ${sendResult.status}`,
        SorobanZkErrorCode.TRANSACTION_REJECTED
      );
    }

    logger.debug("verifyOnChain", "transaction submitted", { txHash: sendResult.hash, status: sendResult.status });

    const started = Date.now();
    while (Date.now() - started < DEFAULT_TIMEOUT_MS) {
      logger.debug("verifyOnChain", "polling transaction status", { txHash: sendResult.hash });
      const result = await server.getTransaction(sendResult.hash);

      if (result.status === rpc.Api.GetTransactionStatus.NOT_FOUND) {
        await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
        continue;
      }

      if (result.status === rpc.Api.GetTransactionStatus.FAILED) {
        throw new SorobanZkError(
          `Transaction ${result.txHash} failed on ledger ${result.ledger}`,
          SorobanZkErrorCode.TRANSACTION_REJECTED
        );
      }

      if (typeof result.ledger !== "number" || !result.resultXdr) {
        throw new SorobanZkError(
          `Transaction ${result.txHash} did not include the expected success payload`,
          SorobanZkErrorCode.CONTRACT_INVOCATION_FAILED
        );
      }

      const returnValue = decodeVerifyReturnValue(result);
      if (typeof returnValue !== "boolean") {
        throw new SorobanZkError(
          `Transaction ${result.txHash} carried no decodable verify_proof return value`,
          SorobanZkErrorCode.CONTRACT_INVOCATION_FAILED
        );
      }

      const verifyResult = {
        verified: returnValue,
        txHash: result.txHash,
        ledger: result.ledger,
        fee: feeFromResult(result.resultXdr)
      };

      logger.info("verifyOnChain", "transaction confirmed", {
        txHash: verifyResult.txHash,
        ledger: verifyResult.ledger,
        fee: verifyResult.fee,
        verified: verifyResult.verified
      });

      emitProofStage(opts.onProgress, "submit_done");
      return verifyResult;
    }

    throw new SorobanZkError(
      "Timed out waiting for transaction confirmation",
      SorobanZkErrorCode.NETWORK_ERROR
    );
  } catch (error) {
    if (error instanceof SorobanZkError) {
      logger.error("verifyOnChain", "verification failed", { code: error.code, message: error.message });
      throw error;
    }
    const classified = classifyError(error);
    logger.error("verifyOnChain", "verification failed", { code: classified.code, message: classified.message });
    throw classified;
  }
}
