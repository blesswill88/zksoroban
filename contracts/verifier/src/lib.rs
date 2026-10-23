#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine, BN254_G1_SERIALIZED_SIZE, BN254_G2_SERIALIZED_SIZE},
    vec, Address, Bytes, BytesN, Env, String, Vec,
};

const PROOF_A_LEN: usize = BN254_G1_SERIALIZED_SIZE;
const PROOF_B_LEN: usize = BN254_G2_SERIALIZED_SIZE;
const CIRCUIT_PUBLIC_INPUT_COUNT: u32 = 1;
const EXPECTED_PUBLIC_INPUT_COUNT: u32 = CIRCUIT_PUBLIC_INPUT_COUNT + 1;
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Typed, numbered failure modes for the verifier contract.
///
/// Error codes are stable: never renumber an existing variant. New variants
/// must take the next unused number. See `docs/architecture.md` for the
/// canonical code table.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VerifierError {
    /// The contract has not been initialized (no admin/limits stored).
    NotInitialized = 1,
    /// `window_size` must be strictly positive.
    InvalidWindowSize = 2,
    /// Verifying key `ic` length does not match `EXPECTED_PUBLIC_INPUT_COUNT`.
    InvalidVerifyingKey = 3,
    /// `execute_vk_update` was called with no pending update proposed.
    NoPendingVkUpdate = 4,
    /// `execute_vk_update` was called before the timelock elapsed.
    TimelockNotElapsed = 5,
    /// Contract is paused; `verify_proof`/`verify_batch` are rejected.
    ContractPaused = 6,
    /// A proof point (A, B or C) has the wrong serialized length.
    InvalidProofLength = 7,
    /// The number of public inputs does not match the verifying key.
    InvalidPublicInputCount = 8,
    /// A public input could not be parsed as a BN254 scalar.
    InvalidPublicInput = 9,
    /// The caller is not on the allowlist while allowlist mode is enabled.
    CallerNotAllowlisted = 10,
    /// The caller exceeded the rate limit for the current window.
    RateLimitExceeded = 11,
    /// The Groth16 pairing check failed: the proof is invalid.
    ProofVerificationFailed = 12,
    /// No pending admin transfer exists to accept.
    NoPendingAdmin = 13,
    /// The caller is not the pending admin attempting to accept a transfer.
    NotPendingAdmin = 14,
    /// The batch was empty.
    EmptyBatch = 15,
}

#[contracttype]
#[derive(Clone)]
pub struct VerifyingKey {
    pub alpha: BytesN<64>,
    pub beta: BytesN<128>,
    pub gamma: BytesN<128>,
    pub delta: BytesN<128>,
    pub ic: Vec<BytesN<64>>,
}

#[contracttype]
#[derive(Clone)]
pub struct Limits {
    pub max_calls: u32,
    pub window_size: u32,
}

/// A read-only snapshot of all non-sensitive contract configuration fields.
/// Fields that the current contract does not implement are returned as `None`.
#[contracttype]
#[derive(Clone)]
pub struct ContractConfig {
    /// The contract administrator address.
    pub admin: Address,
    /// Whether the contract is paused — see `pause`/`unpause`.
    pub paused: bool,
    /// Optional fee amount in stroops (not implemented; always `None`).
    pub fee_amount: Option<i128>,
    /// Optional fee token contract address (not implemented; always `None`).
    pub fee_token: Option<Address>,
    /// Maximum number of `verify_proof` calls allowed per caller per window.
    pub rate_limit_max: u32,
    /// Rate-limit window size in ledgers.
    pub rate_limit_window: u32,
    /// Ledgers a proposed verifying key update must wait before
    /// `execute_vk_update` will accept it — see `propose_vk_update`.
    pub timelock_delay: Option<u32>,
    /// Whether the caller allowlist is currently enforced.
    pub allowlist_enabled: bool,
}

#[contracttype]
enum DataKey {
    Admin,
    PendingAdmin,
    Limits,
    Vk,
    CallCount(Address, u32),
    AllowlistEnabled,
    Allowlist(Address),
    VerificationCount(BytesN<32>),
    VkUpdateDelay,
    PendingVkUpdate,
    Paused,
    Nullifier(BytesN<32>),
}

/// Emitted on every `verify_proof` call, regardless of outcome.
#[contractevent(topics = ["zk", "verify"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationResult {
    pub success: bool,
    pub caller: Address,
    /// sha256 of the concatenated public inputs, in call order.
    pub inputs_hash: BytesN<32>,
}

/// One entry in a `verify_batch` call — the same fields `verify_proof` takes,
/// minus `caller`, since a batch shares one caller across all its proofs.
#[contracttype]
#[derive(Clone)]
pub struct ProofItem {
    pub proof_a: Bytes,
    pub proof_b: Bytes,
    pub proof_c: Bytes,
    pub public_inputs: Vec<BytesN<32>>,
}

#[contract]
pub struct VerifierContract;

#[contractimpl]
impl VerifierContract {
    pub fn __constructor(
        env: Env,
        admin: Address,
        max_calls: u32,
        window_size: u32,
        vk: VerifyingKey,
        vk_update_delay: u32,
    ) -> Result<(), VerifierError> {
        if window_size == 0 {
            return Err(VerifierError::InvalidWindowSize);
        }
        if vk.ic.len() != EXPECTED_PUBLIC_INPUT_COUNT {
            return Err(VerifierError::InvalidVerifyingKey);
        }

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::Limits, &Limits { max_calls, window_size });
        env.storage().instance().set(&DataKey::Vk, &vk);
        env.storage()
            .instance()
            .set(&DataKey::VkUpdateDelay, &vk_update_delay);
        Ok(())
    }

    pub fn limits(env: Env) -> Result<Limits, VerifierError> {
        env.storage()
            .instance()
            .get(&DataKey::Limits)
            .ok_or(VerifierError::NotInitialized)
    }

    pub fn version(env: Env) -> String {
        String::from_str(&env, CONTRACT_VERSION)
    }

    /// Number of times `verify_proof`/`verify_batch` has successfully
    /// verified a proof for `commitment` — the sha256 hash of the
    /// concatenated public inputs, i.e. the same value published as
    /// `inputs_hash` in `VerificationResult`. Intended for off-chain
    /// analytics and abuse detection (e.g. flagging a commitment verified
    /// far more often than legitimate usage would produce).
    ///
    /// Returns 0 for a commitment that has never been successfully
    /// verified.
    pub fn verification_count(env: Env, commitment: BytesN<32>) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::VerificationCount(commitment))
            .unwrap_or(0)
    }

    pub fn set_limits(env: Env, max_calls: u32, window_size: u32) -> Result<(), VerifierError> {
        if window_size == 0 {
            return Err(VerifierError::InvalidWindowSize);
        }

        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(VerifierError::NotInitialized)?;
        admin.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::Limits, &Limits { max_calls, window_size });
        Ok(())
    }

    /// Propose `vk` as the next verifying key. Requires the stored admin's
    /// auth. Does not take effect until `execute_vk_update` is called no
    /// earlier than `vk_update_delay` ledgers from now (the delay fixed at
    /// construction) — see [zksoroban#46](https://github.com/yusufadeagbo/zksoroban/issues/46).
    /// A second `propose_vk_update` call before the first one executes
    /// replaces it outright, resetting the delay against the new proposal.
    pub fn propose_vk_update(env: Env, vk: VerifyingKey) -> Result<(), VerifierError> {
        if vk.ic.len() != EXPECTED_PUBLIC_INPUT_COUNT {
            return Err(VerifierError::InvalidVerifyingKey);
        }

        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(VerifierError::NotInitialized)?;
        admin.require_auth();

        let delay: u32 = env
            .storage()
            .instance()
            .get(&DataKey::VkUpdateDelay)
            .ok_or(VerifierError::NotInitialized)?;
        let effective_ledger = env.ledger().sequence() + delay;

        env.storage()
            .instance()
            .set(&DataKey::PendingVkUpdate, &(vk, effective_ledger));
        Ok(())
    }

    /// Apply the currently-proposed verifying key update. Permissionless —
    /// anyone can call this, not just the admin — because by the time the
    /// delay has elapsed the change was already publicly visible via
    /// `get_pending_vk_update`; what's actually being enforced is the
    /// admin's own timelock on itself, not a fresh authorization.
    pub fn execute_vk_update(env: Env) -> Result<(), VerifierError> {
        let (vk, effective_ledger): (VerifyingKey, u32) = env
            .storage()
            .instance()
            .get(&DataKey::PendingVkUpdate)
            .ok_or(VerifierError::NoPendingVkUpdate)?;

        if env.ledger().sequence() < effective_ledger {
            return Err(VerifierError::TimelockNotElapsed);
        }

        env.storage().instance().set(&DataKey::Vk, &vk);
        env.storage().instance().remove(&DataKey::PendingVkUpdate);
        Ok(())
    }

    /// The currently-proposed verifying key update, if any: the proposed
    /// key and the ledger sequence at/after which `execute_vk_update` will
    /// succeed. `None` once executed, or if nothing has been proposed.
    pub fn get_pending_vk_update(env: Env) -> Option<(VerifyingKey, u32)> {
        env.storage().instance().get(&DataKey::PendingVkUpdate)
    }

    pub fn set_allowlist_mode(env: Env, enabled: bool) -> Result<(), VerifierError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(VerifierError::NotInitialized)?;
        admin.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::AllowlistEnabled, &enabled);
        Ok(())
    }

    pub fn allowlist_enabled(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::AllowlistEnabled)
            .unwrap_or(false)
    }

    /// Emergency stop: while paused, `verify_proof`/`verify_batch` reject
    /// every call with `VerifierError::ContractPaused` before doing anything
    /// else (no auth check, no rate-limit read, no proof parsing). Requires
    /// the stored admin's auth. Does not affect any other entry point — the
    /// admin can still call `propose_vk_update`/`execute_vk_update`/
    /// `upgrade`/`unpause` etc. while paused, since those are exactly how
    /// a real incident gets resolved.
    pub fn pause(env: Env) -> Result<(), VerifierError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(VerifierError::NotInitialized)?;
        admin.require_auth();

        env.storage().instance().set(&DataKey::Paused, &true);
        Ok(())
    }

    /// Clears the pause flag `pause` set. Requires the stored admin's auth.
    pub fn unpause(env: Env) -> Result<(), VerifierError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(VerifierError::NotInitialized)?;
        admin.require_auth();

        env.storage().instance().set(&DataKey::Paused, &false);
        Ok(())
    }

    /// Whether `pause` is currently in effect. `false` until `pause` has
    /// ever been called (the constructor doesn't set this explicitly).
    pub fn is_paused(env: Env) -> bool {
        is_contract_paused(&env)
    }

    pub fn add_to_allowlist(env: Env, addr: Address) -> Result<(), VerifierError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(VerifierError::NotInitialized)?;
        admin.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::Allowlist(addr), &true);
        Ok(())
    }
}
