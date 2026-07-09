#![no_std]

use soroban_sdk::{
    auth::InvokerContractAuthEntry,
    contract, contracterror, contractimpl, contracttype, panic_with_error, token, Address, BytesN,
    Env, Symbol, Val, Vec,
};

/// Educational contract for the blog topic:
///
///     Authorization boundary and access-control failures
///
/// This contract intentionally combines several vulnerability patterns under
/// one theme:
///
///     The caller may be authenticated, but the policy boundary may still be
///     wrong.
///
/// Included vulnerable patterns:
///
/// 1. Generic dapp invoker bypasses wallet token policies.
/// 2. Nested auth entries can bypass wallet token policies.
/// 3. Direct owner upgrade bypasses governance-approved WASM policy.
/// 4. Governance proposal threshold is not snapshotted.
/// 5. Admins can be added but not revoked.
/// 6. Ownership transfer is one-step instead of accept-based.
/// 7. Trusted relayer can be replaced without authorization.
///
/// This is intentionally not production code.
#[contract]
pub struct AuthorizationBoundaryLab;

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Owner,
    PendingOwner,

    GovernanceAdmin,

    SpendLimit,
    MaxAllowanceExpirationDelta,

    TrackedToken(Address),

    ApprovedWasm(BytesN<32>),

    Admin(Address),

    Voter(Address),
    VoterCount,

    Proposal(u64),
    Voted(u64, Address),

    TrustedRelayer,
}

#[derive(Clone)]
#[contracttype]
pub struct Proposal {
    pub wasm_hash: BytesN<32>,
    pub yes_votes: u32,

    /// 0 means no snapshot was taken.
    ///
    /// The vulnerable proposal path leaves this as 0 and checks against the
    /// current voter set at execution time.
    ///
    /// The fixed proposal path stores the threshold here at proposal creation.
    pub threshold_snapshot: u32,

    pub active: bool,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    InvalidAmount = 3,
    LimitExceeded = 4,
    ExpirationTooLong = 5,
    ExpirationOverflow = 6,
    TokenCallBlocked = 7,
    WasmNotApproved = 8,
    NotAdmin = 9,
    NotVoter = 10,
    ProposalNotFound = 11,
    ProposalInactive = 12,
    AlreadyVoted = 13,
    NotEnoughVotes = 14,
    NoPendingOwner = 15,
    NotPendingOwner = 16,
    NoTrustedRelayer = 17,
}

fn read_owner(env: &Env) -> Address {
    match env.storage().instance().get::<DataKey, Address>(&DataKey::Owner) {
        Some(owner) => owner,
        None => panic_with_error!(env, Error::NotInitialized),
    }
}

fn read_pending_owner(env: &Env) -> Address {
    match env
        .storage()
        .instance()
        .get::<DataKey, Address>(&DataKey::PendingOwner)
    {
        Some(owner) => owner,
        None => panic_with_error!(env, Error::NoPendingOwner),
    }
}

fn read_governance_admin(env: &Env) -> Address {
    match env
        .storage()
        .instance()
        .get::<DataKey, Address>(&DataKey::GovernanceAdmin)
    {
        Some(admin) => admin,
        None => panic_with_error!(env, Error::NotInitialized),
    }
}

fn read_spend_limit(env: &Env) -> i128 {
    match env
        .storage()
        .instance()
        .get::<DataKey, i128>(&DataKey::SpendLimit)
    {
        Some(limit) => limit,
        None => panic_with_error!(env, Error::NotInitialized),
    }
}

fn read_max_allowance_expiration_delta(env: &Env) -> u32 {
    match env
        .storage()
        .instance()
        .get::<DataKey, u32>(&DataKey::MaxAllowanceExpirationDelta)
    {
        Some(delta) => delta,
        None => panic_with_error!(env, Error::NotInitialized),
    }
}

fn read_voter_count(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get::<DataKey, u32>(&DataKey::VoterCount)
        .unwrap_or(0)
}

fn read_trusted_relayer(env: &Env) -> Address {
    match env
        .storage()
        .instance()
        .get::<DataKey, Address>(&DataKey::TrustedRelayer)
    {
        Some(relayer) => relayer,
        None => panic_with_error!(env, Error::NoTrustedRelayer),
    }
}

fn read_proposal(env: &Env, proposal_id: u64) -> Proposal {
    match env
        .storage()
        .instance()
        .get::<DataKey, Proposal>(&DataKey::Proposal(proposal_id))
    {
        Some(proposal) => proposal,
        None => panic_with_error!(env, Error::ProposalNotFound),
    }
}

fn write_proposal(env: &Env, proposal_id: u64, proposal: Proposal) {
    env.storage()
        .instance()
        .set(&DataKey::Proposal(proposal_id), &proposal);
}

fn is_tracked_token(env: &Env, token: &Address) -> bool {
    env.storage()
        .instance()
        .get::<DataKey, bool>(&DataKey::TrackedToken(token.clone()))
        .unwrap_or(false)
}

fn is_wasm_approved(env: &Env, wasm_hash: &BytesN<32>) -> bool {
    env.storage()
        .instance()
        .get::<DataKey, bool>(&DataKey::ApprovedWasm(wasm_hash.clone()))
        .unwrap_or(false)
}

fn is_admin(env: &Env, admin: &Address) -> bool {
    env.storage()
        .instance()
        .get::<DataKey, bool>(&DataKey::Admin(admin.clone()))
        .unwrap_or(false)
}

fn is_voter(env: &Env, voter: &Address) -> bool {
    env.storage()
        .instance()
        .get::<DataKey, bool>(&DataKey::Voter(voter.clone()))
        .unwrap_or(false)
}

fn has_voted(env: &Env, proposal_id: u64, voter: &Address) -> bool {
    env.storage()
        .instance()
        .get::<DataKey, bool>(&DataKey::Voted(proposal_id, voter.clone()))
        .unwrap_or(false)
}

fn require_admin(env: &Env, admin: &Address) {
    if !is_admin(env, admin) {
        panic_with_error!(env, Error::NotAdmin);
    }
}

fn require_voter(env: &Env, voter: &Address) {
    if !is_voter(env, voter) {
        panic_with_error!(env, Error::NotVoter);
    }
}

fn require_positive_amount(env: &Env, amount: i128) {
    if amount <= 0 {
        panic_with_error!(env, Error::InvalidAmount);
    }
}

fn require_nonnegative_amount(env: &Env, amount: i128) {
    if amount < 0 {
        panic_with_error!(env, Error::InvalidAmount);
    }
}

fn require_within_spend_limit(env: &Env, amount: i128) {
    let spend_limit = read_spend_limit(env);

    if amount > spend_limit {
        panic_with_error!(env, Error::LimitExceeded);
    }
}

fn max_allowance_expiration_ledger(env: &Env) -> u32 {
    let current_ledger = env.ledger().sequence();
    let max_delta = read_max_allowance_expiration_delta(env);

    match current_ledger.checked_add(max_delta) {
        Some(expiration) => expiration,
        None => panic_with_error!(env, Error::ExpirationOverflow),
    }
}

fn require_allowance_expiration_in_policy(env: &Env, expiration_ledger: u32) {
    let max_expiration = max_allowance_expiration_ledger(env);

    if expiration_ledger > max_expiration {
        panic_with_error!(env, Error::ExpirationTooLong);
    }
}

fn majority_threshold(voter_count: u32) -> u32 {
    (voter_count / 2) + 1
}

fn token_policy_function(env: &Env, func: &Symbol) -> bool {
    let transfer = Symbol::new(env, "transfer");
    let transfer_from = Symbol::new(env, "transfer_from");
    let approve = Symbol::new(env, "approve");
    let burn = Symbol::new(env, "burn");
    let burn_from = Symbol::new(env, "burn_from");

    func == &transfer
        || func == &transfer_from
        || func == &approve
        || func == &burn
        || func == &burn_from
}

fn reject_tracked_token_policy_call(env: &Env, target: &Address, func: &Symbol) {
    if is_tracked_token(env, target) && token_policy_function(env, func) {
        panic_with_error!(env, Error::TokenCallBlocked);
    }
}

fn reject_forbidden_nested_auth(env: &Env, auth_entries: Vec<InvokerContractAuthEntry>) {
    let mut i = 0;

    while i < auth_entries.len() {
        let entry = auth_entries.get(i).unwrap();

        match entry {
            InvokerContractAuthEntry::Contract(invocation) => {
                reject_tracked_token_policy_call(
                    env,
                    &invocation.context.contract,
                    &invocation.context.fn_name,
                );

                reject_forbidden_nested_auth(env, invocation.sub_invocations);
            }
            _ => {
                // Host-function authorization is outside this demo.
            }
        }

        i += 1;
    }
}

#[contractimpl]
impl AuthorizationBoundaryLab {
    /// Initializes the lab contract.
    ///
    /// `owner` controls wallet-like operations.
    /// `governance_admin` controls governance setup.
    ///
    /// This function is intentionally not the initialization demo. The blog
    /// topic for this file is authorization boundaries.
    pub fn initialize(
        env: Env,
        owner: Address,
        governance_admin: Address,
        spend_limit: i128,
        max_allowance_expiration_delta: u32,
    ) {
        if env.storage().instance().has(&DataKey::Owner) {
            panic_with_error!(&env, Error::AlreadyInitialized);
        }

        owner.require_auth();
        governance_admin.require_auth();

        require_positive_amount(&env, spend_limit);

        env.storage().instance().set(&DataKey::Owner, &owner);
        env.storage()
            .instance()
            .set(&DataKey::GovernanceAdmin, &governance_admin);
        env.storage().instance().set(&DataKey::SpendLimit, &spend_limit);
        env.storage().instance().set(
            &DataKey::MaxAllowanceExpirationDelta,
            &max_allowance_expiration_delta,
        );

        env.storage()
            .instance()
            .set(&DataKey::Admin(owner.clone()), &true);
        env.storage()
            .instance()
            .set(&DataKey::Voter(owner.clone()), &true);
        env.storage().instance().set(&DataKey::VoterCount, &1u32);
    }

    // ---------------------------------------------------------------------
    // SECTION 1:
    // POLICY-ENFORCED TOKEN ENTRY POINTS
    // ---------------------------------------------------------------------

    pub fn track_token(env: Env, token: Address) {
        let owner = read_owner(&env);
        owner.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::TrackedToken(token), &true);
    }

    pub fn deposit(env: Env, token: Address, from: Address, amount: i128) {
        require_positive_amount(&env, amount);

        let wallet = env.current_contract_address();
        let token_client = token::Client::new(&env, &token);

        token_client.transfer(&from, &wallet, &amount);
    }

    pub fn balance(env: Env, token: Address) -> i128 {
        let wallet = env.current_contract_address();
        let token_client = token::Client::new(&env, &token);

        token_client.balance(&wallet)
    }

    /// Intended safe token outflow path.
    ///
    /// Policy:
    /// - owner auth,
    /// - positive amount,
    /// - amount <= spend_limit.
    pub fn withdraw_policy(env: Env, token: Address, to: Address, amount: i128) {
        let owner = read_owner(&env);
        owner.require_auth();

        require_positive_amount(&env, amount);
        require_within_spend_limit(&env, amount);

        let wallet = env.current_contract_address();
        let token_client = token::Client::new(&env, &token);

        token_client.transfer(&wallet, &to, &amount);
    }

    /// Intended safe approval path.
    ///
    /// Policy:
    /// - owner auth,
    /// - nonnegative amount,
    /// - amount <= spend_limit,
    /// - expiration bounded by wallet policy.
    pub fn approve_policy(
        env: Env,
        token: Address,
        spender: Address,
        amount: i128,
        expiration_ledger: u32,
    ) {
        let owner = read_owner(&env);
        owner.require_auth();

        require_nonnegative_amount(&env, amount);
        require_within_spend_limit(&env, amount);
        require_allowance_expiration_in_policy(&env, expiration_ledger);

        let wallet = env.current_contract_address();
        let token_client = token::Client::new(&env, &token);

        token_client.approve(&wallet, &spender, &amount, &expiration_ledger);
    }

    // ---------------------------------------------------------------------
    // SECTION 2:
    // VULNERABLE GENERIC DAPP INVOKER
    // ---------------------------------------------------------------------

    /// VULNERABLE:
    ///
    /// Authenticates the owner, then allows arbitrary contract invocation.
    ///
    /// This bypasses the wallet's effect-level policy:
    ///
    ///     "Tracked token transfers, burns, and approvals from this wallet must
    ///      go through policy-enforced functions."
    ///
    /// Example:
    ///
    /// - withdraw_policy(token, recipient, 500) fails if spend_limit is 100.
    /// - dapp_invoker_vulnerable(token, "transfer", [wallet, recipient, 500])
    ///   succeeds because it calls the token contract directly.
    ///
    /// The same bypass applies to approve(), burn(), and nested auth entries.
    pub fn dapp_invoker_vulnerable(
        env: Env,
        target: Address,
        func: Symbol,
        args: Vec<Val>,
        nested_auth_entries: Vec<InvokerContractAuthEntry>,
    ) -> Val {
        let owner = read_owner(&env);
        owner.require_auth();

        if nested_auth_entries.len() > 0 {
            env.authorize_as_current_contract(nested_auth_entries);
        }

        env.invoke_contract::<Val>(&target, &func, args)
    }

    /// FIXED:
    ///
    /// Blocks direct and nested calls to effectful token functions on tracked
    /// tokens.
    ///
    /// A production system may instead parse the token-call arguments and route
    /// them through shared policy validation. Blocking is simpler for this lab.
    pub fn dapp_invoker_fixed(
        env: Env,
        target: Address,
        func: Symbol,
        args: Vec<Val>,
        nested_auth_entries: Vec<InvokerContractAuthEntry>,
    ) -> Val {
        let owner = read_owner(&env);
        owner.require_auth();

        reject_tracked_token_policy_call(&env, &target, &func);
        reject_forbidden_nested_auth(&env, nested_auth_entries.clone());

        if nested_auth_entries.len() > 0 {
            env.authorize_as_current_contract(nested_auth_entries);
        }

        env.invoke_contract::<Val>(&target, &func, args)
    }

    // ---------------------------------------------------------------------
    // SECTION 3:
    // DIRECT UPGRADE BYPASSING GOVERNANCE-APPROVED WASM POLICY
    // ---------------------------------------------------------------------

    /// Intended governance approval step.
    pub fn approve_wasm_by_governance(env: Env, wasm_hash: BytesN<32>) {
        let governance_admin = read_governance_admin(&env);
        governance_admin.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::ApprovedWasm(wasm_hash), &true);
    }

    /// VULNERABLE:
    ///
    /// Direct owner upgrade bypasses the governance-approved WASM policy.
    ///
    /// The owner is authenticated, but the protected effect is wrong:
    /// upgrading code should be constrained to governance-approved WASM.
    pub fn upgrade_vulnerable(env: Env, new_wasm_hash: BytesN<32>) {
        let owner = read_owner(&env);
        owner.require_auth();

        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    /// FIXED:
    ///
    /// Owner can execute the upgrade only if governance approved the hash.
    pub fn upgrade_fixed(env: Env, new_wasm_hash: BytesN<32>) {
        let owner = read_owner(&env);
        owner.require_auth();

        if !is_wasm_approved(&env, &new_wasm_hash) {
            panic_with_error!(&env, Error::WasmNotApproved);
        }

        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    // ---------------------------------------------------------------------
    // SECTION 4:
    // NON-SNAPSHOTTED GOVERNANCE THRESHOLD
    // ---------------------------------------------------------------------

    pub fn add_voter(env: Env, voter: Address) {
        let governance_admin = read_governance_admin(&env);
        governance_admin.require_auth();

        if !is_voter(&env, &voter) {
            let count = read_voter_count(&env);
            env.storage()
                .instance()
                .set(&DataKey::VoterCount, &(count + 1));
        }

        env.storage().instance().set(&DataKey::Voter(voter), &true);
    }

    pub fn remove_voter(env: Env, voter: Address) {
        let governance_admin = read_governance_admin(&env);
        governance_admin.require_auth();

        if is_voter(&env, &voter) {
            let count = read_voter_count(&env);
            env.storage()
                .instance()
                .set(&DataKey::VoterCount, &(count - 1));
        }

        env.storage().instance().set(&DataKey::Voter(voter), &false);
    }

    /// VULNERABLE:
    ///
    /// Creates a proposal without snapshotting the threshold.
    ///
    /// apply_governance_upgrade_vulnerable() will use the current voter count
    /// at execution time. If voters are removed after proposal creation, the
    /// threshold can become easier to satisfy.
    pub fn propose_governance_upgrade_vulnerable(
        env: Env,
        proposal_id: u64,
        wasm_hash: BytesN<32>,
    ) {
        let governance_admin = read_governance_admin(&env);
        governance_admin.require_auth();

        let proposal = Proposal {
            wasm_hash,
            yes_votes: 0,
            threshold_snapshot: 0,
            active: true,
        };

        write_proposal(&env, proposal_id, proposal);
    }

    /// FIXED:
    ///
    /// Snapshots the majority threshold at proposal creation.
    pub fn propose_governance_upgrade_fixed(env: Env, proposal_id: u64, wasm_hash: BytesN<32>) {
        let governance_admin = read_governance_admin(&env);
        governance_admin.require_auth();

        let count = read_voter_count(&env);
        let proposal = Proposal {
            wasm_hash,
            yes_votes: 0,
            threshold_snapshot: majority_threshold(count),
            active: true,
        };

        write_proposal(&env, proposal_id, proposal);
    }

    pub fn vote_for_upgrade(env: Env, proposal_id: u64, voter: Address) {
        voter.require_auth();
        require_voter(&env, &voter);

        if has_voted(&env, proposal_id, &voter) {
            panic_with_error!(&env, Error::AlreadyVoted);
        }

        let mut proposal = read_proposal(&env, proposal_id);

        if !proposal.active {
            panic_with_error!(&env, Error::ProposalInactive);
        }

        proposal.yes_votes += 1;

        env.storage()
            .instance()
            .set(&DataKey::Voted(proposal_id, voter), &true);

        write_proposal(&env, proposal_id, proposal);
    }

    /// VULNERABLE:
    ///
    /// Uses current voter count, not the voter count at proposal creation.
    pub fn apply_governance_upgrade_vulnerable(env: Env, proposal_id: u64) {
        let mut proposal = read_proposal(&env, proposal_id);

        if !proposal.active {
            panic_with_error!(&env, Error::ProposalInactive);
        }

        let current_threshold = majority_threshold(read_voter_count(&env));

        if proposal.yes_votes < current_threshold {
            panic_with_error!(&env, Error::NotEnoughVotes);
        }

        proposal.active = false;
        write_proposal(&env, proposal_id, proposal.clone());

        env.deployer()
            .update_current_contract_wasm(proposal.wasm_hash);
    }

    /// FIXED:
    ///
    /// Uses the threshold snapshotted at proposal creation.
    pub fn apply_governance_upgrade_fixed(env: Env, proposal_id: u64) {
        let mut proposal = read_proposal(&env, proposal_id);

        if !proposal.active {
            panic_with_error!(&env, Error::ProposalInactive);
        }

        if proposal.threshold_snapshot == 0 {
            panic_with_error!(&env, Error::NotEnoughVotes);
        }

        if proposal.yes_votes < proposal.threshold_snapshot {
            panic_with_error!(&env, Error::NotEnoughVotes);
        }

        proposal.active = false;
        write_proposal(&env, proposal_id, proposal.clone());

        env.deployer()
            .update_current_contract_wasm(proposal.wasm_hash);
    }

    // ---------------------------------------------------------------------
    // SECTION 5:
    // ADMIN REVOCATION / STALE ADMIN AUTHORITY
    // ---------------------------------------------------------------------

    /// VULNERABLE DESIGN:
    ///
    /// Admins can be added, and admin functions can use their authority.
    ///
    /// This lab intentionally exposes add_admin_vulnerable() and an admin-only
    /// withdrawal function, but the vulnerable design has no corresponding
    /// remove_admin_vulnerable().
    ///
    /// That means any added admin remains privileged forever.
    pub fn add_admin_vulnerable(env: Env, new_admin: Address) {
        let owner = read_owner(&env);
        owner.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::Admin(new_admin), &true);
    }

    /// VULNERABLE EFFECT:
    ///
    /// Any stored admin can move tracked wallet funds without spend-limit
    /// policy. If an admin is compromised and cannot be revoked, this remains
    /// exploitable indefinitely.
    pub fn admin_emergency_withdraw_vulnerable(
        env: Env,
        admin: Address,
        token: Address,
        to: Address,
        amount: i128,
    ) {
        admin.require_auth();
        require_admin(&env, &admin);

        require_positive_amount(&env, amount);

        let wallet = env.current_contract_address();
        let token_client = token::Client::new(&env, &token);

        token_client.transfer(&wallet, &to, &amount);
    }

    /// FIXED:
    ///
    /// Admins must be revocable.
    pub fn remove_admin_fixed(env: Env, admin_to_remove: Address) {
        let owner = read_owner(&env);
        owner.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::Admin(admin_to_remove), &false);
    }

    // ---------------------------------------------------------------------
    // SECTION 6:
    // ONE-STEP OWNER TRANSFER
    // ---------------------------------------------------------------------

    /// VULNERABLE:
    ///
    /// Transfers ownership immediately.
    ///
    /// If `new_owner` is wrong, mistyped, or unable to sign, ownership may be
    /// lost or transferred unexpectedly.
    pub fn transfer_owner_vulnerable(env: Env, new_owner: Address) {
        let owner = read_owner(&env);
        owner.require_auth();

        env.storage().instance().set(&DataKey::Owner, &new_owner);
    }

    /// FIXED STEP 1:
    ///
    /// Current owner nominates a pending owner.
    pub fn propose_owner_transfer_fixed(env: Env, new_owner: Address) {
        let owner = read_owner(&env);
        owner.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::PendingOwner, &new_owner);
    }

    /// FIXED STEP 2:
    ///
    /// Pending owner must explicitly accept.
    pub fn accept_owner_transfer_fixed(env: Env) {
        let pending_owner = read_pending_owner(&env);
        pending_owner.require_auth();

        let stored_pending = read_pending_owner(&env);

        if pending_owner != stored_pending {
            panic_with_error!(&env, Error::NotPendingOwner);
        }

        env.storage().instance().set(&DataKey::Owner, &pending_owner);
        env.storage().instance().remove(&DataKey::PendingOwner);
    }

    // ---------------------------------------------------------------------
    // SECTION 7:
    // MUTABLE TRUSTED RELAYER / INDIRECT AUTHORIZATION BYPASS
    // ---------------------------------------------------------------------

    /// VULNERABLE:
    ///
    /// Anyone can set the trusted relayer.
    ///
    /// This is an indirect authorization bypass: execute_relayer_action()
    /// looks protected because it requires relayer auth, but the relayer itself
    /// can be replaced by an attacker.
    pub fn set_trusted_relayer_vulnerable(env: Env, new_relayer: Address) {
        env.storage()
            .instance()
            .set(&DataKey::TrustedRelayer, &new_relayer);
    }

    /// FIXED:
    ///
    /// Only owner can update the trusted relayer.
    pub fn set_trusted_relayer_fixed(env: Env, new_relayer: Address) {
        let owner = read_owner(&env);
        owner.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::TrustedRelayer, &new_relayer);
    }

    /// Relayer-authorized action.
    ///
    /// This function itself checks relayer auth. The vulnerability is in
    /// set_trusted_relayer_vulnerable(), which lets anyone choose the relayer.
    pub fn execute_relayer_action(
        env: Env,
        token: Address,
        to: Address,
        amount: i128,
    ) {
        let relayer = read_trusted_relayer(&env);
        relayer.require_auth();

        require_positive_amount(&env, amount);

        let wallet = env.current_contract_address();
        let token_client = token::Client::new(&env, &token);

        token_client.transfer(&wallet, &to, &amount);
    }

    // ---------------------------------------------------------------------
    // GETTERS
    // ---------------------------------------------------------------------

    pub fn owner(env: Env) -> Address {
        read_owner(&env)
    }

    pub fn pending_owner(env: Env) -> Address {
        read_pending_owner(&env)
    }

    pub fn governance_admin(env: Env) -> Address {
        read_governance_admin(&env)
    }

    pub fn spend_limit(env: Env) -> i128 {
        read_spend_limit(&env)
    }

    pub fn max_allowance_expiration_delta(env: Env) -> u32 {
        read_max_allowance_expiration_delta(&env)
    }

    pub fn token_tracked(env: Env, token: Address) -> bool {
        is_tracked_token(&env, &token)
    }

    pub fn approved_wasm(env: Env, wasm_hash: BytesN<32>) -> bool {
        is_wasm_approved(&env, &wasm_hash)
    }

    pub fn admin(env: Env, admin: Address) -> bool {
        is_admin(&env, &admin)
    }

    pub fn voter(env: Env, voter: Address) -> bool {
        is_voter(&env, &voter)
    }

    pub fn voter_count(env: Env) -> u32 {
        read_voter_count(&env)
    }

    pub fn proposal(env: Env, proposal_id: u64) -> Proposal {
        read_proposal(&env, proposal_id)
    }

    pub fn trusted_relayer(env: Env) -> Address {
        read_trusted_relayer(&env)
    }
}