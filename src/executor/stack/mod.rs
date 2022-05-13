mod state;

pub use self::state::{MemoryStackState, MemoryStackSubstate, StackState};

use crate::gasometer::{self, Gasometer};
use crate::{
    executor::traces, Capture, Config, Context, CreateScheme, ExitError, ExitReason, ExitSucceed,
    Handler, Opcode, Runtime, Stack, Transfer,
};
use alloc::{rc::Rc, vec::Vec};
use core::{cmp::min, convert::Infallible};
use evm_runtime::CallScheme;
use primitive_types::{H160, H256, U256};
use sha3::{Digest, Keccak256};

use super::traces::Trace;

pub enum StackExitKind {
    Succeeded,
    Reverted,
    Failed,
}

pub struct StackSubstateMetadata<'config> {
    gasometer: Gasometer<'config>,
    is_static: bool,
    depth: Option<usize>,
}

impl<'config> StackSubstateMetadata<'config> {
    pub fn new(gas_limit: u64, config: &'config Config) -> Self {
        Self {
            gasometer: Gasometer::new(gas_limit, config),
            is_static: false,
            depth: None,
        }
    }

    pub fn swallow_commit(&mut self, other: Self) -> Result<(), ExitError> {
        self.gasometer.record_stipend(other.gasometer.gas())?;
        self.gasometer
            .record_refund(other.gasometer.refunded_gas())?;

        Ok(())
    }

    pub fn swallow_revert(&mut self, other: Self) -> Result<(), ExitError> {
        self.gasometer.record_stipend(other.gasometer.gas())?;

        Ok(())
    }

    pub fn swallow_discard(&mut self, _other: Self) -> Result<(), ExitError> {
        Ok(())
    }

    pub fn spit_child(&self, gas_limit: u64, is_static: bool) -> Self {
        Self {
            gasometer: Gasometer::new(gas_limit, self.gasometer.config()),
            is_static: is_static || self.is_static,
            depth: match self.depth {
                None => Some(0),
                Some(n) => Some(n + 1),
            },
        }
    }
}

/// Stack-based executor.
pub struct StackExecutor<'config, 'precompile, S> {
    config: &'config Config,
    precompile: Option<
        &'precompile mut dyn FnMut(
            H160,
            &[u8],
            Option<u64>,
            &Context,
        )
            -> Option<Result<(ExitSucceed, Vec<u8>, u64), ExitError>>,
    >,
    state: S,
    tracer: traces::TraceTracker,
}

impl<'config, 'precompile, S: StackState<'config>> StackExecutor<'config, 'precompile, S> {
    /// Create a new stack-based executor.
    pub fn new(state: S, config: &'config Config) -> Self {
        Self {
            config,
            precompile: None,
            state,
            tracer: traces::TraceTracker::new(),
        }
    }
    /// Create a new stack-based executor with given precompiles.
    pub fn new_with_precompile(
        state: S,
        config: &'config Config,
        precompile: &'precompile mut dyn FnMut(
            H160,
            &[u8],
            Option<u64>,
            &Context,
        ) -> Option<
            Result<(ExitSucceed, Vec<u8>, u64), ExitError>,
        >,
    ) -> Self {
        Self {
            config,
            precompile: Some(precompile),
            state,
            tracer: traces::TraceTracker::new(),
        }
    }
    pub fn take_traces(&mut self) -> Vec<Trace> {
        self.tracer.take_traces()
    }

    pub fn state(&self) -> &S {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }

    pub fn into_state(self) -> S {
        self.state
    }

    /// Create a substate executor from the current executor.
    pub fn enter_substate(&mut self, gas_limit: u64, is_static: bool) {
        self.state.enter(gas_limit, is_static);
    }

    /// Exit a substate. Panic if it results an empty substate stack.
    pub fn exit_substate(&mut self, kind: StackExitKind) -> Result<(), ExitError> {
        match kind {
            StackExitKind::Succeeded => self.state.exit_commit(),
            StackExitKind::Reverted => self.state.exit_revert(),
            StackExitKind::Failed => self.state.exit_discard(),
        }
    }

    /// Execute the runtime until it returns.
    pub fn execute(&mut self, runtime: &mut Runtime) -> ExitReason {
        match runtime.run(self) {
            Capture::Exit(s) => s,
            Capture::Trap(_) => unreachable!("Trap is Infallible"),
        }
    }

    /// Get remaining gas.
    pub fn gas(&self) -> u64 {
        self.state.metadata().gasometer.gas()
    }

    /// Execute a `CREATE` transaction.
    pub fn transact_create(
        &mut self,
        caller: H160,
        value: U256,
        init_code: Vec<u8>,
        gas_limit: u64,
    ) -> ExitReason {
        let transaction_cost = gasometer::create_transaction_cost(&init_code);
        match self
            .state
            .metadata_mut()
            .gasometer
            .record_transaction(transaction_cost)
        {
            Ok(()) => (),
            Err(e) => return e.into(),
        }

        match self.create_inner(
            caller,
            CreateScheme::Legacy { caller },
            value,
            init_code,
            Some(gas_limit),
            false,
        ) {
            Capture::Exit((s, _, _)) => s,
            Capture::Trap(_) => unreachable!(),
        }
    }

    /// Execute a `CREATE2` transaction.
    pub fn transact_create2(
        &mut self,
        caller: H160,
        value: U256,
        init_code: Vec<u8>,
        salt: H256,
        gas_limit: u64,
    ) -> ExitReason {
        let transaction_cost = gasometer::create_transaction_cost(&init_code);
        match self
            .state
            .metadata_mut()
            .gasometer
            .record_transaction(transaction_cost)
        {
            Ok(()) => (),
            Err(e) => return e.into(),
        }
        let code_hash = H256::from_slice(Keccak256::digest(&init_code).as_slice());

        match self.create_inner(
            caller,
            CreateScheme::Create2 {
                caller,
                code_hash,
                salt,
            },
            value,
            init_code,
            Some(gas_limit),
            false,
        ) {
            Capture::Exit((s, _, _)) => s,
            Capture::Trap(_) => unreachable!(),
        }
    }

    /// Execute a `CALL` transaction.
    pub fn transact_call(
        &mut self,
        caller: H160,
        address: H160,
        value: U256,
        data: Vec<u8>,
        gas_limit: u64,
    ) -> (ExitReason, Vec<u8>) {
        let transaction_cost = gasometer::call_transaction_cost(&data);
        match self
            .state
            .metadata_mut()
            .gasometer
            .record_transaction(transaction_cost)
        {
            Ok(()) => (),
            Err(e) => return (e.into(), Vec::new()),
        }

        self.state.inc_nonce(caller);

        let context = Context {
            caller,
            address,
            apparent_value: value,
        };

        match self.call_inner(
            address,
            Some(Transfer {
                source: caller,
                target: address,
                value,
            }),
            data,
            Some(gas_limit),
            None,
            false,
            false,
            context,
        ) {
            Capture::Exit((s, v)) => (s, v),
            Capture::Trap(_) => unreachable!(),
        }
    }

    /// Get used gas for the current executor, given the price.
    pub fn used_gas(&self) -> u64 {
        self.state.metadata().gasometer.total_used_gas()
            - min(
                self.state.metadata().gasometer.total_used_gas() / 2,
                self.state.metadata().gasometer.refunded_gas() as u64,
            )
    }

    /// Get fee needed for the current executor, given the price.
    pub fn fee(&self, price: U256) -> U256 {
        let used_gas = self.used_gas();
        U256::from(used_gas) * price
    }

    /// Get account nonce.
    pub fn nonce(&self, address: H160) -> U256 {
        self.state.basic(address).nonce
    }

    /// Get the create address from given scheme.
    pub fn create_address(&self, scheme: CreateScheme) -> H160 {
        match scheme {
            CreateScheme::Create2 {
                caller,
                code_hash,
                salt,
            } => {
                let mut hasher = Keccak256::new();
                hasher.input(&[0xff]);
                hasher.input(&caller[..]);
                hasher.input(&salt[..]);
                hasher.input(&code_hash[..]);
                H256::from_slice(hasher.result().as_slice()).into()
            }
            CreateScheme::Legacy { caller } => {
                let nonce = self.nonce(caller);
                let mut stream = rlp::RlpStream::new_list(2);
                stream.append(&caller);
                stream.append(&nonce);
                H256::from_slice(Keccak256::digest(&stream.out()).as_slice()).into()
            }
            CreateScheme::Fixed(naddress) => naddress,
        }
    }
    fn create_inner(
        &mut self,
        caller: H160,
        scheme: CreateScheme,
        value: U256,
        init_code: Vec<u8>,
        target_gas: Option<u64>,
        take_l64: bool,
    ) -> Capture<(ExitReason, Option<H160>, Vec<u8>), Infallible> {
        let gas_before = self.gas_left();
        self.tracer
            .start_create(caller, value, gas_before, init_code.clone(), scheme.clone());
        match self._create_inner(caller, scheme, value, init_code, target_gas, take_l64) {
            Capture::Exit((reason, contract, output)) => {
                let output = if let Some(address) = contract {
                    self.state.code(address)
                } else {
                    output
                };
                self.tracer.end_subroutine(
                    gas_before.saturating_sub(self.gas_left()),
                    contract,
                    output.clone(),
                    reason.clone(),
                );
                Capture::Exit((reason, contract, output))
            }
            Capture::Trap(_) => unreachable!(),
        }
    }

    fn _create_inner(
        &mut self,
        caller: H160,
        scheme: CreateScheme,
        value: U256,
        init_code: Vec<u8>,
        target_gas: Option<u64>,
        take_l64: bool,
    ) -> Capture<(ExitReason, Option<H160>, Vec<u8>), Infallible> {
        macro_rules! try_or_fail {
            ( $e:expr ) => {
                match $e {
                    Ok(v) => v,
                    Err(e) => return Capture::Exit((e.into(), None, Vec::new())),
                }
            };
        }

        fn l64(gas: u64) -> u64 {
            gas - gas / 64
        }

        if let Some(depth) = self.state.metadata().depth {
            if depth > self.config.call_stack_limit {
                return Capture::Exit((ExitError::CallTooDeep.into(), None, Vec::new()));
            }
        }

        if self.balance(caller) < value {
            return Capture::Exit((ExitError::OutOfFund.into(), None, Vec::new()));
        }

        let after_gas = if take_l64 && self.config.call_l64_after_gas {
            l64(self.state.metadata().gasometer.gas())
        } else {
            self.state.metadata().gasometer.gas()
        };

        let target_gas = target_gas.unwrap_or(after_gas);

        let gas_limit = min(after_gas, target_gas);
        try_or_fail!(self.state.metadata_mut().gasometer.record_cost(gas_limit));

        let address = self.create_address(scheme);
        self.state.inc_nonce(caller);

        self.enter_substate(gas_limit, false);

        {
            if self.code_size(address) != U256::zero() {
                let _ = self.exit_substate(StackExitKind::Failed);
                return Capture::Exit((ExitError::CreateCollision.into(), None, Vec::new()));
            }

            if self.nonce(address) > U256::zero() {
                let _ = self.exit_substate(StackExitKind::Failed);
                return Capture::Exit((ExitError::CreateCollision.into(), None, Vec::new()));
            }

            self.state.reset_storage(address);
        }

        let context = Context {
            address,
            caller,
            apparent_value: value,
        };
        let transfer = Transfer {
            source: caller,
            target: address,
            value,
        };
        match self.state.transfer(transfer) {
            Ok(()) => (),
            Err(e) => {
                let _ = self.exit_substate(StackExitKind::Reverted);
                return Capture::Exit((ExitReason::Error(e), None, Vec::new()));
            }
        }

        if self.config.create_increase_nonce {
            self.state.inc_nonce(address);
        }

        let mut runtime = Runtime::new(
            Rc::new(init_code),
            Rc::new(Vec::new()),
            context,
            self.config,
        );

        let reason = self.execute(&mut runtime);
        log::debug!(target: "evm", "Create execution using address {}: {:?}", address, reason);

        match reason {
            ExitReason::Succeed(s) => {
                let out = runtime.machine().return_value();

                if let Some(limit) = self.config.create_contract_limit {
                    if out.len() > limit {
                        self.state.metadata_mut().gasometer.fail();
                        let _ = self.exit_substate(StackExitKind::Failed);
                        return Capture::Exit((
                            ExitError::CreateContractLimit.into(),
                            None,
                            Vec::new(),
                        ));
                    }
                }

                match self
                    .state
                    .metadata_mut()
                    .gasometer
                    .record_deposit(out.len())
                {
                    Ok(()) => {
                        let e = self.exit_substate(StackExitKind::Succeeded);
                        self.state.set_code(address, out);
                        try_or_fail!(e);
                        Capture::Exit((ExitReason::Succeed(s), Some(address), Vec::new()))
                    }
                    Err(e) => {
                        let _ = self.exit_substate(StackExitKind::Failed);
                        Capture::Exit((ExitReason::Error(e), None, Vec::new()))
                    }
                }
            }
            ExitReason::Error(e) => {
                self.state.metadata_mut().gasometer.fail();
                let _ = self.exit_substate(StackExitKind::Failed);
                Capture::Exit((ExitReason::Error(e), None, Vec::new()))
            }
            ExitReason::Revert(e) => {
                let _ = self.exit_substate(StackExitKind::Reverted);
                Capture::Exit((
                    ExitReason::Revert(e),
                    None,
                    runtime.machine().return_value(),
                ))
            }
            ExitReason::Fatal(e) => {
                self.state.metadata_mut().gasometer.fail();
                let _ = self.exit_substate(StackExitKind::Failed);
                Capture::Exit((ExitReason::Fatal(e), None, Vec::new()))
            }
        }
    }

    fn call_inner(
        &mut self,
        code_address: H160,
        transfer: Option<Transfer>,
        input: Vec<u8>,
        target_gas: Option<u64>,
        call_scheme: Option<CallScheme>,
        take_l64: bool,
        take_stipend: bool,
        context: Context,
    ) -> Capture<(ExitReason, Vec<u8>), Infallible> {
        let gas_before = self.gas_left();
        self.tracer.start_call(
            code_address,
            context.clone(),
            gas_before,
            input.clone(),
            call_scheme,
        );
        match self._call_inner(
            code_address,
            transfer,
            input,
            target_gas,
            call_scheme.map_or(false, |c| c == CallScheme::StaticCall),
            take_l64,
            take_stipend,
            context,
        ) {
            Capture::Exit((reason, output)) => {
                self.tracer.end_subroutine(
                    gas_before.saturating_sub(self.gas_left()),
                    None,
                    output.clone(),
                    reason.clone(),
                );
                Capture::Exit((reason, output))
            }
            Capture::Trap(_) => unreachable!(),
        }
    }

    fn _call_inner(
        &mut self,
        code_address: H160,
        transfer: Option<Transfer>,
        input: Vec<u8>,
        target_gas: Option<u64>,
        is_static: bool,
        take_l64: bool,
        take_stipend: bool,
        context: Context,
    ) -> Capture<(ExitReason, Vec<u8>), Infallible> {
        macro_rules! try_or_fail {
            ( $e:expr ) => {
                match $e {
                    Ok(v) => v,
                    Err(e) => return Capture::Exit((e.into(), Vec::new())),
                }
            };
        }

        fn l64(gas: u64) -> u64 {
            gas - gas / 64
        }

        let after_gas = if take_l64 && self.config.call_l64_after_gas {
            l64(self.state.metadata().gasometer.gas())
        } else {
            self.state.metadata().gasometer.gas()
        };

        let target_gas = target_gas.unwrap_or(after_gas);
        let mut gas_limit = min(target_gas, after_gas);

        try_or_fail!(self.state.metadata_mut().gasometer.record_cost(gas_limit));

        if let Some(transfer) = transfer.as_ref() {
            if take_stipend && transfer.value != U256::zero() {
                gas_limit = gas_limit.saturating_add(self.config.call_stipend);
            }
        }

        let code = self.code(code_address);

        self.enter_substate(gas_limit, is_static);
        self.state.touch(context.address);

        if let Some(depth) = self.state.metadata().depth {
            if depth > self.config.call_stack_limit {
                let _ = self.exit_substate(StackExitKind::Reverted);
                return Capture::Exit((ExitError::CallTooDeep.into(), Vec::new()));
            }
        }

        if let Some(transfer) = transfer {
            match self.state.transfer(transfer) {
                Ok(()) => (),
                Err(e) => {
                    let _ = self.exit_substate(StackExitKind::Reverted);
                    return Capture::Exit((ExitReason::Error(e), Vec::new()));
                }
            }
        }

        if let Some(ret) = self
            .precompile
            .as_mut()
            .and_then(|e| e(code_address, &input, Some(gas_limit), &context))
        {
            return match ret {
                Ok((s, out, cost)) => {
                    let _ = self.state.metadata_mut().gasometer.record_cost(cost);
                    let _ = self.exit_substate(StackExitKind::Succeeded);
                    Capture::Exit((ExitReason::Succeed(s), out))
                }
                Err(e) => {
                    let _ = self.exit_substate(StackExitKind::Failed);
                    Capture::Exit((ExitReason::Error(e), Vec::new()))
                }
            };
        }

        let mut runtime = Runtime::new(Rc::new(code), Rc::new(input), context, self.config);

        let reason = self.execute(&mut runtime);
        log::debug!(target: "evm", "Call execution using address {}: {:?}", code_address, reason);

        match reason {
            ExitReason::Succeed(s) => {
                let _ = self.exit_substate(StackExitKind::Succeeded);
                Capture::Exit((ExitReason::Succeed(s), runtime.machine().return_value()))
            }
            ExitReason::Error(e) => {
                let _ = self.exit_substate(StackExitKind::Failed);
                Capture::Exit((ExitReason::Error(e), Vec::new()))
            }
            ExitReason::Revert(e) => {
                let _ = self.exit_substate(StackExitKind::Reverted);
                Capture::Exit((ExitReason::Revert(e), runtime.machine().return_value()))
            }
            ExitReason::Fatal(e) => {
                self.state.metadata_mut().gasometer.fail();
                let _ = self.exit_substate(StackExitKind::Failed);
                Capture::Exit((ExitReason::Fatal(e), Vec::new()))
            }
        }
    }
}

impl<'config, 'precompile, S: StackState<'config>> Handler
    for StackExecutor<'config, 'precompile, S>
{
    type CreateInterrupt = Infallible;
    type CreateFeedback = Infallible;
    type CallInterrupt = Infallible;
    type CallFeedback = Infallible;

    fn balance(&self, address: H160) -> U256 {
        self.state.basic(address).balance
    }

    fn code_size(&self, address: H160) -> U256 {
        U256::from(self.state.code(address).len())
    }

    fn code_hash(&self, address: H160) -> H256 {
        if !self.exists(address) {
            return H256::default();
        }

        H256::from_slice(Keccak256::digest(&self.state.code(address)).as_slice())
    }

    fn code(&self, address: H160) -> Vec<u8> {
        self.state.code(address)
    }

    fn storage(&self, address: H160, index: H256) -> H256 {
        self.state.storage(address, index)
    }

    fn original_storage(&self, address: H160, index: H256) -> H256 {
        self.state
            .original_storage(address, index)
            .unwrap_or_default()
    }

    fn exists(&self, address: H160) -> bool {
        if self.config.empty_considered_exists {
            self.state.exists(address)
        } else {
            self.state.exists(address) && !self.state.is_empty(address)
        }
    }

    fn gas_left(&self) -> U256 {
        U256::from(self.state.metadata().gasometer.gas())
    }

    fn gas_price(&self) -> U256 {
        self.state.gas_price()
    }
    fn origin(&self) -> H160 {
        self.state.origin()
    }
    fn block_hash(&self, number: U256) -> H256 {
        self.state.block_hash(number)
    }
    fn block_number(&self) -> U256 {
        self.state.block_number()
    }
    fn block_coinbase(&self) -> H160 {
        self.state.block_coinbase()
    }
    fn block_timestamp(&self) -> U256 {
        self.state.block_timestamp()
    }
    fn block_difficulty(&self) -> U256 {
        self.state.block_difficulty()
    }
    fn block_gas_limit(&self) -> U256 {
        self.state.block_gas_limit()
    }
    fn chain_id(&self) -> U256 {
        self.state.chain_id()
    }

    fn deleted(&self, address: H160) -> bool {
        self.state.deleted(address)
    }

    fn set_storage(&mut self, address: H160, index: H256, value: H256) -> Result<(), ExitError> {
        self.state.set_storage(address, index, value);
        Ok(())
    }

    fn log(&mut self, address: H160, topics: Vec<H256>, data: Vec<u8>) -> Result<(), ExitError> {
        self.state.log(address, topics, data);
        Ok(())
    }

    fn mark_delete(&mut self, address: H160, target: H160) -> Result<(), ExitError> {
        let balance = self.balance(address);

        self.state.transfer(Transfer {
            source: address,
            target: target,
            value: balance,
        })?;
        self.state.reset_balance(address);
        self.state.set_deleted(address);

        Ok(())
    }

    fn create(
        &mut self,
        caller: H160,
        scheme: CreateScheme,
        value: U256,
        init_code: Vec<u8>,
        target_gas: Option<u64>,
    ) -> Capture<(ExitReason, Option<H160>, Vec<u8>), Self::CreateInterrupt> {
        self.create_inner(caller, scheme, value, init_code, target_gas, true)
    }

    fn call(
        &mut self,
        code_address: H160,
        transfer: Option<Transfer>,
        input: Vec<u8>,
        target_gas: Option<u64>,
        call_scheme: CallScheme,
        context: Context,
    ) -> Capture<(ExitReason, Vec<u8>), Self::CallInterrupt> {
        self.call_inner(
            code_address,
            transfer,
            input,
            target_gas,
            Some(call_scheme),
            true,
            true,
            context,
        )
    }

    #[inline]
    fn pre_validate(
        &mut self,
        context: &Context,
        opcode: Opcode,
        stack: &Stack,
    ) -> Result<(), ExitError> {
        log::info!(target: "evm", "Running opcode: {:?}, Pre gas-left: {:?}", opcode, gasometer.gas());

        if let Some(cost) = gasometer::static_opcode_cost(opcode) {
            self.state.metadata_mut().gasometer.record_cost(cost)?;
        } else {
            let is_static = self.state.metadata().is_static;
            let (gas_cost, memory_cost) = gasometer::dynamic_opcode_cost(
                context.address,
                opcode,
                stack,
                is_static,
                &self.config,
                self,
            )?;

            let gasometer = &mut self.state.metadata_mut().gasometer;

            gasometer.record_dynamic_cost(gas_cost, memory_cost)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, collections::BTreeMap};
    use primitive_types::{H160, U256};
    use evm_runtime::Config;
    use crate::backend::{MemoryAccount, MemoryVicinity, MemoryBackend};
    use crate::executor::{MemoryStackState, StackExecutor, StackSubstateMetadata};

    fn dummy_account() -> MemoryAccount {
        MemoryAccount {
            nonce: U256::one(),
            balance: U256::from(10000000),
            storage: BTreeMap::new(),
            code: Vec::new(),
        }
    }

    #[test]
    fn test_call_inner_with_estimate() {
        let config_estimate = Config { estimate: true, ..Config::istanbul() };
        let config_no_estimate = Config::istanbul();

        let vicinity = MemoryVicinity {
            gas_price: U256::zero(),
            origin: H160::default(),
            block_hashes: Vec::new(),
            block_number: Default::default(),
            block_coinbase: Default::default(),
            block_timestamp: Default::default(),
            block_difficulty: Default::default(),
            block_gas_limit: Default::default(),
            chain_id: U256::one(),
        };

        let mut state = BTreeMap::new();
        let caller_address = H160::from_str("0xf000000000000000000000000000000000000000").unwrap();
        let contract_address = H160::from_str("0x1000000000000000000000000000000000000000").unwrap();
        state.insert(caller_address, dummy_account());
        state.insert(
            contract_address,
            MemoryAccount {
                nonce: U256::one(),
                balance: U256::from(10000000),
                storage: BTreeMap::new(),
                // proxy contract code
                code: hex::decode("608060405260043610610041576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680632da4e75c1461006a575b6000543660008037600080366000845af43d6000803e8060008114610065573d6000f35b600080fd5b34801561007657600080fd5b506100ab600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506100ad565b005b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561010957600080fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550505600a165627a7a72305820f58232a59d38bc7ca7fcefa0993365e57f4cd4e8b3fa746e0d170c5b47a787920029").unwrap(),
            }
        );

        let call_data = hex::decode("6057361d0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let transact_call = |config, gas_limit| {
            let backend = MemoryBackend::new(&vicinity, state.clone());
            let metadata = StackSubstateMetadata::new(gas_limit, config);
            let state = MemoryStackState::new(metadata, &backend);
            let mut executor = StackExecutor::new(state, config);

            let _reason = executor.transact_call(
                caller_address,
                contract_address,
                U256::zero(),
                call_data.clone(),
                gas_limit,
            );
            executor.used_gas()
        };
        {
            let gas_limit = u64::MAX;
            let gas_used_estimate = transact_call(&config_estimate, gas_limit);
            let gas_used_no_estimate = transact_call(&config_no_estimate, gas_limit);
            assert!(gas_used_estimate >= gas_used_no_estimate);
            assert!(gas_used_estimate < gas_used_no_estimate + gas_used_no_estimate / 4,
                "gas_used with estimate=true is too high, gas_used_estimate={}, gas_used_no_estimate={}",
                gas_used_estimate, gas_used_no_estimate);
        }

        {
            let gas_limit: u64 = 300_000_000;
            let gas_used_estimate = transact_call(&config_estimate, gas_limit);
            let gas_used_no_estimate = transact_call(&config_no_estimate, gas_limit);
            assert!(gas_used_estimate >= gas_used_no_estimate);
            assert!(gas_used_estimate < gas_used_no_estimate + gas_used_no_estimate / 4,
                "gas_used with estimate=true is too high, gas_used_estimate={}, gas_used_no_estimate={}",
                gas_used_estimate, gas_used_no_estimate);
        }
    }

    #[test]
    fn test_create_inner_with_estimate() {
        let config_estimate = Config { estimate: true, ..Config::istanbul() };
        let config_no_estimate = Config::istanbul();

        let vicinity = MemoryVicinity {
            gas_price: U256::zero(),
            origin: H160::default(),
            block_hashes: Vec::new(),
            block_number: Default::default(),
            block_coinbase: Default::default(),
            block_timestamp: Default::default(),
            block_difficulty: Default::default(),
            block_gas_limit: Default::default(),
            chain_id: U256::one(),
        };

        let mut state = BTreeMap::new();
        let caller_address = H160::from_str("0xf000000000000000000000000000000000000000").unwrap();
        let contract_address = H160::from_str("0x1000000000000000000000000000000000000000").unwrap();
        state.insert(caller_address, dummy_account());
        state.insert(
            contract_address,
            MemoryAccount {
                nonce: U256::one(),
                balance: U256::from(10000000),
                storage: BTreeMap::new(),
                // creator contract code
                code: hex::decode("6080604052348015600f57600080fd5b506004361060285760003560e01c8063fb971d0114602d575b600080fd5b60336035565b005b60006040516041906062565b604051809103906000f080158015605c573d6000803e3d6000fd5b50905050565b610170806100708339019056fe608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100a1565b60405180910390f35b610073600480360381019061006e91906100ed565b61007e565b005b60008054905090565b8060008190555050565b6000819050919050565b61009b81610088565b82525050565b60006020820190506100b66000830184610092565b92915050565b600080fd5b6100ca81610088565b81146100d557600080fd5b50565b6000813590506100e7816100c1565b92915050565b600060208284031215610103576101026100bc565b5b6000610111848285016100d8565b9150509291505056fea264697066735822122044f0132d3ce474198482cc3f79c22d7ed4cece5e1dcbb2c7cb533a23068c5d6064736f6c634300080d0033a2646970667358221220a7ba80fb064accb768e9e7126cd0b69e3889378082d659ad1b17317e6d578b9a64736f6c634300080d0033").unwrap(),
            }
        );

        let call_data = hex::decode("fb971d01").unwrap();
        let transact_call = |config, gas_limit| {
            let backend = MemoryBackend::new(&vicinity, state.clone());
            let metadata = StackSubstateMetadata::new(gas_limit, config);
            let state = MemoryStackState::new(metadata, &backend);
            let mut executor = StackExecutor::new(state, config);

            let _reason = executor.transact_call(
                caller_address,
                contract_address,
                U256::zero(),
                call_data.clone(),
                gas_limit,
            );
            executor.used_gas()
        };
        {
            let gas_limit = u64::MAX;
            let gas_used_estimate = transact_call(&config_estimate, gas_limit);
            let gas_used_no_estimate = transact_call(&config_no_estimate, gas_limit);
            assert!(gas_used_estimate >= gas_used_no_estimate);
            assert!(gas_used_estimate < gas_used_no_estimate + gas_used_no_estimate / 4,
                    "gas_used with estimate=true is too high, gas_used_estimate={}, gas_used_no_estimate={}",
                    gas_used_estimate, gas_used_no_estimate);
        }

        {
            let gas_limit: u64 = 300_000_000;
            let gas_used_estimate = transact_call(&config_estimate, gas_limit);
            let gas_used_no_estimate = transact_call(&config_no_estimate, gas_limit);
            assert!(gas_used_estimate >= gas_used_no_estimate);
            assert!(gas_used_estimate < gas_used_no_estimate + gas_used_no_estimate / 4,
                    "gas_used with estimate=true is too high, gas_used_estimate={}, gas_used_no_estimate={}",
                    gas_used_estimate, gas_used_no_estimate);
        }
    }
}