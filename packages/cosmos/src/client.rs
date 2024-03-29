use std::{fmt::Display, str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use cosmos_sdk_proto::{
    cosmos::{
        auth::v1beta1::{BaseAccount, QueryAccountRequest},
        bank::v1beta1::{MsgSend, QueryAllBalancesRequest},
        base::{
            abci::v1beta1::TxResponse, query::v1beta1::PageRequest,
            tendermint::v1beta1::GetBlockByHeightRequest, v1beta1::Coin,
        },
        tx::v1beta1::{
            AuthInfo, BroadcastMode, BroadcastTxRequest, Fee, GetTxRequest, GetTxsEventRequest,
            ModeInfo, OrderBy, SignDoc, SignerInfo, SimulateRequest, SimulateResponse, Tx, TxBody,
        },
    },
    cosmwasm::wasm::v1::{
        ContractInfo, MsgExecuteContract, MsgInstantiateContract, MsgMigrateContract, MsgStoreCode,
        QueryContractHistoryRequest, QueryContractHistoryResponse, QueryContractInfoRequest,
        QueryRawContractStateRequest, QuerySmartContractStateRequest,
    },
    traits::Message,
};
use serde::de::Visitor;
use tokio::sync::Mutex;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::{address::HasAddressType, Address, AddressType};

use super::Wallet;

#[derive(Clone)]
pub struct Cosmos {
    inner: Arc<CosmosInner>,
}

impl HasAddressType for Cosmos {
    fn get_address_type(&self) -> AddressType {
        self.inner.address_type
    }
}

struct CosmosInner {
    chain_id: String,
    gas_coin: String,
    address_type: AddressType,
    auth_query_client:
        Mutex<cosmos_sdk_proto::cosmos::auth::v1beta1::query_client::QueryClient<Channel>>,
    bank_query_client:
        Mutex<cosmos_sdk_proto::cosmos::bank::v1beta1::query_client::QueryClient<Channel>>,
    tx_service_client:
        Mutex<cosmos_sdk_proto::cosmos::tx::v1beta1::service_client::ServiceClient<Channel>>,
    wasm_query_client:
        Mutex<cosmos_sdk_proto::cosmwasm::wasm::v1::query_client::QueryClient<Channel>>,
    tendermint_client: Mutex<
        cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_client::ServiceClient<Channel>,
    >,
    /// Coins used per 1000 gas
    coins_per_kgas: u64,
    /// How many attempts to give a transaction before giving up
    transaction_attempts: usize,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum CosmosNetwork {
    JunoTestnet,
    JunoMainnet,
    JunoLocal,
    OsmosisMainnet,
    OsmosisTestnet,
    Dragonfire,
}

/// Build a connection
pub struct CosmosBuilder {
    pub grpc_url: String,
    pub chain_id: String,
    pub gas_coin: String,
    pub address_type: AddressType,
    pub coins_per_kgas: u64,
    pub transaction_attempts: usize,
}

impl CosmosBuilder {
    pub async fn build(self) -> Result<Cosmos> {
        Cosmos::new(self).await
    }
}

impl serde::Serialize for CosmosNetwork {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for CosmosNetwork {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(CosmosNetworkVisitor)
    }
}

struct CosmosNetworkVisitor;

impl<'de> Visitor<'de> for CosmosNetworkVisitor {
    type Value = CosmosNetwork;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("CosmosNetwork")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        CosmosNetwork::from_str(v).map_err(E::custom)
    }
}

impl CosmosNetwork {
    fn as_str(self) -> &'static str {
        match self {
            CosmosNetwork::JunoTestnet => "juno-testnet",
            CosmosNetwork::JunoMainnet => "juno-mainnet",
            CosmosNetwork::JunoLocal => "juno-local",
            CosmosNetwork::OsmosisMainnet => "osmosis-mainnet",
            CosmosNetwork::OsmosisTestnet => "osmosis-testnet",
            CosmosNetwork::Dragonfire => "dragonfire",
        }
    }
}

impl Display for CosmosNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CosmosNetwork {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "juno-testnet" => Ok(CosmosNetwork::JunoTestnet),
            "juno-mainnet" => Ok(CosmosNetwork::JunoMainnet),
            "juno-local" => Ok(CosmosNetwork::JunoLocal),
            "osmosis-mainnet" => Ok(CosmosNetwork::OsmosisMainnet),
            "osmosis-testnet" => Ok(CosmosNetwork::OsmosisTestnet),
            "dragonfire" => Ok(CosmosNetwork::Dragonfire),
            _ => Err(anyhow::anyhow!("Unknown network: {s}")),
        }
    }
}

impl CosmosNetwork {
    pub async fn connect(self) -> Result<Cosmos> {
        self.builder().build().await
    }

    pub fn builder(self) -> CosmosBuilder {
        match self {
            CosmosNetwork::JunoTestnet => Cosmos::new_juno_testnet(),
            CosmosNetwork::JunoMainnet => Cosmos::new_juno_mainnet(),
            CosmosNetwork::JunoLocal => Cosmos::new_juno_local(),
            CosmosNetwork::OsmosisMainnet => Cosmos::new_osmosis_mainnet(),
            CosmosNetwork::OsmosisTestnet => Cosmos::new_osmosis_testnet(),
            CosmosNetwork::Dragonfire => Cosmos::new_dragonfire(),
        }
    }

    pub fn address_type(self) -> AddressType {
        match self {
            CosmosNetwork::JunoTestnet => AddressType::Juno,
            CosmosNetwork::JunoMainnet => AddressType::Juno,
            CosmosNetwork::JunoLocal => AddressType::Juno,
            CosmosNetwork::OsmosisMainnet => AddressType::Osmo,
            CosmosNetwork::OsmosisTestnet => AddressType::Osmo,
            CosmosNetwork::Dragonfire => AddressType::Levana,
        }
    }
}

impl Cosmos {
    pub async fn new(
        CosmosBuilder {
            grpc_url,
            chain_id,
            gas_coin,
            address_type,
            coins_per_kgas,
            transaction_attempts,
        }: CosmosBuilder,
    ) -> Result<Self> {
        let grpc_endpoint = grpc_url.parse::<Endpoint>()?;
        let grpc_endpoint = if grpc_url.starts_with("https://") {
            grpc_endpoint.tls_config(ClientTlsConfig::new())?
        } else {
            grpc_endpoint
        };
        let grpc_channel = match tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            grpc_endpoint.connect(),
        )
        .await
        {
            Ok(grpc_channel) => grpc_channel
                .with_context(|| format!("Error establishing gRPC connection to {grpc_url}"))?,
            Err(_) => anyhow::bail!("Timed out while connecting to {grpc_url}"),
        };
        let inner = Arc::new(CosmosInner {
            chain_id,
            gas_coin,
            auth_query_client: Mutex::new(
                cosmos_sdk_proto::cosmos::auth::v1beta1::query_client::QueryClient::new(
                    grpc_channel.clone(),
                ),
            ),
            bank_query_client: Mutex::new(
                cosmos_sdk_proto::cosmos::bank::v1beta1::query_client::QueryClient::new(
                    grpc_channel.clone(),
                ),
            ),
            tx_service_client: Mutex::new(
                cosmos_sdk_proto::cosmos::tx::v1beta1::service_client::ServiceClient::new(
                    grpc_channel.clone(),
                ),
            ),
            wasm_query_client: Mutex::new(
                cosmos_sdk_proto::cosmwasm::wasm::v1::query_client::QueryClient::new(grpc_channel.clone()),
            ),
            tendermint_client: Mutex::new(
                cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_client::ServiceClient::new(grpc_channel)
            ),
            address_type,
            coins_per_kgas,
            transaction_attempts,
        });
        Ok(Cosmos { inner })
    }

    pub fn new_juno_testnet() -> CosmosBuilder {
        CosmosBuilder {
            grpc_url: "https://grpc-testnet.juno.sandbox.levana.finance:443".to_owned(),
            // Backup choice:
            // "http://juno-testnet-grpc.polkachu.com:12690",
            chain_id: "uni-5".to_owned(),
            gas_coin: "ujunox".to_owned(),
            address_type: AddressType::Juno,
            coins_per_kgas: 30,
            transaction_attempts: 30,
        }
    }

    pub fn new_juno_local() -> CosmosBuilder {
        CosmosBuilder {
            grpc_url: "http://localhost:9090".to_owned(),
            chain_id: "testing".to_owned(),
            gas_coin: "ujunox".to_owned(),
            address_type: AddressType::Juno,
            coins_per_kgas: 30,
            transaction_attempts: 3, // fail faster during testing
        }
    }

    pub fn new_juno_mainnet() -> CosmosBuilder {
        // Found at: https://cosmos.directory/juno/nodes
        CosmosBuilder {
            grpc_url: "https://grpc.juno.chaintools.tech:443".to_owned(),
            chain_id: "juno-1".to_owned(),
            gas_coin: "ujuno".to_owned(),
            address_type: AddressType::Juno,
            coins_per_kgas: 30,
            transaction_attempts: 30,
        }
    }

    pub fn new_osmosis_mainnet() -> CosmosBuilder {
        // Found at: https://docs.osmosis.zone/networks/
        CosmosBuilder {
            grpc_url: "http://grpc.osmosis.zone:9090".to_owned(),
            chain_id: "osmosis-1".to_owned(),
            gas_coin: "uosmo".to_owned(),
            address_type: AddressType::Osmo,
            coins_per_kgas: 30,
            transaction_attempts: 30,
        }
    }

    pub fn new_osmosis_testnet() -> CosmosBuilder {
        // Found at: https://docs.osmosis.zone/networks/
        CosmosBuilder {
            grpc_url: "https://grpc-testnet.osmosis.sandbox.levana.finance:443".to_owned(),
            chain_id: "osmo-test-4".to_owned(),
            gas_coin: "uosmo".to_owned(),
            address_type: AddressType::Osmo,
            coins_per_kgas: 30,
            transaction_attempts: 30,
        }
    }

    pub fn new_dragonfire() -> CosmosBuilder {
        // Found at: https://docs.osmosis.zone/networks/
        CosmosBuilder {
            grpc_url: "https://grpc-v3-udb8dydv.dragonfire.sandbox.levana.finance:443".to_owned(),
            chain_id: "dragonfire-3".to_owned(),
            gas_coin: "udragonfire".to_owned(),
            address_type: AddressType::Levana,
            coins_per_kgas: 30,
            transaction_attempts: 30,
        }
    }

    pub async fn get_base_account(&self, address: impl Into<String>) -> Result<BaseAccount> {
        let res = self
            .inner
            .auth_query_client
            .lock()
            .await
            .account(QueryAccountRequest {
                address: address.into(),
            })
            .await?
            .into_inner();

        Ok(prost::Message::decode(
            res.account.context("no account found")?.value.as_ref(),
        )?)
    }

    pub async fn all_balances(&self, address: impl Into<String>) -> Result<Vec<Coin>> {
        let address = address.into();
        let mut coins = Vec::new();
        let mut pagination = None;
        loop {
            let mut res = self
                .inner
                .bank_query_client
                .lock()
                .await
                .all_balances(QueryAllBalancesRequest {
                    address: address.clone(),
                    pagination: pagination.take(),
                })
                .await?
                .into_inner();
            coins.append(&mut res.balances);
            match res.pagination {
                Some(x) if !x.next_key.is_empty() => {
                    pagination = Some(PageRequest {
                        key: x.next_key,
                        offset: 0,
                        limit: 0,
                        count_total: false,
                        reverse: false,
                    })
                }
                _ => break Ok(coins),
            }
        }
    }

    pub async fn wasm_query(
        &self,
        address: impl Into<String>,
        query_data: impl Into<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        Ok(self
            .inner
            .wasm_query_client
            .lock()
            .await
            .smart_contract_state(QuerySmartContractStateRequest {
                address: address.into(),
                query_data: query_data.into(),
            })
            .await?
            .into_inner()
            .data)
    }

    pub async fn wasm_raw_query(
        &self,
        address: impl Into<String>,
        key: impl Into<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        Ok(self
            .inner
            .wasm_query_client
            .lock()
            .await
            .raw_contract_state(QueryRawContractStateRequest {
                address: address.into(),
                query_data: key.into(),
            })
            .await?
            .into_inner()
            .data)
    }

    pub async fn wait_for_transaction(&self, txhash: impl Into<String>) -> Result<TxResponse> {
        self.wait_for_transaction_body(txhash).await.map(|x| x.1)
    }

    pub async fn wait_for_transaction_body(
        &self,
        txhash: impl Into<String>,
    ) -> Result<(TxBody, TxResponse)> {
        const DELAY_SECONDS: u64 = 2;
        let txhash = txhash.into();
        for attempt in 1..=self.inner.transaction_attempts {
            let mut client = self.inner.tx_service_client.lock().await;
            let txres = client
                .get_tx(GetTxRequest {
                    hash: txhash.clone(),
                })
                .await;
            match txres {
                Ok(txres) => {
                    let txres = txres.into_inner();
                    return Ok((
                        txres
                            .tx
                            .with_context(|| format!("Missing tx for transaction {txhash}"))?
                            .body
                            .with_context(|| format!("Missing body for transaction {txhash}"))?,
                        txres.tx_response.with_context(|| {
                            format!("Missing tx_response for transaction {txhash}")
                        })?,
                    ));
                }
                Err(e) => {
                    // For some reason, it looks like Osmosis testnet isn't returning a NotFound. Ugly workaround...
                    if e.code() == tonic::Code::NotFound || e.message().contains("not found") {
                        log::debug!(
                            "Transaction {txhash} not ready, attempt #{attempt}/{}",
                            self.inner.transaction_attempts
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(DELAY_SECONDS)).await;
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }
        Err(anyhow::anyhow!(
            "Timed out waiting for {txhash} to be ready"
        ))
    }

    pub async fn list_transactions_for(
        &self,
        address: Address,
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> Result<Vec<String>> {
        let x = self
            .inner
            .tx_service_client
            .lock()
            .await
            .get_txs_event(GetTxsEventRequest {
                events: vec![format!("message.sender='{address}'")],
                pagination: Some(PageRequest {
                    key: vec![],
                    offset: offset.unwrap_or_default(),
                    limit: limit.unwrap_or(10),
                    count_total: false,
                    reverse: false,
                }),
                order_by: OrderBy::Asc as i32,
            })
            .await?;
        Ok(x.into_inner()
            .tx_responses
            .into_iter()
            .map(|x| x.txhash)
            .collect())
    }

    pub fn get_address_type(&self) -> AddressType {
        self.inner.address_type
    }

    pub fn get_gas_coin(&self) -> &String {
        &self.inner.gas_coin
    }

    fn gas_to_coins(&self, gas: u64) -> u64 {
        gas * self.inner.coins_per_kgas / 1000
    }

    pub async fn contract_info(&self, address: impl Into<String>) -> Result<ContractInfo> {
        self.inner
            .wasm_query_client
            .lock()
            .await
            .contract_info(QueryContractInfoRequest {
                address: address.into(),
            })
            .await?
            .into_inner()
            .contract_info
            .context("contract_info: missing contract_info (ironic...)")
    }

    pub async fn contract_history(
        &self,
        address: impl Into<String>,
    ) -> Result<QueryContractHistoryResponse> {
        Ok(self
            .inner
            .wasm_query_client
            .lock()
            .await
            .contract_history(QueryContractHistoryRequest {
                address: address.into(),
                pagination: None,
            })
            .await?
            .into_inner())
    }

    pub async fn get_block_info(&self, height: i64) -> Result<BlockInfo> {
        let res = self
            .inner
            .tendermint_client
            .lock()
            .await
            .get_block_by_height(GetBlockByHeightRequest { height })
            .await?
            .into_inner();
        let block_id = res.block_id.context("get_block_info: block_id is None")?;
        let block = res.block.context("get_block_info: block is None")?;
        let header = block.header.context("get_block_info: header is None")?;
        let time = header.time.context("get_block_info: time is None")?;
        let data = block.data.context("get_block_info: data is None")?;
        anyhow::ensure!(
            height == header.height,
            "Mismatched height from blockchain. Got {}, expected {height}",
            header.height
        );
        let mut txhashes = vec![];
        for tx in data.txs {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(tx);
            let digest = hasher.finalize();
            txhashes.push(hex::encode_upper(digest));
        }
        Ok(BlockInfo {
            height: header.height,
            block_hash: hex::encode_upper(block_id.hash),
            timestamp: Utc.timestamp_nanos(time.seconds * 1_000_000_000 + i64::from(time.nanos)),
            txhashes,
        })
    }
}

#[derive(Debug)]
pub struct BlockInfo {
    pub height: i64,
    pub block_hash: String,
    pub timestamp: DateTime<Utc>,
    pub txhashes: Vec<String>,
}

#[derive(Default)]
pub struct TxBuilder {
    messages: Vec<cosmos_sdk_proto::Any>,
    memo: Option<String>,
    skip_code_check: bool,
}

impl TxBuilder {
    pub fn add_message(mut self, msg: impl Into<TypedMessage>) -> Self {
        self.messages.push(msg.into().0);
        self
    }

    pub fn add_message_mut(&mut self, msg: impl Into<TypedMessage>) {
        self.messages.push(msg.into().0);
    }

    pub fn set_memo(mut self, memo: impl Into<String>) -> Self {
        self.memo = Some(memo.into());
        self
    }

    pub fn set_optional_memo(mut self, memo: impl Into<Option<String>>) -> Self {
        self.memo = memo.into();
        self
    }

    /// When calling [TxBuilder::sign_and_broadcast], skip the check of whether the code is 0
    pub fn skip_code_check(mut self, skip_code_check: bool) -> Self {
        self.skip_code_check = skip_code_check;
        self
    }

    /// Simulate the amount of gas needed to run a transaction.
    pub async fn simulate(&self, cosmos: &Cosmos, wallet: &Wallet) -> Result<FullSimulateResponse> {
        let base_account = cosmos.get_base_account(wallet.address()).await?;

        // Deal with account sequence errors, overall relevant issue is: https://phobosfinance.atlassian.net/browse/PERP-283
        //
        // There may be a bug in Cosmos where simulating expects the wrong
        // sequence number. So: we simulate, trying out the suggested sequence
        // number if necessary, and then we broadcast, again trying the sequence
        // number they recommend if necessary.
        //
        // See: https://github.com/cosmos/cosmos-sdk/issues/11597

        Ok(
            match self
                .simulate_inner(cosmos, wallet, base_account.sequence)
                .await
            {
                Ok(pair) => pair,
                Err(ExpectedSequenceError::RealError(e)) => return Err(e),
                Err(ExpectedSequenceError::NewNumber(x, e)) => {
                    log::warn!("Received an account sequence error while simulating a transaction, retrying with new number {x}: {e:?}");
                    self.simulate_inner(cosmos, wallet, x).await?
                }
            },
        )
    }

    /// Sign transaction, broadcast, wait for it to complete, confirm that it was successful
    pub async fn sign_and_broadcast(&self, cosmos: &Cosmos, wallet: &Wallet) -> Result<TxResponse> {
        let simres = self.simulate(cosmos, wallet).await?;
        self.execute_gas(cosmos, wallet, Some(simres.body), simres.gas_used * 13 / 10)
            .await
    }

    /// Sign transaction and broadcast using the given amount of gas to request
    pub async fn execute_gas(
        &self,
        cosmos: &Cosmos,
        wallet: &Wallet,
        body: Option<TxBody>,
        gas_to_request: u64,
    ) -> Result<TxResponse> {
        let base_account = cosmos.get_base_account(wallet.address()).await?;
        let body = body.unwrap_or_else(|| self.make_tx_body());

        match self
            .sign_and_broadcast_with(
                cosmos,
                wallet,
                base_account.account_number,
                base_account.sequence,
                body.clone(),
                gas_to_request,
            )
            .await
        {
            Ok(res) => Ok(res),
            Err(ExpectedSequenceError::RealError(e)) => Err(e),
            Err(ExpectedSequenceError::NewNumber(x, e)) => {
                log::warn!("Received an account sequence error while broadcasting a transaction, retrying with new number {x}: {e:?}");
                self.sign_and_broadcast_with(
                    cosmos,
                    wallet,
                    base_account.account_number,
                    x,
                    body,
                    gas_to_request,
                )
                .await
                .map_err(|x| x.into())
            }
        }
    }

    fn make_signer_infos(&self, wallet: &Wallet, sequence: u64) -> Vec<SignerInfo> {
        vec![SignerInfo {
            public_key: Some(cosmos_sdk_proto::Any {
                type_url: "/cosmos.crypto.secp256k1.PubKey".to_owned(),
                value: cosmos_sdk_proto::tendermint::crypto::PublicKey {
                    sum: Some(
                        cosmos_sdk_proto::tendermint::crypto::public_key::Sum::Ed25519(
                            wallet.public_key_bytes().to_owned(),
                        ),
                    ),
                }
                .encode_to_vec(),
            }),
            mode_info: Some(ModeInfo {
                sum: Some(
                    cosmos_sdk_proto::cosmos::tx::v1beta1::mode_info::Sum::Single(
                        cosmos_sdk_proto::cosmos::tx::v1beta1::mode_info::Single { mode: 1 },
                    ),
                ),
            }),
            sequence,
        }]
    }

    /// Make a [TxBody] for this builder
    fn make_tx_body(&self) -> TxBody {
        TxBody {
            messages: self.messages.clone(),
            memo: self.memo.as_deref().unwrap_or_default().to_owned(),
            timeout_height: 0,
            extension_options: vec![],
            non_critical_extension_options: vec![],
        }
    }

    /// Simulate to calculate the gas costs
    async fn simulate_inner(
        &self,
        cosmos: &Cosmos,
        wallet: &Wallet,
        sequence: u64,
    ) -> Result<FullSimulateResponse, ExpectedSequenceError> {
        let body = self.make_tx_body();

        // First simulate the request with no signature and fake gas
        let simulate_tx = Tx {
            auth_info: Some(AuthInfo {
                fee: Some(Fee {
                    amount: vec![],
                    gas_limit: 0,
                    payer: "".to_owned(),
                    granter: "".to_owned(),
                }),
                signer_infos: self.make_signer_infos(wallet, sequence),
            }),
            signatures: vec![vec![]],
            body: Some(body.clone()),
        };

        #[allow(deprecated)]
        let simulate_req = SimulateRequest {
            tx: None,
            tx_bytes: simulate_tx.encode_to_vec(),
        };

        let simres = cosmos
            .inner
            .tx_service_client
            .lock()
            .await
            .simulate(simulate_req)
            .await;

        // PERP-283: detect account sequence mismatches
        let simres = match simres {
            Ok(simres) => simres.into_inner(),
            Err(e) => {
                let is_sequence = get_expected_sequence(e.message());
                let e = anyhow::Error::from(e).context("Unable to simulate transaction");
                return match is_sequence {
                    None => Err(ExpectedSequenceError::RealError(e)),
                    Some(number) => Err(ExpectedSequenceError::NewNumber(number, e)),
                };
            }
        };
        let gas_used = simres
            .gas_info
            .as_ref()
            .context("Missing gas_info in SimulateResponse")?
            .gas_used;

        Ok(FullSimulateResponse {
            body,
            simres,
            gas_used,
        })
    }

    async fn sign_and_broadcast_with(
        &self,
        cosmos: &Cosmos,
        wallet: &Wallet,
        account_number: u64,
        sequence: u64,
        body: TxBody,
        gas_to_request: u64,
    ) -> Result<TxResponse, ExpectedSequenceError> {
        let auth_info = AuthInfo {
            signer_infos: self.make_signer_infos(wallet, sequence),
            fee: Some(Fee {
                amount: vec![Coin {
                    denom: cosmos.inner.gas_coin.clone(),
                    amount: cosmos.gas_to_coins(gas_to_request).to_string(),
                }],
                gas_limit: gas_to_request,
                payer: "".to_owned(),
                granter: "".to_owned(),
            }),
        };

        let sign_doc = SignDoc {
            body_bytes: body.encode_to_vec(),
            auth_info_bytes: auth_info.encode_to_vec(),
            chain_id: cosmos.inner.chain_id.clone(),
            account_number,
        };
        let sign_doc_bytes = sign_doc.encode_to_vec();
        let signature = wallet.sign_bytes(&sign_doc_bytes);

        let tx = Tx {
            body: Some(body),
            auth_info: Some(auth_info),
            signatures: vec![signature.serialize_compact().to_vec()],
        };

        let res = cosmos
            .inner
            .tx_service_client
            .lock()
            .await
            .broadcast_tx(BroadcastTxRequest {
                tx_bytes: tx.encode_to_vec(),
                mode: BroadcastMode::Sync as i32,
            })
            .await
            .context("Unable to broadcast transaction")?
            .into_inner()
            .tx_response
            .context("Missing inner tx_response")?;

        if !self.skip_code_check && res.code != 0 {
            let e = anyhow::anyhow!(
                "Initial transaction broadcast failed with code {}. Raw log: {}",
                res.code,
                res.raw_log
            );
            let is_sequence = get_expected_sequence(&res.raw_log);
            return Err(match is_sequence {
                None => ExpectedSequenceError::RealError(e),
                Some(number) => ExpectedSequenceError::NewNumber(number, e),
            });
        };

        log::debug!("Initial BroadcastTxResponse: {res:?}");

        Ok(cosmos.wait_for_transaction(res.txhash).await?)
    }
}

pub struct TypedMessage(cosmos_sdk_proto::Any);

impl From<MsgStoreCode> for TypedMessage {
    fn from(msg: MsgStoreCode) -> Self {
        TypedMessage(cosmos_sdk_proto::Any {
            type_url: "/cosmwasm.wasm.v1.MsgStoreCode".to_owned(),
            value: msg.encode_to_vec(),
        })
    }
}

impl From<MsgInstantiateContract> for TypedMessage {
    fn from(msg: MsgInstantiateContract) -> Self {
        TypedMessage(cosmos_sdk_proto::Any {
            type_url: "/cosmwasm.wasm.v1.MsgInstantiateContract".to_owned(),
            value: msg.encode_to_vec(),
        })
    }
}

impl From<MsgMigrateContract> for TypedMessage {
    fn from(msg: MsgMigrateContract) -> Self {
        TypedMessage(cosmos_sdk_proto::Any {
            type_url: "/cosmwasm.wasm.v1.MsgMigrateContract".to_owned(),
            value: msg.encode_to_vec(),
        })
    }
}

impl From<MsgExecuteContract> for TypedMessage {
    fn from(msg: MsgExecuteContract) -> Self {
        TypedMessage(cosmos_sdk_proto::Any {
            type_url: "/cosmwasm.wasm.v1.MsgExecuteContract".to_owned(),
            value: msg.encode_to_vec(),
        })
    }
}

impl From<MsgSend> for TypedMessage {
    fn from(msg: MsgSend) -> Self {
        TypedMessage(cosmos_sdk_proto::Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_owned(),
            value: msg.encode_to_vec(),
        })
    }
}

pub trait HasCosmos {
    fn get_cosmos(&self) -> &Cosmos;
}

impl HasCosmos for Cosmos {
    fn get_cosmos(&self) -> &Cosmos {
        self
    }
}

impl<T: HasCosmos> HasCosmos for &T {
    fn get_cosmos(&self) -> &Cosmos {
        HasCosmos::get_cosmos(*self)
    }
}

/// Returned the expected account sequence mismatch based on an error message, if present
fn get_expected_sequence(message: &str) -> Option<u64> {
    for line in message.lines() {
        if let Some(x) = get_expected_sequence_single(line) {
            return Some(x);
        }
    }
    None
}

fn get_expected_sequence_single(message: &str) -> Option<u64> {
    let s = message.strip_prefix("account sequence mismatch, expected ")?;
    let comma = s.find(',')?;
    s[..comma].parse().ok()
}

/// Either a real error that should be propagated, or a new account sequence number to try
enum ExpectedSequenceError {
    RealError(anyhow::Error),
    NewNumber(u64, anyhow::Error),
}

impl From<anyhow::Error> for ExpectedSequenceError {
    fn from(e: anyhow::Error) -> Self {
        ExpectedSequenceError::RealError(e)
    }
}

impl From<ExpectedSequenceError> for anyhow::Error {
    fn from(e: ExpectedSequenceError) -> Self {
        match e {
            ExpectedSequenceError::RealError(e) => e,
            ExpectedSequenceError::NewNumber(_, e) => e,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_expected_sequence_good() {
        assert_eq!(
            get_expected_sequence("account sequence mismatch, expected 5, got 0"),
            Some(5)
        );
        assert_eq!(
            get_expected_sequence("account sequence mismatch, expected 2, got 7"),
            Some(2)
        );
        assert_eq!(
            get_expected_sequence("account sequence mismatch, expected 20000001, got 7"),
            Some(20000001)
        );
    }

    #[test]
    fn get_expected_sequence_extra_prelude() {
        assert_eq!(
            get_expected_sequence("blah blah blah\n\naccount sequence mismatch, expected 5, got 0"),
            Some(5)
        );
        assert_eq!(
            get_expected_sequence(
                "foajodifjaolkdfjas aiodjfaof\n\n\naccount sequence mismatch, expected 2, got 7"
            ),
            Some(2)
        );
        assert_eq!(
            get_expected_sequence(
                "iiiiiiiiiiiiii\n\naccount sequence mismatch, expected 20000001, got 7"
            ),
            Some(20000001)
        );
    }

    #[test]
    fn get_expected_sequence_bad() {
        assert_eq!(
            get_expected_sequence("Totally different error message"),
            None
        );
        assert_eq!(
            get_expected_sequence("account sequence mismatch, expected XXXXX, got 7"),
            None
        );
    }
}

pub struct FullSimulateResponse {
    pub body: TxBody,
    pub simres: SimulateResponse,
    pub gas_used: u64,
}
