mod parsed_coin;

use std::{io::Write, path::PathBuf, str::FromStr};

use anyhow::Result;
use clap::{CommandFactory, Parser};
use cosmos::{
    proto::{
        cosmos::base::abci::v1beta1::TxResponse,
        cosmwasm::wasm::v1::{
            ContractCodeHistoryEntry, ContractInfo, QueryContractHistoryResponse,
        },
    },
    Address, AddressType, CodeId, Coin, CosmosNetwork, RawWallet, Wallet,
};
use parsed_coin::ParsedCoin;

/// Command line tool for common Levana NFT activities
#[derive(clap::Parser)]
struct Cmd {
    #[clap(flatten)]
    opt: Opt,
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Parser)]
struct Opt {
    /// Network to use, either mainnet or testnet
    #[clap(
        long,
        default_value = "juno-testnet",
        env = "COSMOS_NETWORK",
        global = true
    )]
    network: CosmosNetwork,
    /// Turn on verbose output
    #[clap(long, short, global = true)]
    verbose: bool,
}

impl Opt {
    fn init_logger(&self) {
        let env = env_logger::Env::default().default_filter_or(if self.verbose {
            format!("{}=debug,cosmos=debug,info", env!("CARGO_CRATE_NAME"))
        } else {
            "info".to_owned()
        });
        env_logger::Builder::from_env(env).init();
    }
}

#[derive(clap::Parser)]
struct TxOpt {
    /// Mnemonic phrase
    #[clap(long, env = "COSMOS_WALLET")]
    wallet: RawWallet,
    /// Memo to put on transaction
    #[clap(long)]
    memo: Option<String>,
}

impl TxOpt {
    pub(crate) fn get_wallet(&self, opt: &crate::Opt) -> Wallet {
        self.wallet.for_chain(opt.network.address_type())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cmd = Cmd::parse();
    cmd.opt.init_logger();

    cmd.subcommand.go(cmd.opt).await
}

#[derive(clap::Parser)]
enum Subcommand {
    /// Upload contract
    StoreCode {
        #[clap(flatten)]
        tx_opt: TxOpt,
        file: PathBuf,
    },
    /// Instantiate contract
    InstantiateContract {
        #[clap(flatten)]
        tx_opt: TxOpt,
        /// Code to deploy
        code_id: u64,
        /// Label to display
        label: String,
        /// Instantiate message (JSON)
        msg: String,
    },
    /// Print balances
    PrintBalances {
        /// Address on COSMOS blockchain
        address: String,
    },
    /// Query contract
    QueryContract {
        /// Contract address
        address: String,
        /// Query (in JSON)
        query: String,
    },
    /// Look up a raw value in the contract's storage
    RawQueryContract {
        /// Contract address
        address: String,
        /// Key
        key: String,
    },
    /// Migrate contract
    MigrateContract {
        #[clap(flatten)]
        tx_opt: TxOpt,
        /// Contract address
        address: Address,
        /// New code ID
        code_id: u64,
        /// Migrate message (JSON)
        msg: String,
    },
    /// Execute contract
    ExecuteContract {
        #[clap(flatten)]
        tx_opt: TxOpt,
        /// Contract address
        address: Address,
        /// Execute message (JSON)
        msg: String,
        /// Funds. Example 100ujunox
        funds: Option<String>,
    },
    /// Generate wallet
    GenWallet {
        /// Address type: One of cosmos, juno, osmo or levana
        address_type: AddressType,
    },
    /// Print the address for the given phrase
    PrintAddress {
        /// Address type: One of cosmos, juno, osmo or levana
        address_type: AddressType,
        /// Phrase
        phrase: RawWallet,
    },
    /// Send coins to the given address
    SendCoins {
        #[clap(flatten)]
        tx_opt: TxOpt,
        /// Destination address
        dest: Address,
        /// Coins to send
        coins: Vec<ParsedCoin>,
    },
    /// Get contract metadata
    ContractInfo { contract: Address },
    /// Show transaction details
    ShowTx {
        txhash: String,
        /// Show all the data in the transaction?
        #[clap(long)]
        complete: bool,
    },
    /// List transactions for a given wallet
    ListTxsFor {
        address: Address,
        /// Maximum number of transactions to return
        #[clap(long)]
        limit: Option<u64>,
        /// Offset
        #[clap(long)]
        offset: Option<u64>,
    },
    /// Get the contract history
    ContractHistory { contract: Address },
    /// Generate bash shell completion script
    GenerateShellCompletions {
        /// Which shell to generate for
        #[clap(default_value_t = clap_complete::Shell::Bash)]
        shell: clap_complete::Shell,
    },
}

impl Subcommand {
    pub(crate) async fn go(self, opt: Opt) -> Result<()> {
        let cosmos = opt.network.connect().await?;

        match self {
            Subcommand::StoreCode { tx_opt, file } => {
                let wallet = tx_opt.get_wallet(&opt);
                let codeid = cosmos.store_code_path(&wallet, &file).await?;
                println!("Code ID: {codeid}");
            }
            Subcommand::InstantiateContract {
                tx_opt,
                code_id,
                label,
                msg,
            } => {
                let contract = CodeId::new(cosmos, code_id)
                    .instantiate_binary(&tx_opt.get_wallet(&opt), label, vec![], msg)
                    .await?;
                println!("Contract: {contract}");
            }
            Subcommand::PrintBalances { address } => {
                let balances = cosmos.all_balances(address).await?;
                for Coin { denom, amount } in &balances {
                    println!("{amount}{denom}");
                }
                if balances.is_empty() {
                    println!("0");
                }
            }
            Subcommand::QueryContract { address, query } => {
                let x = cosmos.wasm_query(address, query).await?;
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                stdout.write_all(&x)?;
                stdout.write_all(b"\n")?;
            }
            Subcommand::RawQueryContract { address, key } => {
                let x = cosmos.wasm_raw_query(address, key).await?;
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                stdout.write_all(&x)?;
                stdout.write_all(b"\n")?;
            }
            Subcommand::MigrateContract {
                tx_opt,
                address,
                code_id,
                msg,
            } => {
                let contract = cosmos::Contract::new(cosmos, address);
                contract
                    .migrate_binary(&tx_opt.get_wallet(&opt), code_id, msg)
                    .await?;
            }
            Subcommand::ExecuteContract {
                tx_opt,
                address,
                msg,
                funds: amount,
            } => {
                let contract = cosmos::Contract::new(cosmos.clone(), address);
                let amount = match amount {
                    Some(funds) => {
                        let coin = ParsedCoin::from_str(&funds)?.into();
                        vec![coin]
                    }
                    None => vec![],
                };
                let tx = contract
                    .execute_binary(&tx_opt.get_wallet(&opt), amount, msg)
                    .await?;
                println!("Transaction hash: {}", tx.txhash);
                println!("Raw log: {}", tx.raw_log);
            }
            Subcommand::GenWallet { address_type } => gen_wallet(address_type)?,
            Subcommand::PrintAddress {
                address_type,
                phrase,
            } => {
                println!("{}", phrase.for_chain(address_type));
            }
            Subcommand::SendCoins {
                tx_opt,
                dest,
                coins,
            } => {
                let txres = tx_opt
                    .get_wallet(&opt)
                    .send_coins(
                        &cosmos,
                        &dest,
                        coins.into_iter().map(|x| x.into()).collect(),
                    )
                    .await?;
                println!("{}", txres.txhash);
            }
            Subcommand::ContractInfo { contract } => {
                let ContractInfo {
                    code_id,
                    creator,
                    admin,
                    label,
                    created: _,
                    ibc_port_id: _,
                    extension: _,
                } = cosmos.make_contract(contract).info().await?;
                println!("code_id: {code_id}");
                println!("creator: {creator}");
                println!("admin: {admin}");
                println!("label: {label}");
            }
            Subcommand::ShowTx { txhash, complete } => {
                let TxResponse {
                    height,
                    txhash: _,
                    codespace,
                    code,
                    data,
                    raw_log,
                    logs,
                    info,
                    gas_wanted,
                    gas_used,
                    tx: _,
                    timestamp,
                    events,
                } = cosmos.wait_for_transaction(txhash).await?;
                println!("Height: {height}");
                println!("Code: {code}");
                println!("Codespace: {codespace}");
                println!("Raw log: {raw_log}");
                println!("Info: {info}");
                println!("Gas wanted: {gas_wanted}");
                println!("Gas used: {gas_used}");
                println!("Timestamp: {timestamp}");
                if complete {
                    println!("Data: {data}");
                    for (idx, log) in logs.into_iter().enumerate() {
                        println!("Log #{idx}: {log:?}");
                    }
                    for (idx, event) in events.into_iter().enumerate() {
                        println!("Event #{idx}: {event:?}");
                    }
                }
            }
            Subcommand::ListTxsFor {
                address,
                limit,
                offset,
            } => {
                for txhash in cosmos.list_transactions_for(address, limit, offset).await? {
                    println!("{txhash}");
                }
            }
            Subcommand::ContractHistory { contract } => {
                let QueryContractHistoryResponse {
                    entries,
                    pagination: _,
                } = cosmos.make_contract(contract).history().await?;
                for ContractCodeHistoryEntry {
                    operation,
                    code_id,
                    updated,
                    msg,
                } in entries
                {
                    println!("Operation: {operation}. Code ID: {code_id}. Updated: {updated:?}. Message: {:?}", String::from_utf8(msg))
                }
            }
            Subcommand::GenerateShellCompletions { shell } => {
                clap_complete::generate(
                    shell,
                    &mut Subcommand::command(),
                    "levana",
                    &mut std::io::stdout(),
                );
            }
        }

        Ok(())
    }
}

fn gen_wallet(address_type: AddressType) -> Result<()> {
    let phrase = cosmos::Wallet::generate_phrase();
    let wallet = cosmos::Wallet::from_phrase(&phrase, address_type)?;
    println!("Mnemonic: {phrase}");
    println!("Address: {wallet}");
    Ok(())
}
