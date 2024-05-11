#[cfg(not(target_arch = "wasm32"))] use super::*;
use mm2_core::mm_ctx::{MmArc, MmCtxBuilder};
#[cfg(not(target_arch = "wasm32"))]
use mm2_test_helpers::for_tests::{eth_sepolia_conf, ETH_SEPOLIA_SWAP_CONTRACT};

lazy_static! {
    static ref MM_CTX: MmArc = MmCtxBuilder::new().into_mm_arc();
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn eth_coin_for_test(
    coin_type: EthCoinType,
    urls: &[&str],
    fallback_swap_contract: Option<Address>,
    chain_id: u64,
) -> (MmArc, EthCoin) {
    let key_pair = KeyPair::from_secret_slice(
        &hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap(),
    )
    .unwrap();
    eth_coin_from_keypair(coin_type, urls, fallback_swap_contract, key_pair, chain_id)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn eth_coin_from_keypair(
    coin_type: EthCoinType,
    urls: &[&str],
    fallback_swap_contract: Option<Address>,
    key_pair: KeyPair,
    chain_id: u64,
) -> (MmArc, EthCoin) {
    let mut web3_instances = vec![];
    for url in urls.iter() {
        let node = HttpTransportNode {
            uri: url.parse().unwrap(),
            gui_auth: false,
        };
        let transport = Web3Transport::new_http(node);
        let web3 = Web3::new(transport);
        web3_instances.push(Web3Instance { web3, is_parity: false });
    }
    drop_mutability!(web3_instances);

    let conf = json!({ "coins": [eth_sepolia_conf()] });
    let ctx = MmCtxBuilder::new().with_conf(conf).into_mm_arc();
    let ticker = match coin_type {
        EthCoinType::Eth => "ETH".to_string(),
        EthCoinType::Erc20 { .. } => "JST".to_string(),
        EthCoinType::Nft { ref platform } => platform.to_string(),
    };
    let my_address = key_pair.address();

    let eth_coin = EthCoin(Arc::new(EthCoinImpl {
        coin_type,
        decimals: 18,
        gas_station_url: None,
        gas_station_decimals: ETH_GAS_STATION_DECIMALS,
        history_sync_state: Mutex::new(HistorySyncState::NotEnabled),
        gas_station_policy: GasStationPricePolicy::MeanAverageFast,
        sign_message_prefix: Some(String::from("Ethereum Signed Message:\n")),
        priv_key_policy: key_pair.into(),
        derivation_method: Arc::new(DerivationMethod::SingleAddress(my_address)),
        swap_contract_address: Address::from_str(ETH_SEPOLIA_SWAP_CONTRACT).unwrap(),
        fallback_swap_contract,
        contract_supports_watchers: false,
        ticker,
        web3_instances: AsyncMutex::new(web3_instances),
        ctx: ctx.weak(),
        required_confirmations: 1.into(),
        chain_id,
        trezor_coin: None,
        logs_block_range: DEFAULT_LOGS_BLOCK_RANGE,
        address_nonce_locks: Arc::new(AsyncMutex::new(new_nonce_lock())),
        erc20_tokens_infos: Default::default(),
        nfts_infos: Arc::new(Default::default()),
        abortable_system: AbortableQueue::default(),
    }));
    (ctx, eth_coin)
}