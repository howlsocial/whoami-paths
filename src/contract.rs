#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    ensure_eq, from_binary, to_binary, Addr, BankMsg, Binary, CosmosMsg, Deps, DepsMut, Env,
    MessageInfo, QuerierWrapper, Response, StdResult, Uint128, WasmMsg,
};
use cw2::set_contract_version;
use cw20::{BalanceResponse, Cw20ExecuteMsg, Cw20QueryMsg, Cw20ReceiveMsg, TokenInfoResponse};
use cw721::{Cw721QueryMsg, Cw721ReceiveMsg, OwnerOfResponse};
use cw_storage_plus::Item;
use cw_utils::{must_pay, nonpayable};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ContractError;
use crate::msg::{
    ClaimInfoResponse, ExecuteMsg, InstantiateMsg, MigrateMsg, PaymentDetails,
    PaymentDetailsBalanceResponse, PaymentDetailsResponse, QueryMsg, ReceiveMsg,
};
use crate::state::{Config, CONFIG, PAYMENT_DETAILS};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:whoami-paths";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

fn assert_cw20(deps: Deps, cw20_addr: &Addr) -> Result<(), ContractError> {
    let _resp: TokenInfoResponse = deps
        .querier
        .query_wasm_smart(cw20_addr, &cw20_base::msg::QueryMsg::TokenInfo {})
        .map_err(|_err| ContractError::InvalidCw20 {})?;
    Ok(())
}

pub fn mint_path_msg(
    whoami_address: String,
    contract: String, // our contract address
    owner: String,    // the person who made the MintMsg call
    token_id: String,
    path: String,
) -> StdResult<Vec<WasmMsg>> {
    let whoami_msg = whoami::msg::ExecuteMsg::MintPath(whoami::msg::MintMsg {
        token_id: path.clone(),
        owner: contract,
        token_uri: None,
        extension: whoami::msg::Extension {
            image: None,
            image_data: None,
            email: None,
            external_url: None,
            public_name: None,
            public_bio: None,
            twitter_id: None,
            discord_id: None,
            telegram_id: None,
            keybase_id: None,
            validator_operator_address: None,
            contract_address: None,
            parent_token_id: Some(token_id.clone()),
            pgp_public_key: None,
        },
    });
    let wasm_msg1 = WasmMsg::Execute {
        contract_addr: whoami_address.clone(),
        msg: to_binary(&whoami_msg)?,
        funds: vec![],
    };

    let transfer_msg = whoami::msg::ExecuteMsg::TransferNft {
        recipient: owner,
        token_id: format!("{}::{}", token_id, path),
    };
    let wasm_msg2 = WasmMsg::Execute {
        contract_addr: whoami_address,
        msg: to_binary(&transfer_msg)?,
        funds: vec![],
    };

    Ok(vec![wasm_msg1, wasm_msg2])
}

fn get_dens_owner(
    querier: &QuerierWrapper,
    token_id: String,
    address_minting_the_path: String,
) -> Option<String> {
    querier
        .query_wasm_smart(
            &address_minting_the_path,
            &Cw721QueryMsg::OwnerOf {
                token_id,
                include_expired: None,
            },
        )
        .map(|resp: OwnerOfResponse| resp.owner)
        .ok()
}

fn is_in_claim_window(
    path_root_claim_window: Option<u64>,
    init_height: u64,
    current_height: u64,
) -> bool {
    match path_root_claim_window {
        Some(w) => {
            if let Some(height_plus_claim_window) = init_height.checked_add(w) {
                height_plus_claim_window > current_height
            } else {
                false
            }
        }
        None => false,
    }
}

fn is_claimable(
    env: &Env,
    querier: &QuerierWrapper,
    config: &Config,
    path: &str,
    sender: &str,
) -> Result<bool, ContractError> {
    let is_in_claim_window_ = is_in_claim_window(
        config.reserve_root_for_n_blocks,
        config.initial_height,
        env.block.height,
    );

    if is_in_claim_window_ {
        ensure_eq!(
            config.reserve_root_names,
            true,
            ContractError::ReserveRootNameDisabled {}
        );

        let path_as_base_owner =
            get_dens_owner(querier, String::from(path), config.whoami_address.clone());

        if let Some(path_as_base_owner) = path_as_base_owner {
            ensure_eq!(
                sender,
                path_as_base_owner,
                ContractError::RootInClaimWindowToken {}
            );

            Ok::<bool, ContractError>(true)
        } else {
            Ok(false)
        }
    } else {
        Ok(false)
    }
}

fn mint(
    env: Env,
    whoami_address: String,
    token_id: String,
    path: String,
    address_minting_the_path: String,
    amount_paid: Uint128,
    amount_required: Uint128,
) -> Result<Response, ContractError> {
    if amount_paid != amount_required {
        return Err(ContractError::InsufficientFunds {});
    }

    let wasm_msg = mint_path_msg(
        whoami_address,
        env.contract.address.to_string(),
        address_minting_the_path,
        token_id,
        path,
    )?;
    Ok(Response::new()
        .add_attribute("action", "mint_path")
        .add_messages(wasm_msg))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let whoami_address = deps.api.addr_validate(&msg.whoami_address)?;
    let admin = deps.api.addr_validate(&msg.admin)?;

    let config = Config {
        whoami_address: whoami_address.to_string(),
        admin: admin.clone(),
        token_id: None,
        initial_height: env.block.height,
        reserve_root_names: msg.reserve_root_names,
        reserve_root_for_n_blocks: msg.reserve_root_for_n_blocks,
    };

    CONFIG.save(deps.storage, &config)?;

    if let Some(payment_details) = msg.payment_details {
        match payment_details.clone() {
            PaymentDetails::Cw20 {
                token_address,
                amount,
            } => {
                let validated_addr = deps.api.addr_validate(&token_address)?;
                assert_cw20(deps.as_ref(), &validated_addr)?;
                if amount.is_zero() {
                    return Err(ContractError::InvalidPaymentAmount {});
                }
            }
            PaymentDetails::Native { denom: _, amount } => {
                if amount.is_zero() {
                    return Err(ContractError::InvalidPaymentAmount {});
                }
            }
        }
        PAYMENT_DETAILS.save(deps.storage, &payment_details)?;
    }

    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("admin", admin.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Receive(cw20_receive) => execute_receive_cw20(deps, env, info, cw20_receive),
        ExecuteMsg::ReceiveNft(cw721_receive) => {
            execute_receive_cw721(deps, env, info, cw721_receive)
        }
        ExecuteMsg::MintPath { path } => execute_mint_path(deps, env, info, path),
        ExecuteMsg::UpdateAdmin { new_admin } => execute_update_admin(deps, env, info, new_admin),
        ExecuteMsg::WithdrawRootToken {} => execute_withdraw_root_token(deps, env, info),
        ExecuteMsg::WithdrawPayments {} => execute_withdraw_payments(deps, env, info),
    }
}

pub fn execute_receive_cw20(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    cw20_receive: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    let payment_details = PAYMENT_DETAILS.may_load(deps.storage)?;
    let config = CONFIG.load(deps.storage)?;

    if payment_details.is_none() {
        // We do not need to pay a CW20 to mint, use base execute route
        return Err(ContractError::NoPaymentNeeded {});
    }

    if config.token_id.is_none() {
        // We have no token to mint off of
        return Err(ContractError::NoRootToken {});
    }

    let token_id = String::from(config.token_id.as_ref().unwrap());
    let payment_details = payment_details.unwrap();
    let recv_msg: ReceiveMsg = from_binary(&cw20_receive.msg)?;
    let path = match recv_msg {
        ReceiveMsg::MintPath { path } => path,
    };

    if is_claimable(
        &env,
        &deps.querier,
        &config,
        path.as_str(),
        cw20_receive.sender.as_str(),
    )? {
        return Err(ContractError::NoPaymentNeeded {});
    }

    match payment_details {
        PaymentDetails::Cw20 {
            amount,
            token_address,
        } => {
            if info.sender != token_address {
                // Unrecognised token
                return Err(ContractError::UnrecognisedToken {});
            }

            mint(
                env,
                config.whoami_address,
                token_id,
                path,
                cw20_receive.sender,
                cw20_receive.amount,
                amount,
            )
        }
        // TODO: Improve error
        PaymentDetails::Native { .. } => Err(ContractError::Unauthorized {}),
    }
}

pub fn execute_receive_cw721(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    cw721_receive: Cw721ReceiveMsg,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    if config.whoami_address != info.sender {
        // Coming from a different contract
        return Err(ContractError::Unauthorized {});
    }

    if config.token_id.is_some() {
        // We already have a token
        return Err(ContractError::ExistingRootToken {});
    }

    if cw721_receive.sender != config.admin {
        // Only admin can transfer in the name
        return Err(ContractError::Unauthorized {});
    }

    config.token_id = Some(cw721_receive.token_id);

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new().add_attribute("action", "receive_cw721"))
}

pub fn execute_mint_path(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    path: String,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let payment_details = PAYMENT_DETAILS.may_load(deps.storage)?;
    if config.token_id.is_none() {
        // No token to mint off of
        return Err(ContractError::NoRootToken {});
    }
    let token_id = String::from(config.token_id.as_ref().unwrap());

    let override_payment = is_claimable(
        &env,
        &deps.querier,
        &config,
        path.as_str(),
        info.sender.as_str(),
    )?;

    if let Some(pd) = payment_details {
        match (pd, override_payment) {
            (PaymentDetails::Native { denom, amount }, false) => {
                let paid_amount = must_pay(&info, &denom)?;
                mint(
                    env,
                    config.whoami_address,
                    token_id,
                    path,
                    info.sender.to_string(),
                    paid_amount,
                    amount,
                )
            }
            (PaymentDetails::Cw20 { .. }, false) => Err(ContractError::Unauthorized {}),
            (PaymentDetails::Cw20 { .. }, true) | (PaymentDetails::Native { .. }, true) => {
                nonpayable(&info)?;
                mint(
                    env,
                    config.whoami_address,
                    token_id,
                    path,
                    info.sender.to_string(),
                    Uint128::zero(),
                    Uint128::zero(),
                )
            }
        }
    } else {
        nonpayable(&info)?;
        mint(
            env,
            config.whoami_address,
            token_id,
            path,
            info.sender.to_string(),
            Uint128::zero(),
            Uint128::zero(),
        )
    }
}

pub fn execute_update_admin(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    new_admin: String,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        // Only existing admin can set
        return Err(ContractError::Unauthorized {});
    }
    let old_admin = config.admin.clone();
    let validated_new_admin = deps.api.addr_validate(&new_admin)?;

    config.admin = validated_new_admin.clone();

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "update_admin")
        .add_attribute("old_admin", old_admin.to_string())
        .add_attribute("new_admin", validated_new_admin.to_string()))
}

pub fn execute_withdraw_root_token(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    let admin = config.admin.clone();
    let whoami_address = config.whoami_address.clone();

    if info.sender != admin {
        return Err(ContractError::Unauthorized {});
    }

    if config.token_id.is_none() {
        return Err(ContractError::NoRootToken {});
    }
    let token_id = config.token_id.unwrap();

    let transfer_msg = whoami::msg::ExecuteMsg::TransferNft {
        recipient: admin.to_string(),
        token_id,
    };
    let wasm_msg = WasmMsg::Execute {
        contract_addr: whoami_address,
        msg: to_binary(&transfer_msg)?,
        funds: vec![],
    };

    config.token_id = None;
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "withdraw_root_token")
        .add_message(wasm_msg))
}

pub fn execute_withdraw_payments(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let payment_details = PAYMENT_DETAILS.may_load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized {});
    }

    if payment_details.is_none() {
        return Err(ContractError::NoPaymentsToCollect {});
    }
    let payment_details = payment_details.unwrap();

    let payment_msg = match payment_details {
        PaymentDetails::Cw20 {
            token_address,
            amount: _,
        } => {
            let resp: BalanceResponse = deps.querier.query_wasm_smart(
                &token_address,
                &Cw20QueryMsg::Balance {
                    address: env.contract.address.to_string(),
                },
            )?;
            if resp.balance.is_zero() {
                return Err(ContractError::NoPaymentsToCollect {});
            }

            let send_msg = Cw20ExecuteMsg::Transfer {
                recipient: config.admin.to_string(),
                amount: resp.balance,
            };

            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: token_address,
                msg: to_binary(&send_msg)?,
                funds: vec![],
            })
        }
        PaymentDetails::Native { denom, amount: _ } => {
            let balance = deps.querier.query_balance(env.contract.address, denom)?;
            if balance.amount.is_zero() {
                return Err(ContractError::NoPaymentsToCollect {});
            }

            CosmosMsg::Bank(BankMsg::Send {
                to_address: config.admin.to_string(),
                amount: vec![balance],
            })
        }
    };

    Ok(Response::new()
        .add_attribute("action", "withdraw_payments")
        .add_message(payment_msg))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&CONFIG.load(deps.storage)?),
        QueryMsg::PaymentDetails {} => to_binary(&PaymentDetailsResponse {
            payment_details: PAYMENT_DETAILS.may_load(deps.storage)?,
        }),
        QueryMsg::PaymentDetailsBalance {} => query_payment_details_balance(deps, env),
        QueryMsg::ClaimInfo { path } => query_claim_info(deps, env, path),
    }
}

pub fn query_payment_details_balance(deps: Deps, env: Env) -> StdResult<Binary> {
    let payment_details = PAYMENT_DETAILS.may_load(deps.storage)?;
    if let Some(payment_details) = payment_details {
        match payment_details.clone() {
            PaymentDetails::Cw20 { token_address, .. } => {
                let resp: BalanceResponse = deps.querier.query_wasm_smart(
                    &token_address,
                    &Cw20QueryMsg::Balance {
                        address: env.contract.address.to_string(),
                    },
                )?;
                to_binary(&PaymentDetailsBalanceResponse {
                    payment_details: Some(payment_details),
                    amount: resp.balance,
                })
            }
            PaymentDetails::Native { denom, .. } => {
                let balance = deps.querier.query_balance(env.contract.address, denom)?;
                to_binary(&PaymentDetailsBalanceResponse {
                    payment_details: Some(payment_details),
                    amount: balance.amount,
                })
            }
        }
    } else {
        to_binary(&PaymentDetailsBalanceResponse {
            payment_details: None,
            amount: Uint128::zero(),
        })
    }
}

pub fn query_claim_info(deps: Deps, env: Env, path: String) -> StdResult<Binary> {
    let config = CONFIG.load(deps.storage)?;
    let path_as_base_owner = get_dens_owner(&deps.querier, path, config.whoami_address.clone());

    to_binary(&ClaimInfoResponse {
        is_in_claim_window: is_in_claim_window(
            config.reserve_root_for_n_blocks,
            config.initial_height,
            env.block.height,
        ),
        path_as_base_owner,
    })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, env: Env, msg: MigrateMsg) -> Result<Response, ContractError> {
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, Eq)]
    pub struct ConfigV100 {
        pub whoami_address: String,
        pub admin: Addr,
        pub token_id: Option<String>,
    }

    const CONFIG_V100: Item<ConfigV100> = Item::new("config");
    let config_v100 = CONFIG_V100.load(deps.storage)?;

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let config = Config {
        admin: config_v100.admin,
        token_id: config_v100.token_id,
        whoami_address: config_v100.whoami_address,
        initial_height: env.block.height,
        reserve_root_names: msg.reserve_root_names,
        reserve_root_for_n_blocks: msg.reserve_root_for_n_blocks,
    };

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "migrate")
        .add_attribute(
            "reserve_root_for_n_blocks",
            config
                .reserve_root_for_n_blocks
                .unwrap_or_default()
                .to_string(),
        ))
}
