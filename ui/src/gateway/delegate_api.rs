//! API for communicating with delegates and contracts via the Freenet gateway.
//!
//! All functions require an active WebSocket connection (WEB_API must be Some).
//! These are only usable in WASM builds -- native stubs return errors.

#[cfg(target_arch = "wasm32")]
use dioxus::logger::tracing::info;
#[cfg(target_arch = "wasm32")]
use dioxus::prelude::*;
#[cfg(target_arch = "wasm32")]
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, DelegateRequest};
use freenet_stdlib::prelude::*;

/// Send a request to a delegate (harvest or ghostkey).
pub async fn send_delegate_message(
    delegate_key: &DelegateKey,
    payload: Vec<u8>,
) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let request = ClientRequest::DelegateOp(DelegateRequest::ApplicationMessages {
            key: delegate_key.clone(),
            params: Parameters::from(harvest_common::delegate::DELEGATE_PARAMETERS),
            inbound: vec![InboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(payload),
            )],
        });

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("send delegate message: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (delegate_key, payload);
        Err("delegate messaging requires WASM".into())
    }
}

/// GET a contract's state, optionally subscribing to updates.
pub async fn get_contract(
    contract_key: &ContractInstanceId,
    subscribe: bool,
) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        info!("GET contract (subscribe={subscribe}): {:?}", contract_key);

        let request = ClientRequest::ContractOp(ContractRequest::Get {
            key: *contract_key,
            return_contract_code: false,
            subscribe,
            blocking_subscribe: false,
        });

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("get contract: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (contract_key, subscribe);
        Err("contract operations require WASM".into())
    }
}

/// GET-and-subscribe a contract by its raw 32-byte instance id.
///
/// Contract ids reach the UI as `Vec<u8>` -- from delegate registrations and
/// from other contracts' state -- so this is the one place that checks the
/// length before turning them into a `ContractInstanceId`.
pub async fn get_contract_by_id(contract_id: &[u8]) -> Result<(), String> {
    let id_bytes: [u8; 32] = contract_id
        .try_into()
        .map_err(|_| "contract id must be 32 bytes".to_string())?;
    get_contract(&ContractInstanceId::new(id_bytes), true).await
}

/// Put a contract update on the wire, with nothing in front of it.
///
/// Not for direct use: a node that does not yet hold the contract bounces
/// this with a retry request nothing can correlate (harvest#119). Every
/// caller goes through [`super::update_contract`], which waits for the node
/// to answer a GET for the contract first.
pub(super) async fn send_update(
    contract_key: &ContractKey,
    data: UpdateData<'static>,
) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let request = ClientRequest::ContractOp(ContractRequest::Update {
            key: *contract_key,
            data,
        });

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("update contract: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (contract_key, data);
        Err("contract operations require WASM".into())
    }
}

/// PUT a new contract onto the network and subscribe to it.
pub async fn put_contract(contract: ContractContainer, state: WrappedState) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let request = ClientRequest::ContractOp(ContractRequest::Put {
            contract,
            state,
            related_contracts: RelatedContracts::new(),
            subscribe: true,
            blocking_subscribe: false,
        });

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("put contract: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (contract, state);
        Err("contract operations require WASM".into())
    }
}

/// Register a delegate with the Freenet node.
pub async fn register_delegate(delegate_wasm: &[u8]) -> Result<DelegateKey, String> {
    #[cfg(target_arch = "wasm32")]
    {
        let delegate_code = DelegateCode::from(delegate_wasm.to_vec());
        // Half of the delegate's address, so it is named once
        // (`harvest_common::delegate::DELEGATE_PARAMETERS`) rather than spelled
        // out here and again at every other registration site. The address
        // guard reads the same constant, so a change to it shows up as a moved
        // delegate key instead of as nothing at all.
        let params = Parameters::from(harvest_common::delegate::DELEGATE_PARAMETERS);
        let delegate = Delegate::from((&delegate_code, &params));
        let container = DelegateContainer::Wasm(DelegateWasmAPIVersion::V1(delegate));
        let key = container.key().clone();

        // `DelegateRequest::DEFAULT_CIPHER` / `DEFAULT_NONCE` existed in
        // freenet-stdlib 0.6 and are gone in 0.8. Zeroes are the correct
        // replacement rather than a placeholder: since freenet-core#4140 the
        // node IGNORES the client-supplied cipher and nonce entirely and
        // derives a per-delegate key from its own KEK, so these bytes never
        // reach any cryptographic operation. ghostkeys does the same thing for
        // the same reason (`ui/src/api/delegate.rs`).
        let request = ClientRequest::DelegateOp(DelegateRequest::RegisterDelegate {
            delegate: container,
            cipher: [0u8; 32],
            nonce: [0u8; 24],
        });

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("register delegate: {e}"))?;

        info!("Registered delegate: {:?}", key);
        Ok(key)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = delegate_wasm;
        Err("delegate registration requires WASM".into())
    }
}
