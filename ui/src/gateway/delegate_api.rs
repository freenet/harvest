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

/// Arm the Harvest delegate to answer instant-checkout requests for one store
/// (`crate::auto_invoice_flow`).
pub async fn arm_auto_invoice(arm: harvest_common::delegate::AutoInvoiceArm) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let delegate_key = super::APP_STATE
            .read()
            .harvest_delegate_key
            .clone()
            .ok_or("harvest delegate not yet registered")?;
        let payload =
            harvest_common::to_cbor(&harvest_common::HarvestDelegateRequest::ArmAutoInvoice {
                arm: Box::new(arm),
            })
            .map_err(|e| format!("serialize ArmAutoInvoice: {e}"))?;
        send_delegate_message(&delegate_key, payload).await
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = arm;
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

/// Delegate registrations the node has not answered yet (harvest#162,
/// harvest#163).
///
/// The node answers `RegisterDelegate` with an empty `DelegateResponse` only
/// once the delegate is stored and its module compiled, and it runs each
/// client request as its own task, so a message sent to the delegate before
/// that answer can overtake the registration and be refused as
/// `DelegateError::Missing`. That error carries no request id, so nothing
/// retries the message: on the first load after a delegate re-key, the
/// migration walk stopped ("current delegate unavailable") and a request the
/// page waits on (the payment key) never got an answer. So what is sent to a
/// delegate waits for this answer; see [`registered`].
#[derive(Default)]
pub struct RegistrationWaiters {
    waiting: std::collections::HashMap<DelegateKey, futures::channel::oneshot::Sender<()>>,
    receivers: std::collections::HashMap<DelegateKey, futures::channel::oneshot::Receiver<()>>,
}

impl RegistrationWaiters {
    /// A registration of `key` is about to be sent.
    pub fn expect(&mut self, key: DelegateKey) {
        let (tx, rx) = futures::channel::oneshot::channel();
        self.waiting.insert(key.clone(), tx);
        self.receivers.insert(key, rx);
    }

    /// An empty answer from `key` arrived. `true` if it was the answer to a
    /// registration of it, which nothing else may then act on; any later empty
    /// answer is left to its usual reader (the migration walk's "not
    /// registered", `delegate_migrate_ops::offer_empty`).
    pub fn acknowledge(&mut self, key: &DelegateKey) -> bool {
        match self.waiting.remove(key) {
            Some(tx) => {
                let _ = tx.send(());
                true
            }
            None => false,
        }
    }

    /// What to wait on for `key`'s registration, once.
    pub fn take(&mut self, key: &DelegateKey) -> Option<futures::channel::oneshot::Receiver<()>> {
        self.receivers.remove(key)
    }
}

thread_local! {
    static REGISTRATIONS: std::cell::RefCell<RegistrationWaiters> =
        std::cell::RefCell::default();
}

/// Called by the response handler for every empty delegate answer: see
/// [`RegistrationWaiters::acknowledge`].
pub fn acknowledge_registration(key: &DelegateKey) -> bool {
    REGISTRATIONS.with(|r| r.borrow_mut().acknowledge(key))
}

/// How long [`registered`] waits for the node's answer before going ahead
/// anyway, as it did before this wait existed.
pub const REGISTRATION_WAIT_MS: u32 = 30_000;

/// Wait until the node has answered the registration of `key`, or
/// [`REGISTRATION_WAIT_MS`]. `false` on the timeout. Needs the response loop
/// running, so it is awaited from a spawned task, never before the loop.
#[cfg(target_arch = "wasm32")]
pub async fn registered(key: &DelegateKey) -> bool {
    let Some(rx) = REGISTRATIONS.with(|r| r.borrow_mut().take(key)) else {
        return true;
    };
    let timeout = gloo_timers::future::TimeoutFuture::new(REGISTRATION_WAIT_MS);
    futures::pin_mut!(timeout);
    matches!(
        futures::future::select(rx, timeout).await,
        futures::future::Either::Left((Ok(()), _))
    )
}

/// Register a delegate with the Freenet node. What is sent to it afterwards
/// waits for [`registered`].
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
        // Before the send: the answer can arrive as soon as it returns.
        REGISTRATIONS.with(|r| r.borrow_mut().expect(key.clone()));

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

#[cfg(test)]
mod registration_tests {
    use super::*;

    fn key(byte: u8) -> DelegateKey {
        DelegateKey::new([byte; 32], CodeHash::new([byte; 32]))
    }

    /// The first empty answer from a delegate being registered is the
    /// registration's, and releases whatever waits on it; one from any other
    /// delegate, or a second one, is left to its usual reader (harvest#162).
    #[test]
    fn the_first_empty_answer_acknowledges_the_registration() {
        let mut waiters = RegistrationWaiters::default();
        waiters.expect(key(1));
        let mut rx = waiters.take(&key(1)).expect("something to wait on");
        assert!(!waiters.acknowledge(&key(2)));
        assert_eq!(rx.try_recv(), Ok(None), "not yet");
        assert!(waiters.acknowledge(&key(1)));
        assert_eq!(rx.try_recv(), Ok(Some(())));
        assert!(
            !waiters.acknowledge(&key(1)),
            "a later one is not the registration's"
        );
        assert!(waiters.take(&key(1)).is_none(), "waited on once");
    }

    /// Nothing is sent to either delegate, and neither key is published to
    /// the rest of the app, before the node has answered its registration;
    /// the migration walk starts only after the Harvest delegate's (harvest#162,
    /// harvest#163). Pinned by source: the connect flow is wasm-only.
    #[test]
    fn the_app_waits_for_each_registration_before_using_the_delegate() {
        let src = include_str!("../components/app.rs");
        let harvest = &src[src.find("register_delegate(harvest_wasm)").unwrap()..];
        let harvest = &harvest[..harvest.find("register_delegate(gk_wasm)").unwrap()];
        let waited = harvest
            .find("delegate_registered(&key).await")
            .expect("waits");
        let published = harvest
            .find("harvest_delegate_key = Some(key)")
            .expect("key set");
        let first_send = harvest
            .find("recall_conversations_for_known_stores")
            .unwrap();
        let walk = harvest
            .find("delegate_migrate_ops::start()")
            .expect("walk started");
        assert!(waited < published && published < first_send && first_send < walk);

        let ghostkey = &src[src.find("register_delegate(gk_wasm)").unwrap()..];
        let waited = ghostkey
            .find("delegate_registered(&key).await")
            .expect("waits");
        let published = ghostkey.find("ghostkey_delegate_key =").expect("key set");
        let first_send = ghostkey.find("send_delegate_message(").unwrap();
        assert!(waited < published && published < first_send);
        assert_eq!(src.matches("delegate_migrate_ops::start()").count(), 1);

        // And the answer reaches the waiters, before the walk's reader of
        // empty answers can take it.
        let handler = include_str!("response_handler.rs");
        let handler = &handler[handler.find("fn handle_delegate_response(").unwrap()..];
        let ack = handler
            .find("values.is_empty() && super::delegate_api::acknowledge_registration(&key)")
            .expect("acknowledged");
        let empty = handler.find("offer_empty(&key)").expect("walk's reader");
        assert!(ack < empty);
    }
}
