//! Runs the node starts on its own: a wake-up, or the delegate being
//! installed or the node starting (see `node_glue`).
//!
//! # What each does, and why
//!
//! - **A `heartbeat` wake-up** (every five minutes, on a node with
//!   freenet-core#5747) signs a heartbeat for every armed store and sends it
//!   to the store's presence contract, so buyers see the store OPEN while
//!   this node is online, with no tab open. It also records when it ran,
//!   which is how the seller's tab learns this node wakes the delegate and
//!   need not heartbeat itself.
//! - **Installed and NodeStarted** (every node since v0.2.138 that the user
//!   granted background runs) re-subscribe every armed store's mailbox,
//!   store and chain tip, and read the tip. Contract notifications sent
//!   while the node was down are never replayed and a subscription need not
//!   survive a restart, so without this a node that restarted (an automatic
//!   update, say) answered no Buy now until the seller next opened Harvest.
//!   No heartbeat here: on a node without wake-ups the tab heartbeats, and on
//!   one with them the first wake-up comes within about a minute of start.
//!
//! - **A `heartbeat` wake-up** also keeps the next payment addresses
//!   watched: a run with no tab cannot reach the Ghost Key vault
//!   (freenet-core refuses delegate-to-delegate messages from background
//!   runs), so it signs its own watch requests with a watch key the seller's
//!   Ghost Key delegated to it once, while the tab was open
//!   (freenet-bitcoin#30). One inbox read per run; see `watch_delegation`.

use freenet_migrate::SecretStore;
use freenet_stdlib::prelude::{DelegateCtx, DelegateError, OutboundDelegateMsg};

use crate::node_glue::{BackgroundRun, HEARTBEAT_TAG};
use crate::secrets::CtxSecrets;

/// Run one background event against the delegate's secrets.
pub(crate) fn run(
    ctx: &mut DelegateCtx,
    run: BackgroundRun,
    now_ms: u64,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    Ok(on_background(&mut CtxSecrets(ctx), &run, now_ms))
}

pub(crate) fn on_background<S: SecretStore>(
    secrets: &mut S,
    run: &BackgroundRun,
    now_ms: u64,
) -> Vec<OutboundDelegateMsg> {
    match run {
        BackgroundRun::Wakeup { tag } if tag.as_slice() == HEARTBEAT_TAG => {
            // Not once this generation has handed on: it stays registered
            // and is still woken, and a write every five minutes for nothing
            // is waste.
            if secrets.has_secret(crate::auto_invoice::EXPORTED_KEY) {
                return Vec::new();
            }
            crate::auto_invoice::note_wakeup(secrets, now_ms);
            // The payment counter's catch-up goes on with no tab open
            // (#206), before the heartbeats say whether the store is taking
            // orders.
            crate::bitcoin::advance_on_wakeup(secrets);
            // One seller's order book swept (step 2): paid orders move on
            // from the unpaid stage, and unpaid ones past their payment
            // window go.
            crate::seller_orders::sweep(secrets);
            // The delegated watch's one read (the bridge inbox, or an
            // address contract) first in the list. Order in the list is not
            // order of execution: the node handles a run's GETs first, then
            // its UPDATEs, then its SUBSCRIBEs (freenet-core `contract.rs`),
            // and runs at most four operations per run that must reach the
            // network (`MAX_NETWORK_CONTRACT_OPS_PER_PARK`): a GET of a
            // contract it has never seen, the fetch an UPDATE to one it does
            // not hold sets off, or a SUBSCRIBE of an unseen one, all sharing
            // that budget and refused past it. The read's GET therefore goes
            // before the heartbeat UPDATEs' self-heal fetches can use the
            // budget up, and its SUBSCRIBE after them: a SUBSCRIBE refused
            // leaves the copy unsettled, which delays a verdict, never fakes
            // one.
            let mut out = crate::watch_delegation::on_wakeup(secrets, now_ms);
            out.extend(crate::auto_invoice::heartbeats(secrets, now_ms));
            // The mailbox re-reads last: after a refused update, or a run
            // that left messages for later (`auto_invoice::OPEN_BUDGET`),
            // one GET per store with requests waiting.
            out.extend(crate::auto_invoice::mailbox_retries(secrets, now_ms));
            out
        }
        // A tag this generation did not declare (a successor's, say): nothing.
        BackgroundRun::Wakeup { .. } => Vec::new(),
        BackgroundRun::Installed | BackgroundRun::NodeStarted => {
            // Subscriptions of an earlier run may be gone: none of the
            // delegated watch's counts as settled until renewed.
            crate::watch_delegation::on_node_started(secrets);
            crate::auto_invoice::resubscribe_all(secrets)
        }
    }
}
