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
//! What none of them can do is ask the Bitcoin bridge to watch new
//! addresses: that request is signed with the seller's Ghost Key, and a run
//! with no tab cannot reach the Ghost Key vault (freenet-core refuses
//! delegate-to-delegate messages from background runs). The watches the
//! delegate relies on are requested by the tab, for weeks at a time
//! (freenet-bitcoin#26); see `auto_invoice::global_refusal`.

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
            let mut out = crate::auto_invoice::heartbeats(secrets, now_ms);
            out.extend(crate::auto_invoice::mailbox_retries(secrets));
            out
        }
        // A tag this generation did not declare (a successor's, say): nothing.
        BackgroundRun::Wakeup { .. } => Vec::new(),
        BackgroundRun::Installed | BackgroundRun::NodeStarted => {
            crate::auto_invoice::resubscribe_all(secrets)
        }
    }
}
