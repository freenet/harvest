use super::*;

const IMAGE: &[u8] = include_bytes!("../../../harvest-image/tests/fixtures/chromium-canvas.jpg");
const OTHER: &[u8] = include_bytes!("../../../harvest-image/tests/fixtures/firefox-canvas.jpg");
const WEBP: &[u8] = include_bytes!("../../../harvest-image/tests/fixtures/chromium-canvas.webp");

fn params_for(bytes: &[u8]) -> Parameters<'static> {
    Parameters::from(harvest_image::image_hash(bytes).to_vec())
}

fn validate(params: Parameters<'static>, state: &[u8]) -> Result<ValidateResult, ContractError> {
    Contract::validate_state(params, State::from(state.to_vec()), RelatedContracts::new())
}

fn update(held: &[u8], data: Vec<UpdateData<'static>>) -> Result<Vec<u8>, ContractError> {
    Contract::update_state(params_for(IMAGE), State::from(held.to_vec()), data)
        .map(|m| m.unwrap_valid().as_ref().to_vec())
}

fn state(bytes: &[u8]) -> UpdateData<'static> {
    UpdateData::State(State::from(bytes.to_vec()))
}

fn delta(bytes: &[u8]) -> UpdateData<'static> {
    UpdateData::Delta(StateDelta::from(bytes.to_vec()))
}

#[test]
fn an_image_under_its_own_hash_is_valid() {
    assert!(matches!(
        validate(params_for(IMAGE), IMAGE),
        Ok(ValidateResult::Valid)
    ));
}

#[test]
fn the_empty_state_is_invalid_under_any_key() {
    assert!(validate(params_for(IMAGE), &[]).is_err());
    assert!(validate(params_for(&[]), &[]).is_err());
}

#[test]
fn another_image_under_this_key_is_invalid() {
    assert!(validate(params_for(IMAGE), OTHER).is_err());
}

#[test]
fn a_non_jpeg_under_its_own_hash_is_invalid() {
    assert!(validate(params_for(WEBP), WEBP).is_err());
}

#[test]
fn the_first_valid_copy_is_taken() {
    assert_eq!(update(&[], vec![state(IMAGE)]).unwrap(), IMAGE);
}

#[test]
fn an_identical_republish_is_accepted_and_changes_nothing() {
    assert_eq!(update(IMAGE, vec![state(IMAGE)]).unwrap(), IMAGE);
}

#[test]
fn an_empty_update_cannot_blank_a_held_image() {
    // The attack: every image's hash is public, in the signed listing.
    assert!(update(IMAGE, vec![state(&[])]).is_err());
}

#[test]
fn different_bytes_cannot_replace_a_held_image() {
    assert!(update(IMAGE, vec![state(OTHER)]).is_err());
    let mut tampered = IMAGE.to_vec();
    let last = tampered.len() - 3;
    tampered[last] ^= 1;
    assert!(update(IMAGE, vec![state(&tampered)]).is_err());
}

#[test]
fn an_invalid_update_to_an_empty_contract_is_refused() {
    assert!(update(&[], vec![state(OTHER)]).is_err());
    assert!(update(&[], vec![state(&[])]).is_err());
}

#[test]
fn an_empty_delta_changes_nothing() {
    assert_eq!(update(IMAGE, vec![delta(&[])]).unwrap(), IMAGE);
}

#[test]
fn a_delta_is_checked_as_a_whole_image() {
    assert_eq!(update(&[], vec![delta(IMAGE)]).unwrap(), IMAGE);
    assert!(update(&[], vec![delta(OTHER)]).is_err());
    assert!(update(IMAGE, vec![delta(OTHER)]).is_err());
    assert!(update(IMAGE, vec![delta(&IMAGE[..IMAGE.len() / 2])]).is_err());
}

#[test]
fn state_and_delta_is_checked_on_its_state() {
    let both = |s: &[u8]| UpdateData::StateAndDelta {
        state: State::from(s.to_vec()),
        delta: StateDelta::from(Vec::new()),
    };
    assert_eq!(update(&[], vec![both(IMAGE)]).unwrap(), IMAGE);
    assert!(update(IMAGE, vec![both(OTHER)]).is_err());
}

#[test]
fn related_contract_updates_change_nothing() {
    let related = || UpdateData::RelatedState {
        related_to: ContractInstanceId::new([7; 32]),
        state: State::from(OTHER.to_vec()),
    };
    assert_eq!(update(IMAGE, vec![related()]).unwrap(), IMAGE);
    // And cannot stand in for an image either.
    assert!(update(&[], vec![related()]).is_err());
}

#[test]
fn a_wrong_held_copy_is_repaired_by_the_image() {
    // Validation should make a wrong copy impossible to hold. If one is held
    // anyway, its summary differs, the peer is sent the image, and the image
    // must win, or the copy stays wrong for good.
    assert_eq!(update(OTHER, vec![state(IMAGE)]).unwrap(), IMAGE);
    assert_eq!(update(OTHER, vec![delta(IMAGE)]).unwrap(), IMAGE);
    assert_eq!(update(b"junk", vec![delta(IMAGE)]).unwrap(), IMAGE);
}

#[test]
fn an_update_never_returns_an_invalid_state() {
    // Nothing held and nothing new: no valid image to hand back.
    assert!(update(&[], vec![delta(&[])]).is_err());
    assert!(update(&[], vec![]).is_err());
}

#[test]
fn the_summary_is_the_hash_of_what_is_held() {
    let summary = |held: &[u8]| {
        Contract::summarize_state(params_for(IMAGE), State::from(held.to_vec()))
            .unwrap()
            .as_ref()
            .to_vec()
    };
    assert_eq!(summary(IMAGE), harvest_image::image_hash(IMAGE).to_vec());
    // Not the parameters: a copy holding anything else, even nothing, must
    // never look in sync with the real one.
    assert_ne!(summary(&[]), summary(IMAGE));
    assert_ne!(summary(OTHER), summary(IMAGE));
}

#[test]
fn a_peer_in_sync_is_sent_nothing_and_any_other_is_sent_the_image() {
    let delta_for = |summary: Vec<u8>| {
        Contract::get_state_delta(
            params_for(IMAGE),
            State::from(IMAGE.to_vec()),
            StateSummary::from(summary),
        )
        .unwrap()
        .as_ref()
        .to_vec()
    };
    assert!(delta_for(harvest_image::image_hash(IMAGE).to_vec()).is_empty());
    let sent = delta_for(harvest_image::image_hash(&[]).to_vec());
    assert_eq!(sent, IMAGE);
    // And what is sent repairs a peer holding nothing.
    assert_eq!(update(&[], vec![delta(&sent)]).unwrap(), IMAGE);
}
