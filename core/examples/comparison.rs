use assert_matches::assert_matches;
use janus_core::test_util::run_vdaf;
use prio::{
    codec::Encode,
    field::Field64,
    flp::{gadgets::ParallelSumMultithreaded, types::SumVec},
    topology::ping_pong::{PingPongMessage, PingPongState},
    vdaf::{prio2::Prio2, prio3::Prio3, xof::XofHmacSha256Aes128, VdafError},
};
use rand::random;

const DIMENSION: usize = 100_000;
const CHUNK_LENGTH: usize = 393;
const NUM_AGGREGATORS: u8 = 2;
const NUM_PROOFS: u8 = 2;
const PRIO3_SUMVEC_FIELD64_MULTIPROOF_HMACSHA256AES128_ALGORITHM_ID: u32 = 0xFFFF1003;

fn main() -> Result<(), VdafError> {
    let prio3 = Prio3::<_, XofHmacSha256Aes128, 32>::new(
        NUM_AGGREGATORS,
        NUM_PROOFS,
        PRIO3_SUMVEC_FIELD64_MULTIPROOF_HMACSHA256AES128_ALGORITHM_ID,
        SumVec::<Field64, ParallelSumMultithreaded<_, _>>::new(1, DIMENSION, CHUNK_LENGTH)?,
    )?;
    let prio3_transcript = run_vdaf(&prio3, &random(), &(), &random(), &vec![0; DIMENSION]);

    let prio2 = Prio2::new(DIMENSION)?;
    let prio2_transcript = run_vdaf(&prio2, &random(), &(), &random(), &vec![0; DIMENSION]);

    println!("Parameter, Prio3SumVecField64MultiproofHmacSha256Aes128, Prio2");
    println!();

    println!(
        "Public share size, {}, 0",
        prio3_transcript.public_share.get_encoded().unwrap().len(),
    );

    println!(
        "Leader input share size, {}, {}",
        prio3_transcript
            .leader_input_share
            .get_encoded()
            .unwrap()
            .len(),
        prio2_transcript
            .leader_input_share
            .get_encoded()
            .unwrap()
            .len(),
    );

    println!(
        "Helper input share size, {}, {}",
        prio3_transcript
            .helper_input_share
            .get_encoded()
            .unwrap()
            .len(),
        prio2_transcript
            .helper_input_share
            .get_encoded()
            .unwrap()
            .len(),
    );

    println!();

    assert_eq!(prio3_transcript.leader_prepare_transitions.len(), 1);
    assert_eq!(prio2_transcript.leader_prepare_transitions.len(), 1);
    assert!(prio3_transcript.leader_prepare_transitions[0]
        .transition
        .is_none());
    assert!(prio2_transcript.leader_prepare_transitions[0]
        .transition
        .is_none());

    let prio3_leader_prepare_state = assert_matches!(
        &prio3_transcript.leader_prepare_transitions[0].state,
        PingPongState::Continued(state) => state
    );
    let prio2_leader_prepare_state = assert_matches!(
        &prio2_transcript.leader_prepare_transitions[0].state,
        PingPongState::Continued(state) => state
    );
    println!(
        "Leader prepare state size, {}, {}",
        prio3_leader_prepare_state.get_encoded().unwrap().len(),
        prio2_leader_prepare_state.get_encoded().unwrap().len(),
    );

    let prio3_leader_prepare_share = assert_matches!(
        &prio3_transcript.leader_prepare_transitions[0].message,
        PingPongMessage::Initialize { prep_share } => prep_share
    );
    let prio2_leader_prepare_share = assert_matches!(
        &prio2_transcript.leader_prepare_transitions[0].message,
        PingPongMessage::Initialize { prep_share } => prep_share
    );
    println!(
        "Leader prepare share size, {}, {}",
        prio3_leader_prepare_share.len(),
        prio2_leader_prepare_share.len(),
    );

    assert_eq!(prio3_transcript.helper_prepare_transitions.len(), 1);
    assert_eq!(prio2_transcript.helper_prepare_transitions.len(), 1);

    println!(
        "Helper ping pong transition size (prepare state plus prepare message), {}, {}",
        prio3_transcript.helper_prepare_transitions[0]
            .transition
            .get_encoded()
            .unwrap()
            .len(),
        prio2_transcript.helper_prepare_transitions[0]
            .transition
            .get_encoded()
            .unwrap()
            .len(),
    );

    assert_matches!(
        &prio3_transcript.helper_prepare_transitions[0].state,
        PingPongState::Finished(output_share) => assert_eq!(
            output_share.get_encoded().unwrap(),
            prio3_transcript.helper_output_share.get_encoded().unwrap(),
        )
    );
    assert_matches!(
        &prio2_transcript.helper_prepare_transitions[0].state,
        PingPongState::Finished(output_share) => assert_eq!(
            output_share.get_encoded().unwrap(),
            prio2_transcript.helper_output_share.get_encoded().unwrap(),
        )
    );

    let prio3_prepare_message = assert_matches!(
        &prio3_transcript.helper_prepare_transitions[0].message,
        PingPongMessage::Finish { prep_msg } => prep_msg
    );
    let prio2_prepare_message = assert_matches!(
        &prio2_transcript.helper_prepare_transitions[0].message,
        PingPongMessage::Finish { prep_msg } => prep_msg
    );
    println!(
        "Helper prepare message size, {}, {}",
        prio3_prepare_message.len(),
        prio2_prepare_message.len(),
    );

    println!();

    println!(
        "Leader output share size, {}, {}",
        prio3_transcript
            .leader_output_share
            .get_encoded()
            .unwrap()
            .len(),
        prio2_transcript
            .leader_output_share
            .get_encoded()
            .unwrap()
            .len(),
    );

    println!(
        "Helper output share size, {}, {}",
        prio3_transcript
            .helper_output_share
            .get_encoded()
            .unwrap()
            .len(),
        prio2_transcript
            .helper_output_share
            .get_encoded()
            .unwrap()
            .len(),
    );

    Ok(())
}
