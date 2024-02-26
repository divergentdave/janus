use std::{sync::Arc, time::Duration};

use janus_aggregator::aggregator::aggregation_job_creator::AggregationJobCreator;
use janus_aggregator_core::{
    datastore::{models::LeaderStoredReport, test_util::ephemeral_datastore},
    task::{test_util::TaskBuilder, QueryType},
    test_util::noop_meter,
};
use janus_core::{
    hpke::{self, generate_hpke_config_and_private_key, HpkeApplicationInfo, Label},
    time::{Clock, RealClock},
    vdaf::{new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128, VdafInstance},
};
use janus_messages::{
    HpkeAeadId, HpkeKdfId, HpkeKemId, InputShareAad, PlaintextInputShare, ReportId, ReportMetadata,
    Role,
};
use prio::{
    codec::Encode,
    field::Field64,
    flp::{
        gadgets::{Mul, ParallelSum},
        types::SumVec,
    },
    vdaf::{prio3::Prio3, xof::XofHmacSha256Aes128, Client},
};
use rand::random;
use tracing::info;
use tracing_log::LogTracer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Layer, Registry};

type Prio3SumVecField64MultiproofHmacSha256Aes128 =
    Prio3<SumVec<Field64, ParallelSum<Field64, Mul<Field64>>>, XofHmacSha256Aes128, 32>;

#[tokio::main]
async fn main() {
    let filter = EnvFilter::builder().from_env().unwrap();
    let layer = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .pretty()
        .with_filter(filter);
    let subscriber = Registry::default().with(layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();
    LogTracer::init().unwrap();

    // Task parameters
    let query_type = QueryType::FixedSize {
        max_batch_size: Some(1000),
        batch_time_window_size: None,
    };
    let vdaf_instance = VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
        proofs: 2,
        bits: 1,
        length: 100_000,
        chunk_length: 393,
    };
    let task = TaskBuilder::new(query_type, vdaf_instance)
        .with_min_batch_size(100)
        .build();
    let aggregator_task = task.view_for_role(Role::Leader).unwrap();
    let helper_keypair = generate_hpke_config_and_private_key(
        0.into(),
        HpkeKemId::X25519HkdfSha256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes128Gcm,
    )
    .unwrap();
    let vdaf = Arc::new(
        new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128(2, 1, 100_000, 393).unwrap(),
    );

    // Set up common utilities.
    let clock = RealClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = ephemeral_datastore.datastore(clock).await;
    let meter = noop_meter();

    // Provision the task.
    datastore
        .put_aggregator_task(&aggregator_task)
        .await
        .expect("task provisioning failed");

    // Store some reports.
    let measurement = vec![0; 100_000];
    for i in 0..50 {
        info!(i, "sharding report");
        let report_id: ReportId = random();
        let report_metadata = ReportMetadata::new(report_id, clock.now());
        let (public_share, input_shares) = vdaf.shard(&measurement, report_id.as_ref()).unwrap();
        let application_info =
            HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper);
        let plaintext_input_share =
            PlaintextInputShare::new(Vec::new(), input_shares[1].get_encoded().unwrap());
        let aad = InputShareAad::new(
            *task.id(),
            report_metadata.clone(),
            public_share.get_encoded().unwrap(),
        )
        .get_encoded()
        .unwrap();
        let helper_encrypted_input_share = hpke::seal(
            helper_keypair.config(),
            &application_info,
            &plaintext_input_share.get_encoded().unwrap(),
            &aad,
        )
        .unwrap();
        let report = Arc::new(LeaderStoredReport::<
            32,
            Prio3SumVecField64MultiproofHmacSha256Aes128,
        >::new(
            *task.id(),
            report_metadata,
            public_share,
            Vec::new(),
            input_shares[0].clone(),
            helper_encrypted_input_share,
        ));

        info!(i, "storing report");
        datastore
            .run_tx("harness_populate_report", |tx| {
                let vdaf = Arc::clone(&vdaf);
                let report = Arc::clone(&report);
                {
                    Box::pin(async move { tx.put_client_report(vdaf.as_ref(), &report).await })
                }
            })
            .await
            .unwrap();
    }
    drop(measurement);

    // Run the component once.
    let datastore = ephemeral_datastore.datastore(clock).await;
    let aggregation_job_creator = Arc::new(AggregationJobCreator::new(
        datastore,
        meter,
        Duration::from_secs(3600),
        Duration::from_secs(60),
        10,
        10,
        50,
    ));
    info!("running aggregation job creator");
    aggregation_job_creator
        .create_aggregation_jobs_for_task(Arc::new(aggregator_task))
        .await
        .unwrap();
    info!("done");
}
