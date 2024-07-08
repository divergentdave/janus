//! Binary target that runs the main logic of each aggregator component once, for use as a harness
//! in profiling setups. The client, leader, and helper subcommands need to be run a few times in
//! turn to complete a full aggregation and collection. Communication happens via the filesystem,
//! as request and response bodies are written to disk and read by subsequent runs. Note that we
//! have to use a time interval query, because fixed size tasks would assign random batch IDs on
//! each run, making reuse of requests and responses impractical.

use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    process::{self, exit},
    sync::Arc,
    time::Duration,
};

use janus_aggregator::{
    aggregator::{
        aggregation_job_creator::AggregationJobCreator,
        aggregation_job_driver::AggregationJobDriver,
        collection_job_driver::{CollectionJobDriver, RetryStrategy},
        http_handlers::{aggregator_handler, test_util::take_response_body},
        Config,
    },
    config::TaskprovConfig,
};
use janus_aggregator_core::{
    datastore::test_util::ephemeral_datastore, task::AggregatorTask, test_util::noop_meter,
};
use janus_core::{
    hpke::{self, HpkeApplicationInfo},
    retries::test_util::test_http_request_exponential_backoff,
    time::{Clock, MockClock},
    vdaf::new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128,
    TokioRuntime,
};
use janus_messages::{
    AggregationJobId, CollectionJobId, CollectionReq, InputShareAad, Interval, PlaintextInputShare,
    Query, Report, ReportId, ReportMetadata, Role, Time,
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
use serde_json::Value;
use tracing::info;
use tracing_log::LogTracer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Layer, Registry};
use trillium::KnownHeaderName;
use trillium_testing::{
    assert_status,
    methods::{post, put},
};

type Prio3SumVecField64MultiproofHmacSha256Aes128 =
    Prio3<SumVec<Field64, ParallelSum<Field64, Mul<Field64>>>, XofHmacSha256Aes128, 32>;

const REPORT_TIME: Time = Time::from_seconds_since_epoch(1_720_000_000);
const BATCH_INTERVAL_START: Time = Time::from_seconds_since_epoch(1719993600);
const BATCH_INTERVAL_DURATION: janus_messages::Duration =
    janus_messages::Duration::from_seconds(28800);
const REPORT_COUNT: usize = 250;
const BATCH_AGGREGATION_SHARD_COUNT: u64 = 32;

const REPORTS_FILENAME: &str = "reports.bin";
const AGGREGATION_JOB_REQUEST_FILENAME: &str = "aggregation_job_request.bin";
const AGGREGATION_JOB_RESPONSE_FILENAME: &str = "aggregation_job_response.bin";
const AGGREGATE_SHARE_REQUEST_FILENAME: &str = "aggregate_share_request.bin";
const AGGREGATE_SHARE_RESPONSE_FILENAME: &str = "aggregate_share_response.bin";

#[tokio::main]
async fn main() {
    initialize_tracing();

    let mut args = std::env::args();
    let Some(argv0) = args.next() else {
        eprintln!("Usage: profiler_harness {{client,leader,helper}}");
        exit(1);
    };
    match args.next().as_deref() {
        Some("client") => run_client(),
        Some("leader") => run_leader().await,
        Some("helper") => run_helper().await,

        Some(_) | None => eprintln!("Usage: {argv0} {{client,leader,helper}}"),
    }
}

fn initialize_tracing() {
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
}

#[test]
fn generate_task() {
    use janus_aggregator_core::task::{test_util::TaskBuilder, QueryType};
    use janus_core::vdaf::VdafInstance;

    const QUERY_TYPE: QueryType = QueryType::TimeInterval;
    const VDAF_INSTANCE: VdafInstance =
        VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
            proofs: 2,
            bits: 1,
            length: 100_000,
            chunk_length: 393,
        };

    let task = TaskBuilder::new(QUERY_TYPE, VDAF_INSTANCE)
        .with_min_batch_size(REPORT_COUNT as u64)
        .build();
    println!(
        "{}",
        serde_json::to_string_pretty(&task.leader_view().unwrap()).unwrap()
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&task.helper_view().unwrap()).unwrap()
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&task.collector_auth_token()).unwrap()
    );
    println!("{:?}", task.collector_auth_token().request_authentication());
}

fn leader_task(peer_aggregator_endpoint: String) -> AggregatorTask {
    let mut value = serde_json::from_str::<Value>(
        r#"{
    "task_id": "MzbUlnh4ZTed66p-de0ZgW3_OKklnm1sMV-hetvtOYs",
    "peer_aggregator_endpoint": "https://helper.endpoint/",
    "query_type": "TimeInterval",
    "vdaf": {
        "Prio3SumVecField64MultiproofHmacSha256Aes128": {
            "proofs": 2,
            "bits": 1,
            "length": 100000,
            "chunk_length": 393
        }
    },
    "role": "Leader",
    "vdaf_verify_key": "2EocnV0nFUnsOovOML9cvJlJ_X4_5zf6QoDJk7lUFPc",
    "max_batch_query_count": 1,
    "task_expiration": null,
    "report_expiry_age": null,
    "min_batch_size": 250,
    "time_precision": 28800,
    "tolerable_clock_skew": 600,
    "collector_hpke_config": {
        "id": 116,
        "kem_id": "X25519HkdfSha256",
        "kdf_id": "HkdfSha256",
        "aead_id": "Aes128Gcm",
        "public_key": "2CGqBRbxW-wgn__TsLsw02uRVbWzWVttlM1VUoUmnQM"
    },
    "aggregator_auth_token": {
        "type": "Bearer",
        "token": "aCNBccoKCK5q3b5nP4JKPA"
    },
    "aggregator_auth_token_hash": null,
    "collector_auth_token_hash": {
        "type": "Bearer",
        "hash": "3R4lL3OsRIloIEUnG-oLBbj3X2KivU4OWYSqF2qXPoM"
    },
    "hpke_keys": [
        {
            "config": {
                "id": 210,
                "kem_id": "X25519HkdfSha256",
                "kdf_id": "HkdfSha256",
                "aead_id": "Aes128Gcm",
                "public_key": "JSaFrjEamqFXKHyG-nIfMOsny-w49-n2vXsyAD2D2V0"
            },
            "private_key": "aCDVMWdUT8Jag6db58KhMiYNzzBEyfD-pNJTlYOSNcU"
        },
        {
            "config": {
                "id": 1,
                "kem_id": "X25519HkdfSha256",
                "kdf_id": "HkdfSha256",
                "aead_id": "Aes128Gcm",
                "public_key": "I7gTgKTWVJdpzUUGDB-H-lXS4N7XV_y_P4yLyEduFXE"
            },
            "private_key": "ue0S9gEQOhLpIa09qYD1TsZM97_Et4_VGAhznbBfrmU"
        }
    ]
}"#,
    )
    .unwrap();
    value.as_object_mut().unwrap()["peer_aggregator_endpoint"] =
        Value::String(peer_aggregator_endpoint);
    serde_json::from_value(value).unwrap()
}

fn helper_task(peer_aggregator_endpoint: String) -> AggregatorTask {
    let mut value = serde_json::from_str::<Value>(
        r#"{
    "task_id": "MzbUlnh4ZTed66p-de0ZgW3_OKklnm1sMV-hetvtOYs",
    "peer_aggregator_endpoint": "https://leader.endpoint/",
    "query_type": "TimeInterval",
    "vdaf": {
        "Prio3SumVecField64MultiproofHmacSha256Aes128": {
            "proofs": 2,
            "bits": 1,
            "length": 100000,
            "chunk_length": 393
        }
    },
    "role": "Helper",
    "vdaf_verify_key": "2EocnV0nFUnsOovOML9cvJlJ_X4_5zf6QoDJk7lUFPc",
    "max_batch_query_count": 1,
    "task_expiration": null,
    "report_expiry_age": null,
    "min_batch_size": 250,
    "time_precision": 28800,
    "tolerable_clock_skew": 600,
    "collector_hpke_config": {
        "id": 116,
        "kem_id": "X25519HkdfSha256",
        "kdf_id": "HkdfSha256",
        "aead_id": "Aes128Gcm",
        "public_key": "2CGqBRbxW-wgn__TsLsw02uRVbWzWVttlM1VUoUmnQM"
    },
    "aggregator_auth_token": null,
    "aggregator_auth_token_hash": {
        "type": "Bearer",
        "hash": "29dsca0FwzTHZjLnmlTk3oOPZWPnVW4UIJ1qyI0YcVE"
    },
    "collector_auth_token_hash": null,
    "hpke_keys": [
        {
            "config": {
                "id": 214,
                "kem_id": "X25519HkdfSha256",
                "kdf_id": "HkdfSha256",
                "aead_id": "Aes128Gcm",
                "public_key": "eWyC5TcJb0kfXidMpbn5UzJ8A8Mq96LNslPpkCqh7hk"
            },
            "private_key": "1JSDBNPhKP97121fH8Pp5xAlq2IdKr6eS5HwPWUjXww"
        },
        {
            "config": {
                "id": 1,
                "kem_id": "X25519HkdfSha256",
                "kdf_id": "HkdfSha256",
                "aead_id": "Aes128Gcm",
                "public_key": "C_ONhiWIwHJ68fi9oO1kHvQssF0RerhjHKNELCGzhgQ"
            },
            "private_key": "RjpeEnn7NwVNg2I8fQ7DJ2x-IcehwhtQ85vAcUfi5hU"
        }
    ]
}"#,
    )
    .unwrap();
    value.as_object_mut().unwrap()["peer_aggregator_endpoint"] =
        Value::String(peer_aggregator_endpoint);
    serde_json::from_value(value).unwrap()
}

fn vdaf() -> Prio3SumVecField64MultiproofHmacSha256Aes128 {
    new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128(2, 1, 100_000, 393).unwrap()
}

fn clock() -> MockClock {
    MockClock::new(REPORT_TIME)
}

fn write_u64(mut write: impl Write, value: u64) -> io::Result<()> {
    write.write_all(&u64::to_be_bytes(value))
}

fn read_u64(mut read: impl Read) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    read.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

fn slurp(mut read: impl Read) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    read.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Shard reports, and save them in a file.
fn run_client() {
    let path = Path::new(REPORTS_FILENAME);
    if path.is_file() {
        println!("{REPORTS_FILENAME} already exists, exiting");
        return;
    }
    let mut file = OpenOptions::new().create_new(true).open(path).unwrap();

    let measurement = vec![0; 100_000];
    let vdaf = vdaf();

    let leader_task = leader_task("https://example.com/".to_string());
    let helper_task = helper_task("https://example.net/".to_string());
    let task_id = *leader_task.id();
    let leader_hpke_config = leader_task.hpke_keys().values().next().unwrap().config();
    let helper_hpke_config = helper_task.hpke_keys().values().next().unwrap().config();

    write_u64(&mut file, REPORT_COUNT.try_into().unwrap()).unwrap();

    for i in 0..REPORT_COUNT {
        info!(i, "sharding report");
        let report_id: ReportId = random();
        let report_metadata = ReportMetadata::new(report_id, clock().now());
        let (public_share, input_shares) = vdaf.shard(&measurement, report_id.as_ref()).unwrap();
        let leader_application_info = HpkeApplicationInfo::new(
            &janus_core::hpke::Label::InputShare,
            &Role::Client,
            &Role::Leader,
        );
        let leader_plaintext_input_share =
            PlaintextInputShare::new(Vec::new(), input_shares[0].get_encoded().unwrap());
        let aad = InputShareAad::new(
            task_id,
            report_metadata.clone(),
            public_share.get_encoded().unwrap(),
        )
        .get_encoded()
        .unwrap();
        let leader_encrypted_input_share = hpke::seal(
            leader_hpke_config,
            &leader_application_info,
            &leader_plaintext_input_share.get_encoded().unwrap(),
            &aad,
        )
        .unwrap();
        let helper_application_info = HpkeApplicationInfo::new(
            &janus_core::hpke::Label::InputShare,
            &Role::Client,
            &Role::Helper,
        );
        let helper_plaintext_input_share =
            PlaintextInputShare::new(Vec::new(), input_shares[1].get_encoded().unwrap());
        let helper_encrypted_input_share = hpke::seal(
            helper_hpke_config,
            &helper_application_info,
            &helper_plaintext_input_share.get_encoded().unwrap(),
            &aad,
        )
        .unwrap();
        let report = Report::new(
            report_metadata,
            public_share.get_encoded().unwrap(),
            leader_encrypted_input_share,
            helper_encrypted_input_share,
        );
        let encoded_report = report.get_encoded().unwrap();

        file.write_all(&u64::to_be_bytes(encoded_report.len().try_into().unwrap()))
            .unwrap();
        file.write_all(&encoded_report).unwrap();
    }
    file.sync_all().unwrap();
}

/// Load reports from a file, feed them to the upload endpoint, create an aggregation job, and drive
/// the aggregation job. Write the aggregation job request to a file, and load the aggregation job
/// response from another file (failing if it doesn't exist). Likewise, create and run a collection
/// job, using file fixtures for the aggregate share request and response.
async fn run_leader() {
    let clock = clock();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
    let meter = noop_meter();
    let config = Config {
        max_upload_batch_size: 1,
        max_upload_batch_write_delay: Duration::from_secs(0),
        batch_aggregation_shard_count: BATCH_AGGREGATION_SHARD_COUNT,
        task_counter_shard_count: 128,
        global_hpke_configs_refresh_interval: Duration::from_secs(3600),
        task_cache_ttl: Duration::from_secs(3600),
        task_cache_capacity: 1,
        hpke_config_signing_key: None,
        taskprov_config: TaskprovConfig {
            enabled: false,
            ignore_unknown_differential_privacy_mechanism: false,
        },
        log_forbidden_mutations: None,
    };
    let http_client = reqwest::Client::new();
    let mut server = mockito::Server::new_async().await;
    let aggregator_task = Arc::new(leader_task(server.url()));
    let task_id = aggregator_task.id();

    datastore
        .put_aggregator_task(&aggregator_task)
        .await
        .unwrap();

    let handler = aggregator_handler(
        Arc::clone(&datastore),
        clock.clone(),
        TokioRuntime,
        &meter,
        config,
    )
    .await
    .unwrap();

    let mut reports_file = File::open(REPORTS_FILENAME).unwrap();
    let report_count = read_u64(&mut reports_file).unwrap();
    for i in 0..report_count {
        let report_size = read_u64(&mut reports_file).unwrap();
        let mut buffer = vec![0u8; report_size.try_into().unwrap()];
        reports_file.read_exact(&mut buffer).unwrap();
        info!(i, "uploading report");
        let conn = put(format!("tasks/{task_id}/reports"))
            .with_request_header(KnownHeaderName::ContentType, "application/dap-report")
            .with_request_body(buffer)
            .run_async(&handler)
            .await;
        assert_status!(conn, 200);
    }

    let aggregation_job_creator = Arc::new(AggregationJobCreator::new(
        ephemeral_datastore.datastore(clock.clone()).await,
        meter.clone(),
        BATCH_AGGREGATION_SHARD_COUNT,
        Duration::from_secs(3600),
        Duration::from_secs(60),
        REPORT_COUNT,
        REPORT_COUNT,
        5000,
    ));
    info!("running aggregation job creator");
    aggregation_job_creator
        .create_aggregation_jobs_for_task(Arc::clone(&aggregator_task))
        .await
        .unwrap();

    let aggregation_job_driver = Arc::new(AggregationJobDriver::new(
        http_client.clone(),
        test_http_request_exponential_backoff(),
        &meter,
        BATCH_AGGREGATION_SHARD_COUNT,
    ));
    let agg_acquire_callback = aggregation_job_driver
        .make_incomplete_job_acquirer_callback(Arc::clone(&datastore), Duration::from_secs(120));
    let agg_leases = agg_acquire_callback(2).await.unwrap();
    assert_eq!(agg_leases.len(), 1);
    let aggregation_job_id = *agg_leases[0].leased().aggregation_job_id();

    let agg_mock = server
        .mock(
            "PUT",
            format!("/tasks/{task_id}/aggregation_jobs/{aggregation_job_id}").as_str(),
        )
        .expect(1)
        .with_body_from_request(|request| {
            let request_file_path = Path::new(AGGREGATION_JOB_REQUEST_FILENAME);
            if !request_file_path.is_file() {
                let mut request_file = OpenOptions::new()
                    .create_new(true)
                    .open(request_file_path)
                    .unwrap();
                request_file.write_all(request.body().unwrap()).unwrap();
            }
            let Ok(mut response_file) = File::open(AGGREGATION_JOB_RESPONSE_FILENAME) else {
                eprintln!("need aggregation job response file");
                process::exit(1);
            };
            slurp(&mut response_file).unwrap()
        })
        .create_async()
        .await;

    info!("running aggregation job driver");
    let agg_step_callback =
        aggregation_job_driver.make_job_stepper_callback(Arc::clone(&datastore), 1);
    agg_step_callback(agg_leases.into_iter().next().unwrap())
        .await
        .unwrap();

    agg_mock.assert_async().await;

    info!("sending collection request");
    let auth_header_name = "Authorization";
    let auth_header_value = "Bearer yGd7AMofDUFn1wKMDLIqxA";
    let collection_job_id: CollectionJobId = random();
    let collection_job_request = CollectionReq::new(
        Query::new_time_interval(
            Interval::new(BATCH_INTERVAL_START, BATCH_INTERVAL_DURATION).unwrap(),
        ),
        Vec::new(),
    );
    let conn = put(format!(
        "tasks/{task_id}/collection_jobs/{collection_job_id}"
    ))
    .with_request_header(KnownHeaderName::ContentType, "application/dap-collect-req")
    .with_request_header(auth_header_name, auth_header_value)
    .with_request_body(collection_job_request.get_encoded().unwrap())
    .run_async(&handler)
    .await;
    assert_status!(conn, 201);

    let collection_job_driver = Arc::new(CollectionJobDriver::new(
        http_client,
        test_http_request_exponential_backoff(),
        &meter,
        BATCH_AGGREGATION_SHARD_COUNT,
        RetryStrategy::new(Duration::from_secs(0), Duration::from_secs(0), 1.0).unwrap(),
    ));
    let collect_acquire_callback = collection_job_driver
        .make_incomplete_job_acquirer_callback(Arc::clone(&datastore), Duration::from_secs(120));
    let collect_leases = collect_acquire_callback(2).await.unwrap();
    assert_eq!(collect_leases.len(), 1);
    let collection_job_id = *collect_leases[0].leased().collection_job_id();

    let share_mock = server
        .mock(
            "POST",
            format!("/tasks/{task_id}/aggregate_shares").as_str(),
        )
        .expect(1)
        .with_body_from_request(|request| {
            let request_file_path = Path::new(AGGREGATE_SHARE_REQUEST_FILENAME);
            if !request_file_path.is_file() {
                let mut request_file = OpenOptions::new()
                    .create_new(true)
                    .open(request_file_path)
                    .unwrap();
                request_file.write_all(request.body().unwrap()).unwrap();
            }
            let Ok(mut response_file) = File::open(AGGREGATE_SHARE_RESPONSE_FILENAME) else {
                eprintln!("need aggregate share response file");
                process::exit(1);
            };
            slurp(&mut response_file).unwrap()
        })
        .create_async()
        .await;

    info!("running collection job driver");
    let collect_step_callback =
        collection_job_driver.make_job_stepper_callback(Arc::clone(&datastore), 1);
    collect_step_callback(collect_leases.into_iter().next().unwrap())
        .await
        .unwrap();

    share_mock.assert_async().await;

    info!("polling collection job");
    let conn = post(format!(
        "tasks/{task_id}/collection_jobs/{collection_job_id}"
    ))
    .with_request_header(KnownHeaderName::Accept, "application/dap-collection")
    .with_request_header(auth_header_name, auth_header_value)
    .run_async(&handler)
    .await;
    assert_status!(conn, 200);
}

/// Handle an aggregation job request loaded from a file, and write the response out to a file.
/// Likewise, handle an aggregate share request loaded from a file, and write the response out to a
/// file.
async fn run_helper() {
    let clock = clock();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
    let meter = noop_meter();
    let config = Config {
        max_upload_batch_size: 1,
        max_upload_batch_write_delay: Duration::from_secs(0),
        batch_aggregation_shard_count: BATCH_AGGREGATION_SHARD_COUNT,
        task_counter_shard_count: 128,
        global_hpke_configs_refresh_interval: Duration::from_secs(3600),
        task_cache_ttl: Duration::from_secs(3600),
        task_cache_capacity: 1,
        hpke_config_signing_key: None,
        taskprov_config: TaskprovConfig {
            enabled: false,
            ignore_unknown_differential_privacy_mechanism: false,
        },
        log_forbidden_mutations: None,
    };
    let leader_task = leader_task("https://example.com/".to_string());
    let helper_task = helper_task("https://example.net/".to_string());
    let task_id = helper_task.id();

    datastore.put_aggregator_task(&helper_task).await.unwrap();

    let handler = aggregator_handler(datastore, clock, TokioRuntime, &meter, config)
        .await
        .unwrap();

    info!("processing aggregation job request");
    let (auth_header_name, auth_header_value) = leader_task
        .aggregator_auth_token()
        .unwrap()
        .request_authentication();
    let aggregation_job_id: AggregationJobId = random();
    let aggregation_job_request = slurp(
        &mut File::open(AGGREGATION_JOB_REQUEST_FILENAME)
            .expect("need aggregation job request file"),
    )
    .unwrap();
    let mut conn = put(format!(
        "tasks/{task_id}/aggregation_jobs/{aggregation_job_id}"
    ))
    .with_request_header(
        KnownHeaderName::ContentType,
        "application/dap-aggregation-job-init-req",
    )
    .with_request_header(
        KnownHeaderName::Accept,
        "application/dap-aggregation-job-resp",
    )
    .with_request_header(auth_header_name, auth_header_value.clone())
    .with_request_body(aggregation_job_request)
    .run_async(&handler)
    .await;
    assert_status!(conn, 200);
    let aggregation_job_response = take_response_body(&mut conn).await;
    let aggregation_job_response_file_path = Path::new(AGGREGATION_JOB_RESPONSE_FILENAME);
    if !aggregation_job_response_file_path.is_file() {
        let mut response_file = OpenOptions::new()
            .create_new(true)
            .open(aggregation_job_response_file_path)
            .unwrap();
        response_file.write_all(&aggregation_job_response).unwrap();
    }

    info!("processing aggregate share request");
    let aggregate_share_request = slurp(
        &mut File::open(AGGREGATE_SHARE_REQUEST_FILENAME)
            .expect("need aggregate share request file"),
    )
    .unwrap();
    let mut conn = post(format!("tasks/{task_id}/aggregate_shares"))
        .with_request_header(
            KnownHeaderName::ContentType,
            "application/dap-aggregate-share-req",
        )
        .with_request_header(KnownHeaderName::Accept, "application/dap-aggregate-share")
        .with_request_header(auth_header_name, auth_header_value)
        .with_request_body(aggregate_share_request)
        .run_async(&handler)
        .await;
    assert_status!(conn, 200);
    let aggregate_share_response = take_response_body(&mut conn).await;
    let aggregate_share_response_file_path = Path::new(AGGREGATE_SHARE_RESPONSE_FILENAME);
    if !aggregate_share_response_file_path.is_file() {
        let mut response_file = OpenOptions::new()
            .create_new(true)
            .open(aggregate_share_response_file_path)
            .unwrap();
        response_file.write_all(&aggregate_share_response).unwrap();
    }
}
