//! A performance test fixture to reproduce issues with
//! `acquire_incomplete_aggregation_jobs()`.

use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration as StdDuration, Instant},
};

use anyhow::{Context as _, Result};
use janus_aggregator::{
    aggregator::{
        self, aggregation_job_creator::AggregationJobCreator,
        aggregation_job_driver::AggregationJobDriver, http_handlers::aggregator_handler,
    },
    binary_utils::{job_driver::JobDriver, setup_server, setup_signal_handler},
    trace::{install_trace_subscriber, TokioConsoleConfiguration, TraceConfiguration},
};
use janus_aggregator_core::{
    datastore::{models::AggregationJobState, test_util::ephemeral_datastore},
    task::{QueryType, Task},
    SecretBytes,
};
use janus_client::{Client, ClientParameters};
use janus_core::{
    hpke::generate_hpke_config_and_private_key,
    task::VdafInstance,
    time::{Clock, RealClock, TimeExt},
    TokioRuntime,
};
use janus_messages::{Duration, Role};
use opentelemetry::{
    metrics::{noop::NoopMeterProvider, MeterProvider},
    sdk::{
        export::metrics::{aggregation::Histogram, InstrumentationLibraryReader},
        metrics::aggregators::HistogramAggregator,
    },
    Context,
};
use prio::vdaf::prio3::Prio3;
use rand::{distributions::Standard, random, thread_rng, Rng};
use tokio::time::interval_at;
use tracing::{error, info};
use trillium::Headers;
use trillium_tokio::Stopper;

#[tokio::main]
async fn main() -> Result<()> {
    let logging_config = TraceConfiguration {
        use_test_writer: false,
        force_json_output: true,
        stackdriver_json_output: false,
        tokio_console_config: TokioConsoleConfiguration {
            enabled: false,
            listen_address: None,
        },
        open_telemetry_config: None,
        chrome: false,
    };

    // Install tracing subscriber.
    let _guards =
        install_trace_subscriber(&logging_config).context("couldn't install tracing subscriber")?;

    info!("Starting up");

    // Common utilities
    let clock = RealClock::default();
    let client_stopper = Stopper::new();
    let leader_stopper = Stopper::new();
    let helper_stopper = Stopper::new();
    setup_signal_handler(client_stopper.clone())
        .context("failed to register SIGTERM signal handler")?;

    // Set up databases.
    let leader_ephemeral_datastore = ephemeral_datastore().await;
    let leader_datastore = Arc::new(leader_ephemeral_datastore.datastore(clock).await);
    let helper_ephemeral_datastore = ephemeral_datastore().await;
    let helper_datastore = Arc::new(helper_ephemeral_datastore.datastore(clock).await);

    // Disable autovacuum on various tables.
    let leader_db_pool = leader_ephemeral_datastore.pool();
    let conn = leader_db_pool.get().await?;
    conn.execute(
        "ALTER TABLE client_reports SET (autovacuum_enabled = false)",
        &[],
    )
    .await?;
    conn.execute(
        "ALTER TABLE report_aggregations SET (autovacuum_enabled = false)",
        &[],
    )
    .await?;
    conn.execute(
        "ALTER TABLE aggregation_jobs SET (autovacuum_enabled = false)",
        &[],
    )
    .await?;
    drop(conn);
    drop(leader_db_pool);

    // Run two aggregators in-process.
    let leader_aggregator_config = aggregator::Config {
        max_upload_batch_size: 100,
        max_upload_batch_write_delay: StdDuration::from_millis(300),
        batch_aggregation_shard_count: 32,
    };
    let leader_aggregator_handler = aggregator_handler(
        Arc::clone(&leader_datastore),
        clock,
        leader_aggregator_config,
    )?;
    let (leader_aggregator_bound_address, leader_aggregator_server) = setup_server(
        (Ipv4Addr::LOCALHOST, 0).into(),
        Headers::new(),
        leader_stopper.clone(),
        leader_aggregator_handler,
    )
    .await
    .context("failed to create aggregator server")?;
    let helper_aggregator_config = aggregator::Config {
        max_upload_batch_size: 100,
        max_upload_batch_write_delay: StdDuration::from_millis(300),
        batch_aggregation_shard_count: 32,
    };
    let helper_aggregator_handler = aggregator_handler(
        Arc::clone(&helper_datastore),
        clock,
        helper_aggregator_config,
    )?;
    let (helper_aggregator_bound_address, helper_aggregator_server) = setup_server(
        (Ipv4Addr::LOCALHOST, 0).into(),
        Headers::new(),
        helper_stopper.clone(),
        helper_aggregator_handler,
    )
    .await
    .context("failed to create aggregator server")?;

    // Generate task parameters.
    let buckets = (0..16382).collect::<Vec<_>>();
    let vdaf = Prio3::new_histogram(2, &buckets)?;
    let vdaf_instance = VdafInstance::Prio3Histogram {
        buckets: buckets.clone(),
    };
    let task_id = random();
    let query_type = QueryType::TimeInterval;
    let vdaf_verify_keys = Vec::from([SecretBytes::new(
        thread_rng()
            .sample_iter(Standard)
            .take(vdaf_instance.verify_key_length())
            .collect(),
    )]);
    let aggregator_endpoints = Vec::from([
        format!("http://{leader_aggregator_bound_address}/")
            .parse()
            .unwrap(),
        format!("http://{helper_aggregator_bound_address}/")
            .parse()
            .unwrap(),
    ]);
    let collector_keypair = generate_hpke_config_and_private_key(
        0.into(),
        janus_messages::HpkeKemId::X25519HkdfSha256,
        janus_messages::HpkeKdfId::HkdfSha256,
        janus_messages::HpkeAeadId::Aes128Gcm,
    );
    let aggregator_auth_tokens = Vec::from([random()]);
    let time_precision = Duration::from_seconds(300);

    // Store the task in the leader's database.
    let leader_hpke_keypair = generate_hpke_config_and_private_key(
        0.into(),
        janus_messages::HpkeKemId::X25519HkdfSha256,
        janus_messages::HpkeKdfId::HkdfSha256,
        janus_messages::HpkeAeadId::Aes128Gcm,
    );
    let leader_task = Task::new(
        task_id,
        aggregator_endpoints.clone(),
        query_type,
        vdaf_instance.clone(),
        Role::Leader,
        vdaf_verify_keys.clone(),
        1,
        None,
        None,
        10,
        time_precision,
        Duration::from_seconds(60),
        collector_keypair.config().clone(),
        aggregator_auth_tokens.clone(),
        Vec::from([random()]),
        [leader_hpke_keypair.clone()],
    )?;
    leader_datastore.put_task(&leader_task).await?;

    // Store the task in the helper's database.
    let helper_hpke_keypair = generate_hpke_config_and_private_key(
        0.into(),
        janus_messages::HpkeKemId::X25519HkdfSha256,
        janus_messages::HpkeKdfId::HkdfSha256,
        janus_messages::HpkeAeadId::Aes128Gcm,
    );
    let helper_task = Task::new(
        task_id,
        aggregator_endpoints.clone(),
        query_type,
        vdaf_instance,
        Role::Helper,
        vdaf_verify_keys,
        1,
        None,
        None,
        10,
        time_precision,
        Duration::from_seconds(60),
        collector_keypair.config().clone(),
        aggregator_auth_tokens,
        Vec::new(),
        [helper_hpke_keypair.clone()],
    )?;
    helper_datastore.put_task(&helper_task).await?;

    // Run the aggregation job creator.
    let aggregation_job_creator = Arc::new(AggregationJobCreator::new(
        leader_ephemeral_datastore.datastore(clock).await,
        StdDuration::from_secs(3600),
        StdDuration::from_secs(60),
        10,
        10,
    ));
    let aggregation_job_creator_join_handle =
        tokio::spawn(leader_stopper.stop_future(aggregation_job_creator.run()));

    // Set up minimal metrics handling.
    let controller = opentelemetry::sdk::metrics::controllers::basic(
        opentelemetry::sdk::metrics::processors::factory(
            opentelemetry::sdk::metrics::selectors::simple::histogram([
                1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0,
            ]),
            opentelemetry::sdk::export::metrics::aggregation::stateless_temporality_selector(),
        ),
    )
    .build();
    let meter = controller.meter("test");

    // Run the aggregation job driver.
    let aggregation_job_driver = Arc::new(AggregationJobDriver::new(
        reqwest::Client::new(),
        &NoopMeterProvider::new().meter("janus_aggregator"),
        32,
    ));
    let job_driver = Arc::new(JobDriver::new(
        clock,
        TokioRuntime,
        meter,
        StdDuration::from_secs(1),
        StdDuration::from_secs(1),
        10,
        StdDuration::from_secs(60),
        aggregation_job_driver.make_incomplete_job_acquirer_callback(
            Arc::clone(&leader_datastore),
            StdDuration::from_secs(600),
        ),
        aggregation_job_driver.make_job_stepper_callback(Arc::clone(&leader_datastore), 10),
    ));
    let aggregation_job_driver_join_handle =
        tokio::spawn(leader_stopper.stop_future(job_driver.run()));

    // Set up client.
    let client_parameters = ClientParameters::new(task_id, aggregator_endpoints, time_precision);
    let client = Arc::new(Client::new(
        client_parameters,
        vdaf,
        clock,
        &janus_client::default_http_client()?,
        leader_hpke_keypair.config().clone(),
        helper_hpke_keypair.config().clone(),
    ));

    // Spawn many client tasks to wait for ticks from offset intervals, and send reports to the
    // leader.
    const PARALLELISM: u32 = 10;
    const OVERALL_UPLOAD_PERIOD: StdDuration = StdDuration::from_millis(100); // Rate is 10 reports per second
    let mut client_upload_join_handles = Vec::new();
    let start = Instant::now();
    for i in 0..PARALLELISM {
        let mut interval = interval_at(
            (start + OVERALL_UPLOAD_PERIOD * i).into(),
            OVERALL_UPLOAD_PERIOD * PARALLELISM,
        );
        client_upload_join_handles.push(tokio::spawn({
            let stopper = client_stopper.clone();
            let client = Arc::clone(&client);
            async move {
                while stopper.stop_future(interval.tick()).await.is_some() {
                    if let Err(error) = client.upload(&0).await {
                        error!(%error, "Error uploading report");
                    }
                }
            }
        }));
    }
    drop(client);

    // Let uploads and aggregations run for a while.
    tokio::time::sleep(StdDuration::from_secs(300)).await;

    // Perform a graceful shutdown. Stop the clients first, before we stop the leader, because
    // otherwise their upload futures may get sidetracked into HTTP retry loops.
    client_stopper.stop();
    info!("waiting for client tasks to finish");
    for join_handle in client_upload_join_handles {
        join_handle.await?;
    }

    leader_stopper.stop();
    info!("waiting for aggregation job creator task to finish");
    aggregation_job_creator_join_handle.await?;
    info!("waiting for aggregation job driver task to finish");
    aggregation_job_driver_join_handle.await?;
    info!("waiting for leader aggregator server to finish");
    leader_aggregator_server.await;

    helper_stopper.stop();
    info!("waiting for helper aggregator server to finish");
    helper_aggregator_server.await;

    // Inspect database.
    let leader_db_pool = leader_ephemeral_datastore.pool();
    let mut conn = leader_db_pool.get().await?;
    let tx = conn
        .build_transaction()
        .read_only(true)
        .deferrable(true)
        .start()
        .await?;

    let row = tx
        .query_one("SELECT COUNT(*) FROM client_reports", &[])
        .await?;
    println!("{} total reports", row.get::<_, i64>(0));

    let rows = tx
        .query(
            "SELECT state, COUNT(*) FROM aggregation_jobs GROUP BY state",
            &[],
        )
        .await?;
    for row in rows {
        let state: AggregationJobState = row.get(0);
        let count: i64 = row.get(1);
        println!("{} aggregation jobs with state {:?}", count, state);
    }

    let row = tx
        .query_one(
            "SELECT COUNT(*) FROM aggregation_jobs
            JOIN tasks ON tasks.id = aggregation_jobs.task_id
            WHERE tasks.aggregator_role = 'LEADER'
            AND aggregation_jobs.state = 'IN_PROGRESS'
            AND aggregation_jobs.lease_expiry <= $1",
            &[&clock.now().as_naive_date_time()?],
        )
        .await?;
    println!(
        "{} aggregation jobs are eligible for acquisition",
        row.get::<_, i64>(0)
    );

    drop(tx);
    drop(conn);
    drop(leader_db_pool);

    // Inspect metrics.
    controller.collect(&Context::current())?;
    controller.try_for_each(&mut |_, reader| {
        reader.try_for_each(
            &opentelemetry::sdk::export::metrics::aggregation::cumulative_temporality_selector(),
            &mut |record| {
                if record.descriptor().name() != "janus_job_acquire_jobs" {
                    return Ok(());
                }
                if let Some(aggregator) = record.aggregator() {
                    if let Some(histogram_aggregator) =
                        aggregator.as_any().downcast_ref::<HistogramAggregator>()
                    {
                        let buckets = histogram_aggregator.histogram()?;
                        println!(
                            "Boundaries: {:?} (note that bucket intervals are closed on the left, \
                             and open on the right)",
                            buckets.boundaries()
                        );
                        println!("Counts: {:?}", buckets.counts());
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    })?;

    Ok(())
}
