//! A performance test fixture to reproduce issues with
//! `acquire_incomplete_aggregation_jobs()`.

use std::{
    any::Any,
    convert::Infallible,
    net::Ipv4Addr,
    panic::{resume_unwind, AssertUnwindSafe},
    process::Command,
    str::FromStr,
    sync::Arc,
    time::{Duration as StdDuration, Instant},
};

use anyhow::{Context as _, Result};
use chrono::NaiveDateTime;
use deadpool_postgres::{Manager, Pool};
use futures_util::{future::FutureExt, StreamExt};
use janus_aggregator::{
    aggregator::{
        self, aggregation_job_creator::AggregationJobCreator,
        aggregation_job_driver::AggregationJobDriver, http_handlers::aggregator_handler,
    },
    binary_utils::{job_driver::JobDriver, setup_server, setup_signal_handler},
    trace::{install_trace_subscriber, TokioConsoleConfiguration, TraceConfiguration},
};
use janus_aggregator_core::{
    datastore::{
        self,
        models::AggregationJobState,
        test_util::{ephemeral_datastore, EphemeralDatabase, EphemeralDatastore},
        Datastore,
    },
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
use tokio::time::{interval, interval_at};
use tokio_postgres::{Config, NoTls};
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
    let short_circuit_stopper = Stopper::new();
    let client_stopper = Stopper::new();
    let leader_stopper = Stopper::new();
    let helper_stopper = Stopper::new();
    setup_signal_handler(client_stopper.clone())
        .context("failed to register SIGTERM signal handler")?;

    // Set up databases.
    let leader_ephemeral_datastore = ephemeral_datastore().await;
    let leader_base_datastore = leader_ephemeral_datastore.datastore(clock).await;
    let helper_ephemeral_datastore = ephemeral_datastore().await;
    let helper_base_datastore = helper_ephemeral_datastore.datastore(clock).await;

    // Add application_name to connection strings.
    let leader_aggregator_datastore =
        datastore_with_application_name(&leader_ephemeral_datastore, clock, "leader-aggregator")
            .await;
    let leader_aggregation_job_creator_datastore = datastore_with_application_name(
        &leader_ephemeral_datastore,
        clock,
        "leader-aggregation_job_creator",
    )
    .await;
    let leader_aggregation_job_driver_datastore = Arc::new(
        datastore_with_application_name(
            &leader_ephemeral_datastore,
            clock,
            "leader-aggregation_job_driver",
        )
        .await,
    );
    let helper_aggregator_datastore =
        datastore_with_application_name(&helper_ephemeral_datastore, clock, "helper-aggregator")
            .await;

    // Run two aggregators in-process.
    let leader_aggregator_config = aggregator::Config {
        max_upload_batch_size: 100,
        max_upload_batch_write_delay: StdDuration::from_millis(300),
        batch_aggregation_shard_count: 32,
    };
    let leader_aggregator_handler = aggregator_handler(
        Arc::new(leader_aggregator_datastore),
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
        Arc::new(helper_aggregator_datastore),
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
    leader_base_datastore.put_task(&leader_task).await?;

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
    helper_base_datastore.put_task(&helper_task).await?;

    // Run the aggregation job creator.
    let aggregation_job_creator = Arc::new(AggregationJobCreator::new(
        leader_aggregation_job_creator_datastore,
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

    // Run several copies of the aggregation job driver.
    let aggregation_job_driver_join_handles = (0..10)
        .map(|_| {
            let aggregation_job_driver = Arc::new(AggregationJobDriver::new(
                reqwest::Client::new(),
                &NoopMeterProvider::new().meter("janus_aggregator"),
                32,
            ));
            let job_driver = Arc::new(JobDriver::new(
                clock,
                TokioRuntime,
                meter.clone(),
                StdDuration::from_secs(1),
                StdDuration::from_secs(1),
                10,
                StdDuration::from_secs(60),
                aggregation_job_driver.make_incomplete_job_acquirer_callback(
                    Arc::clone(&leader_aggregation_job_driver_datastore),
                    StdDuration::from_secs(600),
                ),
                aggregation_job_driver.make_job_stepper_callback(
                    Arc::clone(&leader_aggregation_job_driver_datastore),
                    10,
                ),
            ));
            tokio::spawn({
                let short_circuit_stopper = short_circuit_stopper.clone();
                let future =
                    AssertUnwindSafe(leader_stopper.stop_future(job_driver.run())).catch_unwind();
                async move {
                    let res: Result<Option<Infallible>, Box<dyn Any + Send + 'static>> =
                        future.await;
                    match res {
                        Ok(_option) => {}
                        Err(panic) => {
                            short_circuit_stopper.stop();
                            resume_unwind(panic);
                        }
                    }
                }
            })
        })
        .collect::<Vec<_>>();

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

    // Analyze the aggregation_jobs table periodically.
    let leader_db_pool = leader_ephemeral_datastore.pool();
    let analyze_join_handle = tokio::spawn({
        let stopper = leader_stopper.clone();
        let pool = leader_db_pool.clone();
        let mut interval = interval(StdDuration::from_secs(60));
        async move {
            let conn = pool.get().await?;
            while stopper.stop_future(interval.tick()).await.is_some() {
                conn.execute("ANALYZE aggregation_jobs", &[]).await?;
            }
            Ok::<_, datastore::Error>(())
        }
    });

    // Dump the lock manager and scan row locks periodically.
    let dump_locks_handle = tokio::spawn({
        let stopper = leader_stopper.clone();
        let pool = leader_db_pool.clone();
        let mut interval = interval(StdDuration::from_secs(20));
        AssertUnwindSafe(async move {
            let conn = pool.get().await?;
            conn.execute("CREATE EXTENSION pgrowlocks", &[]).await?;

            let lock_mgr_statement = conn
                .prepare_cached(
                    "SELECT
    locktype,
    relation::bigint AS relation_oid,
    relation::regclass::text AS relation_name,
    page IS NOT NULL AS is_page,
    tuple IS NOT NULL AS is_tuple,
    mode,
    granted,
    pg_stat_activity.backend_type,
    pg_stat_activity.application_name,
    pg_stat_activity.wait_event_type,
    pg_stat_activity.wait_event,
    pg_stat_activity.state,
    pg_stat_activity.query
FROM pg_locks
LEFT JOIN pg_stat_activity
ON pg_locks.pid = pg_stat_activity.pid
WHERE pg_locks.pid != pg_backend_pid();",
                )
                .await?;
            let lock_mgr_column_headings = [
                "locktype",
                "relation_oid",
                "relation_name",
                "page",
                "tuple",
                "mode",
                "granted",
                "backend_type",
                "application_name",
                "wait_event_type",
                "wait_event",
                "state",
                "query",
            ];

            let row_locks_1_statement = conn
                .prepare_cached(
                    "WITH row_locks AS (
    SELECT modes, pids
    FROM pgrowlocks('aggregation_jobs')
)
SELECT
    mode,
    pg_stat_activity.backend_type,
    pg_stat_activity.application_name,
    pg_stat_activity.wait_event_type,
    pg_stat_activity.wait_event,
    pg_stat_activity.state,
    pg_stat_activity.query
FROM row_locks, unnest(modes, pids) AS unnested_row_locks (mode, pid)
LEFT JOIN pg_stat_activity
ON unnested_row_locks.pid = pg_stat_activity.pid",
                )
                .await?;
            let row_locks_2_statement = conn
                .prepare_cached(
                    "WITH row_locks AS (
    SELECT modes, pids
    FROM pgrowlocks('tasks')
)
SELECT
    mode,
    pg_stat_activity.backend_type,
    pg_stat_activity.application_name,
    pg_stat_activity.wait_event_type,
    pg_stat_activity.wait_event,
    pg_stat_activity.state,
    pg_stat_activity.query
FROM row_locks, unnest(modes, pids) AS unnested_row_locks (mode, pid)
LEFT JOIN pg_stat_activity
ON unnested_row_locks.pid = pg_stat_activity.pid",
                )
                .await?;
            let row_locks_column_headings = [
                "mode",
                "backend_type",
                "application_name",
                "wait_event_type",
                "wait_event",
                "state",
                "query",
            ];

            while stopper.stop_future(interval.tick()).await.is_some() {
                let mut row_stream = Box::pin(conn.query_raw(&lock_mgr_statement, [""; 0]).await?);
                let mut column_widths = lock_mgr_column_headings
                    .iter()
                    .map(|heading| heading.len())
                    .collect::<Vec<usize>>();
                let mut table = Vec::new();
                let mut update_table = |row: [String; 13]| {
                    for (column_width, string) in column_widths.iter_mut().zip(row.iter()) {
                        if string.len() > *column_width {
                            *column_width = string.len();
                        }
                    }
                    table.push(row);
                };
                while let Some(row_res) = row_stream.next().await {
                    let row = row_res?;
                    update_table([
                        row.get::<_, &str>(0).to_owned(),
                        row.get::<_, Option<i64>>(1)
                            .as_ref()
                            .map_or_else(String::new, ToString::to_string),
                        row.get::<_, Option<&str>>(2)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, bool>(3).to_string(),
                        row.get::<_, bool>(4).to_string(),
                        row.get::<_, &str>(5).to_owned(),
                        row.get::<_, bool>(6).to_string(),
                        row.get::<_, Option<&str>>(7)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(8)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(9)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(10)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(11)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(12)
                            .map_or_else(String::new, |query| {
                                const QUERY_SIZE_LIMIT: usize = 30;
                                if query.chars().nth(QUERY_SIZE_LIMIT).is_some() {
                                    let mut abbreviated =
                                        String::with_capacity(QUERY_SIZE_LIMIT + 3);
                                    abbreviated.extend(query.chars().take(QUERY_SIZE_LIMIT).map(
                                        |char| {
                                            if char == '\n' {
                                                ' '
                                            } else {
                                                char
                                            }
                                        },
                                    ));
                                    abbreviated.push_str("...");
                                    abbreviated
                                } else {
                                    query.replace('\n', " ")
                                }
                            }),
                    ]);
                }
                println!("In-memory lock manager:");
                for (heading, width) in lock_mgr_column_headings.iter().zip(column_widths.iter()) {
                    print!("{0:1$} | ", heading, width);
                }
                println!();
                for row in table {
                    for (value, width) in row.iter().zip(column_widths.iter()) {
                        print!("{0:1$} | ", value, width);
                    }
                    println!();
                }
                println!();

                let mut row_stream =
                    Box::pin(conn.query_raw(&row_locks_1_statement, [""; 0]).await?);
                let mut column_widths = row_locks_column_headings
                    .iter()
                    .map(|heading| heading.len())
                    .collect::<Vec<usize>>();
                let mut table = Vec::new();
                let mut update_table = |row: [String; 7]| {
                    for (column_width, string) in column_widths.iter_mut().zip(row.iter()) {
                        if string.len() > *column_width {
                            *column_width = string.len();
                        }
                    }
                    table.push(row);
                };
                while let Some(row_res) = row_stream.next().await {
                    let row = row_res?;
                    update_table([
                        row.get::<_, &str>(0).to_owned(),
                        row.get::<_, Option<&str>>(1)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(2)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(3)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(4)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(5)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(6)
                            .map_or_else(String::new, |query| {
                                const QUERY_SIZE_LIMIT: usize = 30;
                                if query.chars().nth(QUERY_SIZE_LIMIT).is_some() {
                                    let mut abbreviated =
                                        String::with_capacity(QUERY_SIZE_LIMIT + 3);
                                    abbreviated.extend(query.chars().take(QUERY_SIZE_LIMIT).map(
                                        |char| {
                                            if char == '\n' {
                                                ' '
                                            } else {
                                                char
                                            }
                                        },
                                    ));
                                    abbreviated.push_str("...");
                                    abbreviated
                                } else {
                                    query.replace('\n', " ")
                                }
                            }),
                    ]);
                }
                println!("Row locks, aggregation_jobs");
                for (heading, width) in row_locks_column_headings.iter().zip(column_widths.iter()) {
                    print!("{0:1$} | ", heading, width);
                }
                println!();
                for row in table {
                    for (value, width) in row.iter().zip(column_widths.iter()) {
                        print!("{0:1$} | ", value, width);
                    }
                    println!();
                }
                println!();

                let mut row_stream =
                    Box::pin(conn.query_raw(&row_locks_2_statement, [""; 0]).await?);
                let mut column_widths = row_locks_column_headings
                    .iter()
                    .map(|heading| heading.len())
                    .collect::<Vec<usize>>();
                let mut table = Vec::new();
                let mut update_table = |row: [String; 7]| {
                    for (column_width, string) in column_widths.iter_mut().zip(row.iter()) {
                        if string.len() > *column_width {
                            *column_width = string.len();
                        }
                    }
                    table.push(row);
                };
                while let Some(row_res) = row_stream.next().await {
                    let row = row_res?;
                    update_table([
                        row.get::<_, &str>(0).to_owned(),
                        row.get::<_, Option<&str>>(1)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(2)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(3)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(4)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(5)
                            .map_or_else(String::new, ToOwned::to_owned),
                        row.get::<_, Option<&str>>(6)
                            .map_or_else(String::new, |query| {
                                const QUERY_SIZE_LIMIT: usize = 30;
                                if query.chars().nth(QUERY_SIZE_LIMIT).is_some() {
                                    let mut abbreviated =
                                        String::with_capacity(QUERY_SIZE_LIMIT + 3);
                                    abbreviated.extend(query.chars().take(QUERY_SIZE_LIMIT).map(
                                        |char| {
                                            if char == '\n' {
                                                ' '
                                            } else {
                                                char
                                            }
                                        },
                                    ));
                                    abbreviated.push_str("...");
                                    abbreviated
                                } else {
                                    query.replace('\n', " ")
                                }
                            }),
                    ]);
                }
                println!("Row locks, tasks");
                for (heading, width) in row_locks_column_headings.iter().zip(column_widths.iter()) {
                    print!("{0:1$} | ", heading, width);
                }
                println!();
                for row in table {
                    for (value, width) in row.iter().zip(column_widths.iter()) {
                        print!("{0:1$} | ", value, width);
                    }
                    println!();
                }
                println!();
            }
            Ok::<_, datastore::Error>(())
        })
        .catch_unwind()
        .map({
            let short_circuit_stopper = short_circuit_stopper.clone();
            move |res| match res {
                Err(reason) => {
                    short_circuit_stopper.stop();
                    resume_unwind(reason);
                }
                Ok(res @ Err(_)) => {
                    short_circuit_stopper.stop();
                    res
                }
                Ok(Ok(())) => Ok(()),
            }
        })
    });

    // Let uploads and aggregations run for a while.
    short_circuit_stopper
        .stop_future(tokio::time::sleep(StdDuration::from_secs(60 * 5)))
        .await;

    // Save database logs.
    let ephemeral_database = EphemeralDatabase::shared().await;
    Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "docker logs {} > postgres_stdout.log 2> postgres_stderr.log",
            ephemeral_database.container_id()
        ))
        .status()?;

    // Perform a graceful shutdown. Stop the clients first, before we stop the leader, because
    // otherwise their upload futures may get sidetracked into HTTP retry loops.
    client_stopper.stop();
    info!("waiting for client tasks to finish");
    for join_handle in client_upload_join_handles {
        join_handle.await?;
    }

    leader_stopper.stop();
    analyze_join_handle.await??;
    dump_locks_handle.await??;
    info!("waiting for aggregation job creator task to finish");
    aggregation_job_creator_join_handle.await?;
    info!("waiting for aggregation job driver tasks to finish");
    for handle in aggregation_job_driver_join_handles {
        handle.await?;
    }
    info!("waiting for leader aggregator server to finish");
    leader_aggregator_server.await;

    helper_stopper.stop();
    info!("waiting for helper aggregator server to finish");
    helper_aggregator_server.await;

    // Inspect database.
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

    let now = clock.now().as_naive_date_time()?;
    let row = tx
        .query_one(
            "SELECT COUNT(*) FROM aggregation_jobs
            JOIN tasks ON tasks.id = aggregation_jobs.task_id
            WHERE tasks.aggregator_role = 'LEADER'
            AND aggregation_jobs.state = 'IN_PROGRESS'
            AND aggregation_jobs.lease_expiry <= $1",
            &[&now],
        )
        .await?;
    println!(
        "{} aggregation jobs are eligible for acquisition",
        row.get::<_, i64>(0)
    );

    let rows = tx
        .query(
            "EXPLAIN
            WITH incomplete_jobs AS (
                SELECT aggregation_jobs.id FROM aggregation_jobs
                JOIN tasks on tasks.id = aggregation_jobs.task_id
                WHERE tasks.aggregator_role = 'LEADER'
                AND aggregation_jobs.state = 'IN_PROGRESS'
                AND aggregation_jobs.lease_expiry <= $2
                FOR UPDATE OF aggregation_jobs SKIP LOCKED LIMIT $3
            )
            UPDATE aggregation_jobs SET
                lease_expiry = $1,
                lease_token = gen_random_bytes(16),
                lease_attempts = lease_attempts + 1
            FROM tasks
            WHERE tasks.id = aggregation_jobs.task_id
            AND aggregation_jobs.id IN (SELECT id FROM incomplete_jobs)
            RETURNING tasks.task_id, tasks.query_type, tasks.vdaf,
                      aggregation_jobs.aggregation_job_id, aggregation_jobs.lease_token,
                      aggregation_jobs.lease_attempts",
            &[
                &add_naive_date_time_duration(&now, &StdDuration::from_secs(600))?,
                &now,
                &10i64,
            ],
        )
        .await?;
    println!("Query plan (EXPLAIN)");
    for row in rows {
        println!("{}", row.get::<_, &str>(0));
    }

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

/// Add a [`std::time::Duration`] to a [`chrono::NaiveDateTime`].
fn add_naive_date_time_duration(
    time: &NaiveDateTime,
    duration: &StdDuration,
) -> Result<NaiveDateTime, datastore::Error> {
    time.checked_add_signed(chrono::Duration::from_std(*duration).map_err(|_| {
        datastore::Error::TimeOverflow("overflow converting duration to signed duration")
    })?)
    .ok_or(datastore::Error::TimeOverflow(
        "overflow adding duration to time",
    ))
}

/// Produce a [`Datastore`] from an [`EphemeralDatastore`] with `application_name` set in the
/// connection string.
async fn datastore_with_application_name<C>(
    ephemeral_datastore: &EphemeralDatastore,
    clock: C,
    application_name: &str,
) -> Datastore<C>
where
    C: Clock,
{
    Datastore::new(
        Pool::builder(Manager::new(
            Config::from_str(&format!(
                "{}?application_name={application_name}",
                ephemeral_datastore.connection_string()
            ))
            .unwrap(),
            NoTls,
        ))
        .build()
        .unwrap(),
        ephemeral_datastore.crypter(),
        clock,
    )
    .await
    .unwrap()
}
