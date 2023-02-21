//! Janus datastore (durable storage) implementation.

use self::models::{
    AcquiredAggregationJob, AcquiredCollectionJob, AggregateShareJob, AggregationJob,
    AggregatorRole, BatchAggregation, CollectionJob, CollectionJobState, CollectionJobStateCode,
    LeaderStoredReport, Lease, LeaseToken, OutstandingBatch, ReportAggregation,
    ReportAggregationState, ReportAggregationStateCode, SqlInterval,
};
#[cfg(test)]
use crate::aggregator::aggregation_job_creator::VdafHasAggregationParameter;
use crate::{
    aggregator::query_type::{AccumulableQueryType, CollectableQueryType},
    messages::TimeExt,
    task::{self, Task},
    SecretBytes,
};
use anyhow::anyhow;
use chrono::NaiveDateTime;
use futures::future::try_join_all;
use janus_core::{
    hpke::{HpkeKeypair, HpkePrivateKey},
    task::{AuthenticationToken, VdafInstance},
    time::Clock,
};
use janus_messages::{
    query_type::{QueryType, TimeInterval},
    AggregationJobId, BatchId, CollectionJobId, Duration, Extension, HpkeCiphertext, HpkeConfig,
    Interval, ReportId, ReportIdChecksum, ReportMetadata, ReportShare, Role, TaskId, Time,
};
use opentelemetry::{
    metrics::{Counter, Histogram},
    Context, KeyValue,
};
use postgres_types::{Json, ToSql};
use prio::{
    codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode, ParameterizedDecode},
    vdaf,
};
use rand::random;
use ring::aead::{self, LessSafeKey, AES_128_GCM};
use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt::Display,
    future::Future,
    io::Cursor,
    mem::size_of,
    ops::RangeInclusive,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration as StdDuration, Instant},
};
use tokio::try_join;
use tokio_postgres::{error::SqlState, row::RowIndex, IsolationLevel, Row, Statement, ToStatement};
use tracing::error;
use url::Url;

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util;

// TODO(#196): retry network-related & other transient failures once we know what they look like

/// Datastore represents a datastore for Janus, with support for transactional reads and writes.
/// In practice, Datastore instances are currently backed by a PostgreSQL database.
pub struct Datastore<C: Clock> {
    pool: deadpool_postgres::Pool,
    crypter: Crypter,
    clock: C,
    transaction_status_counter: Counter<u64>,
    rollback_error_counter: Counter<u64>,
    transaction_duration_histogram: Histogram<f64>,
}

impl<C: Clock> Datastore<C> {
    /// new creates a new Datastore using the given Client for backing storage. It is assumed that
    /// the Client is connected to a database with a compatible version of the Janus database schema.
    pub fn new(pool: deadpool_postgres::Pool, crypter: Crypter, clock: C) -> Datastore<C> {
        let meter = opentelemetry::global::meter("janus_aggregator");
        let transaction_status_counter = meter
            .u64_counter("janus_database_transactions_total")
            .with_description("Count of database transactions run, with their status.")
            .init();
        let rollback_error_counter = meter
            .u64_counter("janus_database_rollback_errors_total")
            .with_description(concat!(
                "Count of errors received when rolling back a database transaction, ",
                "with their PostgreSQL error code.",
            ))
            .init();
        let transaction_duration_histogram = meter
            .f64_histogram("janus_database_transaction_duration_seconds")
            .with_description("Duration of database transactions.")
            .init();

        Self {
            pool,
            crypter,
            clock,
            transaction_status_counter,
            rollback_error_counter,
            transaction_duration_histogram,
        }
    }

    /// run_tx runs a transaction, whose body is determined by the given function. The transaction
    /// is committed if the body returns a successful value, and rolled back if the body returns an
    /// error value.
    ///
    /// The datastore will automatically retry some failures (e.g. serialization failures) by
    /// rolling back & retrying with a new transaction, so the given function should support being
    /// called multiple times. Values read from the transaction should not be considered as
    /// "finalized" until the transaction is committed, i.e. after `run_tx` is run to completion.
    pub fn run_tx<'s, F, T>(&'s self, f: F) -> impl Future<Output = Result<T, Error>> + 's
    where
        F: 's,
        T: 's,
        for<'a> F:
            Fn(&'a Transaction<C>) -> Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>,
    {
        self.run_tx_with_name("default", f)
    }

    /// See [`Datastore::run_tx`]. This method additionally allows specifying a name for the
    /// transaction, for use in database-related metrics.
    pub async fn run_tx_with_name<F, T>(&self, name: &'static str, f: F) -> Result<T, Error>
    where
        for<'a> F:
            Fn(&'a Transaction<C>) -> Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>,
    {
        loop {
            let before = Instant::now();
            let (rslt, retry) = self.run_tx_once(&f).await;
            let elapsed = before.elapsed();
            self.transaction_duration_histogram.record(
                &Context::current(),
                elapsed.as_secs_f64(),
                &[KeyValue::new("tx", name)],
            );
            match (rslt.as_ref(), retry) {
                (_, true) => self.transaction_status_counter.add(
                    &Context::current(),
                    1,
                    &[KeyValue::new("status", "retry"), KeyValue::new("tx", name)],
                ),
                (Ok(_), _) => self.transaction_status_counter.add(
                    &Context::current(),
                    1,
                    &[
                        KeyValue::new("status", "success"),
                        KeyValue::new("tx", name),
                    ],
                ),
                (Err(Error::Db(_)), _) | (Err(Error::Pool(_)), _) => {
                    self.transaction_status_counter.add(
                        &Context::current(),
                        1,
                        &[
                            KeyValue::new("status", "error_db"),
                            KeyValue::new("tx", name),
                        ],
                    )
                }
                (Err(_), _) => self.transaction_status_counter.add(
                    &Context::current(),
                    1,
                    &[
                        KeyValue::new("status", "error_other"),
                        KeyValue::new("tx", name),
                    ],
                ),
            }
            if retry {
                continue;
            }
            return rslt;
        }
    }

    async fn run_tx_once<F, T>(&self, f: &F) -> (Result<T, Error>, bool)
    where
        for<'a> F:
            Fn(&'a Transaction<C>) -> Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>,
    {
        // Open transaction.
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(err) => return (Err(err.into()), false),
        };
        let raw_tx = match client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
        {
            Ok(raw_tx) => raw_tx,
            Err(err) => return (Err(err.into()), false),
        };
        let tx = Transaction {
            raw_tx,
            retry: AtomicBool::new(false),
            crypter: &self.crypter,
            clock: &self.clock,
        };

        // Run user-provided function with the transaction, then commit/rollback based on result.
        let rslt = f(&tx).await;
        let (raw_tx, retry) = (tx.raw_tx, tx.retry);
        let rslt = match (rslt, retry.load(Ordering::Acquire)) {
            // Commit.
            (Ok(val), false) => match check_error(&retry, raw_tx.commit().await) {
                Ok(()) => Ok(val),
                Err(err) => Err(err.into()),
            },

            // Rollback.
            (rslt, _) => {
                if let Err(rollback_err) = check_error(&retry, raw_tx.rollback().await) {
                    error!("Couldn't roll back transaction: {rollback_err}");
                    self.rollback_error_counter.add(
                        &Context::current(),
                        1,
                        &[KeyValue::new(
                            "code",
                            rollback_err
                                .code()
                                .map(SqlState::code)
                                .unwrap_or("N/A")
                                .to_string(),
                        )],
                    );
                };
                // We return `rslt` unconditionally here: it will either be an error, or we have the
                // retry flag set so that if `rslt` is a success we will be retrying the entire
                // transaction & the result of this attempt doesn't matter.
                rslt
            }
        };
        (rslt, retry.load(Ordering::Acquire))
    }

    /// Write a task into the datastore.
    #[cfg(feature = "test-util")]
    #[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
    pub async fn put_task(&self, task: &Task) -> Result<(), Error> {
        self.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move { tx.put_task(&task).await })
        })
        .await
    }
}

fn check_error<T>(
    retry: &AtomicBool,
    rslt: Result<T, tokio_postgres::Error>,
) -> Result<T, tokio_postgres::Error> {
    if let Err(err) = &rslt {
        if let Some(code) = err.code() {
            if code == &SqlState::T_R_SERIALIZATION_FAILURE
                || code == &SqlState::T_R_DEADLOCK_DETECTED
            {
                retry.store(true, Ordering::Release);
            }
        }
    }
    rslt
}

/// Transaction represents an ongoing datastore transaction.
pub struct Transaction<'a, C: Clock> {
    raw_tx: deadpool_postgres::Transaction<'a>,
    retry: AtomicBool,
    crypter: &'a Crypter,
    clock: &'a C,
}

impl<C: Clock> Transaction<'_, C> {
    fn check_error<T>(
        &self,
        rslt: Result<T, tokio_postgres::Error>,
    ) -> Result<T, tokio_postgres::Error> {
        check_error(&self.retry, rslt)
    }

    async fn execute<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, tokio_postgres::Error>
    where
        T: ?Sized + ToStatement,
    {
        self.check_error(self.raw_tx.execute(statement, params).await)
    }

    async fn prepare_cached(&self, query: &str) -> Result<Statement, tokio_postgres::Error> {
        self.check_error(self.raw_tx.prepare_cached(query).await)
    }

    async fn query<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, tokio_postgres::Error>
    where
        T: ?Sized + ToStatement,
    {
        self.check_error(self.raw_tx.query(statement, params).await)
    }

    async fn query_one<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, tokio_postgres::Error>
    where
        T: ?Sized + ToStatement,
    {
        self.check_error(self.raw_tx.query_one(statement, params).await)
    }

    async fn query_opt<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, tokio_postgres::Error>
    where
        T: ?Sized + ToStatement,
    {
        self.check_error(self.raw_tx.query_opt(statement, params).await)
    }

    /// Writes a task into the datastore.
    #[tracing::instrument(skip(self, task), fields(task_id = ?task.id()), err)]
    pub async fn put_task(&self, task: &Task) -> Result<(), Error> {
        let endpoints: Vec<_> = task
            .aggregator_endpoints()
            .iter()
            .map(Url::as_str)
            .collect();

        // Main task insert.
        let stmt = self
            .prepare_cached(
                "INSERT INTO tasks (
                    task_id, aggregator_role, aggregator_endpoints, query_type, vdaf,
                    max_batch_query_count, task_expiration, report_expiry_age, min_batch_size,
                    time_precision, tolerable_clock_skew, collector_hpke_config)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            )
            .await?;
        self.execute(
            &stmt,
            &[
                /* task_id */ &task.id().as_ref(),
                /* aggregator_role */ &AggregatorRole::from_role(*task.role())?,
                /* aggregator_endpoints */ &endpoints,
                /* query_type */ &Json(task.query_type()),
                /* vdaf */ &Json(task.vdaf()),
                /* max_batch_query_count */
                &i64::try_from(task.max_batch_query_count())?,
                /* task_expiration */ &task.task_expiration().as_naive_date_time()?,
                /* report_expiry_age */
                &task
                    .report_expiry_age()
                    .map(Duration::as_seconds)
                    .map(i64::try_from)
                    .transpose()?,
                /* min_batch_size */ &i64::try_from(task.min_batch_size())?,
                /* time_precision */
                &i64::try_from(task.time_precision().as_seconds())?,
                /* tolerable_clock_skew */
                &i64::try_from(task.tolerable_clock_skew().as_seconds())?,
                /* collector_hpke_config */ &task.collector_hpke_config().get_encoded(),
            ],
        )
        .await?;

        // Aggregator auth tokens.
        let mut aggregator_auth_token_ords = Vec::new();
        let mut aggregator_auth_tokens = Vec::new();
        for (ord, token) in task.aggregator_auth_tokens().iter().enumerate() {
            let ord = i64::try_from(ord)?;

            let mut row_id = [0; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task.id().as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            let encrypted_aggregator_auth_token = self.crypter.encrypt(
                "task_aggregator_auth_tokens",
                &row_id,
                "token",
                token.as_bytes(),
            )?;

            aggregator_auth_token_ords.push(ord);
            aggregator_auth_tokens.push(encrypted_aggregator_auth_token);
        }
        let stmt = self.prepare_cached(
                "INSERT INTO task_aggregator_auth_tokens (task_id, ord, token)
                SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::BIGINT[], $3::BYTEA[])"
            )
            .await?;
        let aggregator_auth_tokens_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id().as_ref(),
            /* ords */ &aggregator_auth_token_ords,
            /* tokens */ &aggregator_auth_tokens,
        ];
        let aggregator_auth_tokens_future = self.execute(&stmt, aggregator_auth_tokens_params);

        // Collector auth tokens.
        let mut collector_auth_token_ords = Vec::new();
        let mut collector_auth_tokens = Vec::new();
        for (ord, token) in task.collector_auth_tokens().iter().enumerate() {
            let ord = i64::try_from(ord)?;

            let mut row_id = [0; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task.id().as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            let encrypted_collector_auth_token = self.crypter.encrypt(
                "task_collector_auth_tokens",
                &row_id,
                "token",
                token.as_bytes(),
            )?;

            collector_auth_token_ords.push(ord);
            collector_auth_tokens.push(encrypted_collector_auth_token);
        }
        let stmt = self.prepare_cached(
            "INSERT INTO task_collector_auth_tokens (task_id, ord, token)
            SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::BIGINT[], $3::BYTEA[])"
        ).await?;
        let collector_auth_tokens_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id().as_ref(),
            /* ords */ &collector_auth_token_ords,
            /* tokens */ &collector_auth_tokens,
        ];
        let collector_auth_tokens_future = self.execute(&stmt, collector_auth_tokens_params);

        // HPKE keys.
        let mut hpke_config_ids: Vec<i16> = Vec::new();
        let mut hpke_configs: Vec<Vec<u8>> = Vec::new();
        let mut hpke_private_keys: Vec<Vec<u8>> = Vec::new();
        for hpke_keypair in task.hpke_keys().values() {
            let mut row_id = [0u8; TaskId::LEN + size_of::<u8>()];
            row_id[..TaskId::LEN].copy_from_slice(task.id().as_ref());
            row_id[TaskId::LEN..]
                .copy_from_slice(&u8::from(*hpke_keypair.config().id()).to_be_bytes());

            let encrypted_hpke_private_key = self.crypter.encrypt(
                "task_hpke_keys",
                &row_id,
                "private_key",
                hpke_keypair.private_key().as_ref(),
            )?;

            hpke_config_ids.push(u8::from(*hpke_keypair.config().id()) as i16);
            hpke_configs.push(hpke_keypair.config().get_encoded());
            hpke_private_keys.push(encrypted_hpke_private_key);
        }
        let stmt = self
            .prepare_cached(
                "INSERT INTO task_hpke_keys (task_id, config_id, config, private_key)
                SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::SMALLINT[], $3::BYTEA[], $4::BYTEA[])",
            )
            .await?;
        let hpke_configs_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id().as_ref(),
            /* config_id */ &hpke_config_ids,
            /* configs */ &hpke_configs,
            /* private_keys */ &hpke_private_keys,
        ];
        let hpke_configs_future = self.execute(&stmt, hpke_configs_params);

        // VDAF verification keys.
        let mut vdaf_verify_keys: Vec<Vec<u8>> = Vec::new();
        for vdaf_verify_key in task.vdaf_verify_keys() {
            let encrypted_vdaf_verify_key = self.crypter.encrypt(
                "task_vdaf_verify_keys",
                task.id().as_ref(),
                "vdaf_verify_key",
                vdaf_verify_key.as_ref(),
            )?;
            vdaf_verify_keys.push(encrypted_vdaf_verify_key);
        }
        let stmt = self
            .prepare_cached(
                "INSERT INTO task_vdaf_verify_keys (task_id, vdaf_verify_key)
                SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::BYTEA[])",
            )
            .await?;
        let vdaf_verify_keys_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id().as_ref(),
            /* vdaf_verify_keys */ &vdaf_verify_keys,
        ];
        let vdaf_verify_keys_future = self.execute(&stmt, vdaf_verify_keys_params);

        try_join!(
            aggregator_auth_tokens_future,
            collector_auth_tokens_future,
            hpke_configs_future,
            vdaf_verify_keys_future
        )?;

        Ok(())
    }

    /// Deletes a task from the datastore. Fails if there is any data related to the task, such as
    /// client reports, aggregations, etc.
    #[tracing::instrument(skip(self))]
    pub async fn delete_task(&self, task_id: &TaskId) -> Result<(), Error> {
        let params: &[&(dyn ToSql + Sync)] = &[&task_id.as_ref()];

        // Clean up dependent tables first.
        let stmt = self
            .prepare_cached(
                "DELETE FROM task_aggregator_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let task_aggregator_auth_tokens_future = self.execute(&stmt, params);

        let stmt = self
            .prepare_cached(
                "DELETE FROM task_collector_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let task_collector_auth_tokens_future = self.execute(&stmt, params);

        let stmt = self
            .prepare_cached(
                "DELETE FROM task_hpke_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let task_hpke_keys_future = self.execute(&stmt, params);

        let stmt = self
            .prepare_cached(
                "DELETE FROM task_vdaf_verify_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let task_vdaf_verify_keys_future = self.execute(&stmt, params);

        try_join!(
            task_aggregator_auth_tokens_future,
            task_collector_auth_tokens_future,
            task_hpke_keys_future,
            task_vdaf_verify_keys_future,
        )?;

        // Then clean up tasks table itself.
        let stmt = self
            .prepare_cached("DELETE FROM tasks WHERE task_id = $1")
            .await?;
        check_single_row_mutation(self.execute(&stmt, params).await?)?;
        Ok(())
    }

    /// Fetch the task parameters corresponing to the provided `task_id`.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_task(&self, task_id: &TaskId) -> Result<Option<Task>, Error> {
        let params: &[&(dyn ToSql + Sync)] = &[&task_id.as_ref()];
        let stmt = self
            .prepare_cached(
                "SELECT aggregator_role, aggregator_endpoints, query_type, vdaf,
                    max_batch_query_count, task_expiration, report_expiry_age, min_batch_size,
                    time_precision, tolerable_clock_skew, collector_hpke_config
                FROM tasks WHERE task_id = $1",
            )
            .await?;
        let task_row = self.query_opt(&stmt, params);

        let stmt = self
            .prepare_cached(
                "SELECT ord, token FROM task_aggregator_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1) ORDER BY ord ASC",
            )
            .await?;
        let aggregator_auth_token_rows = self.query(&stmt, params);

        let stmt = self
            .prepare_cached(
                "SELECT ord, token FROM task_collector_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1) ORDER BY ord ASC",
            )
            .await?;
        let collector_auth_token_rows = self.query(&stmt, params);

        let stmt = self
            .prepare_cached(
                "SELECT config_id, config, private_key FROM task_hpke_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let hpke_key_rows = self.query(&stmt, params);

        let stmt = self
            .prepare_cached(
                "SELECT vdaf_verify_key FROM task_vdaf_verify_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let vdaf_verify_key_rows = self.query(&stmt, params);

        let (
            task_row,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
            hpke_key_rows,
            vdaf_verify_key_rows,
        ) = try_join!(
            task_row,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
            hpke_key_rows,
            vdaf_verify_key_rows,
        )?;
        task_row
            .map(|task_row| {
                self.task_from_rows(
                    task_id,
                    &task_row,
                    &aggregator_auth_token_rows,
                    &collector_auth_token_rows,
                    &hpke_key_rows,
                    &vdaf_verify_key_rows,
                )
            })
            .transpose()
    }

    /// Fetch all the tasks in the database.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_tasks(&self) -> Result<Vec<Task>, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT task_id, aggregator_role, aggregator_endpoints, query_type, vdaf,
                    max_batch_query_count, task_expiration, report_expiry_age, min_batch_size,
                    time_precision, tolerable_clock_skew, collector_hpke_config
                FROM tasks",
            )
            .await?;
        let task_rows = self.query(&stmt, &[]);

        let stmt = self
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_aggregator_auth_tokens.task_id),
                ord, token FROM task_aggregator_auth_tokens ORDER BY ord ASC",
            )
            .await?;
        let aggregator_auth_token_rows = self.query(&stmt, &[]);

        let stmt = self
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_collector_auth_tokens.task_id),
                ord, token FROM task_collector_auth_tokens ORDER BY ord ASC",
            )
            .await?;
        let collector_auth_token_rows = self.query(&stmt, &[]);

        let stmt = self
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_hpke_keys.task_id),
                config_id, config, private_key FROM task_hpke_keys",
            )
            .await?;
        let hpke_config_rows = self.query(&stmt, &[]);

        let stmt = self.prepare_cached(
            "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_vdaf_verify_keys.task_id),
            vdaf_verify_key FROM task_vdaf_verify_keys"
        ).await?;
        let vdaf_verify_key_rows = self.query(&stmt, &[]);

        let (
            task_rows,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
            hpke_config_rows,
            vdaf_verify_key_rows,
        ) = try_join!(
            task_rows,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
            hpke_config_rows,
            vdaf_verify_key_rows
        )?;

        let mut task_row_by_id = Vec::new();
        for row in task_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            task_row_by_id.push((task_id, row));
        }

        let mut aggregator_auth_token_rows_by_task_id: HashMap<TaskId, Vec<Row>> = HashMap::new();
        for row in aggregator_auth_token_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            aggregator_auth_token_rows_by_task_id
                .entry(task_id)
                .or_default()
                .push(row);
        }

        let mut collector_auth_token_rows_by_task_id: HashMap<TaskId, Vec<Row>> = HashMap::new();
        for row in collector_auth_token_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            collector_auth_token_rows_by_task_id
                .entry(task_id)
                .or_default()
                .push(row);
        }

        let mut hpke_config_rows_by_task_id: HashMap<TaskId, Vec<Row>> = HashMap::new();
        for row in hpke_config_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            hpke_config_rows_by_task_id
                .entry(task_id)
                .or_default()
                .push(row);
        }

        let mut vdaf_verify_key_rows_by_task_id: HashMap<TaskId, Vec<Row>> = HashMap::new();
        for row in vdaf_verify_key_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            vdaf_verify_key_rows_by_task_id
                .entry(task_id)
                .or_default()
                .push(row);
        }

        task_row_by_id
            .into_iter()
            .map(|(task_id, row)| {
                self.task_from_rows(
                    &task_id,
                    &row,
                    &aggregator_auth_token_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                    &collector_auth_token_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                    &hpke_config_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                    &vdaf_verify_key_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                )
            })
            .collect::<Result<_, _>>()
    }

    /// Construct a [`Task`] from the contents of the provided (tasks) `Row`,
    /// `hpke_aggregator_auth_tokens` rows, and `task_hpke_keys` rows.
    ///
    /// agg_auth_token_rows must be sorted in ascending order by `ord`.
    fn task_from_rows(
        &self,
        task_id: &TaskId,
        row: &Row,
        aggregator_auth_token_rows: &[Row],
        collector_auth_token_rows: &[Row],
        hpke_key_rows: &[Row],
        vdaf_verify_key_rows: &[Row],
    ) -> Result<Task, Error> {
        // Scalar task parameters.
        let aggregator_role: AggregatorRole = row.get("aggregator_role");
        let endpoints = row
            .get::<_, Vec<String>>("aggregator_endpoints")
            .into_iter()
            .map(|endpoint| Ok(Url::parse(&endpoint)?))
            .collect::<Result<_, Error>>()?;
        let query_type = row.try_get::<_, Json<task::QueryType>>("query_type")?.0;
        let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
        let max_batch_query_count = row.get_bigint_and_convert("max_batch_query_count")?;
        let task_expiration = Time::from_naive_date_time(&row.get("task_expiration"));
        let report_expiry_age = row
            .get_nullable_bigint_and_convert("report_expiry_age")?
            .map(Duration::from_seconds);
        let min_batch_size = row.get_bigint_and_convert("min_batch_size")?;
        let time_precision = Duration::from_seconds(row.get_bigint_and_convert("time_precision")?);
        let tolerable_clock_skew =
            Duration::from_seconds(row.get_bigint_and_convert("tolerable_clock_skew")?);
        let collector_hpke_config = HpkeConfig::get_decoded(row.get("collector_hpke_config"))?;

        // Aggregator authentication tokens.
        let mut aggregator_auth_tokens = Vec::new();
        for row in aggregator_auth_token_rows {
            let ord: i64 = row.get("ord");
            let encrypted_aggregator_auth_token: Vec<u8> = row.get("token");

            let mut row_id = [0u8; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task_id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            aggregator_auth_tokens.push(AuthenticationToken::from(self.crypter.decrypt(
                "task_aggregator_auth_tokens",
                &row_id,
                "token",
                &encrypted_aggregator_auth_token,
            )?));
        }

        // Collector authentication tokens.
        let mut collector_auth_tokens = Vec::new();
        for row in collector_auth_token_rows {
            let ord: i64 = row.get("ord");
            let encrypted_collector_auth_token: Vec<u8> = row.get("token");

            let mut row_id = [0u8; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task_id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            collector_auth_tokens.push(AuthenticationToken::from(self.crypter.decrypt(
                "task_collector_auth_tokens",
                &row_id,
                "token",
                &encrypted_collector_auth_token,
            )?));
        }

        // HPKE keys.
        let mut hpke_keypairs = Vec::new();
        for row in hpke_key_rows {
            let config_id = u8::try_from(row.get::<_, i16>("config_id"))?;
            let config = HpkeConfig::get_decoded(row.get("config"))?;
            let encrypted_private_key: Vec<u8> = row.get("private_key");

            let mut row_id = [0u8; TaskId::LEN + size_of::<u8>()];
            row_id[..TaskId::LEN].copy_from_slice(task_id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&config_id.to_be_bytes());

            let private_key = HpkePrivateKey::new(self.crypter.decrypt(
                "task_hpke_keys",
                &row_id,
                "private_key",
                &encrypted_private_key,
            )?);

            hpke_keypairs.push(HpkeKeypair::new(config, private_key));
        }

        // VDAF verify keys.
        let mut vdaf_verify_keys = Vec::new();
        for row in vdaf_verify_key_rows {
            let encrypted_vdaf_verify_key: Vec<u8> = row.get("vdaf_verify_key");
            vdaf_verify_keys.push(SecretBytes::new(self.crypter.decrypt(
                "task_vdaf_verify_keys",
                task_id.as_ref(),
                "vdaf_verify_key",
                &encrypted_vdaf_verify_key,
            )?));
        }

        Ok(Task::new(
            *task_id,
            endpoints,
            query_type,
            vdaf,
            aggregator_role.as_role(),
            vdaf_verify_keys,
            max_batch_query_count,
            task_expiration,
            report_expiry_age,
            min_batch_size,
            time_precision,
            tolerable_clock_skew,
            collector_hpke_config,
            aggregator_auth_tokens,
            collector_auth_tokens,
            hpke_keypairs,
        )?)
    }

    /// get_client_report retrieves a client report by ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_client_report<const L: usize, A>(
        &self,
        vdaf: &A,
        task_id: &TaskId,
        report_id: &ReportId,
    ) -> Result<Option<LeaderStoredReport<L, A>>, Error>
    where
        A: vdaf::Aggregator<L>,
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    client_reports.client_timestamp,
                    client_reports.extensions,
                    client_reports.public_share,
                    client_reports.leader_input_share,
                    client_reports.helper_encrypted_input_share
                FROM client_reports
                JOIN tasks ON tasks.id = client_reports.task_id
                WHERE tasks.task_id = $1 AND client_reports.report_id = $2",
            )
            .await?;
        self.query_opt(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* report_id */ &report_id.as_ref(),
            ],
        )
        .await?
        .map(|row| Self::client_report_from_row(vdaf, *task_id, *report_id, row))
        .transpose()
    }

    #[cfg(feature = "test-util")]
    pub async fn get_helper_client_reports_for_task(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<ReportMetadata>, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT client_reports.report_id, client_reports.client_timestamp
                FROM client_reports
                JOIN tasks ON tasks.id = client_reports.task_id WHERE tasks.task_id = $1",
            )
            .await?;
        self.query(&stmt, &[&task_id.as_ref()])
            .await?
            .into_iter()
            .map(|row| {
                Ok(ReportMetadata::new(
                    row.get_bytea_and_convert::<ReportId>("report_id")?,
                    Time::from_naive_date_time(&row.get("client_timestamp")),
                ))
            })
            .collect()
    }

    #[cfg(feature = "test-util")]
    pub async fn get_client_reports_for_task<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        vdaf: &A,
        task_id: &TaskId,
    ) -> Result<Vec<LeaderStoredReport<L, A>>, Error>
    where
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    client_reports.report_id,
                    client_reports.client_timestamp,
                    client_reports.extensions,
                    client_reports.public_share,
                    client_reports.leader_input_share,
                    client_reports.helper_encrypted_input_share
                FROM client_reports
                JOIN tasks ON tasks.id = client_reports.task_id
                WHERE tasks.task_id = $1",
            )
            .await?;
        self.query(&stmt, &[/* task_id */ &task_id.as_ref()])
            .await?
            .into_iter()
            .map(|row| {
                Self::client_report_from_row(
                    vdaf,
                    *task_id,
                    row.get_bytea_and_convert::<ReportId>("report_id")?,
                    row,
                )
            })
            .collect()
    }

    fn client_report_from_row<const L: usize, A: vdaf::Aggregator<L>>(
        vdaf: &A,
        task_id: TaskId,
        report_id: ReportId,
        row: Row,
    ) -> Result<LeaderStoredReport<L, A>, Error>
    where
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let time = Time::from_naive_date_time(&row.get("client_timestamp"));

        let encoded_extensions: Vec<u8> = row.get("extensions");
        let extensions: Vec<Extension> =
            decode_u16_items(&(), &mut Cursor::new(&encoded_extensions))?;

        let encoded_public_share: Vec<u8> = row.get("public_share");
        let public_share = A::PublicShare::get_decoded_with_param(&vdaf, &encoded_public_share)?;

        let encoded_leader_input_share: Vec<u8> = row.get("leader_input_share");
        let leader_input_share = A::InputShare::get_decoded_with_param(
            &(vdaf, Role::Leader.index().unwrap()),
            &encoded_leader_input_share,
        )?;

        let encoded_helper_input_share: Vec<u8> = row.get("helper_encrypted_input_share");
        let helper_encrypted_input_share =
            HpkeCiphertext::get_decoded(&encoded_helper_input_share)?;

        Ok(LeaderStoredReport::new(
            task_id,
            ReportMetadata::new(report_id, time),
            public_share,
            extensions,
            leader_input_share,
            helper_encrypted_input_share,
        ))
    }

    /// `get_unaggregated_client_report_ids_for_task` returns some report IDs corresponding to
    /// unaggregated client reports for the task identified by the given task ID. Returned client
    /// reports are marked as aggregation-started: the caller must either create an aggregation job
    /// with, or call `mark_reports_unaggregated` on each returned report as part of the same
    /// transaction.
    ///
    /// This should only be used with VDAFs that have an aggregation parameter of the unit type. It
    /// relies on this assumption to find relevant reports without consulting collection jobs. For
    /// VDAFs that do have a different aggregation parameter,
    /// `get_unaggregated_client_report_ids_by_collect_for_task` should be used instead.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_unaggregated_client_report_ids_for_task(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<(ReportId, Time)>, Error> {
        // TODO(#269): allow the number of returned results to be controlled?
        let stmt = self
            .prepare_cached(
                "UPDATE client_reports SET aggregation_started = TRUE
                WHERE id IN (
                    SELECT id FROM client_reports
                    WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)
                      AND aggregation_started = FALSE
                    LIMIT 5000
                )
                RETURNING report_id, client_timestamp",
            )
            .await?;
        let rows = self.query(&stmt, &[&task_id.as_ref()]).await?;

        rows.into_iter()
            .map(|row| {
                let report_id = row.get_bytea_and_convert::<ReportId>("report_id")?;
                let time = Time::from_naive_date_time(&row.get("client_timestamp"));
                Ok((report_id, time))
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    /// `get_unaggregated_client_report_ids_by_collect_for_task` returns pairs of report IDs and
    /// aggregation parameters, corresponding to client reports that have not yet been aggregated,
    /// or not aggregated with a certain aggregation parameter, and for which there are collect
    /// jobs, for a given task. Returned client reports are marked as aggregation-started, but this
    /// will not stop additional aggregation jobs from being created later with different
    /// aggregation parameters.
    ///
    /// This should only be used with VDAFs with a non-unit type aggregation parameter. If a VDAF
    /// has the unit type as its aggregation parameter, then
    /// `get_unaggregated_client_report_ids_for_task` should be used instead. In such cases, it is
    /// not necessary to wait for a collection job to arrive before preparing reports.
    #[cfg(test)]
    #[tracing::instrument(skip(self), err)]
    pub async fn get_unaggregated_client_report_ids_by_collect_for_task<const L: usize, A>(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<(ReportId, Time, A::AggregationParam)>, Error>
    where
        A: vdaf::Aggregator<L> + VdafHasAggregationParameter,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        // TODO(#269): allow the number of returned results to be controlled?
        let stmt = self
            .prepare_cached(
                "WITH unaggregated_client_report_ids AS (
                    SELECT DISTINCT report_id, client_timestamp, collection_jobs.aggregation_param
                    FROM collection_jobs
                    INNER JOIN client_reports
                    ON collection_jobs.task_id = client_reports.task_id
                    AND client_reports.client_timestamp <@ collection_jobs.batch_interval
                    LEFT JOIN (
                        SELECT report_aggregations.id, report_aggregations.client_report_id,
                            aggregation_jobs.aggregation_param
                        FROM report_aggregations
                        INNER JOIN aggregation_jobs
                        ON aggregation_jobs.id = report_aggregations.aggregation_job_id
                        WHERE aggregation_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                    ) AS report_aggs
                    ON report_aggs.client_report_id = client_reports.id
                    AND report_aggs.aggregation_param = collection_jobs.aggregation_param
                    WHERE client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                    AND collection_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                    AND collection_jobs.state = 'START'
                    AND report_aggs.id IS NULL
                    LIMIT 5000
                ),
                updated_client_reports AS (
                    UPDATE client_reports SET aggregation_started = TRUE
                    FROM unaggregated_client_report_ids
                    WHERE client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                      AND client_reports.report_id = unaggregated_client_report_ids.report_id
                      AND client_reports.client_timestamp = unaggregated_client_report_ids.client_timestamp
                )
                SELECT report_id, client_timestamp, aggregation_param
                FROM unaggregated_client_report_ids",
            )
            .await?;
        let rows = self.query(&stmt, &[&task_id.as_ref()]).await?;

        rows.into_iter()
            .map(|row| {
                let report_id = row.get_bytea_and_convert::<ReportId>("report_id")?;
                let time = Time::from_naive_date_time(&row.get("client_timestamp"));
                let agg_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
                Ok((report_id, time, agg_param))
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    /// `mark_reports_unaggregated` resets the aggregation-started flag on the given client reports,
    /// so that they may once again be returned by `get_unaggregated_client_report_ids_for_task`. It
    /// should generally only be called on report IDs returned from
    /// `get_unaggregated_client_report_ids_for_task`, as part of the same transaction, for any
    /// client reports that are not added to an aggregation job.
    #[tracing::instrument(skip(self, report_ids), err)]
    pub async fn mark_reports_unaggregated(
        &self,
        task_id: &TaskId,
        report_ids: &[ReportId],
    ) -> Result<(), Error> {
        let report_ids: Vec<_> = report_ids.iter().map(ReportId::get_encoded).collect();
        let stmt = self
            .prepare_cached(
                "UPDATE client_reports SET aggregation_started = FALSE
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)
                  AND report_id IN (SELECT * FROM UNNEST($2::BYTEA[]))",
            )
            .await?;
        let row_count = self
            .execute(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* task_id */ &report_ids,
                ],
            )
            .await?;
        if TryInto::<usize>::try_into(row_count)? != report_ids.len() {
            return Err(Error::MutationTargetNotFound);
        }
        Ok(())
    }

    /// Return the number of reports in the provided task whose timestamp falls within the provided
    /// interval, regardless of whether the reports have been aggregated or collected. Applies only
    /// to time-interval queries.
    #[tracing::instrument(skip(self), err)]
    pub async fn count_client_reports_for_interval(
        &self,
        task_id: &TaskId,
        batch_interval: &Interval,
    ) -> Result<u64, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT COUNT(1) AS count FROM client_reports
                WHERE client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                AND client_reports.client_timestamp >= lower($2::TSRANGE)
                AND client_reports.client_timestamp < upper($2::TSRANGE)",
            )
            .await?;
        let row = self
            .query_one(
                &stmt,
                &[
                    /* task_id */ task_id.as_ref(),
                    /* batch_interval */ &SqlInterval::from(batch_interval),
                ],
            )
            .await?;
        Ok(row
            .get::<_, Option<i64>>("count")
            .unwrap_or_default()
            .try_into()?)
    }

    /// Return the number of reports in the provided task & batch, regardless of whether the reports
    /// have been aggregated or collected. Applies only to fixed-size queries.
    pub async fn count_client_reports_for_batch_id(
        &self,
        task_id: &TaskId,
        batch_id: &BatchId,
    ) -> Result<u64, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT COUNT(DISTINCT report_aggregations.client_report_id) AS count
                FROM report_aggregations
                JOIN aggregation_jobs ON aggregation_jobs.id = report_aggregations.aggregation_job_id
                WHERE aggregation_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                  AND aggregation_jobs.batch_id = $2",
            )
            .await?;
        let row = self
            .query_one(
                &stmt,
                &[
                    /* task_id */ task_id.as_ref(),
                    /* batch_id */ &batch_id.get_encoded(),
                ],
            )
            .await?;
        Ok(row
            .get::<_, Option<i64>>("count")
            .unwrap_or_default()
            .try_into()?)
    }

    /// `put_client_report` stores a client report, the associated plaintext leader input share and
    /// the associated encrypted helper share. Returns `Ok(())` if the write succeeds, or if there
    /// was already a row in the table matching `new_report`. Returns an error if something goes
    /// wrong or if the report ID is already in use with different values.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn put_client_report<const L: usize, A>(
        &self,
        vdaf: &A,
        new_report: &LeaderStoredReport<L, A>,
    ) -> Result<(), Error>
    where
        A: vdaf::Aggregator<L>,
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let encoded_public_share = new_report.public_share().get_encoded();
        let encoded_leader_share = new_report.leader_input_share().get_encoded();
        let encoded_helper_share = new_report.helper_encrypted_input_share().get_encoded();
        let mut encoded_extensions = Vec::new();
        encode_u16_items(&mut encoded_extensions, &(), new_report.leader_extensions());

        let stmt = self
            .prepare_cached(
                "INSERT INTO client_reports (
                    task_id,
                    report_id,
                    client_timestamp,
                    extensions,
                    public_share,
                    leader_input_share,
                    helper_encrypted_input_share
                )
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6, $7)
                ON CONFLICT DO NOTHING",
            )
            .await?;
        let rows_affected = self
            .execute(
                &stmt,
                &[
                    /* task_id */ &new_report.task_id().get_encoded(),
                    /* report_id */ &new_report.metadata().id().get_encoded(),
                    /* client_timestamp */
                    &new_report.metadata().time().as_naive_date_time()?,
                    /* extensions */ &encoded_extensions,
                    /* public_share */ &encoded_public_share,
                    /* leader_input_share */ &encoded_leader_share,
                    /* helper_encrypted_input_share */ &encoded_helper_share,
                ],
            )
            .await?;

        if rows_affected > 1 {
            // This should never happen, because the INSERT should affect 0 or 1 rows.
            panic!(
                "INSERT for task ID {} and report ID {} affected multiple rows?",
                new_report.task_id(),
                new_report.metadata().id()
            );
        }

        if rows_affected == 1 {
            // Fast path: one row was affected, meaning there was no conflict and we wrote a new
            // report
            return Ok(());
        }

        // Slow path: no rows were affected, meaning a row with the new report ID already existed
        // and we hit the query's ON CONFLICT DO NOTHING clause. We need to check whether the new
        // report matches the existing one.
        let existing_report = match self
            .get_client_report(vdaf, new_report.task_id(), new_report.metadata().id())
            .await?
        {
            Some(e) => e,
            None => {
                // This should never happen: if we got 0 affected rows earlier, there must be a row
                // matching the task ID and report ID.
                panic!(
                    "found no existing report for task ID {} and report ID {}",
                    new_report.task_id(),
                    new_report.metadata().id(),
                )
            }
        };

        // If the existing report does not match the new report, then someone is trying to mutate an
        // existing report, which is forbidden.
        if !existing_report.eq(new_report) {
            return Err(Error::MutationTargetAlreadyExisted);
        }

        // If the existing report does match the new one, then there is no error (PUTting a report
        // is idempotent).
        Ok(())
    }

    /// put_report_share stores a report share, given its associated task ID.
    ///
    /// This method is intended for use by aggregators acting in the helper role; notably, it does
    /// not store extensions, public_share, or input_shares, as these are not required to be stored
    /// for the helper workflow (and the helper never observes the entire set of encrypted input
    /// shares, so it could not record the full client report in any case).
    ///
    /// Returns `Err(Error::MutationTargetAlreadyExisted)` if an attempt to mutate an existing row
    /// (e.g., changing the timestamp for a known report ID) is detected.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_report_share(
        &self,
        task_id: &TaskId,
        report_share: &ReportShare,
    ) -> Result<(), Error> {
        // On conflict, we update the row, but only if the incoming client timestamp (excluded)
        // doesn't match the existing one.
        // xmax is a PostgreSQL system column whose value is "the identity (transaction ID) of the
        // deleting transaction, or zero for an undeleted row version." The UPDATE in ON CONFLICT DO
        // UPDATE counts as deleting a tuple, and so xmax will be zero if there was no conflict (new
        // report share or not an attempt to mutate an existing one) and nonzero otherwise.
        // https://www.postgresql.org/docs/14/ddl-system-columns.html
        // https://stackoverflow.com/questions/34762732/how-to-find-out-if-an-upsert-was-an-update-with-postgresql-9-5-upsert
        // https://www.cybertec-postgresql.com/en/whats-in-an-xmax/
        let stmt = self
            .prepare_cached("SELECT put_report_share($1, $2, $3) AS success")
            .await?;
        let row = self
            .query_one(
                &stmt,
                &[
                    /* task_id */ &task_id.get_encoded(),
                    /* report_id */ &report_share.metadata().id().as_ref(),
                    /* client_timestamp */
                    &report_share.metadata().time().as_naive_date_time()?,
                ],
            )
            .await?;

        if !row.get::<_, bool>("success") {
            Err(Error::MutationTargetAlreadyExisted)
        } else {
            Ok(())
        }
    }

    /// get_aggregation_job retrieves an aggregation job by ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregation_job<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<Option<AggregationJob<L, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT aggregation_param, batch_id, client_timestamp_interval, state
                FROM aggregation_jobs JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1 AND aggregation_jobs.aggregation_job_id = $2",
            )
            .await?;
        self.query_opt(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* aggregation_job_id */ &aggregation_job_id.as_ref(),
            ],
        )
        .await?
        .map(|row| Self::aggregation_job_from_row(task_id, aggregation_job_id, &row))
        .transpose()
    }

    /// get_aggregation_jobs_for_task returns all aggregation jobs for a given task ID.
    #[cfg(feature = "test-util")]
    #[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregation_jobs_for_task<
        const L: usize,
        Q: QueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<AggregationJob<L, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    aggregation_job_id, aggregation_param, batch_id, client_timestamp_interval,
                    state
                FROM aggregation_jobs JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1",
            )
            .await?;
        self.query(&stmt, &[/* task_id */ &task_id.as_ref()])
            .await?
            .into_iter()
            .map(|row| {
                Self::aggregation_job_from_row(
                    task_id,
                    &row.get_bytea_and_convert::<AggregationJobId>("aggregation_job_id")?,
                    &row,
                )
            })
            .collect()
    }

    fn aggregation_job_from_row<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        row: &Row,
    ) -> Result<AggregationJob<L, Q, A>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        Ok(AggregationJob::new(
            *task_id,
            *aggregation_job_id,
            A::AggregationParam::get_decoded(row.get("aggregation_param"))?,
            Q::PartialBatchIdentifier::get_decoded(row.get::<_, &[u8]>("batch_id"))?,
            row.get::<_, SqlInterval>("client_timestamp_interval")
                .as_interval(),
            row.get("state"),
        ))
    }

    /// acquire_incomplete_aggregation_jobs retrieves & acquires the IDs of unclaimed incomplete
    /// aggregation jobs. At most `maximum_acquire_count` jobs are acquired. The job is acquired
    /// with a "lease" that will time out; the desired duration of the lease is a parameter, and the
    /// returned lease provides the absolute timestamp at which the lease is no longer live.
    pub async fn acquire_incomplete_aggregation_jobs(
        &self,
        lease_duration: &StdDuration,
        maximum_acquire_count: usize,
    ) -> Result<Vec<Lease<AcquiredAggregationJob>>, Error> {
        let now = self.clock.now().as_naive_date_time()?;
        let lease_expiry_time = add_naive_date_time_duration(&now, lease_duration)?;
        let maximum_acquire_count: i64 = maximum_acquire_count.try_into()?;

        // TODO(#224): verify that this query is efficient. I am not sure if we would currently
        // scan over every (in-progress, not-leased) aggregation job for tasks where we are in the
        // HELPER role.
        // We generate the token on the DB to allow each acquired job to receive its own distinct
        // token. This is not strictly necessary as we only care about token collisions on a
        // per-row basis.
        let stmt = self
            .prepare_cached(
                "UPDATE aggregation_jobs SET
                    lease_expiry = $1,
                    lease_token = gen_random_bytes(16),
                    lease_attempts = lease_attempts + 1
                FROM tasks
                WHERE tasks.id = aggregation_jobs.task_id
                AND aggregation_jobs.id IN (SELECT aggregation_jobs.id FROM aggregation_jobs
                    JOIN tasks on tasks.id = aggregation_jobs.task_id
                    WHERE tasks.aggregator_role = 'LEADER'
                    AND aggregation_jobs.state = 'IN_PROGRESS'
                    AND aggregation_jobs.lease_expiry <= $2
                    ORDER BY aggregation_jobs.id DESC LIMIT $3)
                RETURNING tasks.task_id, tasks.query_type, tasks.vdaf,
                          aggregation_jobs.aggregation_job_id, aggregation_jobs.lease_token,
                          aggregation_jobs.lease_attempts",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* lease_expiry */ &lease_expiry_time,
                /* now */ &now,
                /* limit */ &maximum_acquire_count,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            let aggregation_job_id =
                row.get_bytea_and_convert::<AggregationJobId>("aggregation_job_id")?;
            let query_type = row.try_get::<_, Json<task::QueryType>>("query_type")?.0;
            let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
            let lease_token = row.get_bytea_and_convert::<LeaseToken>("lease_token")?;
            let lease_attempts = row.get_bigint_and_convert("lease_attempts")?;
            Ok(Lease::new(
                AcquiredAggregationJob::new(task_id, aggregation_job_id, query_type, vdaf),
                lease_expiry_time,
                lease_token,
                lease_attempts,
            ))
        })
        .collect()
    }

    /// release_aggregation_job releases an acquired (via e.g. acquire_incomplete_aggregation_jobs)
    /// aggregation job. It returns an error if the aggregation job has no current lease.
    pub async fn release_aggregation_job(
        &self,
        lease: &Lease<AcquiredAggregationJob>,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "UPDATE aggregation_jobs SET lease_expiry = TIMESTAMP '-infinity', lease_token = NULL, lease_attempts = 0
                FROM tasks
                WHERE tasks.id = aggregation_jobs.task_id
                  AND tasks.task_id = $1
                  AND aggregation_jobs.aggregation_job_id = $2
                  AND aggregation_jobs.lease_expiry = $3
                  AND aggregation_jobs.lease_token = $4",
            )
            .await?;
        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* task_id */ &lease.leased().task_id().as_ref(),
                    /* aggregation_job_id */
                    &lease.leased().aggregation_job_id().as_ref(),
                    /* lease_expiry */ &lease.lease_expiry_time(),
                    /* lease_token */ &lease.lease_token().as_ref(),
                ],
            )
            .await?,
        )
    }

    /// put_aggregation_job stores an aggregation job.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_aggregation_job<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        aggregation_job: &AggregationJob<L, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "INSERT INTO aggregation_jobs
                (
                    task_id,
                    aggregation_job_id,
                    aggregation_param,
                    batch_id,
                    client_timestamp_interval,
                    state
                )
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6)",
            )
            .await?;
        self.execute(
            &stmt,
            &[
                /* task_id */ &aggregation_job.task_id().as_ref(),
                /* aggregation_job_id */ &aggregation_job.id().as_ref(),
                /* aggregation_param */
                &aggregation_job.aggregation_parameter().get_encoded(),
                /* batch_id */
                &aggregation_job.partial_batch_identifier().get_encoded(),
                /* client_timestamp_interval */
                &SqlInterval::from(aggregation_job.client_timestamp_interval()),
                /* state */ &aggregation_job.state(),
            ],
        )
        .await?;
        Ok(())
    }

    /// update_aggregation_job updates a stored aggregation job.
    #[tracing::instrument(skip(self), err)]
    pub async fn update_aggregation_job<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        aggregation_job: &AggregationJob<L, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "UPDATE aggregation_jobs SET
                    state = $1
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $2)
                  AND aggregation_job_id = $3",
            )
            .await?;
        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* state */ &aggregation_job.state(),
                    /* task_id */ &aggregation_job.task_id().as_ref(),
                    /* aggregation_job_id */
                    &aggregation_job.id().as_ref(),
                ],
            )
            .await?,
        )
    }

    /// Check whether the report has ever been aggregated with the given parameter.
    #[tracing::instrument(skip(self), err)]
    pub async fn check_report_aggregation_exists(
        &self,
        task_id: &TaskId,
        report_id: &ReportId,
        aggregation_param: &[u8],
    ) -> Result<bool, Error> {
        let stmt = self.prepare_cached(
            "SELECT 1 FROM report_aggregations
                JOIN client_reports ON client_reports.id = report_aggregations.client_report_id
                JOIN aggregation_jobs ON aggregation_jobs.id = report_aggregations.aggregation_job_id
                WHERE client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                    AND client_reports.report_id = $2
                    AND aggregation_jobs.aggregation_param = $3"
            )
        .await?;
        Ok(self
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* report_id */ &report_id.as_ref(),
                    /* aggregation_param */ &aggregation_param,
                ],
            )
            .await
            .map(|row| row.is_some())?)
    }

    /// get_report_aggregation gets a report aggregation by ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_report_aggregation<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        vdaf: &A,
        role: &Role,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        report_id: &ReportId,
    ) -> Result<Option<ReportAggregation<L, A>>, Error>
    where
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
        A::OutputShare: for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT client_reports.report_id, client_reports.client_timestamp,
                report_aggregations.ord, report_aggregations.state, report_aggregations.prep_state,
                report_aggregations.prep_msg, report_aggregations.out_share, report_aggregations.error_code
                FROM report_aggregations
                JOIN client_reports ON client_reports.id = report_aggregations.client_report_id
                WHERE report_aggregations.aggregation_job_id = (SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $1)
                  AND client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $2)
                  AND client_reports.report_id = $3",
            )
            .await?;
        self.query_opt(
            &stmt,
            &[
                /* aggregation_job_id */ &aggregation_job_id.as_ref(),
                /* task_id */ &task_id.as_ref(),
                /* report_id */ &report_id.as_ref(),
            ],
        )
        .await?
        .map(|row| {
            Self::report_aggregation_from_row(
                vdaf,
                role,
                task_id,
                aggregation_job_id,
                report_id,
                &row,
            )
        })
        .transpose()
    }

    /// get_report_aggregations_for_aggregation_job retrieves all report aggregations associated
    /// with a given aggregation job, ordered by their natural ordering.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_report_aggregations_for_aggregation_job<
        const L: usize,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        vdaf: &A,
        role: &Role,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<Vec<ReportAggregation<L, A>>, Error>
    where
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
        A::OutputShare: for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT client_reports.report_id, client_reports.client_timestamp,
                report_aggregations.ord, report_aggregations.state, report_aggregations.prep_state,
                report_aggregations.prep_msg, report_aggregations.out_share, report_aggregations.error_code
                FROM report_aggregations
                JOIN client_reports ON client_reports.id = report_aggregations.client_report_id
                WHERE report_aggregations.aggregation_job_id = (SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $1)
                  AND client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $2)
                ORDER BY report_aggregations.ord ASC"
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* aggregation_job_id */ &aggregation_job_id.as_ref(),
                /* task_id */ &task_id.as_ref(),
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            Self::report_aggregation_from_row(
                vdaf,
                role,
                task_id,
                aggregation_job_id,
                &row.get_bytea_and_convert::<ReportId>("report_id")?,
                &row,
            )
        })
        .collect()
    }

    /// get_report_aggregations_for_task retrieves all report aggregations associated with a given
    /// task.
    #[cfg(feature = "test-util")]
    pub async fn get_report_aggregations_for_task<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        vdaf: &A,
        role: &Role,
        task_id: &TaskId,
    ) -> Result<Vec<ReportAggregation<L, A>>, Error>
    where
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
        A::OutputShare: for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    aggregation_jobs.aggregation_job_id, client_reports.report_id,
                    client_reports.client_timestamp, report_aggregations.ord,
                    report_aggregations.state, report_aggregations.prep_state,
                    report_aggregations.prep_msg, report_aggregations.out_share,
                    report_aggregations.error_code
                FROM report_aggregations
                JOIN client_reports ON client_reports.id = report_aggregations.client_report_id
                JOIN aggregation_jobs ON aggregation_jobs.id = report_aggregations.aggregation_job_id
                WHERE aggregation_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        self.query(&stmt, &[/* task_id */ &task_id.as_ref()])
            .await?
            .into_iter()
            .map(|row| {
                Self::report_aggregation_from_row(
                    vdaf,
                    role,
                    task_id,
                    &row.get_bytea_and_convert::<AggregationJobId>("aggregation_job_id")?,
                    &row.get_bytea_and_convert::<ReportId>("report_id")?,
                    &row,
                )
            })
            .collect()
    }

    fn report_aggregation_from_row<const L: usize, A: vdaf::Aggregator<L>>(
        vdaf: &A,
        role: &Role,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        report_id: &ReportId,
        row: &Row,
    ) -> Result<ReportAggregation<L, A>, Error>
    where
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
        A::OutputShare: for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let time = Time::from_naive_date_time(&row.get("client_timestamp"));
        let ord: i64 = row.get("ord");
        let state: ReportAggregationStateCode = row.get("state");
        let prep_state_bytes: Option<Vec<u8>> = row.get("prep_state");
        let prep_msg_bytes: Option<Vec<u8>> = row.get("prep_msg");
        let out_share_bytes: Option<Vec<u8>> = row.get("out_share");
        let error_code: Option<i16> = row.get("error_code");

        let error_code = match error_code {
            Some(c) => {
                let c: u8 = c.try_into().map_err(|err| {
                    Error::DbState(format!("couldn't convert error_code value: {err}"))
                })?;
                Some(c.try_into().map_err(|err| {
                    Error::DbState(format!("couldn't convert error_code value: {err}"))
                })?)
            }
            None => None,
        };

        let agg_state = match state {
            ReportAggregationStateCode::Start => ReportAggregationState::Start,
            ReportAggregationStateCode::Waiting => {
                let agg_index = role.index().ok_or_else(|| {
                    Error::User(anyhow!("unexpected role: {}", role.as_str()).into())
                })?;
                let prep_state = A::PrepareState::get_decoded_with_param(
                    &(vdaf, agg_index),
                    &prep_state_bytes.ok_or_else(|| {
                        Error::DbState(
                            "report aggregation in state WAITING but prep_state is NULL"
                                .to_string(),
                        )
                    })?,
                )?;
                let prep_msg = prep_msg_bytes
                    .map(|bytes| A::PrepareMessage::get_decoded_with_param(&prep_state, &bytes))
                    .transpose()?;
                ReportAggregationState::Waiting(prep_state, prep_msg)
            }
            ReportAggregationStateCode::Finished => ReportAggregationState::Finished(
                A::OutputShare::try_from(&out_share_bytes.ok_or_else(|| {
                    Error::DbState(
                        "report aggregation in state FINISHED but out_share is NULL".to_string(),
                    )
                })?)
                .map_err(|_| {
                    Error::Decode(CodecError::Other("couldn't decode output share".into()))
                })?,
            ),
            ReportAggregationStateCode::Failed => {
                ReportAggregationState::Failed(error_code.ok_or_else(|| {
                    Error::DbState(
                        "report aggregation in state FAILED but error_code is NULL".to_string(),
                    )
                })?)
            }
            ReportAggregationStateCode::Invalid => ReportAggregationState::Invalid,
        };

        Ok(ReportAggregation::new(
            *task_id,
            *aggregation_job_id,
            *report_id,
            time,
            ord,
            agg_state,
        ))
    }

    /// put_report_aggregation stores aggregation data for a single report.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_report_aggregation<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        report_aggregation: &ReportAggregation<L, A>,
    ) -> Result<(), Error>
    where
        A::PrepareState: Encode,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let encoded_state_values = report_aggregation.state().encoded_values_from_state();

        let stmt = self.prepare_cached(
            "INSERT INTO report_aggregations
            (aggregation_job_id, client_report_id, ord, state, prep_state, prep_msg, out_share, error_code)
            VALUES ((SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $1),
                    (SELECT id FROM client_reports
                     WHERE task_id = (SELECT id FROM tasks WHERE task_id = $2)
                     AND report_id = $3),
                    $4, $5, $6, $7, $8, $9)"
        ).await?;
        self.execute(
            &stmt,
            &[
                /* aggregation_job_id */
                &report_aggregation.aggregation_job_id().as_ref(),
                /* task_id */ &report_aggregation.task_id().as_ref(),
                /* report_id */ &report_aggregation.report_id().as_ref(),
                /* ord */ &report_aggregation.ord(),
                /* state */ &report_aggregation.state().state_code(),
                /* prep_state */ &encoded_state_values.prep_state,
                /* prep_msg */ &encoded_state_values.prep_msg,
                /* out_share */ &encoded_state_values.output_share,
                /* error_code */ &encoded_state_values.report_share_err,
            ],
        )
        .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self), err)]
    pub async fn update_report_aggregation<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        report_aggregation: &ReportAggregation<L, A>,
    ) -> Result<(), Error>
    where
        A::PrepareState: Encode,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let encoded_state_values = report_aggregation.state().encoded_values_from_state();

        let stmt = self
            .prepare_cached(
                "UPDATE report_aggregations SET ord = $1, state = $2, prep_state = $3,
                prep_msg = $4, out_share = $5, error_code = $6
                WHERE aggregation_job_id = (SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $7)
                AND client_report_id = (SELECT id FROM client_reports
                    WHERE task_id = (SELECT id FROM tasks WHERE task_id = $8)
                    AND report_id = $9)")
            .await?;
        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* ord */ &report_aggregation.ord(),
                    /* state */ &report_aggregation.state().state_code(),
                    /* prep_state */ &encoded_state_values.prep_state,
                    /* prep_msg */ &encoded_state_values.prep_msg,
                    /* out_share */ &encoded_state_values.output_share,
                    /* error_code */ &encoded_state_values.report_share_err,
                    /* aggregation_job_id */
                    &report_aggregation.aggregation_job_id().as_ref(),
                    /* task_id */ &report_aggregation.task_id().as_ref(),
                    /* report_id */ &report_aggregation.report_id().as_ref(),
                ],
            )
            .await?,
        )
    }

    /// Returns the collection job for the provided ID, or `None` if no such collection job exists.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_collection_job<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        collection_job_id: &CollectionJobId,
    ) -> Result<Option<CollectionJob<L, Q, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    tasks.task_id,
                    collection_jobs.batch_identifier,
                    collection_jobs.aggregation_param,
                    collection_jobs.state,
                    collection_jobs.report_count,
                    collection_jobs.helper_aggregate_share,
                    collection_jobs.leader_aggregate_share
                FROM collection_jobs JOIN tasks ON tasks.id = collection_jobs.task_id
                WHERE collection_jobs.collection_job_id = $1",
            )
            .await?;
        self.query_opt(&stmt, &[&collection_job_id.as_ref()])
            .await?
            .map(|row| {
                let task_id = TaskId::get_decoded(row.get("task_id"))?;
                let batch_identifier =
                    Q::BatchIdentifier::get_decoded(row.get("batch_identifier"))?;
                Self::collection_job_from_row(task_id, batch_identifier, *collection_job_id, &row)
            })
            .transpose()
    }

    /// Returns all collection jobs for the given task which include the given timestamp. Applies only
    /// to time-interval tasks.
    pub async fn get_collection_jobs_including_time<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        task_id: &TaskId,
        timestamp: &Time,
    ) -> Result<Vec<CollectionJob<L, TimeInterval, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    collection_jobs.collection_job_id,
                    collection_jobs.batch_identifier,
                    collection_jobs.aggregation_param,
                    collection_jobs.state,
                    collection_jobs.report_count,
                    collection_jobs.helper_aggregate_share,
                    collection_jobs.leader_aggregate_share
                FROM collection_jobs JOIN tasks ON tasks.id = collection_jobs.task_id
                WHERE tasks.task_id = $1
                  AND collection_jobs.batch_interval @> $2::TIMESTAMP",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* timestamp */ &timestamp.as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let batch_identifier = Interval::get_decoded(row.get("batch_identifier"))?;
            let collection_job_id =
                row.get_bytea_and_convert::<CollectionJobId>("collection_job_id")?;
            Self::collection_job_from_row(*task_id, batch_identifier, collection_job_id, &row)
        })
        .collect()
    }

    /// Returns all collection jobs for the given task whose collect intervals intersect with the given
    /// interval. Applies only to time-interval tasks.
    pub async fn get_collection_jobs_intersecting_interval<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        task_id: &TaskId,
        batch_interval: &Interval,
    ) -> Result<Vec<CollectionJob<L, TimeInterval, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    collection_jobs.collection_job_id,
                    collection_jobs.batch_identifier,
                    collection_jobs.aggregation_param,
                    collection_jobs.state,
                    collection_jobs.report_count,
                    collection_jobs.helper_aggregate_share,
                    collection_jobs.leader_aggregate_share
                FROM collection_jobs JOIN tasks ON tasks.id = collection_jobs.task_id
                WHERE tasks.task_id = $1
                  AND collection_jobs.batch_interval && $2",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* batch_interval */ &SqlInterval::from(batch_interval),
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let batch_identifier = Interval::get_decoded(row.get("batch_identifier"))?;
            let collection_job_id =
                row.get_bytea_and_convert::<CollectionJobId>("collection_job_id")?;
            Self::collection_job_from_row::<L, TimeInterval, A>(
                *task_id,
                batch_identifier,
                collection_job_id,
                &row,
            )
        })
        .collect()
    }

    /// Retrieves all collection jobs for the given batch identifier. Multiple collection jobs may be
    /// returned with distinct aggregation parameters.
    pub async fn get_collection_jobs_by_batch_identifier<
        const L: usize,
        Q: QueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: &TaskId,
        batch_identifier: &Q::BatchIdentifier,
    ) -> Result<Vec<CollectionJob<L, Q, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    collection_jobs.collection_job_id,
                    collection_jobs.aggregation_param,
                    collection_jobs.state,
                    collection_jobs.report_count,
                    collection_jobs.helper_aggregate_share,
                    collection_jobs.leader_aggregate_share
                FROM collection_jobs JOIN tasks ON tasks.id = collection_jobs.task_id
                WHERE tasks.task_id = $1
                  AND collection_jobs.batch_identifier = $2",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* batch_identifier */ &batch_identifier.get_encoded(),
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let collection_job_id =
                row.get_bytea_and_convert::<CollectionJobId>("collection_job_id")?;
            Self::collection_job_from_row(
                *task_id,
                batch_identifier.clone(),
                collection_job_id,
                &row,
            )
        })
        .collect()
    }

    #[cfg(feature = "test-util")]
    pub async fn get_collection_jobs_for_task<
        const L: usize,
        Q: QueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<CollectionJob<L, Q, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    collection_jobs.collection_job_id,
                    collection_jobs.batch_identifier,
                    collection_jobs.aggregation_param,
                    collection_jobs.state,
                    collection_jobs.report_count,
                    collection_jobs.helper_aggregate_share,
                    collection_jobs.leader_aggregate_share
                FROM collection_jobs JOIN tasks ON tasks.id = collection_jobs.task_id
                WHERE tasks.task_id = $1",
            )
            .await?;
        self.query(&stmt, &[/* task_id */ task_id.as_ref()])
            .await?
            .into_iter()
            .map(|row| {
                let collection_job_id =
                    row.get_bytea_and_convert::<CollectionJobId>("collection_job_id")?;
                let batch_identifier =
                    Q::BatchIdentifier::get_decoded(row.get("batch_identifier"))?;
                Self::collection_job_from_row(*task_id, batch_identifier, collection_job_id, &row)
            })
            .collect()
    }

    fn collection_job_from_row<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        task_id: TaskId,
        batch_identifier: Q::BatchIdentifier,
        collection_job_id: CollectionJobId,
        row: &Row,
    ) -> Result<CollectionJob<L, Q, A>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let aggregation_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
        let state: CollectionJobStateCode = row.get("state");
        let report_count: Option<i64> = row.get("report_count");
        let helper_aggregate_share_bytes: Option<Vec<u8>> = row.get("helper_aggregate_share");
        let leader_aggregate_share_bytes: Option<Vec<u8>> = row.get("leader_aggregate_share");

        let state = match state {
            CollectionJobStateCode::Start => CollectionJobState::Start,

            CollectionJobStateCode::Finished => {
                let report_count = u64::try_from(report_count.ok_or_else(|| {
                    Error::DbState(
                        "collection job in state FINISHED but report_count is NULL".to_string(),
                    )
                })?)?;
                let encrypted_helper_aggregate_share = HpkeCiphertext::get_decoded(
                    &helper_aggregate_share_bytes.ok_or_else(|| {
                        Error::DbState(
                            "collection job in state FINISHED but helper_aggregate_share is NULL"
                                .to_string(),
                        )
                    })?,
                )?;
                let leader_aggregate_share = A::AggregateShare::try_from(
                    &leader_aggregate_share_bytes.ok_or_else(|| {
                        Error::DbState(
                            "collection job is in state FINISHED but leader_aggregate_share is NULL"
                                .to_string(),
                        )
                    })?,
                )
                .map_err(|err| {
                    Error::DbState(format!(
                        "leader_aggregate_share stored in database is invalid: {err:?}"
                    ))
                })?;
                CollectionJobState::Finished {
                    report_count,
                    encrypted_helper_aggregate_share,
                    leader_aggregate_share,
                }
            }

            CollectionJobStateCode::Abandoned => CollectionJobState::Abandoned,

            CollectionJobStateCode::Deleted => CollectionJobState::Deleted,
        };

        Ok(CollectionJob::new(
            task_id,
            collection_job_id,
            batch_identifier,
            aggregation_param,
            state,
        ))
    }

    /// Stores a new collection job.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn put_collection_job<
        const L: usize,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        collection_job: &CollectionJob<L, Q, A>,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Encode + std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let batch_interval =
            Q::to_batch_interval(collection_job.batch_identifier()).map(SqlInterval::from);

        let stmt = self
            .prepare_cached(
                "INSERT INTO collection_jobs
                    (collection_job_id, task_id, batch_identifier, batch_interval, aggregation_param,
                    state)
                VALUES ($1, (SELECT id FROM tasks WHERE task_id = $2), $3, $4, $5, $6)",
            )
            .await?;
        self.execute(
            &stmt,
            &[
                /* collection_job_id */ collection_job.collection_job_id().as_ref(),
                /* task_id */ collection_job.task_id().as_ref(),
                /* batch_identifier */ &collection_job.batch_identifier().get_encoded(),
                /* batch_interval */ &batch_interval,
                /* aggregation_param */
                &collection_job.aggregation_parameter().get_encoded(),
                /* state */ &collection_job.state().collection_job_state_code(),
            ],
        )
        .await?;

        Ok(())
    }

    /// acquire_incomplete_time_interval_collection_jobs retrieves & acquires the IDs of unclaimed
    /// incomplete collection jobs. At most `maximum_acquire_count` jobs are acquired. The job is
    /// acquired with a "lease" that will time out; the desired duration of the lease is a
    /// parameter, and the lease expiration time is returned. Applies only to time-interval tasks.
    pub async fn acquire_incomplete_time_interval_collection_jobs(
        &self,
        lease_duration: &StdDuration,
        maximum_acquire_count: usize,
    ) -> Result<Vec<Lease<AcquiredCollectionJob>>, Error> {
        let now = self.clock.now().as_naive_date_time()?;
        let lease_expiry_time = add_naive_date_time_duration(&now, lease_duration)?;
        let maximum_acquire_count: i64 = maximum_acquire_count.try_into()?;

        let stmt = self
            .prepare_cached(
                "
WITH updated as (
    UPDATE collection_jobs SET lease_expiry = $1, lease_token = gen_random_bytes(16), lease_attempts = lease_attempts + 1
    FROM tasks
    WHERE collection_jobs.id IN (
        SELECT collection_jobs.id FROM collection_jobs
        -- Join on aggregation jobs with matching task ID, matching aggregation parameter, and
        -- subsets of the batch interval
        INNER JOIN aggregation_jobs
            ON collection_jobs.aggregation_param = aggregation_jobs.aggregation_param
            AND collection_jobs.task_id = aggregation_jobs.task_id
            AND collection_jobs.batch_interval && aggregation_jobs.client_timestamp_interval
        WHERE
            -- Constraint for tasks table in FROM position
            tasks.id = collection_jobs.task_id
            -- Only return time interval collection jobs.
            AND tasks.query_type ? 'TimeInterval'
            -- Only acquire collection jobs in a non-terminal state.
            AND collection_jobs.state = 'START'
            -- Do not acquire collection jobs with an unexpired lease
            AND collection_jobs.lease_expiry <= $2
        GROUP BY collection_jobs.id
        -- Do not acquire collection jobs where any associated aggregation jobs are not finished
        HAVING bool_and(aggregation_jobs.state != 'IN_PROGRESS')
        -- Honor maximum_acquire_count *after* winnowing down to runnable collection jobs
        LIMIT $3
    )
    RETURNING tasks.task_id, tasks.query_type, tasks.vdaf, collection_jobs.collection_job_id,
              collection_jobs.id, collection_jobs.lease_token, collection_jobs.lease_attempts
)
SELECT task_id, query_type, vdaf, collection_job_id, lease_token, lease_attempts FROM updated
-- TODO (#174): revisit collection job queueing behavior implied by this ORDER BY
ORDER BY id DESC
",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* lease_expiry */ &lease_expiry_time,
                /* now */ &now,
                /* limit */ &maximum_acquire_count,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            let collection_job_id =
                row.get_bytea_and_convert::<CollectionJobId>("collection_job_id")?;
            let query_type = row.try_get::<_, Json<task::QueryType>>("query_type")?.0;
            let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
            let lease_token = row.get_bytea_and_convert::<LeaseToken>("lease_token")?;
            let lease_attempts = row.get_bigint_and_convert("lease_attempts")?;
            Ok(Lease::new(
                AcquiredCollectionJob::new(task_id, collection_job_id, query_type, vdaf),
                lease_expiry_time,
                lease_token,
                lease_attempts,
            ))
        })
        .collect()
    }

    /// acquire_incomplete_fixed_size_collection_jobs retrieves & acquires the IDs of unclaimed
    /// incomplete collection jobs. At most `maximum_acquire_count` jobs are acquired. The job is
    /// acquired with a "lease" that will time out; the desired duration of the lease is a
    /// parameter, and the lease expiration time is returned. Applies only to fixed-size tasks.
    pub async fn acquire_incomplete_fixed_size_collection_jobs(
        &self,
        lease_duration: &StdDuration,
        maximum_acquire_count: usize,
    ) -> Result<Vec<Lease<AcquiredCollectionJob>>, Error> {
        let now = self.clock.now().as_naive_date_time()?;
        let lease_expiry_time = add_naive_date_time_duration(&now, lease_duration)?;
        let maximum_acquire_count: i64 = maximum_acquire_count.try_into()?;

        let stmt = self
            .prepare_cached(
                "
WITH updated as (
    UPDATE collection_jobs SET lease_expiry = $1, lease_token = gen_random_bytes(16), lease_attempts = lease_attempts + 1
    FROM tasks
    WHERE collection_jobs.id IN (
        SELECT collection_jobs.id FROM collection_jobs
        -- Join on aggregation jobs with matching task ID, matching aggregation parameter, and
        -- matching batch identifier.
        INNER JOIN aggregation_jobs
            ON collection_jobs.aggregation_param = aggregation_jobs.aggregation_param
            AND collection_jobs.task_id = aggregation_jobs.task_id
            AND collection_jobs.batch_identifier = aggregation_jobs.batch_id
        WHERE
            -- Constraint for tasks table in FROM position
            tasks.id = collection_jobs.task_id
            -- Only return fixed-size collection jobs.
            AND tasks.query_type ? 'FixedSize'
            -- Only acquire collection jobs in a non-terminal state.
            AND collection_jobs.state = 'START'
            -- Do not acquire collection jobs with an unexpired lease
            AND collection_jobs.lease_expiry <= $2
        GROUP BY collection_jobs.id
        -- Do not acquire collection jobs where any associated aggregation jobs are not finished
        HAVING bool_and(aggregation_jobs.state != 'IN_PROGRESS')
        -- Honor maximum_acquire_count *after* winnowing down to runnable collection jobs
        LIMIT $3
    )
    RETURNING tasks.task_id, tasks.query_type, tasks.vdaf, collection_jobs.collection_job_id,
              collection_jobs.id, collection_jobs.lease_token, collection_jobs.lease_attempts
)
SELECT task_id, query_type, vdaf, collection_job_id, lease_token, lease_attempts FROM updated
-- TODO (#174): revisit collection job queueing behavior implied by this ORDER BY
ORDER BY id DESC
",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* lease_expiry */ &lease_expiry_time,
                /* now */ &now,
                /* limit */ &maximum_acquire_count,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            let collection_job_id =
                row.get_bytea_and_convert::<CollectionJobId>("collection_job_id")?;
            let query_type = row.try_get::<_, Json<task::QueryType>>("query_type")?.0;
            let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
            let lease_token = row.get_bytea_and_convert::<LeaseToken>("lease_token")?;
            let lease_attempts = row.get_bigint_and_convert("lease_attempts")?;
            Ok(Lease::new(
                AcquiredCollectionJob::new(task_id, collection_job_id, query_type, vdaf),
                lease_expiry_time,
                lease_token,
                lease_attempts,
            ))
        })
        .collect()
    }

    /// release_collection_job releases an acquired (via e.g. acquire_incomplete_collection_jobs) collect
    /// job. It returns an error if the collection job has no current lease.
    pub async fn release_collection_job(
        &self,
        lease: &Lease<AcquiredCollectionJob>,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "UPDATE collection_jobs SET lease_expiry = TIMESTAMP '-infinity', lease_token = NULL, lease_attempts = 0
                FROM tasks
                WHERE tasks.id = collection_jobs.task_id
                  AND tasks.task_id = $1
                  AND collection_jobs.collection_job_id = $2
                  AND collection_jobs.lease_expiry = $3
                  AND collection_jobs.lease_token = $4",
            )
            .await?;
        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* task_id */ &lease.leased().task_id().as_ref(),
                    /* collection_job_id */ &lease.leased().collection_job_id().as_ref(),
                    /* lease_expiry */ &lease.lease_expiry_time(),
                    /* lease_token */ &lease.lease_token().as_ref(),
                ],
            )
            .await?,
        )
    }

    /// Updates an existing collection job.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn update_collection_job<
        const L: usize,
        Q: QueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        collection_job: &CollectionJob<L, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let (report_count, leader_aggregate_share, helper_aggregate_share) = match collection_job
            .state()
        {
            CollectionJobState::Start => {
                return Err(Error::InvalidParameter(
                    "cannot update collection job into START state",
                ));
            }
            CollectionJobState::Finished {
                report_count,
                encrypted_helper_aggregate_share,
                leader_aggregate_share,
            } => {
                let report_count: Option<i64> = Some(i64::try_from(*report_count)?);
                let leader_aggregate_share: Option<Vec<u8>> = Some(leader_aggregate_share.into());
                let helper_aggregate_share = Some(encrypted_helper_aggregate_share.get_encoded());

                (report_count, leader_aggregate_share, helper_aggregate_share)
            }
            CollectionJobState::Abandoned | CollectionJobState::Deleted => (None, None, None),
        };

        let stmt = self
            .prepare_cached(
                "UPDATE collection_jobs SET
                    state = $1,
                    report_count = $2,
                    leader_aggregate_share = $3,
                    helper_aggregate_share = $4
                WHERE collection_job_id = $5",
            )
            .await?;

        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* state */ &collection_job.state().collection_job_state_code(),
                    /* report_count */ &report_count,
                    /* leader_aggregate_share */ &leader_aggregate_share,
                    /* helper_aggregate_share */ &helper_aggregate_share,
                    /* collection_job_id */ &collection_job.collection_job_id().as_ref(),
                ],
            )
            .await?,
        )
    }

    pub async fn get_batch_aggregation<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        task_id: &TaskId,
        batch_identifier: &Q::BatchIdentifier,
        aggregation_parameter: &A::AggregationParam,
    ) -> Result<Option<BatchAggregation<L, Q, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT aggregate_share, report_count, checksum
                FROM batch_aggregations
                WHERE
                    task_id = (SELECT id FROM tasks WHERE task_id = $1)
                    AND batch_identifier = $2
                    AND aggregation_param = $3",
            )
            .await?;

        self.query_opt(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* batch_identifier */ &batch_identifier.get_encoded(),
                /* aggregation_param */ &aggregation_parameter.get_encoded(),
            ],
        )
        .await?
        .map(|row| {
            Self::batch_aggregation_from_row(
                *task_id,
                batch_identifier.clone(),
                aggregation_parameter.clone(),
                row,
            )
        })
        .transpose()
    }

    #[cfg(feature = "test-util")]
    pub async fn get_batch_aggregations_for_task<
        const L: usize,
        Q: QueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<BatchAggregation<L, Q, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    batch_identifier, aggregation_param, aggregate_share, report_count, checksum
                FROM batch_aggregations
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;

        self.query(&stmt, &[/* task_id */ &task_id.as_ref()])
            .await?
            .into_iter()
            .map(|row| {
                let batch_identifier =
                    Q::BatchIdentifier::get_decoded(row.get("batch_identifier"))?;
                let aggregation_param =
                    A::AggregationParam::get_decoded(row.get("aggregation_param"))?;

                Self::batch_aggregation_from_row(*task_id, batch_identifier, aggregation_param, row)
            })
            .collect()
    }

    fn batch_aggregation_from_row<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        task_id: TaskId,
        batch_identifier: Q::BatchIdentifier,
        aggregation_parameter: A::AggregationParam,
        row: Row,
    ) -> Result<BatchAggregation<L, Q, A>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let aggregate_share = row.get_bytea_and_convert("aggregate_share")?;
        let report_count = row.get_bigint_and_convert("report_count")?;
        let checksum = ReportIdChecksum::get_decoded(row.get("checksum"))?;

        Ok(BatchAggregation::new(
            task_id,
            batch_identifier,
            aggregation_parameter,
            aggregate_share,
            report_count,
            checksum,
        ))
    }

    /// Store a new `batch_aggregations` row in the datastore.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_batch_aggregation<
        const L: usize,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        batch_aggregation: &BatchAggregation<L, Q, A>,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Encode + std::fmt::Debug,
        A::AggregateShare: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let batch_interval =
            Q::to_batch_interval(batch_aggregation.batch_identifier()).map(SqlInterval::from);

        let stmt = self
            .prepare_cached(
                "INSERT INTO batch_aggregations (
                    task_id, batch_identifier, batch_interval, aggregation_param, aggregate_share,
                    report_count, checksum
                ) VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6, $7)",
            )
            .await?;
        self.execute(
            &stmt,
            &[
                /* task_id */ &batch_aggregation.task_id().as_ref(),
                /* batch_identifier */
                &batch_aggregation.batch_identifier().get_encoded(),
                /* batch_interval */ &batch_interval,
                /* aggregation_param */
                &batch_aggregation.aggregation_parameter().get_encoded(),
                /* aggregate_share */ &batch_aggregation.aggregate_share().into(),
                /* report_count */
                &i64::try_from(batch_aggregation.report_count())?,
                /* checksum */ &batch_aggregation.checksum().get_encoded(),
            ],
        )
        .await?;

        Ok(())
    }

    /// Update an existing `batch_aggregations` row with the values from the provided batch
    /// aggregation.
    #[tracing::instrument(skip(self), err)]
    pub async fn update_batch_aggregation<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        batch_aggregation: &BatchAggregation<L, Q, A>,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Encode + std::fmt::Debug,
        A::AggregateShare: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "UPDATE batch_aggregations
                SET aggregate_share = $1, report_count = $2, checksum = $3
                WHERE
                    task_id = (SELECT id from TASKS WHERE task_id = $4)
                    AND batch_identifier = $5
                    AND aggregation_param = $6",
            )
            .await?;
        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* aggregate_share */
                    &batch_aggregation.aggregate_share().into(),
                    /* report_count */
                    &i64::try_from(batch_aggregation.report_count())?,
                    /* checksum */ &batch_aggregation.checksum().get_encoded(),
                    /* task_id */ &batch_aggregation.task_id().as_ref(),
                    /* batch_identifier */
                    &batch_aggregation.batch_identifier().get_encoded(),
                    /* aggregation_param */
                    &batch_aggregation.aggregation_parameter().get_encoded(),
                ],
            )
            .await?,
        )?;

        Ok(())
    }

    /// Fetch an [`AggregateShareJob`] from the datastore corresponding to given parameters, or
    /// `None` if no such job exists.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregate_share_job<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        task_id: &TaskId,
        batch_identifier: &Q::BatchIdentifier,
        aggregation_parameter: &A::AggregationParam,
    ) -> Result<Option<AggregateShareJob<L, Q, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT helper_aggregate_share, report_count, checksum FROM aggregate_share_jobs
                WHERE
                    task_id = (SELECT id FROM tasks WHERE task_id = $1)
                    AND batch_identifier = $2
                    AND aggregation_param = $3",
            )
            .await?;
        self.query_opt(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* batch_identifier */ &batch_identifier.get_encoded(),
                /* aggregation_param */ &aggregation_parameter.get_encoded(),
            ],
        )
        .await?
        .map(|row| {
            Self::aggregate_share_job_from_row(
                task_id,
                batch_identifier.clone(),
                aggregation_parameter.clone(),
                &row,
            )
        })
        .transpose()
    }

    /// Returns all aggregate share jobs for the given task which include the given timestamp.
    /// Applies only to time-interval tasks.
    pub async fn get_aggregate_share_jobs_including_time<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        task_id: &TaskId,
        timestamp: &Time,
    ) -> Result<Vec<AggregateShareJob<L, TimeInterval, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    aggregate_share_jobs.batch_identifier,
                    aggregate_share_jobs.aggregation_param,
                    aggregate_share_jobs.helper_aggregate_share,
                    aggregate_share_jobs.report_count,
                    aggregate_share_jobs.checksum
                FROM aggregate_share_jobs JOIN tasks ON tasks.id = aggregate_share_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregate_share_jobs.batch_interval @> $2::TIMESTAMP",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* timestamp */ &timestamp.as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let batch_identifier = Interval::get_decoded(row.get("batch_identifier"))?;
            let aggregation_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
            Self::aggregate_share_job_from_row(task_id, batch_identifier, aggregation_param, &row)
        })
        .collect()
    }

    /// Returns all aggregate share jobs for the given task whose collect intervals intersect with
    /// the given interval. Applies only to time-interval tasks.
    pub async fn get_aggregate_share_jobs_intersecting_interval<
        const L: usize,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: &TaskId,
        interval: &Interval,
    ) -> Result<Vec<AggregateShareJob<L, TimeInterval, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    aggregate_share_jobs.batch_identifier,
                    aggregate_share_jobs.aggregation_param,
                    aggregate_share_jobs.helper_aggregate_share,
                    aggregate_share_jobs.report_count,
                    aggregate_share_jobs.checksum
                FROM aggregate_share_jobs JOIN tasks ON tasks.id = aggregate_share_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregate_share_jobs.batch_interval && $2",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* interval */ &SqlInterval::from(interval),
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let batch_identifier = Interval::get_decoded(row.get("batch_identifier"))?;
            let aggregation_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
            Self::aggregate_share_job_from_row(task_id, batch_identifier, aggregation_param, &row)
        })
        .collect()
    }

    /// Returns all aggregate share jobs for the given task with the given batch identifier.
    /// Multiple aggregate share jobs may be returned with distinct aggregation parameters.
    pub async fn get_aggregate_share_jobs_by_batch_identifier<
        const L: usize,
        Q: QueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: &TaskId,
        batch_identifier: &Q::BatchIdentifier,
    ) -> Result<Vec<AggregateShareJob<L, Q, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    aggregate_share_jobs.aggregation_param,
                    aggregate_share_jobs.helper_aggregate_share,
                    aggregate_share_jobs.report_count,
                    aggregate_share_jobs.checksum
                FROM aggregate_share_jobs JOIN tasks ON tasks.id = aggregate_share_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregate_share_jobs.batch_identifier = $2",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* batch_identifier */ &batch_identifier.get_encoded(),
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let aggregation_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
            Self::aggregate_share_job_from_row(
                task_id,
                batch_identifier.clone(),
                aggregation_param,
                &row,
            )
        })
        .collect()
    }

    #[cfg(feature = "test-util")]
    pub async fn get_aggregate_share_jobs_for_task<
        const L: usize,
        Q: QueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<AggregateShareJob<L, Q, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    aggregate_share_jobs.batch_identifier,
                    aggregate_share_jobs.aggregation_param,
                    aggregate_share_jobs.helper_aggregate_share,
                    aggregate_share_jobs.report_count,
                    aggregate_share_jobs.checksum
                FROM aggregate_share_jobs JOIN tasks ON tasks.id = aggregate_share_jobs.task_id
                WHERE tasks.task_id = $1",
            )
            .await?;
        self.query(&stmt, &[/* task_id */ &task_id.as_ref()])
            .await?
            .into_iter()
            .map(|row| {
                let batch_identifier =
                    Q::BatchIdentifier::get_decoded(row.get("batch_identifier"))?;
                let aggregation_param =
                    A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
                Self::aggregate_share_job_from_row(
                    task_id,
                    batch_identifier,
                    aggregation_param,
                    &row,
                )
            })
            .collect()
    }

    fn aggregate_share_job_from_row<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        task_id: &TaskId,
        batch_identifier: Q::BatchIdentifier,
        aggregation_param: A::AggregationParam,
        row: &Row,
    ) -> Result<AggregateShareJob<L, Q, A>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        Ok(AggregateShareJob::new(
            *task_id,
            batch_identifier,
            aggregation_param,
            row.get_bytea_and_convert("helper_aggregate_share")?,
            row.get_bigint_and_convert("report_count")?,
            ReportIdChecksum::get_decoded(row.get("checksum"))?,
        ))
    }

    /// Put an `aggregate_share_job` row into the datastore.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_aggregate_share_job<
        const L: usize,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        job: &AggregateShareJob<L, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    {
        let batch_interval = Q::to_batch_interval(job.batch_identifier()).map(SqlInterval::from);

        let stmt = self
            .prepare_cached(
                "INSERT INTO aggregate_share_jobs (
                    task_id, batch_identifier, batch_interval, aggregation_param,
                    helper_aggregate_share, report_count, checksum
                )
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6, $7)",
            )
            .await?;
        self.execute(
            &stmt,
            &[
                /* task_id */ &job.task_id().as_ref(),
                /* batch_identifier */ &job.batch_identifier().get_encoded(),
                /* batch_interval */ &batch_interval,
                /* aggregation_param */ &job.aggregation_parameter().get_encoded(),
                /* helper_aggregate_share */ &job.helper_aggregate_share().into(),
                /* report_count */ &i64::try_from(job.report_count())?,
                /* checksum */ &job.checksum().get_encoded(),
            ],
        )
        .await?;

        Ok(())
    }

    /// Writes an outstanding batch. (This method does not take an [`OutstandingBatch`] as several
    /// of the included values are read implicitly.)
    pub async fn put_outstanding_batch(
        &self,
        task_id: &TaskId,
        batch_id: &BatchId,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "INSERT INTO outstanding_batches (task_id, batch_id)
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2)",
            )
            .await?;

        self.execute(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* batch_id */ batch_id.as_ref(),
            ],
        )
        .await?;

        Ok(())
    }

    /// Retrieves all [`OutstandingBatch`]es for a given task.
    pub async fn get_outstanding_batches_for_task(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<OutstandingBatch>, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT batch_id FROM outstanding_batches
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;

        try_join_all(
            self.query(&stmt, &[/* task_id */ task_id.as_ref()])
                .await?
                .into_iter()
                .map(|row| async move {
                    let batch_id = BatchId::get_decoded(row.get("batch_id"))?;
                    let size = self.read_batch_size(task_id, &batch_id).await?;
                    Ok(OutstandingBatch::new(*task_id, batch_id, size))
                }),
        )
        .await
    }

    // Return value is an inclusive range [min_size, max_size], where:
    //  * min_size is the minimum possible number of reports included in the batch, i.e. all report
    //    aggregations in the batch which have reached the FINISHED state.
    //  * max_size is the maximum possible number of reports included in the batch, i.e. all report
    //    aggregations in the batch which are in a non-failure state (START/WAITING/FINISHED).
    async fn read_batch_size(
        &self,
        task_id: &TaskId,
        batch_id: &BatchId,
    ) -> Result<RangeInclusive<usize>, Error> {
        let stmt = self
            .prepare_cached(
                "WITH batch_report_aggregation_statuses AS
                    (SELECT report_aggregations.state, COUNT(*) AS count FROM report_aggregations
                     JOIN aggregation_jobs ON report_aggregations.aggregation_job_id = aggregation_jobs.id
                     WHERE aggregation_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                     AND aggregation_jobs.batch_id = $2
                     GROUP BY report_aggregations.state)
                SELECT
                    (SELECT SUM(count)::BIGINT FROM batch_report_aggregation_statuses
                     WHERE state IN ('FINISHED')) AS min_size,
                    (SELECT SUM(count)::BIGINT FROM batch_report_aggregation_statuses
                     WHERE state IN ('START', 'WAITING', 'FINISHED')) AS max_size"
            )
            .await?;

        let row = self
            .query_one(
                &stmt,
                &[
                    /* task_id */ task_id.as_ref(),
                    /* batch_id */ batch_id.as_ref(),
                ],
            )
            .await?;

        Ok(RangeInclusive::new(
            row.get::<_, Option<i64>>("min_size")
                .unwrap_or_default()
                .try_into()?,
            row.get::<_, Option<i64>>("max_size")
                .unwrap_or_default()
                .try_into()?,
        ))
    }

    /// Deletes an outstanding batch.
    pub async fn delete_outstanding_batch(
        &self,
        task_id: &TaskId,
        batch_id: &BatchId,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "DELETE FROM outstanding_batches
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)
                  AND batch_id = $2",
            )
            .await?;

        self.execute(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* batch_id */ batch_id.as_ref(),
            ],
        )
        .await?;
        Ok(())
    }

    /// Retrieves an outstanding batch for the given task with at least the given number of
    /// successfully-aggregated reports.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_filled_outstanding_batch(
        &self,
        task_id: &TaskId,
        min_report_count: u64,
    ) -> Result<Option<BatchId>, Error> {
        let stmt = self
            .prepare_cached(
                "WITH batches AS (
                    SELECT
                        outstanding_batches.batch_id AS batch_id,
                        COUNT(DISTINCT report_aggregations.client_report_id) AS count
                    FROM outstanding_batches
                    JOIN aggregation_jobs
                      ON aggregation_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                     AND aggregation_jobs.batch_id = outstanding_batches.batch_id
                    JOIN report_aggregations
                      ON report_aggregations.aggregation_job_id = aggregation_jobs.id
                     AND report_aggregations.state = 'FINISHED'
                    GROUP BY outstanding_batches.batch_id
                )
                SELECT batch_id FROM batches WHERE count >= $2 LIMIT 1",
            )
            .await?;
        self.query_opt(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* min_report_count */ &i64::try_from(min_report_count)?,
            ],
        )
        .await?
        .map(|row| Ok(BatchId::get_decoded(row.get("batch_id"))?))
        .transpose()
    }

    /// Deletes old client reports for a given task, that is, client reports whose timestamp is
    /// older than a given timestamp which are not included in any report aggregations.
    #[tracing::instrument(skip(self), err)]
    pub async fn delete_expired_client_reports(
        &self,
        task_id: &TaskId,
        oldest_allowed_report_timestamp: Time,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "DELETE FROM client_reports
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1) AND client_timestamp < $2
                AND NOT EXISTS(
                    SELECT FROM report_aggregations
                    WHERE report_aggregations.client_report_id = client_reports.id)",
            )
            .await?;
        self.execute(
            &stmt,
            &[
                /* task_id */ &task_id.get_encoded(),
                /* client_timestamp */
                &oldest_allowed_report_timestamp.as_naive_date_time()?,
            ],
        )
        .await?;
        Ok(())
    }

    /// Deletes old aggregation artifacts (aggregation jobs/report aggregations/batch aggregations)
    /// for a given task, that is, aggregation artifacts for which all associated client reports
    /// have timestamps older than a given timestamp, and which are not included in any collection
    /// artifacts.
    ///
    /// After calling this function, delete_expired_client_reports must be called in the same
    /// transaction to avoid re-aggregating client reports.
    #[tracing::instrument(skip(self), err)]
    pub async fn delete_expired_aggregation_artifacts(
        &self,
        task_id: &TaskId,
        oldest_allowed_report_timestamp: Time,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "WITH aggregation_jobs_to_delete AS (
                    SELECT id FROM aggregation_jobs
                    WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)
                      AND UPPER(client_timestamp_interval) <= $2
                      AND NOT EXISTS (
                          SELECT id FROM collection_jobs
                          WHERE aggregation_jobs.task_id = collection_jobs.task_id
                            AND (aggregation_jobs.batch_id = collection_jobs.batch_identifier
                              OR aggregation_jobs.client_timestamp_interval && collection_jobs.batch_interval))
                      AND NOT EXISTS (
                          SELECT id FROM aggregate_share_jobs
                          WHERE aggregation_jobs.task_id = aggregate_share_jobs.task_id
                            AND (aggregation_jobs.batch_id = aggregate_share_jobs.batch_identifier
                              OR aggregation_jobs.client_timestamp_interval && aggregate_share_jobs.batch_interval)
                      )
                      AND NOT EXISTS (
                          SELECT id FROM outstanding_batches
                          WHERE aggregation_jobs.task_id = outstanding_batches.task_id
                            AND aggregation_jobs.batch_id = outstanding_batches.batch_id)
                ),
                deleted_report_aggregations AS (
                    DELETE FROM report_aggregations
                    WHERE report_aggregations.aggregation_job_id IN (
                        SELECT id FROM aggregation_jobs_to_delete)
                ),
                deleted_batch_aggregations AS (
                    DELETE FROM batch_aggregations
                    WHERE
                        (
                            batch_aggregations.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                            AND UPPER(batch_aggregations.batch_interval) <= $2
                            AND NOT EXISTS (
                                SELECT id FROM collection_jobs
                                WHERE batch_aggregations.task_id = collection_jobs.task_id
                                    AND (batch_aggregations.batch_identifier = collection_jobs.batch_identifier
                                      OR batch_aggregations.batch_interval <@ collection_jobs.batch_interval))
                            AND NOT EXISTS (
                                SELECT id FROM aggregate_share_jobs
                                WHERE batch_aggregations.task_id = aggregate_share_jobs.task_id
                                    AND (batch_aggregations.batch_identifier = aggregate_share_jobs.batch_identifier
                                    OR batch_aggregations.batch_interval <@ aggregate_share_jobs.batch_interval)
                            )
                            AND NOT EXISTS (
                                SELECT id FROM outstanding_batches
                                WHERE batch_aggregations.task_id = outstanding_batches.task_id
                                    AND batch_aggregations.batch_identifier = outstanding_batches.batch_id)
                        ) OR batch_aggregations.batch_identifier IN (
                            SELECT batch_id FROM aggregation_jobs
                            WHERE aggregation_jobs.id IN (SELECT id FROM aggregation_jobs_to_delete)
                        )
                )
                DELETE FROM aggregation_jobs
                WHERE id IN (SELECT id FROM aggregation_jobs_to_delete)",
            )
            .await?;
        self.execute(
            &stmt,
            &[
                /* task_id */ &task_id.get_encoded(),
                /* client_timestamp */
                &oldest_allowed_report_timestamp.as_naive_date_time()?,
            ],
        )
        .await?;
        Ok(())
    }

    /// Deletes old collection artifacts (collection jobs/aggregate share jobs/outstanding batches) for
    /// a given task, that is, collection artifacts for which all associated client reports have
    /// timestamps older than a given timestamp.
    ///
    /// After calling this function, delete_expired_aggregation_artifacts must be called in the same
    /// transaction to avoid re-collecting old aggregations.
    #[tracing::instrument(skip(self), err)]
    pub async fn delete_expired_collection_artifacts(
        &self,
        task_id: &TaskId,
        oldest_allowed_report_timestamp: Time,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "WITH collection_jobs_to_delete AS (
                    SELECT id FROM collection_jobs
                    JOIN (
                        SELECT
                            collection_jobs.id AS collection_job_id,
                            MAX(UPPER(aggregation_jobs.client_timestamp_interval)) AS max_timestamp
                        FROM collection_jobs
                        JOIN aggregation_jobs
                            ON aggregation_jobs.task_id = collection_jobs.task_id
                            AND (aggregation_jobs.batch_id = collection_jobs.batch_identifier
                              OR aggregation_jobs.client_timestamp_interval && collection_jobs.batch_interval)
                        GROUP BY collection_jobs.id
                    ) report_max_timestamps
                        ON report_max_timestamps.collection_job_id = collection_jobs.id
                    WHERE collection_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                        AND report_max_timestamps.max_timestamp <= $2
                ),
                aggregate_share_jobs_to_delete AS (
                    SELECT id FROM aggregate_share_jobs
                    JOIN (
                        SELECT
                            aggregate_share_jobs.id AS aggregate_share_job_id,
                            MAX(UPPER(aggregation_jobs.client_timestamp_interval)) AS max_timestamp
                        FROM aggregate_share_jobs
                        JOIN aggregation_jobs
                            ON aggregation_jobs.task_id = aggregate_share_jobs.task_id
                            AND (aggregation_jobs.batch_id = aggregate_share_jobs.batch_identifier
                              OR aggregation_jobs.client_timestamp_interval && aggregate_share_jobs.batch_interval)
                        GROUP BY aggregate_share_jobs.id
                    ) report_max_timestamps
                        ON report_max_timestamps.aggregate_share_job_id = aggregate_share_jobs.id
                    WHERE aggregate_share_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                      AND report_max_timestamps.max_timestamp <= $2
                ),
                deleted_aggregate_share_jobs AS (
                    DELETE FROM aggregate_share_jobs
                    WHERE id IN (SELECT id FROM aggregate_share_jobs_to_delete)
                ),
                outstanding_batches_to_delete AS (
                    SELECT id FROM outstanding_batches
                    JOIN (
                        SELECT
                            outstanding_batches.batch_id,
                            MAX(UPPER(aggregation_jobs.client_timestamp_interval)) AS max_timestamp
                        FROM outstanding_batches
                        JOIN aggregation_jobs
                            ON aggregation_jobs.task_id = outstanding_batches.task_id
                           AND aggregation_jobs.batch_id = outstanding_batches.batch_id
                        GROUP BY outstanding_batches.batch_id
                    ) report_max_timestamps
                        ON report_max_timestamps.batch_id = outstanding_batches.batch_id
                    WHERE outstanding_batches.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                      AND report_max_timestamps.max_timestamp <= $2
                ),
                deleted_outstanding_batches AS (
                    DELETE FROM outstanding_batches
                    WHERE id IN (SELECT id FROM outstanding_batches_to_delete)
                )
                DELETE FROM collection_jobs WHERE id IN (SELECT id FROM collection_jobs_to_delete)",
            )
            .await?;
        self.execute(
            &stmt,
            &[
                /* task_id */ &task_id.get_encoded(),
                /* client_timestamp */
                &oldest_allowed_report_timestamp.as_naive_date_time()?,
            ],
        )
        .await?;
        Ok(())
    }
}

fn check_single_row_mutation(row_count: u64) -> Result<(), Error> {
    match row_count {
        0 => Err(Error::MutationTargetNotFound),
        1 => Ok(()),
        _ => panic!(
            "update which should have affected at most one row instead affected {row_count} rows"
        ),
    }
}

/// Add a [`std::time::Duration`] to a [`chrono::NaiveDateTime`].
fn add_naive_date_time_duration(
    time: &NaiveDateTime,
    duration: &StdDuration,
) -> Result<NaiveDateTime, Error> {
    time.checked_add_signed(
        chrono::Duration::from_std(*duration)
            .map_err(|_| Error::TimeOverflow("overflow converting duration to signed duration"))?,
    )
    .ok_or(Error::TimeOverflow("overflow adding duration to time"))
}

/// Extensions for [`tokio_postgres::row::Row`]
trait RowExt {
    /// Get a PostgreSQL `BIGINT` from the row, which is represented in Rust as
    /// i64 ([1]), then attempt to convert it to the desired integer type `T`.
    ///
    /// [1]: https://docs.rs/postgres-types/latest/postgres_types/trait.FromSql.html
    fn get_bigint_and_convert<I, T>(&self, idx: I) -> Result<T, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>;

    /// Like [`Self::get_bigint_and_convert`] but handles nullable columns.
    fn get_nullable_bigint_and_convert<I, T>(&self, idx: I) -> Result<Option<T>, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>;

    /// Get a PostgreSQL `BYTEA` from the row and then attempt to convert it to
    /// u64, treating it as an 8 byte big endian array.
    fn get_bytea_as_u64<I>(&self, idx: I) -> Result<u64, Error>
    where
        I: RowIndex + Display;

    /// Get a PostgreSQL `BYTEA` from the row and attempt to convert it to `T`.
    fn get_bytea_and_convert<T>(&self, idx: &'static str) -> Result<T, Error>
    where
        for<'a> T: TryFrom<&'a [u8]>,
        for<'a> <T as TryFrom<&'a [u8]>>::Error: std::fmt::Debug;
}

impl RowExt for Row {
    fn get_bigint_and_convert<I, T>(&self, idx: I) -> Result<T, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>,
    {
        let bigint: i64 = self.try_get(idx)?;
        Ok(T::try_from(bigint)?)
    }

    fn get_nullable_bigint_and_convert<I, T>(&self, idx: I) -> Result<Option<T>, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>,
    {
        let bigint: Option<i64> = self.try_get(idx)?;
        Ok(bigint.map(|bigint| T::try_from(bigint)).transpose()?)
    }

    fn get_bytea_as_u64<I>(&self, idx: I) -> Result<u64, Error>
    where
        I: RowIndex + Display,
    {
        let encoded_u64: Vec<u8> = self.try_get(idx)?;

        // `u64::from_be_bytes` takes `[u8; 8]` and `Vec<u8>::try_into` will
        // fail unless the vector has exactly that length [1].
        //
        // [1]: https://doc.rust-lang.org/std/primitive.array.html#method.try_from-4
        Ok(u64::from_be_bytes(encoded_u64.try_into().map_err(
            // The error is just the vector that was rejected
            |_| Error::DbState("byte array in database does not have expected length".to_string()),
        )?))
    }

    fn get_bytea_and_convert<T>(&self, idx: &'static str) -> Result<T, Error>
    where
        for<'a> T: TryFrom<&'a [u8]>,
        for<'a> <T as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    {
        let encoded: Vec<u8> = self.try_get(idx)?;
        T::try_from(&encoded)
            .map_err(|err| Error::DbState(format!("{idx} stored in database is invalid: {err:?}")))
    }
}

/// A Crypter allows a Datastore to encrypt/decrypt sensitive values stored to the datastore. Values
/// are cryptographically bound to the specific location in the datastore in which they are stored.
/// Rollback protection is not provided.
pub struct Crypter {
    keys: Vec<LessSafeKey>,
}

impl Crypter {
    // The internal serialized format of a Crypter encrypted value is:
    //   ciphertext || tag || nonce
    // (the `ciphertext || tag` portion is as returned from `seal_in_place_append_tag`)

    /// Creates a new Crypter instance, using the given set of keys. The first key in the provided
    /// vector is considered to be the "primary" key, used for encryption operations; any of the
    /// provided keys can be used for decryption operations.
    ///
    /// The keys must be for the AES-128-GCM algorithm.
    pub fn new(keys: Vec<LessSafeKey>) -> Self {
        assert!(!keys.is_empty());
        for key in &keys {
            assert_eq!(key.algorithm(), &AES_128_GCM);
        }
        Self { keys }
    }

    fn encrypt(
        &self,
        table: &str,
        row: &[u8],
        column: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // It is safe to unwrap the key because we have already validated that keys is nonempty
        // in Crypter::new.
        Self::encrypt_with_key(self.keys.first().unwrap(), table, row, column, value)
    }

    fn encrypt_with_key(
        key: &LessSafeKey,
        table: &str,
        row: &[u8],
        column: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Generate a random nonce, compute AAD.
        let nonce_bytes: [u8; aead::NONCE_LEN] = random();
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let aad = aead::Aad::from(Self::aad_bytes_for(table, row, column)?);

        // Encrypt, append nonce.
        let mut result = value.to_vec();
        key.seal_in_place_append_tag(nonce, aad, &mut result)?;
        result.extend(nonce_bytes);
        Ok(result)
    }

    fn decrypt(
        &self,
        table: &str,
        row: &[u8],
        column: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if value.len() < aead::NONCE_LEN {
            return Err(Error::Crypt);
        }

        // TODO(https://github.com/rust-lang/rust/issues/90091): use `rsplit_array_ref` once it is stabilized.
        let (ciphertext_and_tag, nonce_bytes) = value.split_at(value.len() - aead::NONCE_LEN);
        let nonce_bytes: [u8; aead::NONCE_LEN] = nonce_bytes.try_into().unwrap();
        let aad_bytes = Self::aad_bytes_for(table, row, column)?;

        for key in &self.keys {
            let mut ciphertext_and_tag = ciphertext_and_tag.to_vec();
            if let Ok(plaintext) = key.open_in_place(
                aead::Nonce::assume_unique_for_key(nonce_bytes),
                aead::Aad::from(aad_bytes.clone()),
                &mut ciphertext_and_tag,
            ) {
                let len = plaintext.len();
                ciphertext_and_tag.truncate(len);
                return Ok(ciphertext_and_tag);
            }
        }
        Err(Error::Crypt)
    }

    fn aad_bytes_for(table: &str, row: &[u8], column: &str) -> Result<Vec<u8>, Error> {
        // AAD computation is based on (table, row, column).
        // The serialized AAD is:
        //   (length of table) || table || (length of row) || row || (length of column) || column.
        // Lengths are expressed as 8-byte unsigned integers.

        let aad_length = 3 * size_of::<u64>() + table.len() + row.len() + column.len();
        let mut aad_bytes = Vec::with_capacity(aad_length);
        aad_bytes.extend_from_slice(&u64::try_from(table.len())?.to_be_bytes());
        aad_bytes.extend_from_slice(table.as_ref());
        aad_bytes.extend_from_slice(&u64::try_from(row.len())?.to_be_bytes());
        aad_bytes.extend_from_slice(row);
        aad_bytes.extend_from_slice(&u64::try_from(column.len())?.to_be_bytes());
        aad_bytes.extend_from_slice(column.as_ref());
        assert_eq!(aad_bytes.len(), aad_length);

        Ok(aad_bytes)
    }
}

/// Error represents a datastore-level error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the underlying database library.
    #[error("DB error: {0}")]
    Db(#[from] tokio_postgres::Error),
    #[error("DB pool error: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),
    #[error("crypter error")]
    Crypt,
    /// An attempt was made to mutate an entity that does not exist.
    #[error("not found in datastore")]
    MutationTargetNotFound,
    /// An attempt was made to insert an entity that already existed.
    #[error("already in datastore")]
    MutationTargetAlreadyExisted,
    /// The database was in an unexpected state.
    #[error("inconsistent database state: {0}")]
    DbState(String),
    /// An error from decoding a value stored encoded in the underlying database.
    #[error("decoding error: {0}")]
    Decode(#[from] CodecError),
    #[error("base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// An arbitrary error returned from the user callback; unrelated to DB internals. This error
    /// will never be generated by the datastore library itself.
    #[error(transparent)]
    User(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("invalid task parameters: {0}")]
    Task(#[from] task::Error),
    #[error("integer conversion failed: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Message(#[from] janus_messages::Error),
    /// An invalid parameter was provided.
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
    /// An error occurred while manipulating timestamps or durations.
    #[error("{0}")]
    TimeOverflow(&'static str),
}

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::Crypt
    }
}

/// This module contains models used by the datastore that are not DAP messages.
pub mod models {
    use super::Error;
    use crate::{
        messages::{DurationExt, IntervalExt, TimeExt},
        task,
    };
    use base64::{display::Base64Display, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::NaiveDateTime;
    use derivative::Derivative;
    use janus_core::{report_id::ReportIdChecksumExt, task::VdafInstance};
    use janus_messages::{
        query_type::{FixedSize, QueryType, TimeInterval},
        AggregationJobId, BatchId, CollectionJobId, Duration, Extension, HpkeCiphertext, Interval,
        ReportId, ReportIdChecksum, ReportMetadata, ReportShareError, Role, TaskId, Time,
    };
    use postgres_protocol::types::{
        range_from_sql, range_to_sql, timestamp_from_sql, timestamp_to_sql, Range, RangeBound,
    };
    use postgres_types::{accepts, to_sql_checked, FromSql, ToSql};
    use prio::{
        codec::Encode,
        vdaf::{self, Aggregatable},
    };
    use rand::{distributions::Standard, prelude::Distribution};
    use std::fmt::{Debug, Formatter};
    use std::{fmt::Display, ops::RangeInclusive};

    // We have to manually implement [Partial]Eq for a number of types because the derived
    // implementations don't play nice with generic fields, even if those fields are constrained to
    // themselves implement [Partial]Eq.

    /// Represents a report as it is stored in the leader's database, corresponding to a row in
    /// `client_reports`, where `leader_input_share` and `helper_encrypted_input_share` are required
    /// to be populated.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub struct LeaderStoredReport<const L: usize, A>
    where
        A: vdaf::Aggregator<L>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        task_id: TaskId,
        metadata: ReportMetadata,
        #[derivative(Debug = "ignore")]
        public_share: A::PublicShare,
        leader_extensions: Vec<Extension>,
        #[derivative(Debug = "ignore")]
        leader_input_share: A::InputShare,
        #[derivative(Debug = "ignore")]
        helper_encrypted_input_share: HpkeCiphertext,
    }

    impl<const L: usize, A> LeaderStoredReport<L, A>
    where
        A: vdaf::Aggregator<L>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub fn new(
            task_id: TaskId,
            metadata: ReportMetadata,
            public_share: A::PublicShare,
            leader_extensions: Vec<Extension>,
            leader_input_share: A::InputShare,
            helper_encrypted_input_share: HpkeCiphertext,
        ) -> Self {
            Self {
                task_id,
                metadata,
                public_share,
                leader_extensions,
                leader_input_share,
                helper_encrypted_input_share,
            }
        }

        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        pub fn metadata(&self) -> &ReportMetadata {
            &self.metadata
        }

        pub fn public_share(&self) -> &A::PublicShare {
            &self.public_share
        }

        pub fn leader_extensions(&self) -> &[Extension] {
            &self.leader_extensions
        }

        pub fn leader_input_share(&self) -> &A::InputShare {
            &self.leader_input_share
        }

        pub fn helper_encrypted_input_share(&self) -> &HpkeCiphertext {
            &self.helper_encrypted_input_share
        }
    }

    impl<const L: usize, A> PartialEq for LeaderStoredReport<L, A>
    where
        A: vdaf::Aggregator<L>,
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.metadata == other.metadata
                && self.public_share == other.public_share
                && self.leader_extensions == other.leader_extensions
                && self.leader_input_share == other.leader_input_share
                && self.helper_encrypted_input_share == other.helper_encrypted_input_share
        }
    }

    impl<const L: usize, A> Eq for LeaderStoredReport<L, A>
    where
        A: vdaf::Aggregator<L>,
        A::InputShare: Eq,
        A::PublicShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    #[cfg(test)]
    impl LeaderStoredReport<0, janus_core::test_util::dummy_vdaf::Vdaf> {
        pub fn new_dummy(task_id: TaskId, when: Time) -> Self {
            use janus_messages::HpkeConfigId;
            use rand::random;

            Self::new(
                task_id,
                ReportMetadata::new(random(), when),
                (),
                Vec::new(),
                (),
                HpkeCiphertext::new(
                    HpkeConfigId::from(13),
                    Vec::from("encapsulated_context_0"),
                    Vec::from("payload_0"),
                ),
            )
        }
    }

    /// AggregatorRole corresponds to the `AGGREGATOR_ROLE` enum in the schema.
    #[derive(Clone, Debug, ToSql, FromSql)]
    #[postgres(name = "aggregator_role")]
    pub enum AggregatorRole {
        #[postgres(name = "LEADER")]
        Leader,
        #[postgres(name = "HELPER")]
        Helper,
    }

    impl AggregatorRole {
        /// If the provided [`Role`] is an aggregator, returns the corresponding
        /// [`AggregatorRole`], or `None` otherwise.
        pub(super) fn from_role(role: Role) -> Result<Self, Error> {
            match role {
                Role::Leader => Ok(Self::Leader),
                Role::Helper => Ok(Self::Helper),
                _ => Err(Error::Task(task::Error::InvalidParameter(
                    "role is not an aggregator",
                ))),
            }
        }

        /// Returns the [`Role`] corresponding to this value.
        pub(super) fn as_role(&self) -> Role {
            match self {
                Self::Leader => Role::Leader,
                Self::Helper => Role::Helper,
            }
        }
    }

    /// AggregationJob represents an aggregation job from the DAP specification.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub struct AggregationJob<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        #[derivative(Debug = "ignore")]
        aggregation_parameter: A::AggregationParam,
        batch_id: Q::PartialBatchIdentifier,
        client_timestamp_interval: Interval,
        state: AggregationJobState,
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> AggregationJob<L, Q, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Creates a new [`AggregationJob`].
        pub fn new(
            task_id: TaskId,
            aggregation_job_id: AggregationJobId,
            aggregation_parameter: A::AggregationParam,
            batch_id: Q::PartialBatchIdentifier,
            client_timestamp_interval: Interval,
            state: AggregationJobState,
        ) -> Self {
            Self {
                task_id,
                aggregation_job_id,
                aggregation_parameter,
                batch_id,
                client_timestamp_interval,
                state,
            }
        }

        /// Returns the task ID associated with this aggregation job.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Returns the aggregation job ID associated with this aggregation job.
        pub fn id(&self) -> &AggregationJobId {
            &self.aggregation_job_id
        }

        /// Returns the aggregation parameter associated with this aggregation job.
        pub fn aggregation_parameter(&self) -> &A::AggregationParam {
            &self.aggregation_parameter
        }

        /// Gets the partial batch identifier associated with this aggregation job.
        ///
        /// This method would typically be used for code which is generic over the query type.
        /// Query-type specific code will typically call [`Self::batch_id`].
        pub fn partial_batch_identifier(&self) -> &Q::PartialBatchIdentifier {
            &self.batch_id
        }

        /// Returns the minimal interval containing all of the client timestamps associated with
        /// this aggregation job.
        pub fn client_timestamp_interval(&self) -> &Interval {
            &self.client_timestamp_interval
        }

        /// Returns the state of the aggregation job.
        pub fn state(&self) -> &AggregationJobState {
            &self.state
        }

        /// Returns a new [`AggregationJob`] corresponding to this aggregation job updated to have
        /// the given state.
        pub fn with_state(self, state: AggregationJobState) -> Self {
            AggregationJob { state, ..self }
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> AggregationJob<L, FixedSize, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Gets the batch ID associated with this aggregation job.
        pub fn batch_id(&self) -> &BatchId {
            self.partial_batch_identifier()
        }
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> PartialEq for AggregationJob<L, Q, A>
    where
        A::AggregationParam: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.aggregation_job_id == other.aggregation_job_id
                && self.aggregation_parameter == other.aggregation_parameter
                && self.batch_id == other.batch_id
                && self.client_timestamp_interval == other.client_timestamp_interval
                && self.state == other.state
        }
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> Eq for AggregationJob<L, Q, A>
    where
        A::AggregationParam: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// AggregationJobState represents the state of an aggregation job. It corresponds to the
    /// AGGREGATION_JOB_STATE enum in the schema.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, ToSql, FromSql)]
    #[postgres(name = "aggregation_job_state")]
    pub enum AggregationJobState {
        #[postgres(name = "IN_PROGRESS")]
        InProgress,
        #[postgres(name = "FINISHED")]
        Finished,
        #[postgres(name = "ABANDONED")]
        Abandoned,
    }

    /// LeaseToken represents an opaque value used to determine the identity of a lease.
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct LeaseToken([u8; Self::LEN]);

    impl LeaseToken {
        /// The length of a lease token in bytes.
        pub const LEN: usize = 16;
    }

    impl Debug for LeaseToken {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "LeaseToken({})",
                Base64Display::new(&self.0, &URL_SAFE_NO_PAD)
            )
        }
    }

    impl Display for LeaseToken {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", Base64Display::new(&self.0, &URL_SAFE_NO_PAD))
        }
    }

    impl<'a> TryFrom<&'a [u8]> for LeaseToken {
        type Error = &'static str;

        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            Ok(Self(value.try_into().map_err(|_| {
                "byte slice has incorrect length for LeaseToken"
            })?))
        }
    }

    impl AsRef<[u8; Self::LEN]> for LeaseToken {
        fn as_ref(&self) -> &[u8; Self::LEN] {
            &self.0
        }
    }

    impl Distribution<LeaseToken> for Standard {
        fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> LeaseToken {
            LeaseToken(rng.gen())
        }
    }

    /// Lease represents a time-constrained lease for exclusive access to some entity in Janus. It
    /// has an expiry after which it is no longer valid; another process can take a lease on the
    /// same entity after the expiration time.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Lease<T> {
        leased: T,
        lease_expiry_time: NaiveDateTime,
        lease_token: LeaseToken,
        lease_attempts: usize,
    }

    impl<T> Lease<T> {
        /// Creates a new [`Lease`].
        pub(super) fn new(
            leased: T,
            lease_expiry_time: NaiveDateTime,
            lease_token: LeaseToken,
            lease_attempts: usize,
        ) -> Self {
            Self {
                leased,
                lease_expiry_time,
                lease_token,
                lease_attempts,
            }
        }

        /// Create a new artificial lease with a random lease token, acquired for the first time;
        /// intended for use in unit tests.
        #[cfg(test)]
        pub fn new_dummy(leased: T, lease_expiry_time: NaiveDateTime) -> Self {
            use rand::random;
            Self {
                leased,
                lease_expiry_time,
                lease_token: random(),
                lease_attempts: 1,
            }
        }

        /// Returns a reference to the leased entity associated with this lease.
        pub fn leased(&self) -> &T {
            &self.leased
        }

        /// Returns the lease expiry time associated with this lease.
        pub fn lease_expiry_time(&self) -> &NaiveDateTime {
            &self.lease_expiry_time
        }

        /// Returns the lease token associated with this lease.
        pub fn lease_token(&self) -> &LeaseToken {
            &self.lease_token
        }

        /// Returns the number of lease acquiries since the last successful release.
        pub fn lease_attempts(&self) -> usize {
            self.lease_attempts
        }
    }

    /// AcquiredAggregationJob represents an incomplete aggregation job whose lease has been
    /// acquired.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct AcquiredAggregationJob {
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        query_type: task::QueryType,
        vdaf: VdafInstance,
    }

    impl AcquiredAggregationJob {
        /// Creates a new [`AcquiredAggregationJob`].
        pub fn new(
            task_id: TaskId,
            aggregation_job_id: AggregationJobId,
            query_type: task::QueryType,
            vdaf: VdafInstance,
        ) -> Self {
            Self {
                task_id,
                aggregation_job_id,
                query_type,
                vdaf,
            }
        }

        /// Returns the task ID associated with this acquired aggregation job.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Returns the aggregation job ID associated with this acquired aggregation job.
        pub fn aggregation_job_id(&self) -> &AggregationJobId {
            &self.aggregation_job_id
        }

        /// Returns the query type associated with this acquired aggregation job.
        pub fn query_type(&self) -> &task::QueryType {
            &self.query_type
        }

        /// Returns the VDAF associated with this acquired aggregation job.
        pub fn vdaf(&self) -> &VdafInstance {
            &self.vdaf
        }
    }

    /// AcquiredCollectionJob represents an incomplete collection job whose lease has been acquired.
    #[derive(Clone, Debug, PartialOrd, Ord, Eq, PartialEq)]
    pub struct AcquiredCollectionJob {
        task_id: TaskId,
        collection_job_id: CollectionJobId,
        query_type: task::QueryType,
        vdaf: VdafInstance,
    }

    impl AcquiredCollectionJob {
        /// Creates a new [`AcquiredCollectionJob`].
        pub fn new(
            task_id: TaskId,
            collection_job_id: CollectionJobId,
            query_type: task::QueryType,
            vdaf: VdafInstance,
        ) -> Self {
            Self {
                task_id,
                collection_job_id,
                query_type,
                vdaf,
            }
        }

        /// Returns the task ID associated with this acquired collection job.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Returns the collection job ID associated with this acquired collection job.
        pub fn collection_job_id(&self) -> &CollectionJobId {
            &self.collection_job_id
        }

        /// Returns the query type associated with this acquired collection job.
        pub fn query_type(&self) -> &task::QueryType {
            &self.query_type
        }

        /// Returns the VDAF associated with this acquired collection job.
        pub fn vdaf(&self) -> &VdafInstance {
            &self.vdaf
        }
    }

    /// ReportAggregation represents a the state of a single client report's ongoing aggregation.
    #[derive(Clone, Debug)]
    pub struct ReportAggregation<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        report_id: ReportId,
        time: Time,
        ord: i64,
        state: ReportAggregationState<L, A>,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> ReportAggregation<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Creates a new [`ReportAggregation`].
        pub fn new(
            task_id: TaskId,
            aggregation_job_id: AggregationJobId,
            report_id: ReportId,
            time: Time,
            ord: i64,
            state: ReportAggregationState<L, A>,
        ) -> Self {
            Self {
                task_id,
                aggregation_job_id,
                report_id,
                time,
                ord,
                state,
            }
        }

        /// Returns the task ID associated with this report aggregation.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Returns the aggregation job ID associated with this report aggregation.
        pub fn aggregation_job_id(&self) -> &AggregationJobId {
            &self.aggregation_job_id
        }

        /// Returns the report ID associated with this report aggregation.
        pub fn report_id(&self) -> &ReportId {
            &self.report_id
        }

        /// Returns the client timestamp associated with this report aggregation.
        pub fn time(&self) -> &Time {
            &self.time
        }

        /// Returns the order of this report aggregation in its batch.
        pub fn ord(&self) -> i64 {
            self.ord
        }

        /// Returns the state of the report aggregation.
        pub fn state(&self) -> &ReportAggregationState<L, A> {
            &self.state
        }

        /// Returns a new [`ReportAggregation`] corresponding to this aggregation job updated to
        /// have the given state.
        pub fn with_state(self, state: ReportAggregationState<L, A>) -> Self {
            Self { state, ..self }
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for ReportAggregation<L, A>
    where
        A::PrepareState: PartialEq,
        A::PrepareMessage: PartialEq,
        A::OutputShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.aggregation_job_id == other.aggregation_job_id
                && self.report_id == other.report_id
                && self.time == other.time
                && self.ord == other.ord
                && self.state == other.state
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for ReportAggregation<L, A>
    where
        A::PrepareState: Eq,
        A::PrepareMessage: Eq,
        A::OutputShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// ReportAggregationState represents the state of a single report aggregation. It corresponds
    /// to the REPORT_AGGREGATION_STATE enum in the schema, along with the state-specific data.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub enum ReportAggregationState<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        Start,
        Waiting(
            #[derivative(Debug = "ignore")] A::PrepareState,
            #[derivative(Debug = "ignore")] Option<A::PrepareMessage>,
        ),
        Finished(#[derivative(Debug = "ignore")] A::OutputShare),
        Failed(ReportShareError),
        Invalid,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> ReportAggregationState<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub(super) fn state_code(&self) -> ReportAggregationStateCode {
            match self {
                ReportAggregationState::Start => ReportAggregationStateCode::Start,
                ReportAggregationState::Waiting(_, _) => ReportAggregationStateCode::Waiting,
                ReportAggregationState::Finished(_) => ReportAggregationStateCode::Finished,
                ReportAggregationState::Failed(_) => ReportAggregationStateCode::Failed,
                ReportAggregationState::Invalid => ReportAggregationStateCode::Invalid,
            }
        }

        /// Returns the encoded values for the various messages which might be included in a
        /// ReportAggregationState. The order of returned values is preparation state, preparation
        /// message, output share, transition error.
        pub(super) fn encoded_values_from_state(&self) -> EncodedReportAggregationStateValues
        where
            A::PrepareState: Encode,
            for<'a> &'a A::OutputShare: Into<Vec<u8>>,
            for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        {
            let (prep_state, prep_msg, output_share, report_share_err) = match self {
                ReportAggregationState::Start => (None, None, None, None),
                ReportAggregationState::Waiting(prep_state, prep_msg) => (
                    Some(prep_state.get_encoded()),
                    prep_msg.as_ref().map(|msg| msg.get_encoded()),
                    None,
                    None,
                ),
                ReportAggregationState::Finished(output_share) => {
                    (None, None, Some(output_share.into()), None)
                }
                ReportAggregationState::Failed(report_share_err) => {
                    (None, None, None, Some(*report_share_err as i16))
                }
                ReportAggregationState::Invalid => (None, None, None, None),
            };
            EncodedReportAggregationStateValues {
                prep_state,
                prep_msg,
                output_share,
                report_share_err,
            }
        }
    }

    pub(super) struct EncodedReportAggregationStateValues {
        pub(super) prep_state: Option<Vec<u8>>,
        pub(super) prep_msg: Option<Vec<u8>>,
        pub(super) output_share: Option<Vec<u8>>,
        pub(super) report_share_err: Option<i16>,
    }

    // The private ReportAggregationStateCode exists alongside the public ReportAggregationState
    // because there is no apparent way to denote a Postgres enum literal without deriving
    // FromSql/ToSql on a Rust enum type, but it is not possible to derive FromSql/ToSql on a
    // non-C-style enum.
    #[derive(Debug, FromSql, ToSql)]
    #[postgres(name = "report_aggregation_state")]
    pub(super) enum ReportAggregationStateCode {
        #[postgres(name = "START")]
        Start,
        #[postgres(name = "WAITING")]
        Waiting,
        #[postgres(name = "FINISHED")]
        Finished,
        #[postgres(name = "FAILED")]
        Failed,
        #[postgres(name = "INVALID")]
        Invalid,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for ReportAggregationState<L, A>
    where
        A::PrepareState: PartialEq,
        A::PrepareMessage: PartialEq,
        A::OutputShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (
                    Self::Waiting(lhs_prep_state, lhs_prep_msg),
                    Self::Waiting(rhs_prep_state, rhs_prep_msg),
                ) => lhs_prep_state == rhs_prep_state && lhs_prep_msg == rhs_prep_msg,
                (Self::Finished(lhs_out_share), Self::Finished(rhs_out_share)) => {
                    lhs_out_share == rhs_out_share
                }
                (Self::Failed(lhs_report_share_err), Self::Failed(rhs_report_share_err)) => {
                    lhs_report_share_err == rhs_report_share_err
                }
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for ReportAggregationState<L, A>
    where
        A::PrepareState: Eq,
        A::PrepareMessage: Eq,
        A::OutputShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// BatchAggregation corresponds to a row in the `batch_aggregations` table and represents the
    /// possibly-ongoing aggregation of the set of input shares that fall within the batch
    /// identified by `batch_identifier`. This is the finest-grained possible aggregate share we can
    /// emit for this task. The aggregate share constructed to service a collect or aggregate share
    /// request consists of one or more `BatchAggregation`s merged together.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub struct BatchAggregation<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// The task ID for this aggregation result.
        task_id: TaskId,
        /// The identifier of the batch being aggregated over.
        batch_identifier: Q::BatchIdentifier,
        /// The VDAF aggregation parameter used to prepare and accumulate input shares.
        #[derivative(Debug = "ignore")]
        aggregation_parameter: A::AggregationParam,
        /// The aggregate over all the input shares that have been prepared so far by this
        /// aggregator.
        #[derivative(Debug = "ignore")]
        aggregate_share: A::AggregateShare,
        /// The number of reports currently included in this aggregate sahre.
        report_count: u64,
        /// Checksum over the aggregated report shares, as described in §4.4.4.3.
        #[derivative(Debug = "ignore")]
        checksum: ReportIdChecksum,
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> BatchAggregation<L, Q, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Creates a new [`BatchAggregation`].
        pub fn new(
            task_id: TaskId,
            batch_identifier: Q::BatchIdentifier,
            aggregation_parameter: A::AggregationParam,
            aggregate_share: A::AggregateShare,
            report_count: u64,
            checksum: ReportIdChecksum,
        ) -> Self {
            Self {
                task_id,
                batch_identifier,
                aggregation_parameter,
                aggregate_share,
                report_count,
                checksum,
            }
        }

        /// Returns the task ID associated with this batch aggregation.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Gets the batch identifier included in this batch aggregation.
        ///
        /// This method would typically be used for code which is generic over the query type.
        /// Query-type specific code will typically call one of [`Self::batch_interval`] or
        /// [`Self::batch_id`].
        pub fn batch_identifier(&self) -> &Q::BatchIdentifier {
            &self.batch_identifier
        }

        /// Returns the aggregation parameter associated with this batch aggregation.
        pub fn aggregation_parameter(&self) -> &A::AggregationParam {
            &self.aggregation_parameter
        }

        /// Returns the aggregate share associated with this batch aggregation.
        pub fn aggregate_share(&self) -> &A::AggregateShare {
            &self.aggregate_share
        }

        /// Returns the report count associated with this batch aggregation.
        pub fn report_count(&self) -> u64 {
            self.report_count
        }

        /// Returns the checksum associated with this batch aggregation.
        pub fn checksum(&self) -> &ReportIdChecksum {
            &self.checksum
        }

        /// Returns a new [`BatchAggregation`] corresponding to the current batch aggregation
        /// merged with the given parameters.
        pub fn merged_with(
            self,
            aggregate_share: &A::AggregateShare,
            report_count: u64,
            checksum: &ReportIdChecksum,
        ) -> Result<Self, Error> {
            let mut merged_aggregate_share = self.aggregate_share;
            merged_aggregate_share
                .merge(aggregate_share)
                .map_err(|err| Error::User(err.into()))?;
            Ok(Self {
                aggregate_share: merged_aggregate_share,
                report_count: self.report_count + report_count,
                checksum: self.checksum.combined_with(checksum),
                ..self
            })
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> BatchAggregation<L, TimeInterval, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Gets the batch interval associated with this batch aggregation.
        pub fn batch_interval(&self) -> &Interval {
            self.batch_identifier()
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> BatchAggregation<L, FixedSize, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Gets the batch ID associated with this batch aggregation.
        pub fn batch_id(&self) -> &BatchId {
            self.batch_identifier()
        }
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> PartialEq for BatchAggregation<L, Q, A>
    where
        A::AggregationParam: PartialEq,
        A::AggregateShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.batch_identifier == other.batch_identifier
                && self.aggregation_parameter == other.aggregation_parameter
                && self.aggregate_share == other.aggregate_share
                && self.report_count == other.report_count
                && self.checksum == other.checksum
        }
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> Eq for BatchAggregation<L, Q, A>
    where
        A::AggregationParam: Eq,
        A::AggregateShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// CollectionJob represents a row in the `collection_jobs` table, used by leaders to represent
    /// running collection jobs and store the results of completed ones.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub struct CollectionJob<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// The task ID for this collection job.
        task_id: TaskId,
        /// The unique identifier for the collection job.
        collection_job_id: CollectionJobId,
        /// The batch interval covered by the collection job.
        batch_identifier: Q::BatchIdentifier,
        /// The VDAF aggregation parameter used to prepare and aggregate input shares.
        #[derivative(Debug = "ignore")]
        aggregation_parameter: A::AggregationParam,
        /// The current state of the collection job.
        state: CollectionJobState<L, A>,
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> CollectionJob<L, Q, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Creates a new [`CollectionJob`].
        pub fn new(
            task_id: TaskId,
            collection_job_id: CollectionJobId,
            batch_identifier: Q::BatchIdentifier,
            aggregation_parameter: A::AggregationParam,
            state: CollectionJobState<L, A>,
        ) -> Self {
            Self {
                task_id,
                collection_job_id,
                batch_identifier,
                aggregation_parameter,
                state,
            }
        }

        /// Returns the task ID associated with this collection job.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Returns the collection job ID associated with this collection job.
        pub fn collection_job_id(&self) -> &CollectionJobId {
            &self.collection_job_id
        }

        /// Gets the batch identifier associated with this collection job.
        ///
        /// This method would typically be used for code which is generic over the query type.
        /// Query-type specific code will typically call one of [`Self::batch_interval`] or
        /// [`Self::batch_id`].
        pub fn batch_identifier(&self) -> &Q::BatchIdentifier {
            &self.batch_identifier
        }

        /// Returns the aggregation parameter associated with this collection job.
        pub fn aggregation_parameter(&self) -> &A::AggregationParam {
            &self.aggregation_parameter
        }

        /// Returns the state associated with this collection job.
        pub fn state(&self) -> &CollectionJobState<L, A> {
            &self.state
        }

        /// Returns a new [`CollectionJob`] corresponding to this collection job updated to have the given
        /// state.
        pub fn with_state(self, state: CollectionJobState<L, A>) -> Self {
            Self { state, ..self }
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> CollectionJob<L, TimeInterval, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Gets the batch interval associated with this collection job.
        pub fn batch_interval(&self) -> &Interval {
            self.batch_identifier()
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> CollectionJob<L, FixedSize, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Gets the batch ID associated with this collection job.
        pub fn batch_id(&self) -> &BatchId {
            self.batch_identifier()
        }
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> PartialEq for CollectionJob<L, Q, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregationParam: PartialEq,
        CollectionJobState<L, A>: PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.collection_job_id == other.collection_job_id
                && self.batch_identifier == other.batch_identifier
                && self.aggregation_parameter == other.aggregation_parameter
                && self.state == other.state
        }
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> Eq for CollectionJob<L, Q, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregationParam: Eq,
        CollectionJobState<L, A>: Eq,
    {
    }

    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub enum CollectionJobState<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        Start,
        Finished {
            /// The number of reports included in this collection job.
            report_count: u64,
            /// The helper's encrypted aggregate share over the input shares in the interval.
            encrypted_helper_aggregate_share: HpkeCiphertext,
            /// The leader's aggregate share over the input shares in the interval.
            #[derivative(Debug = "ignore")]
            leader_aggregate_share: A::AggregateShare,
        },
        Abandoned,
        Deleted,
    }

    impl<const L: usize, A> CollectionJobState<L, A>
    where
        A: vdaf::Aggregator<L>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub(super) fn collection_job_state_code(&self) -> CollectionJobStateCode {
            match self {
                Self::Start => CollectionJobStateCode::Start,
                Self::Finished { .. } => CollectionJobStateCode::Finished,
                Self::Abandoned => CollectionJobStateCode::Abandoned,
                Self::Deleted => CollectionJobStateCode::Deleted,
            }
        }
    }

    impl<const L: usize, A> Display for CollectionJobState<L, A>
    where
        A: vdaf::Aggregator<L>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{}",
                match self {
                    Self::Start => "start",
                    Self::Finished { .. } => "finished",
                    Self::Abandoned => "abandoned",
                    Self::Deleted => "deleted",
                }
            )
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for CollectionJobState<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregateShare: PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (
                    Self::Finished {
                        report_count: self_report_count,
                        encrypted_helper_aggregate_share: self_helper_agg_share,
                        leader_aggregate_share: self_leader_agg_share,
                    },
                    Self::Finished {
                        report_count: other_report_count,
                        encrypted_helper_aggregate_share: other_helper_agg_share,
                        leader_aggregate_share: other_leader_agg_share,
                    },
                ) => {
                    self_report_count == other_report_count
                        && self_helper_agg_share == other_helper_agg_share
                        && self_leader_agg_share == other_leader_agg_share
                }
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for CollectionJobState<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregateShare: Eq,
    {
    }

    #[derive(Debug, FromSql, ToSql)]
    #[postgres(name = "collection_job_state")]
    pub(super) enum CollectionJobStateCode {
        #[postgres(name = "START")]
        Start,
        #[postgres(name = "FINISHED")]
        Finished,
        #[postgres(name = "ABANDONED")]
        Abandoned,
        #[postgres(name = "DELETED")]
        Deleted,
    }

    /// AggregateShareJob represents a row in the `aggregate_share_jobs` table, used by helpers to
    /// store the results of handling an AggregateShareReq from the leader.

    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub struct AggregateShareJob<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// The task ID for this aggregate share.
        task_id: TaskId,
        /// The batch identifier for the batch covered by the aggregate share.
        batch_identifier: Q::BatchIdentifier,
        /// The VDAF aggregation parameter used to prepare and aggregate input shares.
        #[derivative(Debug = "ignore")]
        aggregation_parameter: A::AggregationParam,
        /// The aggregate share over the input shares in the interval.
        #[derivative(Debug = "ignore")]
        helper_aggregate_share: A::AggregateShare,
        /// The number of reports included in the aggregate share.
        report_count: u64,
        /// Checksum over the aggregated report shares, as described in §4.4.4.3.
        #[derivative(Debug = "ignore")]
        checksum: ReportIdChecksum,
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> AggregateShareJob<L, Q, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Creates a new [`AggregateShareJob`].
        pub fn new(
            task_id: TaskId,
            batch_identifier: Q::BatchIdentifier,
            aggregation_parameter: A::AggregationParam,
            helper_aggregate_share: A::AggregateShare,
            report_count: u64,
            checksum: ReportIdChecksum,
        ) -> Self {
            Self {
                task_id,
                batch_identifier,
                aggregation_parameter,
                helper_aggregate_share,
                report_count,
                checksum,
            }
        }

        /// Gets the task ID associated with this aggregate share job.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Gets the batch identifier associated with this aggregate share job.
        pub fn batch_identifier(&self) -> &Q::BatchIdentifier {
            &self.batch_identifier
        }

        /// Gets the aggregation parameter associated with this aggregate share job.
        pub fn aggregation_parameter(&self) -> &A::AggregationParam {
            &self.aggregation_parameter
        }

        /// Gets the helper aggregate share associated with this aggregate share job.
        pub fn helper_aggregate_share(&self) -> &A::AggregateShare {
            &self.helper_aggregate_share
        }

        /// Gets the report count associated with this aggregate share job.
        pub fn report_count(&self) -> u64 {
            self.report_count
        }

        /// Gets the checksum associated with this aggregate share job.
        pub fn checksum(&self) -> &ReportIdChecksum {
            &self.checksum
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> AggregateShareJob<L, TimeInterval, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Gets the batch interval associated with this aggregate share job.
        pub fn batch_interval(&self) -> &Interval {
            self.batch_identifier()
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> AggregateShareJob<L, FixedSize, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// Gets the batch ID associated with this aggregate share job.
        pub fn batch_id(&self) -> &BatchId {
            self.batch_identifier()
        }
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> PartialEq for AggregateShareJob<L, Q, A>
    where
        A::AggregationParam: PartialEq,
        A::AggregateShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.batch_identifier == other.batch_identifier
                && self.aggregation_parameter == other.aggregation_parameter
                && self.helper_aggregate_share == other.helper_aggregate_share
                && self.report_count == other.report_count
                && self.checksum == other.checksum
        }
    }

    impl<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>> Eq for AggregateShareJob<L, Q, A>
    where
        A::AggregationParam: Eq,
        A::AggregateShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// An outstanding batch, which is a batch which has not yet started collection. Such a batch
    /// may have additional reports allocated to it. Only applies to fixed-size batches.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct OutstandingBatch {
        /// The task ID for this outstanding batch.
        task_id: TaskId,
        /// The batch ID for this outstanding batch.
        batch_id: BatchId,
        /// The range of possible sizes of this batch. The minimum size is the count of reports
        /// which have successfully completed the aggregation process, while the maximum size is the
        /// count of reports which are currently being aggregated or have successfully completed the
        /// aggregation process.
        size: RangeInclusive<usize>,
    }

    impl OutstandingBatch {
        /// Creates a new [`OutstandingBatch`].
        pub fn new(task_id: TaskId, batch_id: BatchId, size: RangeInclusive<usize>) -> Self {
            Self {
                task_id,
                batch_id,
                size,
            }
        }

        /// Gets the [`TaskId`] associated with this outstanding batch.
        pub fn task_id(&self) -> &TaskId {
            &self.task_id
        }

        /// Gets the [`BatchId`] associated with this outstanding batch.
        pub fn id(&self) -> &BatchId {
            &self.batch_id
        }

        /// Gets the range of possible sizes of this batch. The minimum size is the count of reports
        /// which have successfully completed the aggregation process, while the maximum size is the
        /// count of reports which are currently being aggregated or have successfully completed the
        /// aggregation process.
        pub fn size(&self) -> &RangeInclusive<usize> {
            &self.size
        }
    }

    /// The SQL timestamp epoch, midnight UTC on 2000-01-01.
    const SQL_EPOCH_TIME: Time = Time::from_seconds_since_epoch(946_684_800);

    /// Wrapper around [`janus_messages::Interval`] that supports conversions to/from SQL.
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub struct SqlInterval(Interval);

    impl SqlInterval {
        pub fn as_interval(&self) -> Interval {
            self.0
        }
    }

    impl From<Interval> for SqlInterval {
        fn from(interval: Interval) -> Self {
            Self(interval)
        }
    }

    impl From<&Interval> for SqlInterval {
        fn from(interval: &Interval) -> Self {
            Self::from(*interval)
        }
    }

    impl<'a> FromSql<'a> for SqlInterval {
        fn from_sql(
            _: &postgres_types::Type,
            raw: &'a [u8],
        ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
            match range_from_sql(raw)? {
            Range::Empty => Err("Interval cannot represent an empty timestamp range".into()),
            Range::Nonempty(RangeBound::Inclusive(None), _)
            | Range::Nonempty(RangeBound::Exclusive(None), _)
            | Range::Nonempty(_, RangeBound::Inclusive(None))
            | Range::Nonempty(_, RangeBound::Exclusive(None)) => {
                Err("Interval cannot represent a timestamp range with a null bound".into())
            }
            Range::Nonempty(RangeBound::Unbounded, _) | Range::Nonempty(_, RangeBound::Unbounded) => {
                Err("Interval cannot represent an unbounded timestamp range".into())
            }
            Range::Nonempty(RangeBound::Exclusive(_), _) | Range::Nonempty(_, RangeBound::Inclusive(_)) => {
                Err("Interval can only represent timestamp ranges that are closed at the start and open at the end".into())
            }
            Range::Nonempty(RangeBound::Inclusive(Some(start_raw)), RangeBound::Exclusive(Some(end_raw))) => {
                // These timestamps represent the number of microseconds before (if negative) or
                // after (if positive) midnight, 1/1/2000.
                let start_timestamp = timestamp_from_sql(start_raw)?;
                let end_timestamp = timestamp_from_sql(end_raw)?;

                // Convert from SQL timestamp representation to the internal representation.
                let negative = start_timestamp < 0;
                let abs_start_us = start_timestamp.unsigned_abs();
                let abs_start_duration = Duration::from_microseconds(abs_start_us);
                let time = if negative {
                    SQL_EPOCH_TIME.sub(&abs_start_duration).map_err(|_| "Interval cannot represent timestamp ranges starting before the Unix epoch")?
                } else {
                    SQL_EPOCH_TIME.add(&abs_start_duration).map_err(|_| "overflow when converting to Interval")?
                };

                if end_timestamp < start_timestamp {
                    return Err("timestamp range ends before it starts".into());
                }
                let duration_us = end_timestamp.abs_diff(start_timestamp);
                let duration = Duration::from_microseconds(duration_us);

                Ok(SqlInterval(Interval::new(time, duration)?))
            }
        }
        }

        accepts!(TS_RANGE);
    }

    fn time_to_sql_timestamp(time: Time) -> Result<i64, Error> {
        if time.is_after(&SQL_EPOCH_TIME) {
            let absolute_difference_us = time.difference(&SQL_EPOCH_TIME)?.as_microseconds()?;
            Ok(absolute_difference_us.try_into()?)
        } else {
            let absolute_difference_us = SQL_EPOCH_TIME.difference(&time)?.as_microseconds()?;
            Ok(-i64::try_from(absolute_difference_us)?)
        }
    }

    impl ToSql for SqlInterval {
        fn to_sql(
            &self,
            _: &postgres_types::Type,
            out: &mut bytes::BytesMut,
        ) -> Result<postgres_types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
            // Convert the interval start and end to SQL timestamps.
            let start_sql_usec = time_to_sql_timestamp(*self.0.start())
                .map_err(|_| "millisecond timestamp of Interval start overflowed")?;
            let end_sql_usec = time_to_sql_timestamp(self.0.end())
                .map_err(|_| "millisecond timestamp of Interval end overflowed")?;

            range_to_sql(
                |out| {
                    timestamp_to_sql(start_sql_usec, out);
                    Ok(postgres_protocol::types::RangeBound::Inclusive(
                        postgres_protocol::IsNull::No,
                    ))
                },
                |out| {
                    timestamp_to_sql(end_sql_usec, out);
                    Ok(postgres_protocol::types::RangeBound::Exclusive(
                        postgres_protocol::IsNull::No,
                    ))
                },
                out,
            )?;

            Ok(postgres_types::IsNull::No)
        }

        accepts!(TS_RANGE);

        to_sql_checked!();
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aggregator::query_type::CollectableQueryType,
        datastore::{
            models::{
                AcquiredAggregationJob, AggregateShareJob, AggregationJob, AggregationJobState,
                BatchAggregation, CollectionJob, CollectionJobState, LeaderStoredReport, Lease,
                OutstandingBatch, ReportAggregation, ReportAggregationState, SqlInterval,
            },
            test_util::{ephemeral_datastore, generate_aead_key},
            Crypter, Error, Transaction,
        },
        messages::{DurationExt, TimeExt},
        task::{self, test_util::TaskBuilder, Task, PRIO3_AES128_VERIFY_KEY_LENGTH},
    };
    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use chrono::NaiveDate;
    use futures::future::try_join_all;
    use janus_core::{
        hpke::{self, HpkeApplicationInfo, Label},
        task::VdafInstance,
        test_util::{
            dummy_vdaf::{self, AggregateShare, AggregationParam},
            install_test_trace_subscriber, run_vdaf,
        },
        time::{Clock, MockClock, TimeExt as CoreTimeExt},
    };
    use janus_messages::{
        query_type::{FixedSize, QueryType, TimeInterval},
        AggregateShareAad, AggregationJobId, BatchId, BatchSelector, CollectionJobId, Duration,
        Extension, ExtensionType, HpkeCiphertext, HpkeConfigId, Interval, ReportId,
        ReportIdChecksum, ReportMetadata, ReportShare, ReportShareError, Role, TaskId, Time,
    };
    use prio::{
        codec::{Decode, Encode},
        vdaf::prio3::{Prio3, Prio3Aes128Count},
    };
    use rand::{distributions::Standard, random, thread_rng, Rng};
    use std::{
        collections::{HashMap, HashSet},
        iter,
        ops::RangeInclusive,
        sync::Arc,
        time::Duration as StdDuration,
    };

    use super::{models::AcquiredCollectionJob, Datastore};

    #[tokio::test]
    async fn roundtrip_task() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        // Insert tasks, check that they can be retrieved by ID.
        let mut want_tasks = HashMap::new();
        for (vdaf, role) in [
            (VdafInstance::Prio3Aes128Count, Role::Leader),
            (
                VdafInstance::Prio3Aes128CountVec { length: 8 },
                Role::Leader,
            ),
            (
                VdafInstance::Prio3Aes128CountVec { length: 64 },
                Role::Helper,
            ),
            (VdafInstance::Prio3Aes128Sum { bits: 64 }, Role::Helper),
            (VdafInstance::Prio3Aes128Sum { bits: 32 }, Role::Helper),
            (
                VdafInstance::Prio3Aes128Histogram {
                    buckets: Vec::from([0, 100, 200, 400]),
                },
                Role::Leader,
            ),
            (
                VdafInstance::Prio3Aes128Histogram {
                    buckets: Vec::from([0, 25, 50, 75, 100]),
                },
                Role::Leader,
            ),
            (VdafInstance::Poplar1 { bits: 8 }, Role::Helper),
            (VdafInstance::Poplar1 { bits: 64 }, Role::Helper),
        ] {
            let task = TaskBuilder::new(task::QueryType::TimeInterval, vdaf, role)
                .with_report_expiry_age(Some(Duration::from_seconds(3600)))
                .build();
            want_tasks.insert(*task.id(), task.clone());

            let err = ds
                .run_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move { tx.delete_task(task.id()).await })
                })
                .await
                .unwrap_err();
            assert_matches!(err, Error::MutationTargetNotFound);

            let retrieved_task = ds
                .run_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move { tx.get_task(task.id()).await })
                })
                .await
                .unwrap();
            assert_eq!(None, retrieved_task);

            ds.put_task(&task).await.unwrap();

            let retrieved_task = ds
                .run_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move { tx.get_task(task.id()).await })
                })
                .await
                .unwrap();
            assert_eq!(Some(&task), retrieved_task.as_ref());

            ds.run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.delete_task(task.id()).await })
            })
            .await
            .unwrap();

            let retrieved_task = ds
                .run_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move { tx.get_task(task.id()).await })
                })
                .await
                .unwrap();
            assert_eq!(None, retrieved_task);

            let err = ds
                .run_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move { tx.delete_task(task.id()).await })
                })
                .await
                .unwrap_err();
            assert_matches!(err, Error::MutationTargetNotFound);

            // Rewrite & retrieve the task again, to test that the delete is "clean" in the sense
            // that it deletes all task-related data (& therefore does not conflict with a later
            // write to the same task_id).
            ds.put_task(&task).await.unwrap();

            let retrieved_task = ds
                .run_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move { tx.get_task(task.id()).await })
                })
                .await
                .unwrap();
            assert_eq!(Some(task), retrieved_task);
        }

        let got_tasks: HashMap<TaskId, Task> = ds
            .run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .unwrap()
            .into_iter()
            .map(|task| (*task.id(), task))
            .collect();
        assert_eq!(want_tasks, got_tasks);
    }

    #[tokio::test]
    async fn roundtrip_report() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        let task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();

        ds.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move { tx.put_task(&task).await })
        })
        .await
        .unwrap();

        let report_id = ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let report: LeaderStoredReport<0, dummy_vdaf::Vdaf> = LeaderStoredReport::new(
            *task.id(),
            ReportMetadata::new(report_id, Time::from_seconds_since_epoch(12345)),
            (), // public share
            Vec::from([
                Extension::new(ExtensionType::Tbd, Vec::from("extension_data_0")),
                Extension::new(ExtensionType::Tbd, Vec::from("extension_data_1")),
            ]),
            (), // leader input share
            /* Dummy ciphertext for the helper share */
            HpkeCiphertext::new(
                HpkeConfigId::from(13),
                Vec::from("encapsulated_context_1"),
                Vec::from("payload_1"),
            ),
        );

        // Write a report twice to prove it is idempotent
        for _ in 0..2 {
            ds.run_tx(|tx| {
                let report = report.clone();
                Box::pin(async move {
                    tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report)
                        .await
                })
            })
            .await
            .unwrap();

            let retrieved_report = ds
                .run_tx(|tx| {
                    let task_id = *report.task_id();
                    Box::pin(async move {
                        tx.get_client_report::<0, dummy_vdaf::Vdaf>(
                            &dummy_vdaf::Vdaf::new(),
                            &task_id,
                            &report_id,
                        )
                        .await
                    })
                })
                .await
                .unwrap()
                .unwrap();

            assert_eq!(report.task_id(), retrieved_report.task_id());
            assert_eq!(report.metadata(), retrieved_report.metadata());
        }

        // Try to write a different report with the same ID, and verify we get the expected error.
        let result = ds
            .run_tx(|tx| {
                let task_id = *report.task_id();
                Box::pin(async move {
                    tx.put_client_report(
                        &dummy_vdaf::Vdaf::new(),
                        &LeaderStoredReport::<0, dummy_vdaf::Vdaf>::new(
                            task_id,
                            ReportMetadata::new(report_id, Time::from_seconds_since_epoch(54321)),
                            (), // public share
                            Vec::from([
                                Extension::new(ExtensionType::Tbd, Vec::from("extension_data_2")),
                                Extension::new(ExtensionType::Tbd, Vec::from("extension_data_3")),
                            ]),
                            (), // leader input share
                            /* Dummy ciphertext for the helper share */
                            HpkeCiphertext::new(
                                HpkeConfigId::from(14),
                                Vec::from("encapsulated_context_2"),
                                Vec::from("payload_2"),
                            ),
                        ),
                    )
                    .await
                })
            })
            .await;
        assert_matches!(result, Err(Error::MutationTargetAlreadyExisted));
    }

    #[tokio::test]
    async fn report_not_found() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_client_report(
                        &dummy_vdaf::Vdaf::new(),
                        &random(),
                        &ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    )
                    .await
                })
            })
            .await
            .unwrap();

        assert_eq!(rslt, None);
    }

    #[tokio::test]
    async fn get_unaggregated_client_report_ids_for_task() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        let time_precision = Duration::from_seconds(1000);
        let when = MockClock::default()
            .now()
            .to_batch_interval_start(&time_precision)
            .unwrap();

        let task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let unrelated_task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();

        let first_unaggregated_report = LeaderStoredReport::new_dummy(*task.id(), when);
        let second_unaggregated_report = LeaderStoredReport::new_dummy(*task.id(), when);
        let aggregated_report = LeaderStoredReport::new_dummy(*task.id(), when);
        let unrelated_report = LeaderStoredReport::new_dummy(*unrelated_task.id(), when);

        // Set up state.
        ds.run_tx(|tx| {
            let (
                task,
                unrelated_task,
                first_unaggregated_report,
                second_unaggregated_report,
                aggregated_report,
                unrelated_report,
            ) = (
                task.clone(),
                unrelated_task.clone(),
                first_unaggregated_report.clone(),
                second_unaggregated_report.clone(),
                aggregated_report.clone(),
                unrelated_report.clone(),
            );

            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_task(&unrelated_task).await?;

                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &first_unaggregated_report)
                    .await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &second_unaggregated_report)
                    .await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &aggregated_report)
                    .await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &unrelated_report)
                    .await?;

                // Mark aggregated_report as aggregated. (we use SQL here as there is no standard
                // datastore operation to manually mark a client report as aggregated)
                tx.execute(
                    "UPDATE client_reports SET aggregation_started = TRUE
                        WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)
                          AND report_id = $2",
                    &[
                        &task.id().as_ref(),
                        &aggregated_report.metadata().id().as_ref(),
                    ],
                )
                .await?;
                Ok(())
            })
        })
        .await
        .unwrap();

        // Verify that we can acquire both unaggregated reports.
        let got_reports = HashSet::from_iter(
            ds.run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_unaggregated_client_report_ids_for_task(task.id())
                        .await
                })
            })
            .await
            .unwrap(),
        );

        assert_eq!(
            got_reports,
            HashSet::from([
                (
                    *first_unaggregated_report.metadata().id(),
                    *first_unaggregated_report.metadata().time(),
                ),
                (
                    *second_unaggregated_report.metadata().id(),
                    *second_unaggregated_report.metadata().time(),
                ),
            ]),
        );

        // Verify that attempting to acquire again does not return the reports.
        let got_reports = HashSet::<(ReportId, Time)>::from_iter(
            ds.run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_unaggregated_client_report_ids_for_task(task.id())
                        .await
                })
            })
            .await
            .unwrap(),
        );

        assert!(got_reports.is_empty());

        // Mark one report un-aggregated.
        ds.run_tx(|tx| {
            let (task, first_unaggregated_report) =
                (task.clone(), first_unaggregated_report.clone());
            Box::pin(async move {
                tx.mark_reports_unaggregated(
                    task.id(),
                    &[*first_unaggregated_report.metadata().id()],
                )
                .await
            })
        })
        .await
        .unwrap();

        // Verify that we can retrieve the un-aggregated report again.
        let got_reports = HashSet::from_iter(
            ds.run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_unaggregated_client_report_ids_for_task(task.id())
                        .await
                })
            })
            .await
            .unwrap(),
        );

        assert_eq!(
            got_reports,
            HashSet::from([(
                *first_unaggregated_report.metadata().id(),
                *first_unaggregated_report.metadata().time(),
            ),]),
        );
    }

    #[tokio::test]
    async fn get_unaggregated_client_report_ids_with_agg_param_for_task() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        let task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();
        let unrelated_task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();

        let first_unaggregated_report =
            LeaderStoredReport::new_dummy(*task.id(), Time::from_seconds_since_epoch(12345));
        let second_unaggregated_report =
            LeaderStoredReport::new_dummy(*task.id(), Time::from_seconds_since_epoch(12346));
        let aggregated_report =
            LeaderStoredReport::new_dummy(*task.id(), Time::from_seconds_since_epoch(12347));
        let unrelated_report = LeaderStoredReport::new_dummy(
            *unrelated_task.id(),
            Time::from_seconds_since_epoch(12348),
        );

        // Set up state.
        ds.run_tx(|tx| {
            let (
                task,
                unrelated_task,
                first_unaggregated_report,
                second_unaggregated_report,
                aggregated_report,
                unrelated_report,
            ) = (
                task.clone(),
                unrelated_task.clone(),
                first_unaggregated_report.clone(),
                second_unaggregated_report.clone(),
                aggregated_report.clone(),
                unrelated_report.clone(),
            );

            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_task(&unrelated_task).await?;

                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &first_unaggregated_report)
                    .await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &second_unaggregated_report)
                    .await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &aggregated_report)
                    .await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &unrelated_report)
                    .await?;

                // There are no client reports submitted under this task, so we shouldn't see
                // this aggregation parameter at all.
                tx.put_collection_job(&CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *unrelated_task.id(),
                    random(),
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(8).unwrap(),
                    )
                    .unwrap(),
                    AggregationParam(255),
                    CollectionJobState::<0, dummy_vdaf::Vdaf>::Start,
                ))
                .await
            })
        })
        .await
        .unwrap();

        // Run query & verify results. None should be returned yet, as there are no relevant
        // collect requests.
        let got_reports = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_unaggregated_client_report_ids_by_collect_for_task::<0, dummy_vdaf::Vdaf>(task.id())
                        .await
                })
            })
            .await
            .unwrap();
        assert!(got_reports.is_empty());

        // Add collection jobs, and mark one report as having already been aggregated once.
        ds.run_tx(|tx| {
            let (task, aggregated_report_id, aggregated_report_time) = (
                task.clone(),
                *aggregated_report.metadata().id(),
                *aggregated_report.metadata().time(),
            );
            Box::pin(async move {
                tx.put_collection_job(&CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(8).unwrap(),
                    )
                    .unwrap(),
                    AggregationParam(0),
                    CollectionJobState::<0, dummy_vdaf::Vdaf>::Start,
                ))
                .await?;
                tx.put_collection_job(&CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(8).unwrap(),
                    )
                    .unwrap(),
                    AggregationParam(1),
                    CollectionJobState::<0, dummy_vdaf::Vdaf>::Start,
                ))
                .await?;
                // No reports fall in this interval, so we shouldn't see it's aggregation
                // parameter at all.
                tx.put_collection_job(&CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    Interval::new(
                        Time::from_seconds_since_epoch(8 * 3600),
                        Duration::from_hours(8).unwrap(),
                    )
                    .unwrap(),
                    AggregationParam(2),
                    CollectionJobState::<0, dummy_vdaf::Vdaf>::Start,
                ))
                .await?;

                let aggregation_job_id = random();
                tx.put_aggregation_job(&AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    aggregation_job_id,
                    AggregationParam(0),
                    (),
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::InProgress,
                ))
                .await?;
                tx.put_report_aggregation(&ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    aggregation_job_id,
                    aggregated_report_id,
                    aggregated_report_time,
                    0,
                    ReportAggregationState::Start,
                ))
                .await
            })
        })
        .await
        .unwrap();

        // Run query & verify results. We should have two unaggregated reports with one parameter,
        // and three with another.
        let mut got_reports = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_unaggregated_client_report_ids_by_collect_for_task::<0, dummy_vdaf::Vdaf>(task.id())
                        .await
                })
            })
            .await
            .unwrap();

        let mut expected_reports = Vec::from([
            (
                *first_unaggregated_report.metadata().id(),
                *first_unaggregated_report.metadata().time(),
                AggregationParam(0),
            ),
            (
                *first_unaggregated_report.metadata().id(),
                *first_unaggregated_report.metadata().time(),
                AggregationParam(1),
            ),
            (
                *second_unaggregated_report.metadata().id(),
                *second_unaggregated_report.metadata().time(),
                AggregationParam(0),
            ),
            (
                *second_unaggregated_report.metadata().id(),
                *second_unaggregated_report.metadata().time(),
                AggregationParam(1),
            ),
            (
                *aggregated_report.metadata().id(),
                *aggregated_report.metadata().time(),
                AggregationParam(1),
            ),
        ]);
        got_reports.sort();
        expected_reports.sort();
        assert_eq!(got_reports, expected_reports);

        // Add overlapping collection jobs with repeated aggregation parameters. Make sure we don't
        // repeat result tuples, which could lead to double counting in batch aggregations.
        ds.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move {
                tx.put_collection_job(&CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(16).unwrap(),
                    )
                    .unwrap(),
                    AggregationParam(0),
                    CollectionJobState::Start,
                ))
                .await?;
                tx.put_collection_job(&CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(16).unwrap(),
                    )
                    .unwrap(),
                    AggregationParam(1),
                    CollectionJobState::Start,
                ))
                .await?;
                Ok(())
            })
        })
        .await
        .unwrap();

        // Verify that we get the same result.
        let mut got_reports = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_unaggregated_client_report_ids_by_collect_for_task::<0, dummy_vdaf::Vdaf>(task.id())
                        .await
                })
            })
            .await
            .unwrap();
        got_reports.sort();
        assert_eq!(got_reports, expected_reports);
    }

    #[tokio::test]
    async fn count_client_reports_for_interval() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        let task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();
        let unrelated_task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();
        let no_reports_task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();

        let first_report_in_interval =
            LeaderStoredReport::new_dummy(*task.id(), Time::from_seconds_since_epoch(12340));
        let second_report_in_interval =
            LeaderStoredReport::new_dummy(*task.id(), Time::from_seconds_since_epoch(12341));
        let report_outside_interval =
            LeaderStoredReport::new_dummy(*task.id(), Time::from_seconds_since_epoch(12350));
        let report_for_other_task = LeaderStoredReport::new_dummy(
            *unrelated_task.id(),
            Time::from_seconds_since_epoch(12341),
        );

        // Set up state.
        ds.run_tx(|tx| {
            let (
                task,
                unrelated_task,
                no_reports_task,
                first_report_in_interval,
                second_report_in_interval,
                report_outside_interval,
                report_for_other_task,
            ) = (
                task.clone(),
                unrelated_task.clone(),
                no_reports_task.clone(),
                first_report_in_interval.clone(),
                second_report_in_interval.clone(),
                report_outside_interval.clone(),
                report_for_other_task.clone(),
            );

            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_task(&unrelated_task).await?;
                tx.put_task(&no_reports_task).await?;

                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &first_report_in_interval)
                    .await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &second_report_in_interval)
                    .await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report_outside_interval)
                    .await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report_for_other_task)
                    .await?;

                Ok(())
            })
        })
        .await
        .unwrap();

        let (report_count, no_reports_task_report_count) = ds
            .run_tx(|tx| {
                let (task, no_reports_task) = (task.clone(), no_reports_task.clone());
                Box::pin(async move {
                    let report_count = tx
                        .count_client_reports_for_interval(
                            task.id(),
                            &Interval::new(
                                Time::from_seconds_since_epoch(12340),
                                Duration::from_seconds(5),
                            )
                            .unwrap(),
                        )
                        .await?;

                    let no_reports_task_report_count = tx
                        .count_client_reports_for_interval(
                            no_reports_task.id(),
                            &Interval::new(
                                Time::from_seconds_since_epoch(12340),
                                Duration::from_seconds(5),
                            )
                            .unwrap(),
                        )
                        .await?;

                    Ok((report_count, no_reports_task_report_count))
                })
            })
            .await
            .unwrap();
        assert_eq!(report_count, 2);
        assert_eq!(no_reports_task_report_count, 0);
    }

    #[tokio::test]
    async fn count_client_reports_for_batch_id() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        let task = TaskBuilder::new(
            task::QueryType::FixedSize { max_batch_size: 10 },
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();
        let unrelated_task = TaskBuilder::new(
            task::QueryType::FixedSize { max_batch_size: 10 },
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();

        // Set up state.
        let batch_id = ds
            .run_tx(|tx| {
                let (task, unrelated_task) = (task.clone(), unrelated_task.clone());

                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_task(&unrelated_task).await?;

                    // Create a batch for the first task containing two reports, which has started
                    // aggregation twice with two different aggregation parameters.
                    let batch_id = random();
                    let report_0 = LeaderStoredReport::new_dummy(
                        *task.id(),
                        Time::from_seconds_since_epoch(12340),
                    );
                    let report_1 = LeaderStoredReport::new_dummy(
                        *task.id(),
                        Time::from_seconds_since_epoch(12345),
                    );

                    let aggregation_job_0 = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        AggregationParam(22),
                        batch_id,
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                    );
                    let aggregation_job_0_report_aggregation_0 =
                        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            *aggregation_job_0.id(),
                            *report_0.metadata().id(),
                            *report_0.metadata().time(),
                            0,
                            ReportAggregationState::Start,
                        );
                    let aggregation_job_0_report_aggregation_1 =
                        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            *aggregation_job_0.id(),
                            *report_1.metadata().id(),
                            *report_1.metadata().time(),
                            1,
                            ReportAggregationState::Start,
                        );

                    let aggregation_job_1 = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        AggregationParam(23),
                        batch_id,
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                    );
                    let aggregation_job_1_report_aggregation_0 =
                        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            *aggregation_job_1.id(),
                            *report_0.metadata().id(),
                            *report_0.metadata().time(),
                            0,
                            ReportAggregationState::Start,
                        );
                    let aggregation_job_1_report_aggregation_1 =
                        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            *aggregation_job_1.id(),
                            *report_1.metadata().id(),
                            *report_1.metadata().time(),
                            1,
                            ReportAggregationState::Start,
                        );

                    tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report_0)
                        .await?;
                    tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report_1)
                        .await?;

                    tx.put_aggregation_job(&aggregation_job_0).await?;
                    tx.put_report_aggregation(&aggregation_job_0_report_aggregation_0)
                        .await?;
                    tx.put_report_aggregation(&aggregation_job_0_report_aggregation_1)
                        .await?;

                    tx.put_aggregation_job(&aggregation_job_1).await?;
                    tx.put_report_aggregation(&aggregation_job_1_report_aggregation_0)
                        .await?;
                    tx.put_report_aggregation(&aggregation_job_1_report_aggregation_1)
                        .await?;

                    Ok(batch_id)
                })
            })
            .await
            .unwrap();

        let report_count = ds
            .run_tx(|tx| {
                let task_id = *task.id();
                Box::pin(async move {
                    tx.count_client_reports_for_batch_id(&task_id, &batch_id)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(report_count, 2);
    }

    #[tokio::test]
    async fn roundtrip_report_share() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        let task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let report_share = ReportShare::new(
            ReportMetadata::new(
                ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                Time::from_seconds_since_epoch(12345),
            ),
            Vec::from("public_share"),
            HpkeCiphertext::new(
                HpkeConfigId::from(12),
                Vec::from("encapsulated_context_0"),
                Vec::from("payload_0"),
            ),
        );

        ds.run_tx(|tx| {
            let (task, report_share) = (task.clone(), report_share.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_report_share(task.id(), &report_share).await?;

                Ok(())
            })
        })
        .await
        .unwrap();

        let (got_task_id, got_extensions, got_leader_input_share, got_helper_input_share) = ds
            .run_tx(|tx| {
                let report_share_metadata = report_share.metadata().clone();
                Box::pin(async move {
                    let row = tx
                        .query_one(
                            "SELECT
                                tasks.task_id,
                                client_reports.report_id,
                                client_reports.client_timestamp,
                                client_reports.extensions,
                                client_reports.leader_input_share,
                                client_reports.helper_encrypted_input_share
                            FROM client_reports JOIN tasks ON tasks.id = client_reports.task_id
                            WHERE report_id = $1 AND client_timestamp = $2",
                            &[
                                /* report_id */ &report_share_metadata.id().as_ref(),
                                /* client_timestamp */
                                &report_share_metadata.time().as_naive_date_time()?,
                            ],
                        )
                        .await?;

                    let task_id = TaskId::get_decoded(row.get("task_id"))?;

                    let maybe_extensions: Option<Vec<u8>> = row.get("extensions");
                    let maybe_leader_input_share: Option<Vec<u8>> = row.get("leader_input_share");
                    let maybe_helper_input_share: Option<Vec<u8>> =
                        row.get("helper_encrypted_input_share");

                    Ok((
                        task_id,
                        maybe_extensions,
                        maybe_leader_input_share,
                        maybe_helper_input_share,
                    ))
                })
            })
            .await
            .unwrap();

        assert_eq!(task.id(), &got_task_id);
        assert!(got_extensions.is_none());
        assert!(got_leader_input_share.is_none());
        assert!(got_helper_input_share.is_none());

        // Put the same report share again. This should not cause an error.
        ds.run_tx(|tx| {
            let (task_id, report_share) = (*task.id(), report_share.clone());
            Box::pin(async move {
                tx.put_report_share(&task_id, &report_share).await.unwrap();

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn roundtrip_aggregation_job() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        // We use a dummy VDAF & fixed-size task for this test, to better exercise the
        // serialization/deserialization roundtrip of the batch_identifier & aggregation_param.
        let task = TaskBuilder::new(
            task::QueryType::FixedSize { max_batch_size: 10 },
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();
        let batch_id = random();
        let leader_aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
            *task.id(),
            random(),
            AggregationParam(23),
            batch_id,
            Interval::new(
                Time::from_seconds_since_epoch(5432),
                Duration::from_seconds(1234),
            )
            .unwrap(),
            AggregationJobState::InProgress,
        );
        let helper_aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
            *task.id(),
            random(),
            AggregationParam(23),
            random(),
            Interval::new(
                Time::from_seconds_since_epoch(1007),
                Duration::from_seconds(6209),
            )
            .unwrap(),
            AggregationJobState::InProgress,
        );

        ds.run_tx(|tx| {
            let (task, leader_aggregation_job, helper_aggregation_job) = (
                task.clone(),
                leader_aggregation_job.clone(),
                helper_aggregation_job.clone(),
            );
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_aggregation_job(&leader_aggregation_job).await?;
                tx.put_aggregation_job(&helper_aggregation_job).await
            })
        })
        .await
        .unwrap();

        let (got_leader_aggregation_job, got_helper_aggregation_job) = ds
            .run_tx(|tx| {
                let (leader_aggregation_job, helper_aggregation_job) = (
                    leader_aggregation_job.clone(),
                    helper_aggregation_job.clone(),
                );
                Box::pin(async move {
                    Ok((
                        tx.get_aggregation_job(
                            leader_aggregation_job.task_id(),
                            leader_aggregation_job.id(),
                        )
                        .await?,
                        tx.get_aggregation_job(
                            helper_aggregation_job.task_id(),
                            helper_aggregation_job.id(),
                        )
                        .await?,
                    ))
                })
            })
            .await
            .unwrap();
        assert_eq!(
            Some(&leader_aggregation_job),
            got_leader_aggregation_job.as_ref()
        );
        assert_eq!(
            Some(&helper_aggregation_job),
            got_helper_aggregation_job.as_ref()
        );

        let new_aggregation_job = leader_aggregation_job
            .clone()
            .with_state(AggregationJobState::Finished);
        ds.run_tx(|tx| {
            let new_aggregation_job = new_aggregation_job.clone();
            Box::pin(async move { tx.update_aggregation_job(&new_aggregation_job).await })
        })
        .await
        .unwrap();

        let got_aggregation_job = ds
            .run_tx(|tx| {
                let leader_aggregation_job = leader_aggregation_job.clone();
                Box::pin(async move {
                    tx.get_aggregation_job(
                        leader_aggregation_job.task_id(),
                        leader_aggregation_job.id(),
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(Some(new_aggregation_job), got_aggregation_job);
    }

    #[tokio::test]
    async fn aggregation_job_acquire_release() {
        // Setup: insert a few aggregation jobs.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        const AGGREGATION_JOB_COUNT: usize = 10;
        let task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let mut aggregation_job_ids: Vec<_> = thread_rng()
            .sample_iter(Standard)
            .take(AGGREGATION_JOB_COUNT)
            .collect();
        aggregation_job_ids.sort();

        ds.run_tx(|tx| {
            let (task, aggregation_job_ids) = (task.clone(), aggregation_job_ids.clone());
            Box::pin(async move {
                // Write a few aggregation jobs we expect to be able to retrieve with
                // acquire_incomplete_aggregation_jobs().
                tx.put_task(&task).await?;
                for aggregation_job_id in aggregation_job_ids {
                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        (),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                    ))
                    .await?;
                }

                // Write an aggregation job that is finished. We don't want to retrieve this one.
                tx.put_aggregation_job(&AggregationJob::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Count,
                >::new(
                    *task.id(),
                    random(),
                    (),
                    (),
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::Finished,
                ))
                .await?;

                // Write an aggregation job for a task that we are taking on the helper role for.
                // We don't want to retrieve this one, either.
                let helper_task = TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Prio3Aes128Count,
                    Role::Helper,
                )
                .build();
                tx.put_task(&helper_task).await?;
                tx.put_aggregation_job(&AggregationJob::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Count,
                >::new(
                    *helper_task.id(),
                    random(),
                    (),
                    (),
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::InProgress,
                ))
                .await
            })
        })
        .await
        .unwrap();

        // Run: run several transactions that all call acquire_incomplete_aggregation_jobs
        // concurrently. (We do things concurrently in an attempt to make sure the
        // mutual-exclusivity works properly.)
        const TX_COUNT: usize = 10;
        const LEASE_DURATION: StdDuration = StdDuration::from_secs(300);
        const MAXIMUM_ACQUIRE_COUNT: usize = 4;

        // Sanity check constants: ensure we acquire jobs across multiple calls to exercise the
        // maximum-jobs-per-call functionality. Make sure we're attempting to acquire enough jobs
        // in total to cover the number of acquirable jobs we created.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(MAXIMUM_ACQUIRE_COUNT < AGGREGATION_JOB_COUNT);
            assert!(MAXIMUM_ACQUIRE_COUNT.checked_mul(TX_COUNT).unwrap() >= AGGREGATION_JOB_COUNT);
        }

        let results = try_join_all(
            iter::repeat_with(|| {
                ds.run_tx(|tx| {
                    Box::pin(async move {
                        tx.acquire_incomplete_aggregation_jobs(
                            &LEASE_DURATION,
                            MAXIMUM_ACQUIRE_COUNT,
                        )
                        .await
                    })
                })
            })
            .take(TX_COUNT),
        )
        .await
        .unwrap();

        // Verify: check that we got all of the desired aggregation jobs, with no duplication, and
        // the expected lease expiry.
        let want_expiry_time = clock.now().as_naive_date_time().unwrap()
            + chrono::Duration::from_std(LEASE_DURATION).unwrap();
        let want_aggregation_jobs: Vec<_> = aggregation_job_ids
            .iter()
            .map(|&agg_job_id| {
                (
                    AcquiredAggregationJob::new(
                        *task.id(),
                        agg_job_id,
                        task::QueryType::TimeInterval,
                        VdafInstance::Prio3Aes128Count,
                    ),
                    want_expiry_time,
                )
            })
            .collect();
        let mut got_leases = Vec::new();
        for result in results {
            assert!(result.len() <= MAXIMUM_ACQUIRE_COUNT);
            got_leases.extend(result.into_iter());
        }
        let mut got_aggregation_jobs: Vec<_> = got_leases
            .iter()
            .map(|lease| {
                assert_eq!(lease.lease_attempts(), 1);
                (lease.leased().clone(), *lease.lease_expiry_time())
            })
            .collect();
        got_aggregation_jobs.sort();

        assert_eq!(want_aggregation_jobs, got_aggregation_jobs);

        // Run: release a few jobs, then attempt to acquire jobs again.
        const RELEASE_COUNT: usize = 2;

        // Sanity check constants: ensure we release fewer jobs than we're about to acquire to
        // ensure we can acquire them in all in a single call, while leaving headroom to acquire
        // at least one unwanted job if there is a logic bug.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(RELEASE_COUNT < MAXIMUM_ACQUIRE_COUNT);
        }

        let leases_to_release: Vec<_> = got_leases.into_iter().take(RELEASE_COUNT).collect();
        let mut jobs_to_release: Vec<_> = leases_to_release
            .iter()
            .map(|lease| (lease.leased().clone(), *lease.lease_expiry_time()))
            .collect();
        jobs_to_release.sort();
        ds.run_tx(|tx| {
            let leases_to_release = leases_to_release.clone();
            Box::pin(async move {
                for lease in leases_to_release {
                    tx.release_aggregation_job(&lease).await?;
                }
                Ok(())
            })
        })
        .await
        .unwrap();

        let mut got_aggregation_jobs: Vec<_> = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.acquire_incomplete_aggregation_jobs(&LEASE_DURATION, MAXIMUM_ACQUIRE_COUNT)
                        .await
                })
            })
            .await
            .unwrap()
            .into_iter()
            .map(|lease| {
                assert_eq!(lease.lease_attempts(), 1);
                (lease.leased().clone(), *lease.lease_expiry_time())
            })
            .collect();
        got_aggregation_jobs.sort();

        // Verify: we should have re-acquired the jobs we released.
        assert_eq!(jobs_to_release, got_aggregation_jobs);

        // Run: advance time by the lease duration (which implicitly releases the jobs), and attempt
        // to acquire aggregation jobs again.
        clock.advance(Duration::from_seconds(LEASE_DURATION.as_secs()));
        let want_expiry_time = clock.now().as_naive_date_time().unwrap()
            + chrono::Duration::from_std(LEASE_DURATION).unwrap();
        let want_aggregation_jobs: Vec<_> = aggregation_job_ids
            .iter()
            .map(|&job_id| {
                (
                    AcquiredAggregationJob::new(
                        *task.id(),
                        job_id,
                        task::QueryType::TimeInterval,
                        VdafInstance::Prio3Aes128Count,
                    ),
                    want_expiry_time,
                )
            })
            .collect();
        let mut got_aggregation_jobs: Vec<_> = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    // This time, we just acquire all jobs in a single go for simplicity -- we've
                    // already tested the maximum acquire count functionality above.
                    tx.acquire_incomplete_aggregation_jobs(&LEASE_DURATION, AGGREGATION_JOB_COUNT)
                        .await
                })
            })
            .await
            .unwrap()
            .into_iter()
            .map(|lease| {
                let job = (lease.leased().clone(), *lease.lease_expiry_time());
                let expected_attempts = if jobs_to_release.contains(&job) { 1 } else { 2 };
                assert_eq!(lease.lease_attempts(), expected_attempts);
                job
            })
            .collect();
        got_aggregation_jobs.sort();

        // Verify: we got all the jobs.
        assert_eq!(want_aggregation_jobs, got_aggregation_jobs);

        // Run: advance time again to release jobs, acquire a single job, modify its lease token
        // to simulate a previously-held lease, and attempt to release it. Verify that releasing
        // fails.
        clock.advance(Duration::from_seconds(LEASE_DURATION.as_secs()));
        let lease = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    Ok(tx
                        .acquire_incomplete_aggregation_jobs(&LEASE_DURATION, 1)
                        .await?
                        .remove(0))
                })
            })
            .await
            .unwrap();
        let lease_with_random_token = Lease::new(
            lease.leased().clone(),
            *lease.lease_expiry_time(),
            random(),
            lease.lease_attempts(),
        );
        ds.run_tx(|tx| {
            let lease_with_random_token = lease_with_random_token.clone();
            Box::pin(async move { tx.release_aggregation_job(&lease_with_random_token).await })
        })
        .await
        .unwrap_err();

        // Replace the original lease token and verify that we can release successfully with it in
        // place.
        ds.run_tx(|tx| {
            let lease = lease.clone();
            Box::pin(async move { tx.release_aggregation_job(&lease).await })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn aggregation_job_not_found() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                        &random(),
                        &random(),
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(rslt, None);

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.update_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                        &AggregationJob::new(
                            random(),
                            random(),
                            (),
                            (),
                            Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
                            AggregationJobState::InProgress,
                        ),
                    )
                    .await
                })
            })
            .await;
        assert_matches!(rslt, Err(Error::MutationTargetNotFound));
    }

    #[tokio::test]
    async fn get_aggregation_jobs_for_task() {
        // Setup.
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        // We use a dummy VDAF & fixed-size task for this test, to better exercise the
        // serialization/deserialization roundtrip of the batch_identifier & aggregation_param.
        let task = TaskBuilder::new(
            task::QueryType::FixedSize { max_batch_size: 10 },
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();
        let first_aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
            *task.id(),
            random(),
            AggregationParam(23),
            random(),
            Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
            AggregationJobState::InProgress,
        );
        let second_aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
            *task.id(),
            random(),
            AggregationParam(42),
            random(),
            Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
            AggregationJobState::InProgress,
        );

        ds.run_tx(|tx| {
            let (task, first_aggregation_job, second_aggregation_job) = (
                task.clone(),
                first_aggregation_job.clone(),
                second_aggregation_job.clone(),
            );
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_aggregation_job(&first_aggregation_job).await?;
                tx.put_aggregation_job(&second_aggregation_job).await?;

                // Also write an unrelated aggregation job with a different task ID to check that it
                // is not returned.
                let unrelated_task = TaskBuilder::new(
                    task::QueryType::FixedSize { max_batch_size: 10 },
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .build();
                tx.put_task(&unrelated_task).await?;
                tx.put_aggregation_job(&AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *unrelated_task.id(),
                    random(),
                    AggregationParam(82),
                    random(),
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::InProgress,
                ))
                .await
            })
        })
        .await
        .unwrap();

        // Run.
        let mut want_agg_jobs = Vec::from([first_aggregation_job, second_aggregation_job]);
        want_agg_jobs.sort_by_key(|agg_job| *agg_job.id());
        let mut got_agg_jobs = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.get_aggregation_jobs_for_task(task.id()).await })
            })
            .await
            .unwrap();
        got_agg_jobs.sort_by_key(|agg_job| *agg_job.id());

        // Verify.
        assert_eq!(want_agg_jobs, got_agg_jobs);
    }

    #[tokio::test]
    async fn roundtrip_report_aggregation() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        let report_id = ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());
        let verify_key: [u8; PRIO3_AES128_VERIFY_KEY_LENGTH] = random();
        let vdaf_transcript = run_vdaf(vdaf.as_ref(), &verify_key, &(), &report_id, &0);
        let prep_state = vdaf_transcript.prep_state(0, Role::Leader);

        for (ord, state) in [
            ReportAggregationState::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::Start,
            ReportAggregationState::Waiting(prep_state.clone(), None),
            ReportAggregationState::Waiting(
                prep_state.clone(),
                Some(vdaf_transcript.prepare_messages[0].clone()),
            ),
            ReportAggregationState::Finished(vdaf_transcript.output_share(Role::Leader).clone()),
            ReportAggregationState::Failed(ReportShareError::VdafPrepError),
            ReportAggregationState::Invalid,
        ]
        .into_iter()
        .enumerate()
        {
            let task = TaskBuilder::new(
                task::QueryType::TimeInterval,
                VdafInstance::Prio3Aes128Count,
                Role::Leader,
            )
            .build();
            let aggregation_job_id = random();
            let time = Time::from_seconds_since_epoch(12345);
            let report_id = ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

            let report_aggregation = ds
                .run_tx(|tx| {
                    let (task, state) = (task.clone(), state.clone());
                    Box::pin(async move {
                        tx.put_task(&task).await?;
                        tx.put_aggregation_job(&AggregationJob::<
                            PRIO3_AES128_VERIFY_KEY_LENGTH,
                            TimeInterval,
                            Prio3Aes128Count,
                        >::new(
                            *task.id(),
                            aggregation_job_id,
                            (),
                            (),
                            Interval::new(
                                Time::from_seconds_since_epoch(0),
                                Duration::from_seconds(1),
                            )
                            .unwrap(),
                            AggregationJobState::InProgress,
                        ))
                        .await?;
                        tx.put_report_share(
                            task.id(),
                            &ReportShare::new(
                                ReportMetadata::new(report_id, time),
                                Vec::from("public_share"),
                                HpkeCiphertext::new(
                                    HpkeConfigId::from(12),
                                    Vec::from("encapsulated_context_0"),
                                    Vec::from("payload_0"),
                                ),
                            ),
                        )
                        .await?;

                        let report_aggregation = ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            report_id,
                            time,
                            ord as i64,
                            state,
                        );
                        tx.put_report_aggregation(&report_aggregation).await?;
                        Ok(report_aggregation)
                    })
                })
                .await
                .unwrap();

            let got_report_aggregation = ds
                .run_tx(|tx| {
                    let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
                    Box::pin(async move {
                        tx.get_report_aggregation(
                            vdaf.as_ref(),
                            &Role::Leader,
                            task.id(),
                            &aggregation_job_id,
                            &report_id,
                        )
                        .await
                    })
                })
                .await
                .unwrap();
            assert_eq!(Some(&report_aggregation), got_report_aggregation.as_ref());

            let new_report_aggregation = ReportAggregation::new(
                *report_aggregation.task_id(),
                *report_aggregation.aggregation_job_id(),
                *report_aggregation.report_id(),
                *report_aggregation.time(),
                report_aggregation.ord() + 10,
                report_aggregation.state().clone(),
            );
            ds.run_tx(|tx| {
                let new_report_aggregation = new_report_aggregation.clone();
                Box::pin(async move { tx.update_report_aggregation(&new_report_aggregation).await })
            })
            .await
            .unwrap();

            let got_report_aggregation = ds
                .run_tx(|tx| {
                    let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
                    Box::pin(async move {
                        tx.get_report_aggregation(
                            vdaf.as_ref(),
                            &Role::Leader,
                            task.id(),
                            &aggregation_job_id,
                            &report_id,
                        )
                        .await
                    })
                })
                .await
                .unwrap();
            assert_eq!(Some(new_report_aggregation), got_report_aggregation);
        }
    }

    #[tokio::test]
    async fn check_report_aggregation_exists() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());
        let task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Fake,
            Role::Helper,
        )
        .build();

        ds.put_task(&task).await.unwrap();

        let aggregation_job_id = random();
        let report_id = ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        ds.run_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move {
                tx.put_aggregation_job(&AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    task_id,
                    aggregation_job_id,
                    dummy_vdaf::AggregationParam(0),
                    (),
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::InProgress,
                ))
                .await?;
                tx.put_report_share(
                    &task_id,
                    &ReportShare::new(
                        ReportMetadata::new(report_id, Time::from_seconds_since_epoch(12345)),
                        Vec::from("public_share"),
                        HpkeCiphertext::new(
                            HpkeConfigId::from(12),
                            Vec::from("encapsulated_context_0"),
                            Vec::from("payload_0"),
                        ),
                    ),
                )
                .await?;

                let report_aggregation = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                    task_id,
                    aggregation_job_id,
                    report_id,
                    Time::from_seconds_since_epoch(12345),
                    0,
                    ReportAggregationState::Start,
                );
                tx.put_report_aggregation(&report_aggregation).await?;
                Ok(())
            })
        })
        .await
        .unwrap();

        ds.run_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move {
                assert!(tx
                    .check_report_aggregation_exists(
                        &task_id,
                        &report_id,
                        &dummy_vdaf::AggregationParam(0).get_encoded(),
                    )
                    .await
                    .unwrap());

                // Wrong task ID
                assert!(!tx
                    .check_report_aggregation_exists(
                        &random(),
                        &report_id,
                        &dummy_vdaf::AggregationParam(0).get_encoded(),
                    )
                    .await
                    .unwrap());

                // Wrong report ID
                assert!(!tx
                    .check_report_aggregation_exists(
                        &task_id,
                        &random(),
                        &dummy_vdaf::AggregationParam(0).get_encoded(),
                    )
                    .await
                    .unwrap());

                // Wrong aggregation param
                assert!(!tx
                    .check_report_aggregation_exists(
                        &task_id,
                        &report_id,
                        &dummy_vdaf::AggregationParam(1).get_encoded(),
                    )
                    .await
                    .unwrap());

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn report_aggregation_not_found() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        let vdaf = Arc::new(dummy_vdaf::Vdaf::default());

        let rslt = ds
            .run_tx(|tx| {
                let vdaf = Arc::clone(&vdaf);
                Box::pin(async move {
                    tx.get_report_aggregation(
                        vdaf.as_ref(),
                        &Role::Leader,
                        &random(),
                        &random(),
                        &ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(rslt, None);

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.update_report_aggregation::<0, dummy_vdaf::Vdaf>(&ReportAggregation::new(
                        random(),
                        random(),
                        ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                        Time::from_seconds_since_epoch(12345),
                        0,
                        ReportAggregationState::Invalid,
                    ))
                    .await
                })
            })
            .await;
        assert_matches!(rslt, Err(Error::MutationTargetNotFound));
    }

    #[tokio::test]
    async fn get_report_aggregations_for_aggregation_job() {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        let report_id = ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());
        let verify_key: [u8; PRIO3_AES128_VERIFY_KEY_LENGTH] = random();
        let vdaf_transcript = run_vdaf(vdaf.as_ref(), &verify_key, &(), &report_id, &0);

        let task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let aggregation_job_id = random();
        let time = Time::from_seconds_since_epoch(12345);

        let report_aggregations = ds
            .run_tx(|tx| {
                let (task, prep_msg, prep_state, output_share) = (
                    task.clone(),
                    vdaf_transcript.prepare_messages[0].clone(),
                    vdaf_transcript.prep_state(0, Role::Leader).clone(),
                    vdaf_transcript.output_share(Role::Leader).clone(),
                );
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        (),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                    ))
                    .await?;

                    let mut report_aggregations = Vec::new();
                    for (ord, state) in
                        [
                            ReportAggregationState::<
                                PRIO3_AES128_VERIFY_KEY_LENGTH,
                                Prio3Aes128Count,
                            >::Start,
                            ReportAggregationState::Waiting(prep_state.clone(), None),
                            ReportAggregationState::Waiting(prep_state, Some(prep_msg)),
                            ReportAggregationState::Finished(output_share),
                            ReportAggregationState::Failed(ReportShareError::VdafPrepError),
                            ReportAggregationState::Invalid,
                        ]
                        .iter()
                        .enumerate()
                    {
                        let report_id = ReportId::from((ord as u128).to_be_bytes());
                        tx.put_report_share(
                            task.id(),
                            &ReportShare::new(
                                ReportMetadata::new(report_id, time),
                                Vec::from("public_share"),
                                HpkeCiphertext::new(
                                    HpkeConfigId::from(12),
                                    Vec::from("encapsulated_context_0"),
                                    Vec::from("payload_0"),
                                ),
                            ),
                        )
                        .await?;

                        let report_aggregation = ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            report_id,
                            time,
                            ord as i64,
                            state.clone(),
                        );
                        tx.put_report_aggregation(&report_aggregation).await?;
                        report_aggregations.push(report_aggregation);
                    }
                    Ok(report_aggregations)
                })
            })
            .await
            .unwrap();

        let got_report_aggregations = ds
            .run_tx(|tx| {
                let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
                Box::pin(async move {
                    tx.get_report_aggregations_for_aggregation_job(
                        vdaf.as_ref(),
                        &Role::Leader,
                        task.id(),
                        &aggregation_job_id,
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(report_aggregations, got_report_aggregations);
    }

    #[tokio::test]
    async fn crypter() {
        let crypter = Crypter::new(Vec::from([generate_aead_key(), generate_aead_key()]));
        let bad_key = generate_aead_key();

        const TABLE: &str = "some_table";
        const ROW: &[u8] = b"12345";
        const COLUMN: &str = "some_column";
        const PLAINTEXT: &[u8] = b"This is my plaintext value.";

        // Test that roundtripping encryption works.
        let ciphertext = crypter.encrypt(TABLE, ROW, COLUMN, PLAINTEXT).unwrap();
        let plaintext = crypter.decrypt(TABLE, ROW, COLUMN, &ciphertext).unwrap();
        assert_eq!(PLAINTEXT, &plaintext);

        // Roundtripping encryption works even if a non-primary key was used for encryption.
        let ciphertext =
            Crypter::encrypt_with_key(crypter.keys.last().unwrap(), TABLE, ROW, COLUMN, PLAINTEXT)
                .unwrap();
        let plaintext = crypter.decrypt(TABLE, ROW, COLUMN, &ciphertext).unwrap();
        assert_eq!(PLAINTEXT, &plaintext);

        // Roundtripping encryption with an unknown key fails.
        let ciphertext =
            Crypter::encrypt_with_key(&bad_key, TABLE, ROW, COLUMN, PLAINTEXT).unwrap();
        assert!(crypter.decrypt(TABLE, ROW, COLUMN, &ciphertext).is_err());

        // Roundtripping encryption with a mismatched table, row, or column fails.
        let ciphertext = crypter.encrypt(TABLE, ROW, COLUMN, PLAINTEXT).unwrap();
        assert!(crypter
            .decrypt("wrong_table", ROW, COLUMN, &ciphertext)
            .is_err());
        assert!(crypter
            .decrypt(TABLE, b"wrong_row", COLUMN, &ciphertext)
            .is_err());
        assert!(crypter
            .decrypt(TABLE, ROW, "wrong_column", &ciphertext)
            .is_err());
    }

    #[tokio::test]
    async fn get_collection_job() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();
        let first_batch_interval = Interval::new(
            Time::from_seconds_since_epoch(100),
            Duration::from_seconds(100),
        )
        .unwrap();
        let second_batch_interval = Interval::new(
            Time::from_seconds_since_epoch(200),
            Duration::from_seconds(200),
        )
        .unwrap();
        let aggregation_param = AggregationParam(13);

        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        ds.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move {
                tx.put_task(&task).await.unwrap();

                let first_collection_job = CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    first_batch_interval,
                    aggregation_param,
                    CollectionJobState::Start,
                );
                tx.put_collection_job(&first_collection_job).await.unwrap();

                let second_collection_job = CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    second_batch_interval,
                    aggregation_param,
                    CollectionJobState::Start,
                );
                tx.put_collection_job(&second_collection_job).await.unwrap();

                let first_collection_job_again = tx
                    .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        first_collection_job.collection_job_id(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(first_collection_job, first_collection_job_again);

                let second_collection_job_again = tx
                    .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        second_collection_job.collection_job_id(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(second_collection_job, second_collection_job_again);

                let encrypted_helper_aggregate_share = hpke::seal(
                    task.collector_hpke_config(),
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Helper,
                        &Role::Collector,
                    ),
                    &[0, 1, 2, 3, 4, 5],
                    &AggregateShareAad::new(
                        *task.id(),
                        BatchSelector::new_time_interval(first_batch_interval),
                    )
                    .get_encoded(),
                )
                .unwrap();

                let first_collection_job =
                    first_collection_job.with_state(CollectionJobState::Finished {
                        report_count: 12,
                        encrypted_helper_aggregate_share,
                        leader_aggregate_share: AggregateShare(41),
                    });

                tx.update_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &first_collection_job,
                )
                .await
                .unwrap();

                let updated_first_collection_job = tx
                    .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        first_collection_job.collection_job_id(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(first_collection_job, updated_first_collection_job);

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn update_collection_jobs() {
        // Setup: write collection jobs to the datastore.
        install_test_trace_subscriber();

        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        let task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Fake,
            Role::Leader,
        )
        .build();
        let abandoned_batch_interval = Interval::new(
            Time::from_seconds_since_epoch(100),
            Duration::from_seconds(100),
        )
        .unwrap();
        let deleted_batch_interval = Interval::new(
            Time::from_seconds_since_epoch(200),
            Duration::from_seconds(100),
        )
        .unwrap();

        ds.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move {
                tx.put_task(&task).await?;

                let aggregation_param = AggregationParam(10);
                let abandoned_collection_job =
                    CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        abandoned_batch_interval,
                        aggregation_param,
                        CollectionJobState::Start,
                    );
                tx.put_collection_job(&abandoned_collection_job).await?;

                let deleted_collection_job =
                    CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        deleted_batch_interval,
                        aggregation_param,
                        CollectionJobState::Start,
                    );
                tx.put_collection_job(&deleted_collection_job).await?;

                let abandoned_collection_job_again = tx
                    .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        abandoned_collection_job.collection_job_id(),
                    )
                    .await?
                    .unwrap();

                // Verify: initial state.
                assert_eq!(abandoned_collection_job, abandoned_collection_job_again);

                // Setup: update the collection jobs.
                let abandoned_collection_job =
                    abandoned_collection_job.with_state(CollectionJobState::Abandoned);
                let deleted_collection_job =
                    deleted_collection_job.with_state(CollectionJobState::Deleted);

                tx.update_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &abandoned_collection_job,
                )
                .await?;
                tx.update_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &deleted_collection_job,
                )
                .await?;

                let abandoned_collection_job_again = tx
                    .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        abandoned_collection_job.collection_job_id(),
                    )
                    .await?
                    .unwrap();

                let deleted_collection_job_again = tx
                    .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        deleted_collection_job.collection_job_id(),
                    )
                    .await?
                    .unwrap();

                // Verify: collection jobs were updated.
                assert_eq!(abandoned_collection_job, abandoned_collection_job_again);
                assert_eq!(deleted_collection_job, deleted_collection_job_again);

                // Setup: try to update a job into state `Start`
                let abandoned_collection_job =
                    abandoned_collection_job.with_state(CollectionJobState::Start);

                // Verify: Update should fail
                tx.update_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &abandoned_collection_job,
                )
                .await
                .unwrap_err();
                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[derive(Copy, Clone)]
    enum CollectionJobTestCaseState {
        Start,
        Finished,
        Deleted,
        Abandoned,
    }

    #[derive(Clone)]
    struct CollectionJobTestCase<Q: QueryType> {
        should_be_acquired: bool,
        task_id: TaskId,
        batch_identifier: Q::BatchIdentifier,
        agg_param: AggregationParam,
        collection_job_id: Option<CollectionJobId>,
        state: CollectionJobTestCaseState,
    }

    #[derive(Clone)]
    struct CollectionJobAcquireTestCase<Q: CollectableQueryType> {
        task_ids: Vec<TaskId>,
        query_type: task::QueryType,
        reports: Vec<LeaderStoredReport<0, dummy_vdaf::Vdaf>>,
        aggregation_jobs: Vec<AggregationJob<0, Q, dummy_vdaf::Vdaf>>,
        report_aggregations: Vec<ReportAggregation<0, dummy_vdaf::Vdaf>>,
        collection_job_test_cases: Vec<CollectionJobTestCase<Q>>,
    }

    async fn setup_collection_job_acquire_test_case<Q: CollectableQueryType>(
        ds: &Datastore<MockClock>,
        test_case: CollectionJobAcquireTestCase<Q>,
    ) -> CollectionJobAcquireTestCase<Q> {
        ds.run_tx(|tx| {
            let mut test_case = test_case.clone();
            Box::pin(async move {
                for task_id in &test_case.task_ids {
                    tx.put_task(
                        &TaskBuilder::new(test_case.query_type, VdafInstance::Fake, Role::Leader)
                            .with_id(*task_id)
                            .build(),
                    )
                    .await?;
                }

                for report in &test_case.reports {
                    tx.put_client_report(&dummy_vdaf::Vdaf::new(), report)
                        .await?;
                }

                for aggregation_job in &test_case.aggregation_jobs {
                    tx.put_aggregation_job(aggregation_job).await?;
                }

                for report_aggregation in &test_case.report_aggregations {
                    tx.put_report_aggregation(report_aggregation).await?;
                }

                for test_case in test_case.collection_job_test_cases.iter_mut() {
                    let collection_job = CollectionJob::<0, Q, dummy_vdaf::Vdaf>::new(
                        test_case.task_id,
                        random(),
                        test_case.batch_identifier.clone(),
                        test_case.agg_param,
                        match test_case.state {
                            CollectionJobTestCaseState::Start => CollectionJobState::Start,
                            CollectionJobTestCaseState::Finished => CollectionJobState::Finished {
                                report_count: 1,
                                encrypted_helper_aggregate_share: HpkeCiphertext::new(
                                    HpkeConfigId::from(0),
                                    Vec::new(),
                                    Vec::new(),
                                ),
                                leader_aggregate_share: AggregateShare(0),
                            },
                            CollectionJobTestCaseState::Abandoned => CollectionJobState::Abandoned,
                            CollectionJobTestCaseState::Deleted => CollectionJobState::Deleted,
                        },
                    );
                    tx.put_collection_job(&collection_job).await?;
                    test_case.collection_job_id = Some(*collection_job.collection_job_id());
                }

                Ok(test_case)
            })
        })
        .await
        .unwrap()
    }

    async fn run_collection_job_acquire_test_case<Q: CollectableQueryType>(
        ds: &Datastore<MockClock>,
        test_case: CollectionJobAcquireTestCase<Q>,
    ) -> Vec<Lease<AcquiredCollectionJob>> {
        let test_case = setup_collection_job_acquire_test_case(ds, test_case).await;

        let clock = &ds.clock;
        ds.run_tx(|tx| {
            let test_case = test_case.clone();
            let clock = clock.clone();
            Box::pin(async move {
                let time_interval_leases = tx
                    .acquire_incomplete_time_interval_collection_jobs(
                        &StdDuration::from_secs(100),
                        10,
                    )
                    .await?;
                let fixed_size_leases = tx
                    .acquire_incomplete_fixed_size_collection_jobs(&StdDuration::from_secs(100), 10)
                    .await?;

                let mut leased_collection_jobs: Vec<_> = time_interval_leases
                    .iter()
                    .chain(fixed_size_leases.iter())
                    .map(|lease| (lease.leased().clone(), *lease.lease_expiry_time()))
                    .collect();
                leased_collection_jobs.sort();

                let mut expected_collection_jobs: Vec<_> = test_case
                    .collection_job_test_cases
                    .iter()
                    .filter(|c| c.should_be_acquired)
                    .map(|c| {
                        (
                            AcquiredCollectionJob::new(
                                c.task_id,
                                c.collection_job_id.unwrap(),
                                test_case.query_type,
                                VdafInstance::Fake,
                            ),
                            clock.now().as_naive_date_time().unwrap()
                                + chrono::Duration::seconds(100),
                        )
                    })
                    .collect();
                expected_collection_jobs.sort();

                assert_eq!(leased_collection_jobs, expected_collection_jobs);

                Ok(time_interval_leases
                    .into_iter()
                    .chain(fixed_size_leases.into_iter())
                    .collect())
            })
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn time_interval_collection_job_acquire_release_happy_path() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        let task_id = random();
        let reports = Vec::from([LeaderStoredReport::new_dummy(
            task_id,
            Time::from_seconds_since_epoch(0),
        )]);
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            Duration::from_seconds(100),
        )
        .unwrap();
        let aggregation_job_id = random();
        let aggregation_jobs =
            Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_id,
                AggregationParam(0),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
            )]);
        let report_aggregations = Vec::from([ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_id,
            *reports[0].metadata().id(),
            *reports[0].metadata().time(),
            0,
            ReportAggregationState::Start, // Doesn't matter what state the report aggregation is in
        )]);

        let collection_job_test_cases = Vec::from([CollectionJobTestCase::<TimeInterval> {
            should_be_acquired: true,
            task_id,
            batch_identifier: batch_interval,
            agg_param: AggregationParam(0),
            collection_job_id: None,
            state: CollectionJobTestCaseState::Start,
        }]);

        let collection_job_leases = run_collection_job_acquire_test_case(
            &ds,
            CollectionJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                query_type: task::QueryType::TimeInterval,
                reports,
                aggregation_jobs,
                report_aggregations,
                collection_job_test_cases,
            },
        )
        .await;

        let reacquired_jobs = ds
            .run_tx(|tx| {
                let collection_job_leases = collection_job_leases.clone();
                Box::pin(async move {
                    // Try to re-acquire collection jobs. Nothing should happen because the lease is still
                    // valid.
                    assert!(tx
                        .acquire_incomplete_time_interval_collection_jobs(
                            &StdDuration::from_secs(100),
                            10
                        )
                        .await
                        .unwrap()
                        .is_empty());

                    // Release the lease, then re-acquire it.
                    tx.release_collection_job(&collection_job_leases[0])
                        .await
                        .unwrap();

                    let reacquired_leases = tx
                        .acquire_incomplete_time_interval_collection_jobs(
                            &StdDuration::from_secs(100),
                            10,
                        )
                        .await
                        .unwrap();
                    let reacquired_jobs: Vec<_> = reacquired_leases
                        .iter()
                        .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
                        .collect();

                    let collection_jobs: Vec<_> = collection_job_leases
                        .iter()
                        .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
                        .collect();

                    assert_eq!(reacquired_jobs.len(), 1);
                    assert_eq!(reacquired_jobs, collection_jobs);

                    Ok(reacquired_leases)
                })
            })
            .await
            .unwrap();

        // Advance time by the lease duration
        clock.advance(Duration::from_seconds(100));

        ds.run_tx(|tx| {
            let reacquired_jobs = reacquired_jobs.clone();
            Box::pin(async move {
                // Re-acquire the jobs whose lease should have lapsed.
                let acquired_jobs = tx
                    .acquire_incomplete_time_interval_collection_jobs(
                        &StdDuration::from_secs(100),
                        10,
                    )
                    .await
                    .unwrap();

                for (acquired_job, reacquired_job) in acquired_jobs.iter().zip(reacquired_jobs) {
                    assert_eq!(acquired_job.leased(), reacquired_job.leased());
                    assert_eq!(
                        *acquired_job.lease_expiry_time(),
                        *reacquired_job.lease_expiry_time() + chrono::Duration::seconds(100),
                    );
                }

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn fixed_size_collection_job_acquire_release_happy_path() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        let task_id = random();
        let reports = Vec::from([LeaderStoredReport::new_dummy(
            task_id,
            Time::from_seconds_since_epoch(0),
        )]);
        let batch_id = random();
        let aggregation_job_id = random();
        let aggregation_jobs = Vec::from([AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_id,
            AggregationParam(0),
            batch_id,
            Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
            AggregationJobState::Finished,
        )]);
        let report_aggregations = Vec::from([ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_id,
            *reports[0].metadata().id(),
            *reports[0].metadata().time(),
            0,
            ReportAggregationState::Start, // Doesn't matter what state the report aggregation is in
        )]);

        let collection_job_leases = run_collection_job_acquire_test_case(
            &ds,
            CollectionJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                query_type: task::QueryType::FixedSize { max_batch_size: 10 },
                reports,
                aggregation_jobs,
                report_aggregations,
                collection_job_test_cases: Vec::from([CollectionJobTestCase::<FixedSize> {
                    should_be_acquired: true,
                    task_id,
                    batch_identifier: batch_id,
                    agg_param: AggregationParam(0),
                    collection_job_id: None,
                    state: CollectionJobTestCaseState::Start,
                }]),
            },
        )
        .await;

        let reacquired_jobs = ds
            .run_tx(|tx| {
                let collection_job_leases = collection_job_leases.clone();
                Box::pin(async move {
                    // Try to re-acquire collection jobs. Nothing should happen because the lease is still
                    // valid.
                    assert!(tx
                        .acquire_incomplete_fixed_size_collection_jobs(
                            &StdDuration::from_secs(100),
                            10,
                        )
                        .await
                        .unwrap()
                        .is_empty());

                    // Release the lease, then re-acquire it.
                    tx.release_collection_job(&collection_job_leases[0])
                        .await
                        .unwrap();

                    let reacquired_leases = tx
                        .acquire_incomplete_fixed_size_collection_jobs(
                            &StdDuration::from_secs(100),
                            10,
                        )
                        .await
                        .unwrap();
                    let reacquired_jobs: Vec<_> = reacquired_leases
                        .iter()
                        .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
                        .collect();

                    let collection_jobs: Vec<_> = collection_job_leases
                        .iter()
                        .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
                        .collect();

                    assert_eq!(reacquired_jobs.len(), 1);
                    assert_eq!(reacquired_jobs, collection_jobs);

                    Ok(reacquired_leases)
                })
            })
            .await
            .unwrap();

        // Advance time by the lease duration
        clock.advance(Duration::from_seconds(100));

        ds.run_tx(|tx| {
            let reacquired_jobs = reacquired_jobs.clone();
            Box::pin(async move {
                // Re-acquire the jobs whose lease should have lapsed.
                let acquired_jobs = tx
                    .acquire_incomplete_fixed_size_collection_jobs(&StdDuration::from_secs(100), 10)
                    .await
                    .unwrap();

                for (acquired_job, reacquired_job) in acquired_jobs.iter().zip(reacquired_jobs) {
                    assert_eq!(acquired_job.leased(), reacquired_job.leased());
                    assert_eq!(
                        *acquired_job.lease_expiry_time(),
                        *reacquired_job.lease_expiry_time() + chrono::Duration::seconds(100),
                    );
                }

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn collection_job_acquire_no_aggregation_job_with_task_id() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        let task_id = random();
        let other_task_id = random();

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            Duration::from_seconds(100),
        )
        .unwrap();
        let aggregation_jobs =
            Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                // Aggregation job task ID does not match collection job task ID
                other_task_id,
                random(),
                AggregationParam(0),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
            )]);

        let collection_job_test_cases = Vec::from([CollectionJobTestCase::<TimeInterval> {
            should_be_acquired: false,
            task_id,
            batch_identifier: batch_interval,
            agg_param: AggregationParam(0),
            collection_job_id: None,
            state: CollectionJobTestCaseState::Start,
        }]);

        run_collection_job_acquire_test_case(
            &ds,
            CollectionJobAcquireTestCase {
                task_ids: Vec::from([task_id, other_task_id]),
                query_type: task::QueryType::TimeInterval,
                reports: Vec::new(),
                aggregation_jobs,
                report_aggregations: Vec::new(),
                collection_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collection_job_acquire_no_aggregation_job_with_agg_param() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        let task_id = random();
        let reports = Vec::from([LeaderStoredReport::new_dummy(
            task_id,
            Time::from_seconds_since_epoch(0),
        )]);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            Duration::from_seconds(100),
        )
        .unwrap();
        let aggregation_jobs =
            Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                random(),
                // Aggregation job agg param does not match collection job agg param
                AggregationParam(1),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
            )]);

        let collection_job_test_cases = Vec::from([CollectionJobTestCase::<TimeInterval> {
            should_be_acquired: false,
            task_id,
            batch_identifier: batch_interval,
            agg_param: AggregationParam(0),
            collection_job_id: None,
            state: CollectionJobTestCaseState::Start,
        }]);

        run_collection_job_acquire_test_case(
            &ds,
            CollectionJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                query_type: task::QueryType::TimeInterval,
                reports,
                aggregation_jobs,
                report_aggregations: Vec::new(),
                collection_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collection_job_acquire_report_shares_outside_interval() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        let task_id = random();
        let reports = Vec::from([LeaderStoredReport::new_dummy(
            task_id,
            // Report associated with the aggregation job is outside the collection job's batch
            // interval
            Time::from_seconds_since_epoch(200),
        )]);
        let aggregation_job_id = random();
        let aggregation_jobs =
            Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_id,
                AggregationParam(0),
                (),
                Interval::new(
                    Time::from_seconds_since_epoch(200),
                    Duration::from_seconds(1),
                )
                .unwrap(),
                AggregationJobState::Finished,
            )]);
        let report_aggregations = Vec::from([ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_id,
            *reports[0].metadata().id(),
            *reports[0].metadata().time(),
            0,
            ReportAggregationState::Start, // Shouldn't matter what state the report aggregation is in
        )]);

        run_collection_job_acquire_test_case(
            &ds,
            CollectionJobAcquireTestCase::<TimeInterval> {
                task_ids: Vec::from([task_id]),
                query_type: task::QueryType::TimeInterval,
                reports,
                aggregation_jobs,
                report_aggregations,
                collection_job_test_cases: Vec::from([CollectionJobTestCase::<TimeInterval> {
                    should_be_acquired: false,
                    task_id,
                    batch_identifier: Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_seconds(100),
                    )
                    .unwrap(),
                    agg_param: AggregationParam(0),
                    collection_job_id: None,
                    state: CollectionJobTestCaseState::Start,
                }]),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collection_job_acquire_release_job_finished() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        let task_id = random();
        let reports = Vec::from([LeaderStoredReport::new_dummy(
            task_id,
            Time::from_seconds_since_epoch(0),
        )]);
        let aggregation_job_id = random();
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            Duration::from_seconds(100),
        )
        .unwrap();
        let aggregation_jobs =
            Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_id,
                AggregationParam(0),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
            )]);

        let report_aggregations = Vec::from([ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_id,
            *reports[0].metadata().id(),
            *reports[0].metadata().time(),
            0,
            ReportAggregationState::Start,
        )]);

        let collection_job_test_cases = Vec::from([CollectionJobTestCase::<TimeInterval> {
            should_be_acquired: false,
            task_id,
            batch_identifier: batch_interval,
            agg_param: AggregationParam(0),
            collection_job_id: None,
            // collection job has already run to completion
            state: CollectionJobTestCaseState::Finished,
        }]);

        run_collection_job_acquire_test_case(
            &ds,
            CollectionJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                query_type: task::QueryType::TimeInterval,
                reports,
                aggregation_jobs,
                report_aggregations,
                collection_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collection_job_acquire_release_aggregation_job_in_progress() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        let task_id = random();
        let reports = Vec::from([
            LeaderStoredReport::new_dummy(task_id, Time::from_seconds_since_epoch(0)),
            LeaderStoredReport::new_dummy(task_id, Time::from_seconds_since_epoch(50)),
        ]);

        let aggregation_job_ids: [_; 2] = random();
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            Duration::from_seconds(100),
        )
        .unwrap();
        let aggregation_jobs = Vec::from([
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[0],
                AggregationParam(0),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
            ),
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[1],
                AggregationParam(0),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                // Aggregation job included in collect request is in progress
                AggregationJobState::InProgress,
            ),
        ]);

        let report_aggregations = Vec::from([
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[0],
                *reports[0].metadata().id(),
                *reports[0].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[1],
                *reports[1].metadata().id(),
                *reports[1].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
        ]);

        let collection_job_test_cases = Vec::from([CollectionJobTestCase::<TimeInterval> {
            should_be_acquired: false,
            task_id,
            batch_identifier: batch_interval,
            agg_param: AggregationParam(0),
            collection_job_id: None,
            state: CollectionJobTestCaseState::Start,
        }]);

        run_collection_job_acquire_test_case(
            &ds,
            CollectionJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                query_type: task::QueryType::TimeInterval,
                reports,
                aggregation_jobs,
                report_aggregations,
                collection_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collection_job_acquire_job_max() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        let task_id = random();
        let reports = Vec::from([LeaderStoredReport::new_dummy(
            task_id,
            Time::from_seconds_since_epoch(0),
        )]);
        let aggregation_job_ids: [_; 2] = random();
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            Duration::from_seconds(100),
        )
        .unwrap();
        let aggregation_jobs = Vec::from([
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[0],
                AggregationParam(0),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
            ),
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[1],
                AggregationParam(1),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
            ),
        ]);
        let report_aggregations = Vec::from([
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[0],
                *reports[0].metadata().id(),
                *reports[0].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[1],
                *reports[0].metadata().id(),
                *reports[0].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
        ]);

        let collection_job_test_cases = Vec::from([
            CollectionJobTestCase::<TimeInterval> {
                should_be_acquired: true,
                task_id,
                batch_identifier: batch_interval,
                agg_param: AggregationParam(0),
                collection_job_id: None,
                state: CollectionJobTestCaseState::Start,
            },
            CollectionJobTestCase::<TimeInterval> {
                should_be_acquired: true,
                task_id,
                batch_identifier: Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(100),
                )
                .unwrap(),
                agg_param: AggregationParam(1),
                collection_job_id: None,
                state: CollectionJobTestCaseState::Start,
            },
        ]);

        let test_case = setup_collection_job_acquire_test_case(
            &ds,
            CollectionJobAcquireTestCase::<TimeInterval> {
                task_ids: Vec::from([task_id]),
                query_type: task::QueryType::TimeInterval,
                reports,
                aggregation_jobs,
                report_aggregations,
                collection_job_test_cases,
            },
        )
        .await;

        ds.run_tx(|tx| {
            let test_case = test_case.clone();
            let clock = clock.clone();
            Box::pin(async move {
                // Acquire a single collection job, twice. Each call should yield one job. We don't
                // care what order they are acquired in.
                let mut acquired_collection_jobs = tx
                    .acquire_incomplete_time_interval_collection_jobs(
                        &StdDuration::from_secs(100),
                        1,
                    )
                    .await?;
                assert_eq!(acquired_collection_jobs.len(), 1);

                acquired_collection_jobs.extend(
                    tx.acquire_incomplete_time_interval_collection_jobs(
                        &StdDuration::from_secs(100),
                        1,
                    )
                    .await?,
                );

                assert_eq!(acquired_collection_jobs.len(), 2);

                let mut acquired_collection_jobs: Vec<_> = acquired_collection_jobs
                    .iter()
                    .map(|lease| (lease.leased().clone(), *lease.lease_expiry_time()))
                    .collect();
                acquired_collection_jobs.sort();

                let mut expected_collection_jobs: Vec<_> = test_case
                    .collection_job_test_cases
                    .iter()
                    .filter(|c| c.should_be_acquired)
                    .map(|c| {
                        (
                            AcquiredCollectionJob::new(
                                c.task_id,
                                c.collection_job_id.unwrap(),
                                task::QueryType::TimeInterval,
                                VdafInstance::Fake,
                            ),
                            clock.now().as_naive_date_time().unwrap()
                                + chrono::Duration::seconds(100),
                        )
                    })
                    .collect();
                expected_collection_jobs.sort();

                assert_eq!(acquired_collection_jobs, expected_collection_jobs);

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn collection_job_acquire_state_filtering() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        let task_id = random();
        let reports = Vec::from([LeaderStoredReport::new_dummy(
            task_id,
            Time::from_seconds_since_epoch(0),
        )]);
        let aggregation_job_ids: [_; 3] = random();
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            Duration::from_seconds(100),
        )
        .unwrap();
        let aggregation_jobs = Vec::from([
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[0],
                AggregationParam(0),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
            ),
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[1],
                AggregationParam(1),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
            ),
            AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[2],
                AggregationParam(2),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
            ),
        ]);
        let report_aggregations = Vec::from([
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[0],
                *reports[0].metadata().id(),
                *reports[0].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[1],
                *reports[0].metadata().id(),
                *reports[0].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
            ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_ids[2],
                *reports[0].metadata().id(),
                *reports[0].metadata().time(),
                0,
                ReportAggregationState::Start,
            ),
        ]);

        let collection_job_test_cases = Vec::from([
            CollectionJobTestCase::<TimeInterval> {
                should_be_acquired: true,
                task_id,
                batch_identifier: batch_interval,
                agg_param: AggregationParam(0),
                collection_job_id: None,
                state: CollectionJobTestCaseState::Finished,
            },
            CollectionJobTestCase::<TimeInterval> {
                should_be_acquired: true,
                task_id,
                batch_identifier: batch_interval,
                agg_param: AggregationParam(1),
                collection_job_id: None,
                state: CollectionJobTestCaseState::Abandoned,
            },
            CollectionJobTestCase::<TimeInterval> {
                should_be_acquired: true,
                task_id,
                batch_identifier: batch_interval,
                agg_param: AggregationParam(2),
                collection_job_id: None,
                state: CollectionJobTestCaseState::Deleted,
            },
        ]);

        setup_collection_job_acquire_test_case(
            &ds,
            CollectionJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                query_type: task::QueryType::TimeInterval,
                reports,
                aggregation_jobs,
                report_aggregations,
                collection_job_test_cases,
            },
        )
        .await;

        ds.run_tx(|tx| {
            Box::pin(async move {
                // No collection jobs should be acquired because none of them are in the START state
                let acquired_collection_jobs = tx
                    .acquire_incomplete_time_interval_collection_jobs(
                        &StdDuration::from_secs(100),
                        10,
                    )
                    .await?;
                assert!(acquired_collection_jobs.is_empty());

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn roundtrip_batch_aggregation_time_interval() {
        install_test_trace_subscriber();

        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        ds.run_tx(|tx| {
            Box::pin(async move {
                let time_precision = Duration::from_seconds(100);
                let task = TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .with_time_precision(time_precision)
                .build();
                let other_task = TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .build();
                let aggregate_share = AggregateShare(23);
                let aggregation_param = AggregationParam(12);

                tx.put_task(&task).await?;
                tx.put_task(&other_task).await?;

                let first_batch_aggregation =
                    BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(100), time_precision).unwrap(),
                        aggregation_param,
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    );

                let second_batch_aggregation =
                    BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(200), time_precision).unwrap(),
                        aggregation_param,
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    );

                let third_batch_aggregation =
                    BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(300), time_precision).unwrap(),
                        aggregation_param,
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    );

                // Start of this aggregation's interval is before the interval queried below.
                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(0), time_precision).unwrap(),
                        aggregation_param,
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    ),
                )
                .await?;

                // Following three batches are within the interval queried below.
                tx.put_batch_aggregation(&first_batch_aggregation).await?;
                tx.put_batch_aggregation(&second_batch_aggregation).await?;
                tx.put_batch_aggregation(&third_batch_aggregation).await?;

                // Aggregation parameter differs from the one queried below.
                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(100), time_precision).unwrap(),
                        AggregationParam(13),
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    ),
                )
                .await?;

                // Start of this aggregation's interval is after the interval queried below.
                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(400), time_precision).unwrap(),
                        aggregation_param,
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    ),
                )
                .await?;

                // Task ID differs from that queried below.
                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *other_task.id(),
                        Interval::new(Time::from_seconds_since_epoch(200), time_precision).unwrap(),
                        aggregation_param,
                        aggregate_share.clone(),
                        0,
                        ReportIdChecksum::default(),
                    ),
                )
                .await?;

                let batch_aggregations =
                    TimeInterval::get_batch_aggregations_for_collect_identifier::<
                        0,
                        dummy_vdaf::Vdaf,
                        _,
                    >(
                        tx,
                        &task,
                        &Interval::new(
                            Time::from_seconds_since_epoch(100),
                            Duration::from_seconds(3 * time_precision.as_seconds()),
                        )
                        .unwrap(),
                        &aggregation_param,
                    )
                    .await?;

                assert_eq!(batch_aggregations.len(), 3, "{batch_aggregations:#?}");
                for batch_aggregation in [
                    &first_batch_aggregation,
                    &second_batch_aggregation,
                    &third_batch_aggregation,
                ] {
                    assert!(
                        batch_aggregations.contains(batch_aggregation),
                        "{batch_aggregations:#?}"
                    );
                }

                let first_batch_aggregation =
                    BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *first_batch_aggregation.task_id(),
                        *first_batch_aggregation.batch_interval(),
                        *first_batch_aggregation.aggregation_parameter(),
                        AggregateShare(92),
                        1,
                        ReportIdChecksum::get_decoded(&[1; 32]).unwrap(),
                    );
                tx.update_batch_aggregation(&first_batch_aggregation)
                    .await?;

                let batch_aggregations =
                    TimeInterval::get_batch_aggregations_for_collect_identifier::<
                        0,
                        dummy_vdaf::Vdaf,
                        _,
                    >(
                        tx,
                        &task,
                        &Interval::new(
                            Time::from_seconds_since_epoch(100),
                            Duration::from_seconds(3 * time_precision.as_seconds()),
                        )
                        .unwrap(),
                        &aggregation_param,
                    )
                    .await?;

                assert_eq!(batch_aggregations.len(), 3, "{batch_aggregations:#?}");
                for batch_aggregation in [
                    &first_batch_aggregation,
                    &second_batch_aggregation,
                    &third_batch_aggregation,
                ] {
                    assert!(
                        batch_aggregations.contains(batch_aggregation),
                        "{batch_aggregations:#?}"
                    );
                }

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn roundtrip_batch_aggregation_fixed_size() {
        install_test_trace_subscriber();

        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        ds.run_tx(|tx| {
            Box::pin(async move {
                let task = TaskBuilder::new(
                    task::QueryType::FixedSize { max_batch_size: 10 },
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .build();
                let other_task = TaskBuilder::new(
                    task::QueryType::FixedSize { max_batch_size: 10 },
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .build();
                let batch_id = random();
                let aggregate_share = AggregateShare(23);
                let aggregation_param = AggregationParam(12);

                tx.put_task(&task).await?;
                tx.put_task(&other_task).await?;

                let batch_aggregation = BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    batch_id,
                    aggregation_param,
                    aggregate_share.clone(),
                    0,
                    ReportIdChecksum::default(),
                );

                // Following three batches are within the interval queried below.
                tx.put_batch_aggregation(&batch_aggregation).await?;

                // Wrong batch ID.
                tx.put_batch_aggregation(&BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    AggregationParam(13),
                    aggregate_share.clone(),
                    0,
                    ReportIdChecksum::default(),
                ))
                .await?;

                // Task ID differs from that queried below.
                tx.put_batch_aggregation(&BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *other_task.id(),
                    batch_id,
                    aggregation_param,
                    aggregate_share.clone(),
                    0,
                    ReportIdChecksum::default(),
                ))
                .await?;

                let got_batch_aggregation = tx
                    .get_batch_aggregation::<0, FixedSize, dummy_vdaf::Vdaf>(
                        task.id(),
                        &batch_id,
                        &aggregation_param,
                    )
                    .await?;
                assert_eq!(got_batch_aggregation.as_ref(), Some(&batch_aggregation));

                let batch_aggregation = BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *batch_aggregation.task_id(),
                    *batch_aggregation.batch_id(),
                    *batch_aggregation.aggregation_parameter(),
                    AggregateShare(92),
                    1,
                    ReportIdChecksum::get_decoded(&[1; 32]).unwrap(),
                );
                tx.update_batch_aggregation(&batch_aggregation).await?;

                let got_batch_aggregation = tx
                    .get_batch_aggregation::<0, FixedSize, dummy_vdaf::Vdaf>(
                        task.id(),
                        &batch_id,
                        &aggregation_param,
                    )
                    .await?;
                assert_eq!(got_batch_aggregation, Some(batch_aggregation));
                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn roundtrip_aggregate_share_job() {
        install_test_trace_subscriber();

        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(MockClock::default());

        ds.run_tx(|tx| {
            Box::pin(async move {
                let task =
                    TaskBuilder::new(task::QueryType::TimeInterval, VdafInstance::Fake, Role::Helper)
                        .build();
                tx.put_task(&task).await?;

                let aggregate_share = AggregateShare(42);
                let batch_interval = Interval::new(
                    Time::from_seconds_since_epoch(100),
                    Duration::from_seconds(100),
                )
                .unwrap();
                let other_batch_interval = Interval::new(
                    Time::from_seconds_since_epoch(101),
                    Duration::from_seconds(101),
                )
                .unwrap();
                let report_count = 10;
                let checksum = ReportIdChecksum::get_decoded(&[1; 32]).unwrap();
                let aggregation_param = AggregationParam(11);

                let aggregate_share_job =
                    AggregateShareJob::new(
                        *task.id(),
                        batch_interval,
                        aggregation_param,
                        aggregate_share.clone(),
                        report_count,
                        checksum,
                    );

                tx.put_aggregate_share_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &aggregate_share_job,
                )
                .await
                .unwrap();

                let aggregate_share_job_again = tx
                    .get_aggregate_share_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        task.id(),
                        &batch_interval,
                        &aggregation_param,
                    )
                    .await
                    .unwrap()
                    .unwrap();

                assert_eq!(aggregate_share_job, aggregate_share_job_again);

                assert!(tx
                    .get_aggregate_share_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        task.id(),
                        &other_batch_interval,
                        &aggregation_param,
                    )
                    .await
                    .unwrap()
                    .is_none());

                let want_aggregate_share_jobs = Vec::from([aggregate_share_job]);

                let got_aggregate_share_jobs = tx
                    .get_aggregate_share_jobs_including_time::<0, dummy_vdaf::Vdaf>(
                        task.id(),
                        &Time::from_seconds_since_epoch(150),
                    )
                    .await?;
                assert_eq!(got_aggregate_share_jobs, want_aggregate_share_jobs);

                let got_aggregate_share_jobs = tx
                    .get_aggregate_share_jobs_intersecting_interval::<0, dummy_vdaf::Vdaf>(
                        task.id(),
                        &Interval::new(
                            Time::from_seconds_since_epoch(145),
                            Duration::from_seconds(10),
                        )
                        .unwrap(),
                    )
                    .await?;
                assert_eq!(got_aggregate_share_jobs, want_aggregate_share_jobs);

                let got_aggregate_share_jobs = tx
                    .get_aggregate_share_jobs_by_batch_identifier::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        task.id(),
                        &batch_interval
                    ).await?;
                assert_eq!(got_aggregate_share_jobs, want_aggregate_share_jobs);

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn roundtrip_outstanding_batch() {
        install_test_trace_subscriber();

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        let (task_id, batch_id) = ds
            .run_tx(|tx| {
                let clock = clock.clone();
                Box::pin(async move {
                    let task = TaskBuilder::new(
                        task::QueryType::FixedSize { max_batch_size: 10 },
                        VdafInstance::Fake,
                        Role::Leader,
                    )
                    .build();
                    tx.put_task(&task).await?;
                    let batch_id = random();
                    tx.put_outstanding_batch(task.id(), &batch_id).await?;

                    // Write a few aggregation jobs & report aggregations to produce useful
                    // min_size/max_size values to validate later.
                    let aggregation_job_0 = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        AggregationParam(0),
                        batch_id,
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::Finished,
                    );
                    let report_aggregation_0_0 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_0.id(),
                        random(),
                        clock.now(),
                        0,
                        ReportAggregationState::Start, // Counted among max_size.
                    );
                    let report_aggregation_0_1 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_0.id(),
                        random(),
                        clock.now(),
                        1,
                        ReportAggregationState::Waiting((), Some(())), // Counted among max_size.
                    );
                    let report_aggregation_0_2 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_0.id(),
                        random(),
                        clock.now(),
                        2,
                        ReportAggregationState::Failed(ReportShareError::VdafPrepError), // Not counted among min_size or max_size.
                    );
                    let report_aggregation_0_3 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_0.id(),
                        random(),
                        clock.now(),
                        3,
                        ReportAggregationState::Invalid, // Not counted among min_size or max_size.
                    );

                    let aggregation_job_1 = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        AggregationParam(0),
                        batch_id,
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::Finished,
                    );
                    let report_aggregation_1_0 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_1.id(),
                        random(),
                        clock.now(),
                        0,
                        ReportAggregationState::Finished(dummy_vdaf::OutputShare()), // Counted among min_size and max_size.
                    );
                    let report_aggregation_1_1 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_1.id(),
                        random(),
                        clock.now(),
                        1,
                        ReportAggregationState::Finished(dummy_vdaf::OutputShare()), // Counted among min_size and max_size.
                    );
                    let report_aggregation_1_2 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_1.id(),
                        random(),
                        clock.now(),
                        2,
                        ReportAggregationState::Failed(ReportShareError::VdafPrepError), // Not counted among min_size or max_size.
                    );
                    let report_aggregation_1_3 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_1.id(),
                        random(),
                        clock.now(),
                        3,
                        ReportAggregationState::Invalid, // Not counted among min_size or max_size.
                    );

                    for aggregation_job in &[aggregation_job_0, aggregation_job_1] {
                        tx.put_aggregation_job(aggregation_job).await?;
                    }
                    for report_aggregation in &[
                        report_aggregation_0_0,
                        report_aggregation_0_1,
                        report_aggregation_0_2,
                        report_aggregation_0_3,
                        report_aggregation_1_0,
                        report_aggregation_1_1,
                        report_aggregation_1_2,
                        report_aggregation_1_3,
                    ] {
                        tx.put_client_report(
                            &dummy_vdaf::Vdaf::new(),
                            &LeaderStoredReport::new(
                                *report_aggregation.task_id(),
                                ReportMetadata::new(
                                    *report_aggregation.report_id(),
                                    *report_aggregation.time(),
                                ),
                                (), // Dummy public share
                                Vec::new(),
                                (), // Dummy leader input share
                                // Dummy helper encrypted input share
                                HpkeCiphertext::new(
                                    HpkeConfigId::from(13),
                                    Vec::from("encapsulated_context_0"),
                                    Vec::from("payload_0"),
                                ),
                            ),
                        )
                        .await?;
                        tx.put_report_aggregation(report_aggregation).await?;
                    }

                    Ok((*task.id(), batch_id))
                })
            })
            .await
            .unwrap();

        let (outstanding_batches, outstanding_batch_1, outstanding_batch_2, outstanding_batch_3) =
            ds.run_tx(|tx| {
                Box::pin(async move {
                    let outstanding_batches = tx.get_outstanding_batches_for_task(&task_id).await?;
                    let outstanding_batch_1 = tx.get_filled_outstanding_batch(&task_id, 1).await?;
                    let outstanding_batch_2 = tx.get_filled_outstanding_batch(&task_id, 2).await?;
                    let outstanding_batch_3 = tx.get_filled_outstanding_batch(&task_id, 3).await?;
                    Ok((
                        outstanding_batches,
                        outstanding_batch_1,
                        outstanding_batch_2,
                        outstanding_batch_3,
                    ))
                })
            })
            .await
            .unwrap();
        assert_eq!(
            outstanding_batches,
            Vec::from([OutstandingBatch::new(
                task_id,
                batch_id,
                RangeInclusive::new(2, 4)
            )])
        );
        assert_eq!(outstanding_batch_1, Some(batch_id));
        assert_eq!(outstanding_batch_2, Some(batch_id));
        assert_eq!(outstanding_batch_3, None);

        // Delete the outstanding batch, then check that it is no longer available.
        ds.run_tx(|tx| {
            Box::pin(async move { tx.delete_outstanding_batch(&task_id, &batch_id).await })
        })
        .await
        .unwrap();

        let outstanding_batches = ds
            .run_tx(|tx| {
                Box::pin(async move { tx.get_outstanding_batches_for_task(&task_id).await })
            })
            .await
            .unwrap();
        assert!(outstanding_batches.is_empty());
    }

    #[async_trait]
    trait ExpirationQueryTypeExt: CollectableQueryType {
        fn batch_identifier_for_client_timestamps(
            client_timestamps: &[Time],
        ) -> Self::BatchIdentifier;

        fn shortened_batch_identifier(
            batch_identifier: &Self::BatchIdentifier,
        ) -> Self::BatchIdentifier;

        async fn write_outstanding_batch(
            tx: &Transaction<MockClock>,
            task_id: &TaskId,
            batch_identifier: &Self::BatchIdentifier,
        ) -> Option<(TaskId, BatchId)>;
    }

    #[async_trait]
    impl ExpirationQueryTypeExt for TimeInterval {
        fn batch_identifier_for_client_timestamps(
            client_timestamps: &[Time],
        ) -> Self::BatchIdentifier {
            let min_client_timestamp = *client_timestamps.iter().min().unwrap();
            let max_client_timestamp = *client_timestamps.iter().max().unwrap();
            Interval::new(
                min_client_timestamp,
                Duration::from_seconds(
                    max_client_timestamp
                        .difference(&min_client_timestamp)
                        .unwrap()
                        .as_seconds()
                        + 1,
                ),
            )
            .unwrap()
        }

        fn shortened_batch_identifier(
            batch_identifier: &Self::BatchIdentifier,
        ) -> Self::BatchIdentifier {
            Interval::new(
                *batch_identifier.start(),
                Duration::from_seconds(batch_identifier.duration().as_seconds() / 2),
            )
            .unwrap()
        }

        async fn write_outstanding_batch(
            _: &Transaction<MockClock>,
            _: &TaskId,
            _: &Self::BatchIdentifier,
        ) -> Option<(TaskId, BatchId)> {
            None
        }
    }

    #[async_trait]
    impl ExpirationQueryTypeExt for FixedSize {
        fn batch_identifier_for_client_timestamps(_: &[Time]) -> Self::BatchIdentifier {
            random()
        }

        fn shortened_batch_identifier(
            batch_identifier: &Self::BatchIdentifier,
        ) -> Self::BatchIdentifier {
            *batch_identifier
        }

        async fn write_outstanding_batch(
            tx: &Transaction<MockClock>,
            task_id: &TaskId,
            batch_identifier: &Self::BatchIdentifier,
        ) -> Option<(TaskId, BatchId)> {
            tx.put_outstanding_batch(task_id, batch_identifier)
                .await
                .unwrap();
            Some((*task_id, *batch_identifier))
        }
    }

    #[tokio::test]
    async fn delete_expired_client_reports() {
        install_test_trace_subscriber();

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());
        let vdaf = dummy_vdaf::Vdaf::new();

        // Setup.
        const OLDEST_ALLOWED_REPORT_TIMESTAMP: Time = Time::from_seconds_since_epoch(1000);
        let (task_id, new_report_id, attached_report_id, other_task_id, other_task_report_id) = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    let task = TaskBuilder::new(
                        task::QueryType::TimeInterval,
                        VdafInstance::Fake,
                        Role::Leader,
                    )
                    .build();
                    let other_task = TaskBuilder::new(
                        task::QueryType::TimeInterval,
                        VdafInstance::Fake,
                        Role::Leader,
                    )
                    .build();
                    tx.put_task(&task).await?;
                    tx.put_task(&other_task).await?;

                    let old_report = LeaderStoredReport::new_dummy(
                        *task.id(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(1))
                            .unwrap(),
                    );
                    let new_report =
                        LeaderStoredReport::new_dummy(*task.id(), OLDEST_ALLOWED_REPORT_TIMESTAMP);
                    let attached_report = LeaderStoredReport::new_dummy(
                        *task.id(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(1))
                            .unwrap(),
                    );
                    let other_task_report = LeaderStoredReport::new_dummy(
                        *other_task.id(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(1))
                            .unwrap(),
                    );
                    tx.put_client_report(&dummy_vdaf::Vdaf::new(), &old_report)
                        .await?;
                    tx.put_client_report(&dummy_vdaf::Vdaf::new(), &new_report)
                        .await?;
                    tx.put_client_report(&dummy_vdaf::Vdaf::new(), &attached_report)
                        .await?;
                    tx.put_client_report(&dummy_vdaf::Vdaf::new(), &other_task_report)
                        .await?;

                    let aggregation_job = AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        AggregationParam(0),
                        (),
                        Interval::new(
                            *attached_report.metadata().time(),
                            Duration::from_seconds(1),
                        )
                        .unwrap(),
                        AggregationJobState::InProgress,
                    );
                    let report_aggregation = ReportAggregation::new(
                        *task.id(),
                        *aggregation_job.id(),
                        *attached_report.metadata().id(),
                        *attached_report.metadata().time(),
                        0,
                        ReportAggregationState::<0, dummy_vdaf::Vdaf>::Start,
                    );

                    tx.put_aggregation_job(&aggregation_job).await?;
                    tx.put_report_aggregation(&report_aggregation).await?;

                    Ok((
                        *task.id(),
                        *new_report.metadata().id(),
                        *attached_report.metadata().id(),
                        *other_task.id(),
                        *other_task_report.metadata().id(),
                    ))
                })
            })
            .await
            .unwrap();

        // Run.
        ds.run_tx(|tx| {
            Box::pin(async move {
                tx.delete_expired_client_reports(&task_id, OLDEST_ALLOWED_REPORT_TIMESTAMP)
                    .await
            })
        })
        .await
        .unwrap();

        // Verify.
        let want_report_ids =
            HashSet::from([new_report_id, attached_report_id, other_task_report_id]);
        let got_report_ids = ds
            .run_tx(|tx| {
                let vdaf = vdaf.clone();
                Box::pin(async move {
                    let task_client_reports =
                        tx.get_client_reports_for_task(&vdaf, &task_id).await?;
                    let other_task_client_reports = tx
                        .get_client_reports_for_task(&vdaf, &other_task_id)
                        .await?;
                    Ok(HashSet::from_iter(
                        task_client_reports
                            .into_iter()
                            .chain(other_task_client_reports)
                            .map(|report| *report.metadata().id()),
                    ))
                })
            })
            .await
            .unwrap();
        assert_eq!(want_report_ids, got_report_ids);
    }

    #[tokio::test]
    async fn delete_expired_aggregation_artifacts() {
        install_test_trace_subscriber();

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());
        let vdaf = dummy_vdaf::Vdaf::new();

        // Setup.
        async fn write_aggregation_artifacts<Q: ExpirationQueryTypeExt>(
            tx: &Transaction<'_, MockClock>,
            task_id: &TaskId,
            client_timestamps: &[Time],
        ) -> (
            Q::BatchIdentifier,
            AggregationJobId,   // aggregation job ID
            Q::BatchIdentifier, // batch aggregation ID
            Vec<ReportId>,      // client report IDs
        ) {
            let batch_identifier = Q::batch_identifier_for_client_timestamps(client_timestamps);

            let mut report_ids_and_timestamps = Vec::new();
            for client_timestamp in client_timestamps {
                let report = LeaderStoredReport::new_dummy(*task_id, *client_timestamp);
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report)
                    .await
                    .unwrap();
                report_ids_and_timestamps.push((*report.metadata().id(), *client_timestamp));
            }

            // We arbitrarily extend the client_timestamp_interval by one second in each direction
            // in order to test that GC occurs correctly even if aggregation jobs overlap with, but
            // are not contained within, collection jobs.
            let min_client_timestamp = client_timestamps
                .iter()
                .min()
                .unwrap()
                .sub(&Duration::from_seconds(1))
                .unwrap();
            let max_client_timestamp = client_timestamps
                .iter()
                .max()
                .unwrap()
                .add(&Duration::from_seconds(1))
                .unwrap();
            let client_timestamp_interval = Interval::new(
                min_client_timestamp,
                max_client_timestamp
                    .difference(&min_client_timestamp)
                    .unwrap()
                    .add(&Duration::from_seconds(1))
                    .unwrap(),
            )
            .unwrap();

            let aggregation_job = AggregationJob::<0, Q, dummy_vdaf::Vdaf>::new(
                *task_id,
                random(),
                AggregationParam(0),
                Q::partial_batch_identifier(&batch_identifier).clone(),
                client_timestamp_interval,
                AggregationJobState::InProgress,
            );
            tx.put_aggregation_job(&aggregation_job).await.unwrap();

            for (ord, (report_id, client_timestamp)) in report_ids_and_timestamps.iter().enumerate()
            {
                let report_aggregation = ReportAggregation::new(
                    *task_id,
                    *aggregation_job.id(),
                    *report_id,
                    *client_timestamp,
                    ord.try_into().unwrap(),
                    ReportAggregationState::<0, dummy_vdaf::Vdaf>::Start,
                );
                tx.put_report_aggregation(&report_aggregation)
                    .await
                    .unwrap();
            }

            let shortened_batch_identifier = Q::shortened_batch_identifier(&batch_identifier);
            let batch_aggregation = BatchAggregation::<0, Q, dummy_vdaf::Vdaf>::new(
                *task_id,
                shortened_batch_identifier.clone(),
                AggregationParam(0),
                AggregateShare(0),
                0,
                ReportIdChecksum::default(),
            );
            tx.put_batch_aggregation(&batch_aggregation).await.unwrap();

            (
                batch_identifier,
                *aggregation_job.id(),
                shortened_batch_identifier,
                report_ids_and_timestamps
                    .into_iter()
                    .map(|(report_id, _)| report_id)
                    .collect(),
            )
        }

        const OLDEST_ALLOWED_REPORT_TIMESTAMP: Time = Time::from_seconds_since_epoch(1000);
        let (
            leader_time_interval_task_id,
            helper_time_interval_task_id,
            leader_fixed_size_task_id,
            helper_fixed_size_task_id,
            other_task_id,
            want_aggregation_job_ids,
            want_batch_aggregation_ids,
            want_report_ids,
        ) = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    let leader_time_interval_task = TaskBuilder::new(
                        task::QueryType::TimeInterval,
                        VdafInstance::Fake,
                        Role::Leader,
                    )
                    .build();
                    let helper_time_interval_task = TaskBuilder::new(
                        task::QueryType::TimeInterval,
                        VdafInstance::Fake,
                        Role::Helper,
                    )
                    .build();
                    let leader_fixed_size_task = TaskBuilder::new(
                        task::QueryType::FixedSize { max_batch_size: 10 },
                        VdafInstance::Fake,
                        Role::Leader,
                    )
                    .build();
                    let helper_fixed_size_task = TaskBuilder::new(
                        task::QueryType::FixedSize { max_batch_size: 10 },
                        VdafInstance::Fake,
                        Role::Helper,
                    )
                    .build();
                    let other_task = TaskBuilder::new(
                        task::QueryType::TimeInterval,
                        VdafInstance::Fake,
                        Role::Leader,
                    )
                    .build();
                    tx.put_task(&leader_time_interval_task).await?;
                    tx.put_task(&helper_time_interval_task).await?;
                    tx.put_task(&leader_fixed_size_task).await?;
                    tx.put_task(&helper_fixed_size_task).await?;
                    tx.put_task(&other_task).await?;

                    let mut aggregation_job_ids = HashSet::new();
                    let mut batch_aggregation_ids = HashSet::new();
                    let mut all_report_ids = HashSet::new();

                    // Leader, time-interval aggregation job with old reports [GC'ed].
                    write_aggregation_artifacts::<TimeInterval>(
                        tx,
                        leader_time_interval_task.id(),
                        &[
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(20))
                                .unwrap(),
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(19))
                                .unwrap(),
                        ],
                    )
                    .await;

                    // Leader, time-interval aggregation job with old & new reports [not GC'ed].
                    let (_, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<TimeInterval>(
                            tx,
                            leader_time_interval_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(5))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(8))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    // Leader, time-interval aggregation job with new reports [not GC'ed].
                    let (_, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<TimeInterval>(
                            tx,
                            leader_time_interval_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(19))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(20))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    // Leader, time-interval aggregation job with attached collection job [not GC'ed].
                    let (batch_identifier, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<TimeInterval>(
                            tx,
                            leader_time_interval_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(10))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(9))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    tx.put_collection_job(
                        &CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *leader_time_interval_task.id(),
                            random(),
                            batch_identifier,
                            AggregationParam(0),
                            CollectionJobState::Start,
                        ),
                    )
                    .await
                    .unwrap();
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    // Helper, time-interval aggregation job with old reports [GC'ed].
                    write_aggregation_artifacts::<TimeInterval>(
                        tx,
                        helper_time_interval_task.id(),
                        &[
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(20))
                                .unwrap(),
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(19))
                                .unwrap(),
                        ],
                    )
                    .await;

                    // Helper, time-interval task with old & new reports [not GC'ed].
                    let (_, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<TimeInterval>(
                            tx,
                            helper_time_interval_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(5))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(8))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    // Helper, time-interval task with new reports [not GC'ed].
                    let (_, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<TimeInterval>(
                            tx,
                            helper_time_interval_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(19))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(20))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    // Helper, time-interval task with attached aggregate share job [not GC'ed].
                    let (batch_identifier, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<TimeInterval>(
                            tx,
                            helper_time_interval_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(10))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(9))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    tx.put_aggregate_share_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &AggregateShareJob::new(
                            *helper_time_interval_task.id(),
                            batch_identifier,
                            AggregationParam(23),
                            AggregateShare(5),
                            2,
                            random(),
                        ),
                    )
                    .await
                    .unwrap();
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    // Leader, fixed-size aggregation job with old reports [GC'ed].
                    write_aggregation_artifacts::<FixedSize>(
                        tx,
                        leader_fixed_size_task.id(),
                        &[
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(20))
                                .unwrap(),
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(19))
                                .unwrap(),
                        ],
                    )
                    .await;

                    // Leader, fixed-size aggregation job with old & new reports [not GC'ed].
                    let (_, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<FixedSize>(
                            tx,
                            leader_fixed_size_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(5))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(8))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    // Leader, fixed-size aggregation job with new reports [not GC'ed].
                    let (_, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<FixedSize>(
                            tx,
                            leader_fixed_size_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(19))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(20))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    // Leader, fixed-size aggregation job with attached collection job [not GC'ed].
                    let (batch_identifier, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<FixedSize>(
                            tx,
                            leader_fixed_size_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(10))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(9))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    tx.put_collection_job(&CollectionJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *leader_fixed_size_task.id(),
                        random(),
                        batch_identifier,
                        AggregationParam(0),
                        CollectionJobState::Start,
                    ))
                    .await
                    .unwrap();
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    // Leader, fixed-size aggregation job with attached outstanding batch [not GC'ed].
                    let (batch_identifier, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<FixedSize>(
                            tx,
                            leader_fixed_size_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(8))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(7))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    tx.put_outstanding_batch(leader_fixed_size_task.id(), &batch_identifier)
                        .await
                        .unwrap();
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    // Helper, fixed-size aggregation job with old reports [GC'ed].
                    write_aggregation_artifacts::<FixedSize>(
                        tx,
                        helper_fixed_size_task.id(),
                        &[
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(20))
                                .unwrap(),
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(19))
                                .unwrap(),
                        ],
                    )
                    .await;

                    // Helper, fixed-size aggregation job with old & new reports [not GC'ed].
                    let (_, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<FixedSize>(
                            tx,
                            helper_fixed_size_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(5))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(8))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    // Helper, fixed-size aggregation job with new reports [not GC'ed].
                    let (_, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<FixedSize>(
                            tx,
                            helper_fixed_size_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(19))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(20))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    // Helper, fixed-size aggregation job with attached aggregate share job [not GC'ed].
                    let (batch_identifier, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<FixedSize>(
                            tx,
                            helper_fixed_size_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(10))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(9))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    tx.put_aggregate_share_job::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &AggregateShareJob::new(
                            *helper_fixed_size_task.id(),
                            batch_identifier,
                            AggregationParam(23),
                            AggregateShare(5),
                            2,
                            random(),
                        ),
                    )
                    .await
                    .unwrap();
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    // Aggregation job for a different task [not GC'ed].
                    let (_, aggregation_job_id, batch_aggregation_id, report_ids) =
                        write_aggregation_artifacts::<TimeInterval>(
                            tx,
                            other_task.id(),
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(8))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(7))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    aggregation_job_ids.insert(aggregation_job_id);
                    batch_aggregation_ids.insert(batch_aggregation_id.get_encoded());
                    all_report_ids.extend(report_ids);

                    Ok((
                        *leader_time_interval_task.id(),
                        *helper_time_interval_task.id(),
                        *leader_fixed_size_task.id(),
                        *helper_fixed_size_task.id(),
                        *other_task.id(),
                        aggregation_job_ids,
                        batch_aggregation_ids,
                        all_report_ids,
                    ))
                })
            })
            .await
            .unwrap();

        // Run.
        ds.run_tx(|tx| {
            Box::pin(async move {
                tx.delete_expired_aggregation_artifacts(
                    &leader_time_interval_task_id,
                    OLDEST_ALLOWED_REPORT_TIMESTAMP,
                )
                .await?;
                tx.delete_expired_aggregation_artifacts(
                    &helper_time_interval_task_id,
                    OLDEST_ALLOWED_REPORT_TIMESTAMP,
                )
                .await?;
                tx.delete_expired_aggregation_artifacts(
                    &leader_fixed_size_task_id,
                    OLDEST_ALLOWED_REPORT_TIMESTAMP,
                )
                .await?;
                tx.delete_expired_aggregation_artifacts(
                    &helper_fixed_size_task_id,
                    OLDEST_ALLOWED_REPORT_TIMESTAMP,
                )
                .await?;
                Ok(())
            })
        })
        .await
        .unwrap();

        // Verify.
        let (got_aggregation_job_ids, got_batch_aggregation_ids, got_report_ids) = ds
            .run_tx(|tx| {
                let vdaf = vdaf.clone();
                Box::pin(async move {
                    let leader_time_interval_aggregation_job_ids = tx
                        .get_aggregation_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &leader_time_interval_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|job| *job.id());
                    let helper_time_interval_aggregation_job_ids = tx
                        .get_aggregation_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &helper_time_interval_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|job| *job.id());
                    let leader_fixed_size_aggregation_job_ids = tx
                        .get_aggregation_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                            &leader_fixed_size_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|job| *job.id());
                    let helper_fixed_size_aggregation_job_ids = tx
                        .get_aggregation_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                            &helper_fixed_size_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|job| *job.id());
                    let other_task_aggregation_job_ids = tx
                        .get_aggregation_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &other_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|job| *job.id());
                    let got_aggregation_job_ids = leader_time_interval_aggregation_job_ids
                        .chain(helper_time_interval_aggregation_job_ids)
                        .chain(leader_fixed_size_aggregation_job_ids)
                        .chain(helper_fixed_size_aggregation_job_ids)
                        .chain(other_task_aggregation_job_ids)
                        .collect();

                    let leader_time_interval_batch_aggregation_ids = tx
                        .get_batch_aggregations_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &leader_time_interval_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|agg| agg.batch_identifier().get_encoded());
                    let helper_time_interval_batch_aggregation_ids = tx
                        .get_batch_aggregations_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &helper_time_interval_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|agg| agg.batch_identifier().get_encoded());
                    let leader_fixed_size_batch_aggregation_ids = tx
                        .get_batch_aggregations_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                            &leader_fixed_size_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|agg| agg.batch_identifier().get_encoded());
                    let helper_fixed_size_batch_aggregation_ids = tx
                        .get_batch_aggregations_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                            &helper_fixed_size_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|agg| agg.batch_identifier().get_encoded());
                    let other_task_batch_aggregation_ids = tx
                        .get_batch_aggregations_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &other_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|agg| agg.batch_identifier().get_encoded());
                    let got_batch_aggregation_ids = leader_time_interval_batch_aggregation_ids
                        .chain(helper_time_interval_batch_aggregation_ids)
                        .chain(leader_fixed_size_batch_aggregation_ids)
                        .chain(helper_fixed_size_batch_aggregation_ids)
                        .chain(other_task_batch_aggregation_ids)
                        .collect();

                    let leader_time_interval_report_aggregations = tx
                        .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                            &vdaf,
                            &Role::Leader,
                            &leader_time_interval_task_id,
                        )
                        .await
                        .unwrap();
                    let helper_time_interval_report_aggregations = tx
                        .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                            &vdaf,
                            &Role::Helper,
                            &helper_time_interval_task_id,
                        )
                        .await
                        .unwrap();
                    let leader_fixed_size_report_aggregations = tx
                        .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                            &vdaf,
                            &Role::Leader,
                            &leader_fixed_size_task_id,
                        )
                        .await
                        .unwrap();
                    let helper_fixed_size_report_aggregations = tx
                        .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                            &vdaf,
                            &Role::Helper,
                            &helper_fixed_size_task_id,
                        )
                        .await
                        .unwrap();
                    let other_task_report_aggregations = tx
                        .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                            &vdaf,
                            &Role::Leader,
                            &other_task_id,
                        )
                        .await
                        .unwrap();
                    let got_report_ids = leader_time_interval_report_aggregations
                        .into_iter()
                        .chain(helper_time_interval_report_aggregations)
                        .chain(leader_fixed_size_report_aggregations)
                        .chain(helper_fixed_size_report_aggregations)
                        .chain(other_task_report_aggregations)
                        .map(|report_aggregation| *report_aggregation.report_id())
                        .collect();

                    Ok((
                        got_aggregation_job_ids,
                        got_batch_aggregation_ids,
                        got_report_ids,
                    ))
                })
            })
            .await
            .unwrap();
        assert_eq!(want_aggregation_job_ids, got_aggregation_job_ids);
        assert_eq!(want_batch_aggregation_ids, got_batch_aggregation_ids);
        assert_eq!(want_report_ids, got_report_ids);
    }

    #[tokio::test]
    async fn delete_expired_collection_artifacts() {
        install_test_trace_subscriber();

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        // Setup.
        async fn write_collect_artifacts<Q: ExpirationQueryTypeExt>(
            tx: &Transaction<'_, MockClock>,
            task: &Task,
            client_timestamps: &[Time],
        ) -> (
            Option<CollectionJobId>,   // collection job ID
            Option<(TaskId, Vec<u8>)>, // aggregate share job ID (task ID, encoded batch identifier)
            Option<(TaskId, BatchId)>, // outstanding batch ID
        ) {
            let batch_identifier = Q::batch_identifier_for_client_timestamps(client_timestamps);
            for client_timestamp in client_timestamps {
                let report = LeaderStoredReport::new_dummy(*task.id(), *client_timestamp);
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report)
                    .await
                    .unwrap();

                let aggregation_job = AggregationJob::<0, Q, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    AggregationParam(0),
                    Q::partial_batch_identifier(&batch_identifier).clone(),
                    Interval::new(*client_timestamp, Duration::from_seconds(1)).unwrap(),
                    AggregationJobState::InProgress,
                );
                tx.put_aggregation_job(&aggregation_job).await.unwrap();

                let report_aggregation = ReportAggregation::new(
                    *task.id(),
                    *aggregation_job.id(),
                    *report.metadata().id(),
                    *client_timestamp,
                    0,
                    ReportAggregationState::<0, dummy_vdaf::Vdaf>::Start,
                );
                tx.put_report_aggregation(&report_aggregation)
                    .await
                    .unwrap();
            }

            if task.role() == &Role::Leader {
                let collection_job = CollectionJob::<0, Q, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    batch_identifier.clone(),
                    AggregationParam(0),
                    CollectionJobState::Start,
                );
                tx.put_collection_job(&collection_job).await.unwrap();

                let outstanding_batch_id =
                    Q::write_outstanding_batch(tx, task.id(), &batch_identifier).await;

                return (
                    Some(*collection_job.collection_job_id()),
                    None,
                    outstanding_batch_id,
                );
            } else {
                let aggregate_share_job = AggregateShareJob::new(
                    *task.id(),
                    batch_identifier.clone(),
                    AggregationParam(23),
                    AggregateShare(11),
                    client_timestamps.len().try_into().unwrap(),
                    random(),
                );
                tx.put_aggregate_share_job::<0, Q, dummy_vdaf::Vdaf>(&aggregate_share_job)
                    .await
                    .unwrap();

                return (
                    None,
                    Some((*task.id(), batch_identifier.get_encoded())),
                    None,
                );
            }
        }

        const OLDEST_ALLOWED_REPORT_TIMESTAMP: Time = Time::from_seconds_since_epoch(1000);
        let (
            leader_time_interval_task_id,
            helper_time_interval_task_id,
            leader_fixed_size_task_id,
            helper_fixed_size_task_id,
            other_task_id,
            want_collection_job_ids,
            want_aggregate_share_job_ids,
            want_outstanding_batch_ids,
        ) = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    let leader_time_interval_task = TaskBuilder::new(
                        task::QueryType::TimeInterval,
                        VdafInstance::Fake,
                        Role::Leader,
                    )
                    .build();
                    let helper_time_interval_task = TaskBuilder::new(
                        task::QueryType::TimeInterval,
                        VdafInstance::Fake,
                        Role::Helper,
                    )
                    .build();
                    let leader_fixed_size_task = TaskBuilder::new(
                        task::QueryType::FixedSize { max_batch_size: 10 },
                        VdafInstance::Fake,
                        Role::Leader,
                    )
                    .build();
                    let helper_fixed_size_task = TaskBuilder::new(
                        task::QueryType::FixedSize { max_batch_size: 10 },
                        VdafInstance::Fake,
                        Role::Helper,
                    )
                    .build();
                    let other_task = TaskBuilder::new(
                        task::QueryType::TimeInterval,
                        VdafInstance::Fake,
                        Role::Leader,
                    )
                    .build();
                    tx.put_task(&leader_time_interval_task).await?;
                    tx.put_task(&helper_time_interval_task).await?;
                    tx.put_task(&leader_fixed_size_task).await?;
                    tx.put_task(&helper_fixed_size_task).await?;
                    tx.put_task(&other_task).await?;

                    let mut collection_job_ids = HashSet::new();
                    let mut aggregate_share_job_ids = HashSet::new();
                    let mut outstanding_batch_ids = HashSet::new();

                    // Leader, time-interval collection artifacts with old reports. [GC'ed]
                    write_collect_artifacts::<TimeInterval>(
                        tx,
                        &leader_time_interval_task,
                        &[
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(10))
                                .unwrap(),
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(9))
                                .unwrap(),
                        ],
                    )
                    .await;

                    // Leader, time-interval collection artifacts with old & new reports. [not GC'ed]
                    let (collection_job_id, aggregate_share_job_id, outstanding_batch_id) =
                        write_collect_artifacts::<TimeInterval>(
                            tx,
                            &leader_time_interval_task,
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(5))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(5))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    collection_job_ids.extend(collection_job_id);
                    aggregate_share_job_ids.extend(aggregate_share_job_id);
                    outstanding_batch_ids.extend(outstanding_batch_id);

                    // Leader, time-interval collection artifacts with new reports. [not GC'ed]
                    let (collection_job_id, aggregate_share_job_id, outstanding_batch_id) =
                        write_collect_artifacts::<TimeInterval>(
                            tx,
                            &leader_time_interval_task,
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(9))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(10))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    collection_job_ids.extend(collection_job_id);
                    aggregate_share_job_ids.extend(aggregate_share_job_id);
                    outstanding_batch_ids.extend(outstanding_batch_id);

                    // Helper, time-interval collection artifacts with old reports. [GC'ed]
                    write_collect_artifacts::<TimeInterval>(
                        tx,
                        &helper_time_interval_task,
                        &[
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(10))
                                .unwrap(),
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(9))
                                .unwrap(),
                        ],
                    )
                    .await;

                    // Helper, time-interval collection artifacts with old & new reports. [not GC'ed]
                    let (collection_job_id, aggregate_share_job_id, outstanding_batch_id) =
                        write_collect_artifacts::<TimeInterval>(
                            tx,
                            &helper_time_interval_task,
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(5))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(5))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    collection_job_ids.extend(collection_job_id);
                    aggregate_share_job_ids.extend(aggregate_share_job_id);
                    outstanding_batch_ids.extend(outstanding_batch_id);

                    // Helper, time-interval collection artifacts with new reports. [not GC'ed]
                    let (collection_job_id, aggregate_share_job_id, outstanding_batch_id) =
                        write_collect_artifacts::<TimeInterval>(
                            tx,
                            &helper_time_interval_task,
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(9))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(10))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    collection_job_ids.extend(collection_job_id);
                    aggregate_share_job_ids.extend(aggregate_share_job_id);
                    outstanding_batch_ids.extend(outstanding_batch_id);

                    // Leader, fixed-size collection artifacts with old reports. [GC'ed]
                    write_collect_artifacts::<FixedSize>(
                        tx,
                        &leader_fixed_size_task,
                        &[
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(10))
                                .unwrap(),
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(9))
                                .unwrap(),
                        ],
                    )
                    .await;

                    // Leader, fixed-size collection artifacts with old & new reports. [not GC'ed]
                    let (collection_job_id, aggregate_share_job_id, outstanding_batch_id) =
                        write_collect_artifacts::<FixedSize>(
                            tx,
                            &leader_fixed_size_task,
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(5))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(5))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    collection_job_ids.extend(collection_job_id);
                    aggregate_share_job_ids.extend(aggregate_share_job_id);
                    outstanding_batch_ids.extend(outstanding_batch_id);

                    // Leader, fixed-size collection artifacts with new reports. [not GC'ed]
                    let (collection_job_id, aggregate_share_job_id, outstanding_batch_id) =
                        write_collect_artifacts::<FixedSize>(tx, &leader_fixed_size_task, &[])
                            .await;
                    collection_job_ids.extend(collection_job_id);
                    aggregate_share_job_ids.extend(aggregate_share_job_id);
                    outstanding_batch_ids.extend(outstanding_batch_id);

                    // Helper, fixed-size collection artifacts with old reports. [GC'ed]
                    write_collect_artifacts::<FixedSize>(
                        tx,
                        &helper_fixed_size_task,
                        &[
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(10))
                                .unwrap(),
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(9))
                                .unwrap(),
                        ],
                    )
                    .await;

                    // Helper, fixed-size collection artifacts with old & new reports. [not GC'ed]
                    let (collection_job_id, aggregate_share_job_id, outstanding_batch_id) =
                        write_collect_artifacts::<FixedSize>(
                            tx,
                            &helper_fixed_size_task,
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(5))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .add(&Duration::from_seconds(5))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    collection_job_ids.extend(collection_job_id);
                    aggregate_share_job_ids.extend(aggregate_share_job_id);
                    outstanding_batch_ids.extend(outstanding_batch_id);

                    // Helper, fixed-size collection artifacts with new reports. [not GC'ed]
                    let (collection_job_id, aggregate_share_job_id, outstanding_batch_id) =
                        write_collect_artifacts::<FixedSize>(tx, &helper_fixed_size_task, &[])
                            .await;
                    collection_job_ids.extend(collection_job_id);
                    aggregate_share_job_ids.extend(aggregate_share_job_id);
                    outstanding_batch_ids.extend(outstanding_batch_id);

                    // Collection artifacts for different task. [not GC'ed]
                    let (collection_job_id, aggregate_share_job_id, outstanding_batch_id) =
                        write_collect_artifacts::<TimeInterval>(
                            tx,
                            &other_task,
                            &[
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(9))
                                    .unwrap(),
                                OLDEST_ALLOWED_REPORT_TIMESTAMP
                                    .sub(&Duration::from_seconds(8))
                                    .unwrap(),
                            ],
                        )
                        .await;
                    collection_job_ids.extend(collection_job_id);
                    aggregate_share_job_ids.extend(aggregate_share_job_id);
                    outstanding_batch_ids.extend(outstanding_batch_id);

                    Ok((
                        *leader_time_interval_task.id(),
                        *helper_time_interval_task.id(),
                        *leader_fixed_size_task.id(),
                        *helper_fixed_size_task.id(),
                        *other_task.id(),
                        collection_job_ids,
                        aggregate_share_job_ids,
                        outstanding_batch_ids,
                    ))
                })
            })
            .await
            .unwrap();

        // Run.
        ds.run_tx(|tx| {
            Box::pin(async move {
                tx.delete_expired_collection_artifacts(
                    &leader_time_interval_task_id,
                    OLDEST_ALLOWED_REPORT_TIMESTAMP,
                )
                .await?;
                tx.delete_expired_collection_artifacts(
                    &helper_time_interval_task_id,
                    OLDEST_ALLOWED_REPORT_TIMESTAMP,
                )
                .await?;
                tx.delete_expired_collection_artifacts(
                    &leader_fixed_size_task_id,
                    OLDEST_ALLOWED_REPORT_TIMESTAMP,
                )
                .await?;
                tx.delete_expired_collection_artifacts(
                    &helper_fixed_size_task_id,
                    OLDEST_ALLOWED_REPORT_TIMESTAMP,
                )
                .await?;
                Ok(())
            })
        })
        .await
        .unwrap();

        // Verify.
        let (got_collection_job_ids, got_aggregate_share_job_ids, got_outstanding_batch_ids) = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    let leader_time_interval_collection_job_ids = tx
                        .get_collection_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &leader_time_interval_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|collection_job| *collection_job.collection_job_id());
                    let helper_time_interval_collection_job_ids = tx
                        .get_collection_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &helper_time_interval_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|collection_job| *collection_job.collection_job_id());
                    let leader_fixed_size_collection_job_ids = tx
                        .get_collection_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                            &leader_fixed_size_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|collection_job| *collection_job.collection_job_id());
                    let helper_fixed_size_collection_job_ids = tx
                        .get_collection_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                            &helper_fixed_size_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|collection_job| *collection_job.collection_job_id());
                    let other_task_collection_job_ids = tx
                        .get_collection_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &other_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|collection_job| *collection_job.collection_job_id());
                    let got_collection_job_ids = leader_time_interval_collection_job_ids
                        .chain(helper_time_interval_collection_job_ids)
                        .chain(leader_fixed_size_collection_job_ids)
                        .chain(helper_fixed_size_collection_job_ids)
                        .chain(other_task_collection_job_ids)
                        .collect();

                    let leader_time_interval_aggregate_share_job_ids = tx
                        .get_aggregate_share_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &leader_time_interval_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|job| (*job.task_id(), job.batch_identifier().get_encoded()));
                    let helper_time_interval_aggregate_share_job_ids = tx
                        .get_aggregate_share_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &helper_time_interval_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|job| (*job.task_id(), job.batch_identifier().get_encoded()));
                    let leader_fixed_size_aggregate_share_job_ids = tx
                        .get_aggregate_share_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                            &leader_fixed_size_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|job| (*job.task_id(), job.batch_identifier().get_encoded()));
                    let helper_fixed_size_aggregate_share_job_ids = tx
                        .get_aggregate_share_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                            &helper_fixed_size_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|job| (*job.task_id(), job.batch_identifier().get_encoded()));
                    let other_task_aggregate_share_job_ids = tx
                        .get_aggregate_share_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &leader_time_interval_task_id,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|job| (*job.task_id(), job.batch_identifier().get_encoded()));
                    let got_aggregate_share_job_ids = leader_time_interval_aggregate_share_job_ids
                        .chain(helper_time_interval_aggregate_share_job_ids)
                        .chain(leader_fixed_size_aggregate_share_job_ids)
                        .chain(helper_fixed_size_aggregate_share_job_ids)
                        .chain(other_task_aggregate_share_job_ids)
                        .collect();

                    let leader_time_interval_outstanding_batch_ids = tx
                        .get_outstanding_batches_for_task(&leader_time_interval_task_id)
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|batch| (*batch.task_id(), *batch.id()));
                    let helper_time_interval_outstanding_batch_ids = tx
                        .get_outstanding_batches_for_task(&helper_time_interval_task_id)
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|batch| (*batch.task_id(), *batch.id()));
                    let leader_fixed_size_outstanding_batch_ids = tx
                        .get_outstanding_batches_for_task(&leader_fixed_size_task_id)
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|batch| (*batch.task_id(), *batch.id()));
                    let helper_fixed_size_outstanding_batch_ids = tx
                        .get_outstanding_batches_for_task(&helper_fixed_size_task_id)
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|batch| (*batch.task_id(), *batch.id()));
                    let other_task_outstanding_batch_ids = tx
                        .get_outstanding_batches_for_task(&helper_fixed_size_task_id)
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|batch| (*batch.task_id(), *batch.id()));
                    let got_outstanding_batch_ids = leader_time_interval_outstanding_batch_ids
                        .chain(helper_time_interval_outstanding_batch_ids)
                        .chain(leader_fixed_size_outstanding_batch_ids)
                        .chain(helper_fixed_size_outstanding_batch_ids)
                        .chain(other_task_outstanding_batch_ids)
                        .collect();

                    Ok((
                        got_collection_job_ids,
                        got_aggregate_share_job_ids,
                        got_outstanding_batch_ids,
                    ))
                })
            })
            .await
            .unwrap();
        assert_eq!(want_collection_job_ids, got_collection_job_ids);
        assert_eq!(want_aggregate_share_job_ids, got_aggregate_share_job_ids);
        assert_eq!(want_outstanding_batch_ids, got_outstanding_batch_ids);
    }

    #[tokio::test]
    async fn roundtrip_interval_sql() {
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(MockClock::default());

        datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    let interval = tx
                        .query_one(
                            "SELECT '[2020-01-01 10:00, 2020-01-01 10:30)'::tsrange AS interval",
                            &[],
                        )
                        .await?
                        .get::<_, SqlInterval>("interval");
                    let ref_interval = Interval::new(
                        Time::from_naive_date_time(
                            &NaiveDate::from_ymd_opt(2020, 1, 1)
                                .unwrap()
                                .and_hms_opt(10, 0, 0)
                                .unwrap(),
                        ),
                        Duration::from_minutes(30).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(interval.as_interval(), ref_interval);

                    let interval = tx
                        .query_one(
                            "SELECT '[1970-02-03 23:00, 1970-02-04 00:00)'::tsrange AS interval",
                            &[],
                        )
                        .await?
                        .get::<_, SqlInterval>("interval");
                    let ref_interval = Interval::new(
                        Time::from_naive_date_time(
                            &NaiveDate::from_ymd_opt(1970, 2, 3)
                                .unwrap()
                                .and_hms_opt(23, 0, 0)
                                .unwrap(),
                        ),
                        Duration::from_hours(1).unwrap(),
                    )?;
                    assert_eq!(interval.as_interval(), ref_interval);

                    let res = tx
                        .query_one(
                            "SELECT '[1969-01-01 00:00, 1970-01-01 00:00)'::tsrange AS interval",
                            &[],
                        )
                        .await?
                        .try_get::<_, SqlInterval>("interval");
                    assert!(res.is_err());

                    let ok = tx
                        .query_one(
                            "SELECT (lower(interval) = '1972-07-21 05:30:00' AND
                            upper(interval) = '1972-07-21 06:00:00' AND
                            lower_inc(interval) AND
                            NOT upper_inc(interval)) AS ok
                            FROM (VALUES ($1::tsrange)) AS temp (interval)",
                            &[&SqlInterval::from(
                                Interval::new(
                                    Time::from_naive_date_time(
                                        &NaiveDate::from_ymd_opt(1972, 7, 21)
                                            .unwrap()
                                            .and_hms_opt(5, 30, 0)
                                            .unwrap(),
                                    ),
                                    Duration::from_minutes(30).unwrap(),
                                )
                                .unwrap(),
                            )],
                        )
                        .await?
                        .get::<_, bool>("ok");
                    assert!(ok);

                    let ok = tx
                        .query_one(
                            "SELECT (lower(interval) = '2021-10-05 00:00:00' AND
                            upper(interval) = '2021-10-06 00:00:00' AND
                            lower_inc(interval) AND
                            NOT upper_inc(interval)) AS ok
                            FROM (VALUES ($1::tsrange)) AS temp (interval)",
                            &[&SqlInterval::from(
                                Interval::new(
                                    Time::from_naive_date_time(
                                        &NaiveDate::from_ymd_opt(2021, 10, 5)
                                            .unwrap()
                                            .and_hms_opt(0, 0, 0)
                                            .unwrap(),
                                    ),
                                    Duration::from_hours(24).unwrap(),
                                )
                                .unwrap(),
                            )],
                        )
                        .await?
                        .get::<_, bool>("ok");
                    assert!(ok);

                    Ok(())
                })
            })
            .await
            .unwrap();
    }
}
