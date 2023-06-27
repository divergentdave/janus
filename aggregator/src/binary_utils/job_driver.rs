//! Discovery and driving of jobs scheduled elsewhere.

use chrono::NaiveDateTime;
use janus_aggregator_core::datastore::{self, models::Lease};
use janus_core::{time::Clock, Runtime};
use opentelemetry::{
    metrics::{Histogram, Meter, Unit},
    Context, KeyValue,
};
use std::{
    convert::Infallible,
    fmt::{Debug, Display},
    future::Future,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::Semaphore,
    time::{self, Instant},
};
use tracing::{debug, error, info_span, Instrument};

/// Periodically seeks incomplete jobs in the datastore and drives them concurrently.
pub struct JobDriver<C: Clock, R, JobAcquirer, JobStepper> {
    /// Clock used to determine when to schedule jobs.
    clock: C,
    /// Runtime object used to spawn asynchronous tasks.
    runtime: R,
    /// Meter used to process metric values.
    meter: Meter,

    // Configuration values.
    /// Minimum delay between datastore job discovery passes.
    min_job_discovery_delay: Duration,
    /// Maximum delay between datastore job discovery passes.
    max_job_discovery_delay: Duration,
    /// How many jobs to step at the same time in this process.
    max_concurrent_job_workers: usize,
    /// Allowable clock skew between datastore and job driver, used when determining if a lease has
    /// expired.
    worker_lease_clock_skew_allowance: Duration,

    // Callbacks.
    /// Finds incomplete jobs in the datastore and acquires a lease on them.
    incomplete_job_acquirer: JobAcquirer,
    /// Steps an incomplete job.
    job_stepper: JobStepper,
}

impl<
        C,
        R,
        JobStepperError,
        JobAcquirer,
        JobAcquirerFuture,
        JobStepper,
        JobStepperFuture,
        AcquiredJob,
    > JobDriver<C, R, JobAcquirer, JobStepper>
where
    C: Clock,
    R: Runtime + Send + Sync + 'static,
    JobStepperError: Debug + Display + Send + Sync + 'static,
    JobAcquirer: Fn(usize) -> JobAcquirerFuture + Send + Sync + 'static,
    JobAcquirerFuture: Future<Output = Result<Vec<Lease<AcquiredJob>>, datastore::Error>> + Send,
    JobStepper: Fn(Lease<AcquiredJob>) -> JobStepperFuture + Send + Sync + 'static,
    JobStepperFuture: Future<Output = Result<(), JobStepperError>> + Send,
    AcquiredJob: Clone + Debug + Send + Sync + 'static,
{
    /// Create a new [`JobDriver`].
    pub fn new(
        clock: C,
        runtime: R,
        meter: Meter,
        min_job_discovery_delay: Duration,
        max_job_discovery_delay: Duration,
        max_concurrent_job_workers: usize,
        worker_lease_clock_skew_allowance: Duration,
        incomplete_job_acquirer: JobAcquirer,
        job_stepper: JobStepper,
    ) -> Self {
        Self {
            clock,
            runtime,
            meter,
            min_job_discovery_delay,
            max_job_discovery_delay,
            max_concurrent_job_workers,
            worker_lease_clock_skew_allowance,
            incomplete_job_acquirer,
            job_stepper,
        }
    }

    /// Run this job driver, periodically seeking incomplete jobs and stepping them.
    pub async fn run(self: Arc<Self>) -> Infallible {
        // Create metric recorders.
        let job_acquire_time_histogram = self
            .meter
            .f64_histogram("janus_job_acquire_time")
            .with_description("Time spent acquiring jobs.")
            .with_unit(Unit::new("seconds"))
            .init();
        let job_acquire_jobs_histogram = self
            .meter
            .u64_histogram("janus_job_acquire_jobs")
            .with_description("Number of incomplete jobs acquired at once.")
            .init();
        let job_step_time_histogram = self
            .meter
            .f64_histogram("janus_job_step_time")
            .with_description("Time spent stepping jobs.")
            .with_unit(Unit::new("seconds"))
            .init();

        // Set up state for the job driver run.
        let sem = Arc::new(Semaphore::new(self.max_concurrent_job_workers));
        let mut job_discovery_delay = Duration::ZERO;

        loop {
            // Wait out our job discovery delay, if any.
            time::sleep(job_discovery_delay).await;

            // Wait until we are able to start at least one worker. (permit will be immediately released)
            //
            // Unwrap safety: Semaphore::acquire is documented as only returning an error if the
            // semaphore is closed, and we never close this semaphore.
            drop(sem.acquire().await.unwrap());

            // Acquire some jobs which are ready to be stepped.
            //
            // We determine the maximum number of jobs to acquire based on the number of semaphore
            // permits available, since we'd like to start processing any acquired jobs immediately
            // to avoid potentially timing out while waiting on _other_ jobs to finish being
            // stepped. This is racy given that workers may complete (and relinquish their permits)
            // concurrently with us acquiring jobs; but that's OK, since this can only make us
            // underestimate the number of jobs we can acquire, and underestimation is acceptable
            // (we'll pick up any additional jobs on the next iteration of this loop). We can't
            // overestimate since this task is the only place that permits are acquired.
            let max_acquire_count = sem.available_permits();

            let leases = self
                .run_job_acquisition(
                    &mut job_discovery_delay,
                    max_acquire_count,
                    &job_acquire_time_histogram,
                    &job_acquire_jobs_histogram,
                )
                .await;

            // Start up tasks for each acquired job.
            for lease in leases {
                self.runtime.spawn({
                    // We acquire a semaphore in the job-discovery task rather than inside the new
                    // job-stepper task to ensure that acquiring a permit does not race with
                    // checking how many permits we have available in the next iteration of this
                    // loop, to maintain the invariant that this task is the only place we acquire
                    // permits.
                    //
                    // Unwrap safety: we have seen that at least `leases.len()` permits are
                    // available, and this task is the only task that acquires permits.
                    let span = info_span!("Job stepper", acquired_job = ?lease.leased());
                    let (this, permit, job_step_time_histogram) = (
                        Arc::clone(&self),
                        Arc::clone(&sem).try_acquire_owned().unwrap(),
                        job_step_time_histogram.clone(),
                    );

                    async move {
                        debug!(lease_expiry = %lease.lease_expiry_time(), "Stepping job");
                        let (start, mut status) = (Instant::now(), "success");
                        match time::timeout(
                            this.effective_lease_duration(lease.lease_expiry_time()),
                            (this.job_stepper)(lease),
                        )
                        .await
                        {
                            Ok(Ok(_)) => debug!("Job stepped"),
                            Ok(Err(error)) => {
                                error!(?error, "Couldn't step job");
                                status = "error"
                            }
                            Err(_err) => {
                                error!("Stepping job timed out");
                                status = "error"
                            }
                        }
                        job_step_time_histogram.record(
                            &Context::current(),
                            start.elapsed().as_secs_f64(),
                            &[KeyValue::new("status", status)],
                        );
                        drop(permit);
                    }
                    .instrument(span)
                });
            }
        }
    }

    #[tracing::instrument(skip(self, job_acquire_time_histogram))]
    async fn run_job_acquisition(
        self: &Arc<Self>,
        job_discovery_delay: &mut Duration,
        max_acquire_count: usize,
        job_acquire_time_histogram: &Histogram<f64>,
        job_acquire_jobs_histogram: &Histogram<u64>,
    ) -> Vec<Lease<AcquiredJob>> {
        debug!(%max_acquire_count, "Acquiring jobs");
        let start = Instant::now();
        let leases = (self.incomplete_job_acquirer)(max_acquire_count).await;
        let leases = match leases {
            Ok(leases) => leases,
            Err(error) => {
                error!(?error, "Couldn't acquire jobs");

                // Go ahead and step job discovery delay in this error case to ensure we don't
                // tightly loop running transactions that will fail without any delay.
                *job_discovery_delay = self.step_job_discovery_delay(*job_discovery_delay);
                job_acquire_time_histogram.record(
                    &Context::current(),
                    start.elapsed().as_secs_f64(),
                    &[KeyValue::new("status", "error")],
                );
                return Vec::new();
            }
        };
        job_acquire_time_histogram.record(
            &Context::current(),
            start.elapsed().as_secs_f64(),
            &[KeyValue::new("status", "success")],
        );
        job_acquire_jobs_histogram.record(
            &Context::current(),
            leases.len().try_into().unwrap_or(u64::MAX),
            &[],
        );
        if leases.is_empty() {
            debug!("No jobs available");
            *job_discovery_delay = self.step_job_discovery_delay(*job_discovery_delay);
            return Vec::new();
        }
        assert!(
            leases.len() <= max_acquire_count,
            "Acquired {} jobs exceeding maximum of {}\n{:?}",
            leases.len(),
            max_acquire_count,
            leases
        );
        debug!(acquired_job_count = leases.len(), "Acquired jobs");
        *job_discovery_delay = Duration::ZERO;
        leases
    }

    fn step_job_discovery_delay(&self, delay: Duration) -> Duration {
        // A zero delay is stepped to the configured minimum delay.
        if delay == Duration::ZERO {
            return self.min_job_discovery_delay;
        }

        // Nonzero delays are doubled, up to the maximum configured delay.
        // (It's OK to use a saturating multiply here because the following min call causes us to
        // get the right answer even in the case we saturate.)
        let new_delay = Duration::from_secs(delay.as_secs().saturating_mul(2));
        let new_delay = Duration::min(new_delay, self.max_job_discovery_delay);
        debug!(?new_delay, "Updating job discovery delay");
        new_delay
    }

    fn effective_lease_duration(&self, lease_expiry: &NaiveDateTime) -> Duration {
        // Lease expiries are expressed as Time values (i.e. an absolute timestamp). Tokio Instant
        // values, unfortunately, can't be created directly from a timestamp. All we can do is
        // create an Instant::now(), then add durations to it. This function computes how long
        // remains until the expiry time, minus the clock skew allowance. All math saturates, since
        // we want to timeout immediately if any of these subtractions would underflow.
        Duration::from_secs(
            u64::try_from(lease_expiry.timestamp())
                .unwrap_or_default()
                .saturating_sub(self.clock.now().as_seconds_since_epoch())
                .saturating_sub(self.worker_lease_clock_skew_allowance.as_secs()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::JobDriver;
    use chrono::NaiveDateTime;
    use janus_aggregator_core::datastore::{self, models::Lease};
    use janus_core::{
        task::VdafInstance,
        test_util::{install_test_trace_subscriber, runtime::TestRuntimeManager},
        time::MockClock,
        Runtime,
    };
    use janus_messages::{AggregationJobId, TaskId};
    use opentelemetry::global::meter;
    use rand::random;
    use std::{sync::Arc, time::Duration};
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn job_driver() {
        // This is a minimal test that JobDriver::run() will successfully find jobs & step them to
        // completion. More detailed tests of the job execution logic are contained in other tests
        // which do not exercise the job-acquiry loop.
        // Note that we actually step twice to ensure that lease-release & re-acquiry works as
        // expected.

        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let mut runtime_manager = TestRuntimeManager::new();

        /// A fake incomplete job returned by the job acquirer closure.
        #[derive(Clone, Debug)]
        struct IncompleteJob {
            task_id: TaskId,
            job_id: AggregationJobId,
            lease_expiry: NaiveDateTime,
        }

        /// Records a job observed by the job stepper closure.
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct SteppedJob {
            observed_jobs_acquire_counter: usize,
            task_id: TaskId,
            job_id: AggregationJobId,
        }

        #[derive(Clone, Debug)]
        struct TestState {
            // Counter incremented when the job finder closure runs and index into INCOMPLETE_JOBS.
            job_acquire_counter: usize,
            stepped_jobs: Vec<SteppedJob>,
        }

        let test_state = Arc::new(Mutex::new(TestState {
            job_acquire_counter: 0,
            stepped_jobs: Vec::new(),
        }));
        // View of incomplete jobs acquired from datastore fed to job finder closure
        let incomplete_jobs = Arc::new(Vec::from([
            // First job finder call: acquire some jobs.
            Vec::from([
                IncompleteJob {
                    task_id: random(),
                    job_id: random(),
                    lease_expiry: NaiveDateTime::from_timestamp_opt(100, 0).unwrap(),
                },
                IncompleteJob {
                    task_id: random(),
                    job_id: random(),
                    lease_expiry: NaiveDateTime::from_timestamp_opt(200, 0).unwrap(),
                },
            ]),
            // Second job finder call will be immediately after the first: no more jobs
            // available yet. Should cause a minimum delay before job finder runs again.
            Vec::new(),
            // Third job finder call: return some new jobs to simulate lease being released and
            // re-acquired (it doesn't matter if the task and job IDs change).
            Vec::from([
                IncompleteJob {
                    task_id: random(),
                    job_id: random(),
                    lease_expiry: NaiveDateTime::from_timestamp_opt(300, 0).unwrap(),
                },
                IncompleteJob {
                    task_id: random(),
                    job_id: random(),
                    lease_expiry: NaiveDateTime::from_timestamp_opt(400, 0).unwrap(),
                },
            ]),
        ]));

        // Run. Let the aggregation job driver step aggregation jobs, then kill it.
        let job_driver = Arc::new(JobDriver::new(
            clock,
            runtime_manager.with_label("stepper"),
            meter("job_driver_test"),
            Duration::from_secs(1),
            Duration::from_secs(1),
            10,
            Duration::from_secs(60),
            {
                let (test_state, incomplete_jobs) =
                    (Arc::clone(&test_state), Arc::clone(&incomplete_jobs));
                move |max_acquire_count| {
                    let (test_state, incomplete_jobs) =
                        (Arc::clone(&test_state), Arc::clone(&incomplete_jobs));
                    async move {
                        let mut test_state = test_state.lock().await;

                        assert_eq!(max_acquire_count, 10);

                        let incomplete_jobs = incomplete_jobs
                            .get(test_state.job_acquire_counter)
                            // Clone here so that incomplete_jobs will be Vec<_> and not &Vec<_>, which
                            // would be impossible to return from Option::unwrap_or_default.
                            .cloned()
                            .unwrap_or_default();

                        let leases = incomplete_jobs
                            .iter()
                            .map(|job| {
                                Lease::new_dummy(
                                    (job.task_id, VdafInstance::Fake, job.job_id),
                                    job.lease_expiry,
                                )
                            })
                            .collect();

                        test_state.job_acquire_counter += 1;

                        // Create some fake incomplete jobs
                        Ok(leases)
                    }
                }
            },
            {
                let test_state = Arc::clone(&test_state);
                move |lease| {
                    let test_state = Arc::clone(&test_state);
                    async move {
                        let mut test_state = test_state.lock().await;
                        let job_acquire_counter = test_state.job_acquire_counter;

                        assert_eq!(lease.leased().1, VdafInstance::Fake);

                        test_state.stepped_jobs.push(SteppedJob {
                            observed_jobs_acquire_counter: job_acquire_counter,
                            task_id: lease.leased().0,
                            job_id: lease.leased().2,
                        });

                        Ok(()) as Result<(), datastore::Error>
                    }
                }
            },
        ));
        let task_handle = runtime_manager
            .with_label("driver")
            .spawn(async move { job_driver.run().await });

        // Wait for all of the job stepper tasks to be started and for them to finish.
        runtime_manager.wait_for_completed_tasks("stepper", 4).await;
        // Stop the job driver task.
        task_handle.abort();

        // Verify that we got the expected calls to closures.
        let final_test_state = test_state.lock().await;

        // We expect the job acquirer to run at least three times in the time
        // it takes to step the four jobs, but we can't prove it won't run
        // once more.
        assert!(final_test_state.job_acquire_counter >= 3);
        assert_eq!(
            final_test_state.stepped_jobs,
            Vec::from([
                // First acquirer run should have caused INCOMPLETE_JOBS[0] to be stepped.
                SteppedJob {
                    observed_jobs_acquire_counter: 1,
                    task_id: incomplete_jobs[0][0].task_id,
                    job_id: incomplete_jobs[0][0].job_id,
                },
                SteppedJob {
                    observed_jobs_acquire_counter: 1,
                    task_id: incomplete_jobs[0][1].task_id,
                    job_id: incomplete_jobs[0][1].job_id,
                },
                // Second acquirer run should step no jobs
                // Third acquirer run should have caused INCOMPLETE_JOBS[2] to be stepped.
                SteppedJob {
                    observed_jobs_acquire_counter: 3,
                    task_id: incomplete_jobs[2][0].task_id,
                    job_id: incomplete_jobs[2][0].job_id,
                },
                SteppedJob {
                    observed_jobs_acquire_counter: 3,
                    task_id: incomplete_jobs[2][1].task_id,
                    job_id: incomplete_jobs[2][1].job_id,
                },
            ])
        );
    }
}
