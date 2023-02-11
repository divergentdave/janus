# janus
[![Build Status]][actions]

[Build Status]: https://github.com/divviup/janus/workflows/ci-build/badge.svg
[actions]: https://github.com/divviup/janus/actions?query=branch%3Amain

Janus is an experimental implementation of the
[Distributed Aggregation Protocol (DAP) specification](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/).

Janus is currently in active development.

## Draft versions and release branches

The `main` branch is under continuous development and will usually be partway between DAP drafts. Janus uses stable release branches to maintain implementations of different DAP draft versions. Rust crates and container images with versions `x.y.z` are released from a corresponding `release/x.y` branch.

| Git branch | Draft version | Conforms to protocol? | Status |
| ---------- | ------------- | --------------------- | ------ |
| `release/0.1` | [`draft-ietf-ppm-dap-01`](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/01/) | Yes | Unmaintained as of December 7, 2022 |
| `release/0.2` | [`draft-ietf-ppm-dap-02`](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/02/) | Yes | Supported |
| `release/0.3` | [`draft-ietf-ppm-dap-03`](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/03/) | Yes | Unmaintained as of February 6, 2023 |
| `main` | `draft-ietf-ppm-dap-04` (forthcoming) | [Partially](https://github.com/divviup/janus/milestone/3) | Supported, unstable |

## Building

Building Janus with `janus_aggregator`'s `otlp` feature enabled requires the Protocol Buffers
compiler, `protoc`, be installed on the machine performing the build.

To build Janus, execute `cargo build`. There is also support for building containers with the Janus
components; see `.github/workflows/ci-build.yml` for example Docker invocations.

## Running tests

Tests require that [`docker`](https://www.docker.com) & [`kind`](https://kind.sigs.k8s.io) be installed on the machine running the tests and in the `PATH` of the test-runner's environment. The `docker` daemon must be running. CI tests currently use [`kind` 0.17.0](https://github.com/kubernetes-sigs/kind/releases/tag/v0.17.0) and the corresponding Kubernetes 1.24 node image (kindest/node:v1.24.7@sha256:577c630ce8e509131eab1aea12c022190978dd2f745aac5eb1fe65c0807eb315) and using the same versions for local development is recommended.

To run Janus tests, execute `cargo test`.

## Running janus\_server

The aggregator server requires a connection to a PostgreSQL 14 database. Prepare the database by executing the script at `db/schema.sql`. Most server configuration is done via a YAML file, following the structure documented on `aggregator::Config`. Record the database's connection URL, the address the aggregator server should listen on for incoming HTTP requests, and other settings in a YAML file, and pass the file's path on the command line as follows. (The database password can be passed through the command line or an environment variable rather than including it in the connection URL, see `aggregator --help`.)

```bash
aggregator --config-file <config-file> --role <role>
```

## Cargo features

`janus_core` has the following features available.

* `database`: Enables implementations of `postgres_types::ToSql` and `postgres_types::FromSql` on `janus_core::Interval`.
* `test-util`: Enables miscellaneous test-only APIs. This should not be used outside of tests, and any such APIs do not carry any stability guarantees.

`janus_aggregator` has the following features available.

* `jaeger`: Enables tracing support and a Jaeger exporter; [see below](#jaeger).
* `otlp`: Enables OTLP exporter support for both metrics ([see below](#honeycomb-1)) and tracing ([see below](#honeycomb)).
* `prometheus`: Enables metrics support and a Prometheus exporter; [see below](#prometheus).
* `test-util`: Enables miscellaneous test-only APIs. This should not be used outside of tests, and any such APIs do not carry any stability guarantees.
* `tokio-console`: Enables a tracing subscriber and server to support [`tokio-console`](https://github.com/tokio-rs/console). [See below](#monitoring-with-tokio-console) for additional instructions.

### inotify limits

If you experience issues with tests using Kind on Linux, you may need to [adjust inotify sysctls](https://kind.sigs.k8s.io/docs/user/known-issues/#pod-errors-due-to-too-many-open-files). Both systemd and Kubernetes inside each Kind node make use of inotify. When combined with other services and desktop applications, they may exhaust per-user limits.

## Container image

To build a container image, run the following command.

```bash
DOCKER_BUILDKIT=1 docker build --tag=janus_aggregator .
```

## Monitoring with `tokio-console`

Optional support is included to monitor the server's async runtime using `tokio-console`. When enabled, a separate tracing subscriber will be installed to monitor when the async runtime polls tasks, and expose that information to diagnostic tools via a gRPC server. Currently, this requires both changes to the aggregator configuration and to the build flags used at compilation. Add a stanza similar to the following to the configuration file.

```yaml
logging_config:
  tokio_console_config:
    enabled: true
    listen_address: 127.0.0.1:6669
```

Compile the server with the `tokio-console` feature enabled, and provide the flag `--cfg tokio_unstable` to `rustc`, as follows. (If `tokio-console` support is enabled in a build without the `tokio_unstable` flag, the server will panic upon startup)

```bash
RUSTFLAGS="--cfg tokio_unstable" CARGO_TARGET_DIR=target/tokio_unstable cargo build --features tokio-console
```

Install `tokio-console`, run the server, and run `tokio-console http://127.0.0.1:6669` to connect to it and monitor tasks.

## OpenTelemetry Traces

Tracing spans from the server can be exported to distributed tracing systems through the OpenTelemetry SDK, and various exporters.

### Jaeger

[Jaeger](https://www.jaegertracing.io/) is a software stack that stores, indexes, and displays distributed traces. While Jaeger supports the OpenTelemetry object model, it uses its own wire protocols, and thus requires Jaeger-specific exporters.

For local testing, start Jaeger by running `docker run -d -p6831:6831/udp -p6832:6832/udp -p16686:16686 -p14268:14268 jaegertracing/all-in-one:latest`, and open its web interface at http://localhost:16686/. Enable experimental support for Jaeger by compiling with the `jaeger` feature. Add the following configuration file stanza. Trace data will be pushed to the local Jaeger agent via UDP.

```yaml
logging_config:
  open_telemetry_config: jaeger
```

### Honeycomb

[Honeycomb](https://www.honeycomb.io/) is a Software-as-a-Service provider that offers an integrated observability tool. To use it, sign up for an account, create a team and environment, and retrieve the corresponding API key. Compile `janus_aggregator` with the `otlp` feature enabled, to pull in the OTLP exporter. Add the following section to the configuration file, subtituting in the Honeycomb API key. Traces will be sent to Honeycomb via OTLP/gRPC.

```yaml
logging_config:
  open_telemetry_config:
    otlp:
      endpoint: "https://api.honeycomb.io:443"
      metadata:
        x-honeycomb-team: "YOUR_API_KEY"
```

The gRPC metadata can also be specified on the command line, with `--otlp-tracing-metadata x-honeycomb-team=YOUR_API_KEY`, or through the environment variable `OTLP_TRACING_METADATA`.

## OpenTelemetry Metrics

Application-level metrics from the server can be exported to one of the following services.

### Prometheus

When the Prometheus exporter is enabled, a server will listen on port 9464 for metrics scrape requests. Prometheus must be configured to scrape the server, either manually or via an auto-discovery mechanism. Compile `janus_aggregator` with the `prometheus` feature enabled, and add the following to the configuration file.
```yaml
metrics_config:
  exporter:
    prometheus:
      host: 0.0.0.0
      port: 9464
```

The IP address and port that Prometheus exporter listens on can optionally be set in the configuration file as above. If the `host` and `port` are not set, it will fall back to the environment variables `OTEL_EXPORTER_PROMETHEUS_HOST` and `OTEL_EXPORTER_PROMETHEUS_PORT`, or the default values of `0.0.0.0` and 9464.

### Honeycomb

Honeycomb also supports OpenTelemetry-formatted metrics, though only on the Enterprise and Pro plans. Compile `janus_aggregator` with the `otlp` feature enabled, and add the following section to the configuration file. Note that the OTLP/gRPC exporter will push metrics at regular intervals.

```yaml
metrics_config:
  exporter:
    otlp:
      endpoint: "https://api.honeycomb.io:443"
      metadata:
        x-honeycomb-team: "YOUR_API_KEY"
        x-honeycomb-dataset: "YOUR_METRICS_DATASET"
```

The command line flag `--otlp-metrics-metadata` or environment variable `OTLP_METRICS_METADATA` may alternately be used to supply gRPC metadata for the metrics exporter.

## Code Style

* Functions & methods should take the type of argument (reference, mutable reference, or value) that
  they need. For example, a function that computes a predicate on its argument, or returns a
  reference to some part of its argument, should take a reference. A function that mutates its
  argument should take a mutable reference. A function that moves its argument into a
  newly-constructed struct which will be returned should take its arguments by value.

  * This should always be followed for non-`Copy` types to avoid expensive `clone()` calls. Even
    when using `Copy` types, it is a best practice to follow this rule.
  
  * In particular, when writing a constructor, receive the fields by value. Do not take a reference
    and then call `clone()` on it. Doing so may incur an extra `clone()` if the caller already has a
    value in hand which they are OK handing off. (And if they have a reference, or a value that
    they wish to keep ownership of, they can call `clone()` themselves.)

* Structured data intended for "public" use (i.e. outside of the current module & its descendants)
  should not include public fields & should instead provide getters which return references to the
  internal data. This allows the structure to enforce invariants at time of construction, allows
  the fields in the structure to be different from the public API, and permits the structures to be
  refactored to a greater degree while requiring fewer updates to users of the structure.

* Types should generally implement traits rather than custom methods, where it makes sense to do so.
  This is because these traits will "fit in" better with libraries written to work with these
  traits.

  * For example, don't write an `as_bytes() -> &[u8]` method; instead, implement `AsRef<[u8]>`.
    Don't write a `random()` or `generate()` method; instead, `impl Distribution<Type> on Standard`.
    Consider implementing `From` rather than `new` if the type conceptually is the thing it is being
    created from (for example, a newtype over an array of bytes might implement `From<Vec<u8>>`).

* Follow documented best practices of the crates Janus depends on. For exmaple, the `rand` crate
  suggests using `random()` to generate random data, falling back to `thread_rng()` to gain more
  control as-needed.
