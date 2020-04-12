# polytect

[![Build Status](https://travis-ci.org/polyverse/polytect.svg?branch=master)](https://travis-ci.org/polyverse/polytect)

Polytect is the reference implementation for Polyverse's zero-day detection
framework. Its main purpose is to support Polycorder (the Polyverse-hosted
zero-day attack detection and analytics service), but also serve as the
template from which ingestion into other metrics and log analytics systems.

Polyverse's Zero-day detection relies on anomaly-detection much like many other
tools in the cybersecurity landscape. The fundamental difference is in the Polymorphism
which makes anomalies stand out in a loud and noisy manner in terms of side-effects.

Polytect looks for these side-effects, specifically caused by attacking a Polymorphic system,
and reports them to analytics tools.

## Polytect Log Format

An up-to-date JSON Schema of Polytect's log format is always maintained here:
[./schema.json](./schema.json).

## Usage

> NOTE: This section covers usage of polytect the compiled binary program. For practical
polytect usage at scale, see the [Installation Documentation](./install).

Polytect is built as a single statically linked binary (only for Linux) at the moment.

### Recommended usage

The most common mode to run Polytect is with two flags and one option:

```bash
polytect -e -f -p <authkey>
```

The authkey is obtainable in the Polyverse Account Manager hosted at [https://polyverse.com](https://polyverse.com).

It is unlikely you would manually run Polytect though, unless for testing or special circumstances. For most production use, we recommend setting it up as a background daemon. This is described more in the [Installation section](./install).

### All usage options

```bash
polytect --help
Polytect 1.0
Polyverse Corporation <support@polyverse.com>
Detect attempted (and ultimately failed) attacks and exploits using known and unknown vulnerabilities by observing side effects (segfaults, crashes, etc.)

USAGE:
    polytect [FLAGS] [OPTIONS]

FLAGS:
    -e, --enable-exception-trace    Sets the debug.exception-trace value to enable segfaults to be logged to dmesg.
    -f, --enable-fatal-signals      Sets the kernel.print-fatal-signals value to enable details of fatals to be logged to dmesg.
    -h, --help                      Prints help information
    -V, --version                   Prints version information
    -v, --verbose                   Increase debug verbosity of polytect.

OPTIONS:
    -c, --console <text|json>       Prints all monitored data to the console. Optionally takes a value of 'text' or 'json'
    -n, --node <node_identifier>    All reported events are attributed to this 'node' within your overall organization, allowing for filtering, separation and more...
    -p, --polycorder <authkey>      Sends all monitored data to the polycorder service. When specified, must provide a Polyverse Account AuthKey which has an authorized scope to publish to Polyverse.
```

#### Notable flags and options

Two flags and one option are most notable in intended usage.

1. *-e, --enable-exception-trace*: Setting this flag commands Polytect to set a kernel flag that enables writing exception traces to `/dev/kmsg`  (the kernel message buffer.)

2. *-f, --enable-fatal-signals*: Setting this flag commands Polytect to set a kernel flag that enables writing fatal signals to `/dev/kmsg` (the kernel message buffer.)

3. *-p, --polycorder \<authkey\>*: Setting this option commands polytect to set detected events to the online Polycorder endpoint for pre-build detection analytics. It requires an authkey provisioned in the Polyverse Account Manager.
