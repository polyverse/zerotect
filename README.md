# polytect

[![Build Status](https://travis-ci.org/polyverse/polytect.svg?branch=master)](https://travis-ci.org/polyverse/polytect)

## Table of Contents

* [What is Polytect](#what-is-polytect)
* [Installing Polytect](#installing-polytect)
* [Usage](#usage)
  * [Recommended usage](#recommended-usage)
  * [All usage options](#all-usage-options)
  * [Notable flags and options](#notable-flags-and-options)
* [Polytect Log Format](#polytect-log-format)

## What is Polytect

Polytect is the reference implementation for Polyverse's zero-day detection
framework. Its main purpose is to support Polycorder (the Polyverse-hosted
zero-day attack detection and analytics service), but also serve as the
template from which ingestion into other metrics and log analytics systems.

Polyverse's Zero-day detection relies on anomaly-detection much like many other
tools in the cybersecurity landscape. The fundamental difference is in the Polymorphism
which makes anomalies stand out in a loud and noisy manner in terms of side-effects.

Polytect looks for these side-effects, specifically caused by attacking a Polymorphic system,
and reports them to analytics tools.

## Installing Polytect

[Installation Documentation](./install/README.md) explains using Polytect in real at-scale practical deployments.

## Usage

Polytect is built as a single statically linked binary (only for Linux) at the moment.

### Recommended usage

The most common mode to run Polytect is with two flags and one option:

```bash
polytect --auto-configure debug.exception-trace --auto-configure kernel.print-fatal-signals -p <authkey>
```

The authkey is obtainable in the Polyverse Account Manager hosted at [https://polyverse.com](https://polyverse.com).

It is unlikely you would manually run Polytect though, unless for testing or special circumstances. For most production use, we recommend setting it up as a background daemon. This is described more in the [Installation section](./install/README.md).

### All usage options

```bash
Polytect 1.0
Polyverse Corporation <support@polyverse.com>
Detect attempted (and ultimately failed) attacks and exploits using known and unknown vulnerabilities by observing side effects (segfaults, crashes, etc.)

USAGE:
    polytect [FLAGS] [OPTIONS]

FLAGS:
    -v, --verbose    Increase debug verbosity of polytect.
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --configfile <filepath>                                Read configuration from a TOML-formatted file. When specified, all other command-line arguments are ignored. (NOTE: Considerably more options can be configured in the file than through CLI arguments.)
        --auto-configure <sysctl-flag-to-auto-configure>...    Automatically configure the system on the user's behalf. [possible values: debug.exception-trace, kernel.print-fatal-signals]
        --console <format>                                     Prints all monitored data to the console in the specified format. [possible values: text, json]
        --polycorder <authkey>                                 Sends all monitored data to the polycorder service. When specified, must provide a Polyverse Account AuthKey which has an authorized scope to publish to Polyverse.
        --node <node_identifier>                               All reported events are attributed to this 'node' within your overall organization, allowing for filtering, separation and more.
```

#### Notable flags and options

Two options are most notable in intended usage.

1. *--auto-configure*: This option commands Polytect to set a kernel flags on your behalf. This can be very convenient to both configure the right traces, and ensure the traces stay enabled. You can specify this option multiple times with different values to auto-configure:
    * *debug.exception-trace*: enables writing exception traces to `/dev/kmsg`  (the kernel message buffer.)
    * *kernel.print-fatal-signals*: enables writing fatal signals to `/dev/kmsg` (the kernel message buffer.)
2. *-p, --polycorder \<authkey\>*: Setting this option commands polytect to set detected events to the online Polycorder endpoint for pre-build detection analytics. It requires an authkey provisioned in the Polyverse Account Manager.

## Polytect Log Format

An up-to-date JSON Schema of Polytect's log format is always maintained here:
[schema.json](./reference/schema.json).

The log format is important for processing data emitted by Polytect. This enables users of Polycorder to send it data from agents other than Polytect. It enables analytics tools to consume structured Polytect data and make sense of it.
