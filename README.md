# polytect

[![Build Status](https://travis-ci.org/polyverse/polytect.svg?branch=master)](https://travis-ci.org/polyverse/polytect)

## Table of Contents

* [What is Polytect](#what-is-polytect)
* [Install Polytect](#install-polytect)
* [Usage](#usage)
  * [Recommended usage](#recommended-usage)
    * [Understanding the minimal configuration](#understanding-the-minimal-configuration)
  * [All CLI options](#all-cli-options)
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

## Install Polytect

See [Installation](./install/README.md) for deploying polytect on a system.

## Usage

This section running the executable itself, and configuration options it takes.

### Recommended usage

The two most common modes for Polytect are:

1. Using basic CLI arguments to auto-configure kernel tracing, and a Polycorder auth key.

    ```bash
    polytect --auto-configure debug.exception-trace --auto-configure kernel.print-fatal-signals -p <authkey>
    ```

2. Using a config file.

    ```bash
    polytect --configfile /etc/polytect/polytect.toml
    ```

    where the config file might be:

    ```toml
    [auto_configure]
    exception_trace = true
    fatal_signals = true

    [polycorder_config]
    auth_key = 'AuthKeyFromPolyverseAccountManager'
    ```

    See [Reference config.toml](./reference/config.toml) for all the options.

#### Understanding the minimal configuration

1. *--auto-configure*: This option commands Polytect to set a kernel flags on your behalf. This can be very convenient to both configure the right traces, and ensure the traces stay enabled. You can specify this option multiple times with different values to auto-configure:
    * *debug.exception-trace*: enables writing exception traces to `/dev/kmsg`  (the kernel message buffer.)
    * *kernel.print-fatal-signals*: enables writing fatal signals to `/dev/kmsg` (the kernel message buffer.)
2. *-p, --polycorder \<authkey\>*: Setting this option commands polytect to set detected events to the online Polycorder endpoint for pre-build detection analytics. It requires an authkey provisioned in the [Polyverse Account Manager](https://polyverse.com).

#### Required access to `/dev/kmsg`

Polytect requires that it run as root or with sufficient permissions to read `/dev/kmsg` ([The Linux Kernel message buffer](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/dev-kmsg).)

Polytect observes kernel signals through this device.

### All CLI options

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
        --auto-configure <sysctl-flag-to-auto-configure>...    Automatically configure the system on the user\'s behalf. [possible values: debug.exception-trace, kernel.print-fatal-signals]
        --console <format>                                     Prints all monitored data to the console in the specified format. [possible values: text, json]
        --polycorder <authkey>                                 Sends all monitored data to the polycorder service. When specified, must provide a Polyverse Account AuthKey which has an authorized scope to publish to Polyverse.
        --node <node_identifier>                               All reported events are attributed to this 'node' within your overall organization, allowing for filtering, separation and more.
```

## Polytect Log Format

[schema.json](./reference/schema.json) is the authoritative log format.

You may use it to generate parsers. The schema contains documentation comments, explanations of fields, and so forth.
