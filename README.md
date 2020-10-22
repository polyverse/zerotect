# zerotect

[![Build Status](https://travis-ci.org/polyverse/zerotect.svg?branch=master)](https://travis-ci.org/polyverse/zerotect)

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md) 

## Table of Contents

* [What is Zerotect](#what-is-zerotect)
* [Install Zerotect](#install-zerotect)
* [Usage](#usage)
  * [Recommended usage](#recommended-usage)
    * [Understanding the minimal configuration](#understanding-the-minimal-configuration)
  * [All CLI options](#all-cli-options)
* [Zerotect Log Format](#zerotect-log)
* [Contributing](#contributing)
* [Zero Day Reward Program](#zero-day-reward-program)

## What is Zerotect

Detecting malicious scans can be the first indicator of a potential attack.
Watching for things like port scans is commonplace in security circles, but how
do you detect a BROP attack, or any other kind of buffer-overflow attack for 
that matter?

Zerotect is a small open source agent that monitors kernel logs to 
look for conclusive proof of memory-based exploits from the side-effects of those 
attacks. These appear in the form of process crashes (faults). Zerotect doesn't
actively intercept network traffic, but instead, passively monitors kernel logs for
anomalies. This means the attack surface of your servers isn't increased, and the stability
of Zerotect doesn't affect the stability of anything else on the system.

When anomalies are detected, Zerotect can report these anomalies to a variety of analytics
tools. Our intent is to support a variety of tools, and integrations with those tools. Please 
file a Feature Request with examples of how you'd like to configure it and use it.

## Install Zerotect

See [Installation](./install/README.md) for deploying zerotect on a system.

## Usage

This section running the executable itself, and configuration options it takes.

### Recommended usage

The two most common modes for Zerotect are:

1. Using basic CLI arguments to auto-configure kernel tracing, and a Polycorder auth key.

    ```bash
    zerotect --auto-configure debug.exception-trace --auto-configure kernel.print-fatal-signals -p <authkey>
    ```

2. Using a config file.

    ```bash
    zerotect --configfile /etc/zerotect/zerotect.toml
    ```

    where the config file might be:

    ```toml
    [auto_configure]
    exception_trace = true
    fatal_signals = true

    ```

    See [Reference config.toml](./reference/config.toml) for all the options.

#### Understanding the minimal configuration

- *--auto-configure*: This option commands Zerotect to set a kernel flags on your behalf. This can be very convenient to both configure the right traces, and ensure the traces stay enabled. You can specify this option multiple times with different values to auto-configure:
    * *debug.exception-trace*: enables writing exception traces to `/dev/kmsg`  (the kernel message buffer.)
    * *kernel.print-fatal-signals*: enables writing fatal signals to `/dev/kmsg` (the kernel message buffer.)

#### Required access to `/dev/kmsg`

Zerotect requires that it run as root or with sufficient permissions to read `/dev/kmsg` ([The Linux Kernel message buffer](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/dev-kmsg).)

Zerotect observes kernel signals through this device.

### All CLI options

```bash
Zerotect 1.0
Polyverse Corporation <support@polyverse.com>
Detect attempted (and ultimately failed) attacks and exploits using known and unknown vulnerabilities by observing side effects (segfaults, crashes, etc.)

USAGE:
    zerotect [FLAGS] [OPTIONS]

FLAGS:
    -v, --verbose    Increase debug verbosity of zerotect.
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --configfile <filepath>                                Read configuration from a TOML-formatted file. When specified, all other command-line arguments are ignored. (NOTE: Considerably more options can be configured in the file than through CLI arguments.)
        --auto-configure <sysctl-flag-to-auto-configure>...    Automatically configure the system on the user\'s behalf. [possible values: debug.exception-trace, kernel.print-fatal-signals]
        --console <format>                                     Prints all monitored data to the console in the specified format. [possible values: text, json]
```

## Zerotect Log 

Zerotect stores activities in the log file located in /var/log/zerotect.log. Examine this log file for further investigation of potential attacks.

The authoritative log format is defined in [schema.json](./reference/schema.json).

You may use it to generate parsers. The schema contains documentation comments, explanations of fields, and so forth.

## Contributing

We believe that open-source and robust community contributions make everyone safer, 
therefore we accept pretty much ALL contributions so long as: (a) They don't break an 
existing use-case or dependency and (b) They don't do something that is wildly out of scope of the project.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md), and our [Contribution Guidelines](CONTRIBUTING.md) before starting work on a new feature or bug.

# Zero Day Reward Program

Memory and overflow attacks are very difficult to detect, which is the reason we built Zerotect in the first place.
In order to encourage security professonals and enthusiasts to look for this class of attacks, we've started the
Zero Day Reward Program. We're giving $1000 rewards to people and institutions that report evidence of real-world
memory-based attacks using Zerotect. See the [terms and conditions](https://polyverse.com/zerotect-terms-and-conditions/)
for more information.

You can report evidence of a real-world atack using our [live attack form](https://info.polyverse.com/zerotect-contest).
