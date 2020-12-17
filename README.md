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
* [Partners/Integrations](#partnersintegrations)
  * [Micro Focus ArcSight](#micro-focus-arcsight)
  * [PagerDuty](#pagerduty)
* [Zerotect Log](#zerotect-log)
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

See [Installation](/install/README.md) for details on how to install/run Zerotect as a proper monitor in a production environment.

To install quickly:

```.bash
curl -s -L https://github.com/polyverse/zerotect/releases/latest/download/install.sh | sh
```

## Partners/Integrations

Zerotect by itself provides limited actionable value. The best value is derived when Zerotect is one of many signals that a larger monitoring/observability strategy is processing. This could be a SOC, a SIEM, an alerting system or just a simple log aggregator.

To that end Zerotect supports a number of outbound integrations (i.e. where it sends its data) listed below.

### Micro Focus ArcSight

[Zerotect on ArcSight Marketplace](https://marketplace.microfocus.com/arcsight/content/zerotect)

Zerotect sends events to ArcSight through the Syslog SmartConnector. It is easy to configure in a single command. For more details read the [Administration Guide](/integrations/MicrofocusArcSight/MF_Polyverse_ZeroTect_0.4_ArcSight_CEF_Integration_Guide_2020.pdf).

### PagerDuty

Zerotect can send detected events to the PagerDuty Events API V2 through a single configuration. View the [PagerDuty Integration Guide](/integrations/PagerDuty/README.md) for details.

## Zerotect Log

Zerotect stores activities in the log file located in /var/log/zerotect.log. Examine this log file for further investigation of potential attacks.

The authoritative log format is defined in [schema.json](/reference/schema.json).

You may use it to generate parsers. The schema contains documentation comments, explanations of fields, and so forth.

## Contributing

We believe that open-source and robust community contributions make everyone safer,
therefore we accept pretty much ALL contributions so long as: (a) They don't break an
existing use-case or dependency and (b) They don't do something that is wildly out of scope of the project.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md), and our [Contribution Guidelines](CONTRIBUTING.md) before starting work on a new feature or bug.

## Zero Day Reward Program

Memory and overflow attacks are very difficult to detect, which is the reason we built Zerotect in the first place.
In order to encourage security professonals and enthusiasts to look for this class of attacks, we've started the
Zero Day Reward Program. We're giving $1000 rewards to people and institutions that report evidence of real-world
memory-based attacks using Zerotect. See the [terms and conditions](https://polyverse.com/zerotect-terms-and-conditions/)
for more information.

You can report evidence of a real-world atack using our [live attack form](https://info.polyverse.com/zerotect-contest).
