# PagerDuty Integration

This page describes how to send Polytect detections to PagerDuty.

Broadly there are two steps:

1. Generate a PagerDuty Integration Key (or Routing Key)

2. Run Zerotect with that key either through the CLI or Configuration file.

Let's go through each step by step.

## 1. Generate a PagerDuty Integration Key (or Routing Key)

See PagerDuty's Documentation for details: https://support.pagerduty.com/docs/services-and-integrations#create-a-generic-events-api-integration

## 2. Run Zerotect with the PagerDuty Integration/Routing key

The most direct way to run Zerotect with a PagerDuty integration is through the single CLI paramater `pagerduty`:

```.bash
./zerotect --pagerduty <routing_key>
```

The slightly less direct, but more robust way to run Zerotect (and more applicable when running as a daemon) is to set up the PagerDuty key in a config file like this:

`/etc/zerotect/zerotect.toml`

```.toml
pagerduty_routing_key = 'routing_key'
```

And then running Zerotect with the configuration file for input:

```.bash
./zerotect --configfile /etc/zerotect/zerotect.toml
```
