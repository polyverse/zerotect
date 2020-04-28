# Installing Polytect

This describes how polytect can be obtained (securely) and configured so you can build your own recipes.

## Table of Contents

* ["Trust Me" Quickstarts](#trust-me-quickstarts)
  * [systemd](#systemd)
  * [OpenRC](#openrc)
  * [upstart](#upstart)
* [First-Principles Install](#first-principles-install)
  * [Obtain the polytect binary](#obtain-the-polytect-binary)
    * [Download](#download)
    * [Polytect Container image](#polytect-container-image)
    * [Compile from source](#compile-from-source)
  * [Place polytect binary in a durable location](#place-polytect-binary-in-a-durable-location)
  * [polytect lifecycle](#polytect-lifecycle)
    * [Run one polytect per kernel](#run-one-polytect-per-kernel)
    * [Automate polytect lifecycle with your init system](#automate-polytect-lifecycle-with-your-init-system)
    * [One-off direct execution](#one-off-direct-execution)
      * [As a background process](#as-a-background-process)
    * [In the Cloud-Native World](#in-the-cloud-native-world)
      * [1. DaemonSets](#1-daemonsets)
      * [2. Sidecars](#2-sidecars)
  * [Configure with a TOML file](#configure-with-a-toml-file)

## "Trust Me" Quickstarts

Everything described in this document is encapsulated in scripted recipes for various distributions and init-systems. These are a great way to quickly install polytect.

As the scripts follow the curl pipe-to bash pattern, the rest of this document details how you can develop your own automation to deploy polytect, depending on your level of trust (which may be zero trust).

A triaging install script located at the root, can find the specific init system and call the specific script for you. This is particularly useful when you need a uniform command to run across a variety of host types.

To install polytect:

```.bash
curl -s -L https://github.com/polyverse/polytect/releases/latest/download/install.sh | sh -s <polycorder auth key> [optional nodeid]
```

To uninstall polytect:

```.bash
curl -s -L https://github.com/polyverse/polytect/releases/latest/download/install.sh | sh -s uninstall
```

### systemd

All systems running [systemd](https://systemd.io/) can use the [systemd quickstart](./systemd/README.md).

### OpenRC

All systems, especially Alpine, running [OpenRC](https://wiki.gentoo.org/wiki/Project:OpenRC) can use the [OpenRC quickstart](./openrc/README.md).

### upstart

All systems, especially CentOS 6, running [upstart](http://upstart.ubuntu.com) can use the [upstart quickstart](./upstart/README.md).

## First-Principles Install

This section deals with polytect installation primitives (including if necessary, compiling it from source yourself.) This is especially important for security-conscious organizations for a complete auditable trail.

### Obtain the polytect binary

#### Download

Polytect executables are posted in [Github Releases](https://github.com/polyverse/polytect/releases).

The latest polytect executable can be found here: [https://github.com/polyverse/polytect/releases/latest/download/polytect](https://github.com/polyverse/polytect/releases/latest/download/polytect)

For transparency, you can study [.travis.yml](../.travis.yml) and the [build logs](https://travis-ci.org/github/polyverse/polytect) to audit the pre-built binaries.

#### Polytect Container image

As part of the polytect build process, container images are also build and published on Github agailable here:

[https://github.com/polyverse/polytect/packages/199165](https://github.com/polyverse/polytect/packages/199165)

These are particularly useful for running as Sidecars (in Pods/Tasks) or DaemonSets (once-per-host).

More information on this usage is found [In the Cloud-Native World](#in-the-cloud-native-world) section.

#### Compile from source

For complete audit and assurance, you may compile polytect from scratch. Polytect is built in [Rust](https://www.rust-lang.org/).

On a system with [Rust build tools](https://www.rust-lang.org/tools/install) available:

```bash
# clone this repository
git clone https://github.com/polyverse/polytect.git

# Go to the repository root
cd polytect

# Build
cargo build
```

All regular rust tools/options recipes work - from cross-compilation, static linking, build profiles and so forth. You may build it any way you wish.

### Place polytect binary in a durable location

`DURABLE_POLYTECT_LOCATION=/usr/local/bin`

We recommend placing polytect in the `/usr/local/bin` directory. Specifically since polytect needs to run with higher privilege levels than a regular user, it is better to not have it under a user directory.

### polytect lifecycle

To ensure polytect is running when you want it to run, and not running when you don't, you need to plan for some sort of lifecycle management. We present two main recommendations for running polytect.

#### Run one polytect per kernel

Since Polytect detects side-effects from the kernel, it is sufficient to run a single instance of polytect for every Kernel. What this means is, traditional Linux "containers" (using cgroups and namespaces) do not need polytect whtin them so long as either the host is running it, or there's a single container running it.

However, "VM" containers such as Kata Containers, Firecracker VMs, and so forth will warrant a polytect instance per container, since they would not share the same kernel.

#### Automate polytect lifecycle with your init system

Polytect needs to run once-per-kernel. Usually a kernel bootstraps and powers a rather complex system, and the system runs applications (and/or containers) on top of it.

In such cases, polytect should be installed as a manageable service directly on the system.

Example 1: Some applications running on a host

```.text
  application    application    application     polytect process directly
  process 1      process 2      process 3       on kernel host/VM (not
                                                containerized)
+--------------------------------------------------------------------------+
|                                                                          |
|                          Linux Kernel                                    |
|                                                                          |
+--------------------------------------------------------------------------+
```

Example 2: Some containers running on a host

```.text
  +------------+ +------------+ +------------+
  |            | |            | |            |  polytect process directly
  | container1 | | container2 | | container3 |  on kernel host/VM (not
  |            | |            | |            |  containerized)
  +------------+ +------------+ +------------+
+--------------------------------------------------------------------------+
|                                                                          |
|                          Linux Kernel                                    |
|                                                                          |
+--------------------------------------------------------------------------+
```

Example 3: Some applications/containers coexisting on a host

```.text
              +---------------+
              |               |
  application | container 5   | application     polytect process directly
  process 1   |               | process 3       on kernel host/VM (not
              +---------------+                 containerized)
+--------------------------------------------------------------------------+
|                                                                          |
|                          Linux Kernel                                    |
|                                                                          |
+--------------------------------------------------------------------------+
```

In all these cases, it helps to run polytect using the init system ([systemd](https://systemd.io/), [sysvinit](https://en.wikipedia.org/wiki/Init#SYSV), [upstart](http://upstart.ubuntu.com/), etc.)

Now it is possible (and may even be desirable in some cases, such as running a [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) on a [Kubernetes](https://kubernetes.io/) cluster) to run polytect as a privileged container like the model below.

The container itself is now a first-class serivce per host that must be managed through preferred container-management tooling.

Example 4: polytect as a privileged container

```.text
 +-----------------------------------------+
 |                                         |
 |   polytect in privileged container      |
 |   OR sufficient access to read          |
 |   /dev/kmsg                             |
 |     |                                   |
 +-----+-----------------------------------+
       |
       |
+--------------------------------------------------------------------------+
|      |                                                                   |
|      |                                                                   |
|      v                        Linux Kernel                               |
|   /dev/kmsg                                                              |
|                                                                          |
+--------------------------------------------------------------------------+
```

This leaves one question open: How is Polytect run within the container itself?

#### One-off direct execution

This method is the recommended way to run polytect in a container at entrypoint, with its maximum life being that of the container. This can be very useful for testing and validation of config options and parameters, as well as controlled on-demand execution.

```.bash
$DURABLE_POLYTECT_LOCATION/polytect <options>
```

Polytect's lifetime is that of your current context (shell, user session or host). It will not automatically start up when a host/container starts.

##### As a background process

You may push the one-off directly executed process to the background. A concrete example of this use is in [online demos](https://polyverse.com/learn), where polytect doesn't need to be durable long-term.

It also has application in a container where you can spawn the polytect process before the main blocking process is started. Like thus:

```.bash
$DURABLE_POLYTECT_LOCATION/polytect <options> &
```

When iterating/testing, un-orchestrated Docker containers can be monitored quickly without extra scaffolding (such as Docker Desktop testing).

#### In the Cloud-Native World

If you're 100% Cloud-Native and your primitive is a Container, there are two primary ways to run polytect as a container.

##### 1. DaemonSets

Whenever you run containers orchestrated over "Nodes" (Machines that you see and know about, on top of which your containers run), as with [Kubernetes](https://kubernetes.io/), [Nomad](https://www.nomadproject.io/), [ECS](https://aws.amazon.com/ecs/), [CloudRun](https://cloud.google.com/run/), [OpenShift](https://www.openshift.com/) or even plain config management tools like [Ansible](https://www.ansible.com/)/[Chef](https://www.chef.io/)/[Puppet](https://puppet.com/) and use [OCI (Docker) Images](https://www.opencontainers.org/) as purely a packaging/deployment mechanism.

Using the principle of [Run one polytect per kernel](#run-one-polytect-per-kernel), we recommend running the [polytect container](#polytect-container-image) as a [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) or equivalent for your orchestrator.

##### 2. Sidecars

The second is mostly a subset of the first use-case, but where containers are really VMs and do not share a kernel or you do not see the host ([Azure Container Instances](https://azure.microsoft.com/en-us/services/container-instances/), [AWS Fargate](https://aws.amazon.com/fargate/), etc.)

There are a number of isolation projects that make VMs look and feel like containers. These include (but are not limited to) [KataContainers](https://katacontainers.io/) and [Firecracker](https://firecracker-microvm.github.io/).

When multiple containers in a "[Pod](https://kubernetes.io/docs/concepts/workloads/pods/pod-overview/)" or "[Task](https://docs.aws.amazon.com/eks/latest/userguide/fargate-pod-configuration.html)", share the same kernel, it is useful to run polytect as a sidecar within that Pod/Task.

### Configure with a TOML file

While polytect does take command-line parameters (documented in the main [README.md](../README.md)), it is not recommended to embed CLI-based configuration options in your init configuration.

Instead, we recommend running it with a configuration file located at `/etc/polytect/`:

```bash
$DURABLE_POLYTECT_LOCATION/polytect --configfile /etc/polytect/polytect.toml
```

When using a configuration file, no other command-line options are supported. To see all options available in a configuration file, read the [Reference polytect.toml file](../reference/polytect.toml).
