# Installing Polytect

This describes how polytect can be obtained (securely) and configured so you can build your own recipes.

## Table of Contents

* ["Trust Me" Quickstarts](#trust-me-quickstarts)
  * [systemd](#systemd)
* [First-Principles Install](#first-principles-install)
  * [Obtain the polytect binary](#obtain-the-polytect-binary)
    * [Download](#download)
    * [Compile from source](#compile-from-source)
  * [Place polytect binary in a durable location](#place-polytect-binary-in-a-durable-location)
  * [Hook into the init system (or not)](#hook-into-the-init-system-or-not)
  * [Configure with a TOML file](#configure-with-a-toml-file)
  * [Run one polytect per kernel](#run-one-polytect-per-kernel)

## "Trust Me" Quickstarts

Everything described in this document is encapsulated in scripted recipes for various distributions and init-systems. These are a great way to quickly install polytect.

As the scripts follow the curl pipe-to bash pattern, the rest of this document details how you can develop your own automation to deploy polytect, depending on your level of trust (which may be zero trust).

### systemd

All systems running [systemd](https://systemd.io/) can use the [systemd quickstart](./distro-neutral-systemd/README.md).

## First-Principles Install

This section deals with polytect installation primitives (including if necessary, compiling it from source yourself.) This is especially important for security-conscious organizations for a complete auditable trail.

### Obtain the polytect binary

#### Download

Polytect executables are posted in [Github Releases](https://github.com/polyverse/polytect/releases).

The latest polytect executable can be found here: [https://github.com/polyverse/polytect/releases/latest/download/polytect](https://github.com/polyverse/polytect/releases/latest/download/polytect)

For transparency, you can study [.travis.yml](../.travis.yml) and the [build logs](https://travis-ci.org/github/polyverse/polytect) to audit the pre-built binaries.

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

### Hook into the init system (or not)

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

#### Without init integration


For other init systems, you want to ensure you run polytect with the proper configuration.


### Configure with a TOML file

While polytect does take command-line parameters (documented in the main [README.md](../README.md)), it is not recommended to embed CLI-based configuration options in your init configuration.

Instead, we recommend running it with a configuration file located at `/etc/polytect/`:

```bash
$DURABLE_POLYTECT_LOCATION/polytect --configfile /etc/polytect/polytect.toml
```

When using a configuration file, no other command-line options are supported. To see all options available in a configuration file, read the [Reference polytect.toml file](../reference/polytect.toml).

### Run one polytect per kernel

Since Polytect detects side-effects from the kernel, it is sufficient to run a single instance of polytect for every Kernel. What this means is, traditional Linux "containers" (using cgroups and namespaces) do not need polytect whtin them so long as either the host is running it, or there's a single container running it.

However, "VM" containers such as Kata Containers, Firecracker VMs, and so forth will warrant a polytect instance per container, since they would not share the same kernel.

