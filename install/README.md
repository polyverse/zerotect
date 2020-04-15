# Installing Polytect

This describes how polytect can be obtained (securely) and configured so you can build your own recipes.

## Table of Contents

* [systemd recipe](#systemd-recipe)
* [Install Polytect the Hard Way](#install-polytect-the-hard-way)
  * [Obtain the polytect binary](#obtain-the-polytect-binary)
    * [Download](#download)
    * [Compile from source](#compile-from-source)
  * [Configuring using the config file](#configuring-using-the-config-file)
  * [Recommendations for Running Polytect](#recommendations-for-running-polytect)

## SystemD

[systemd recipe](./distro-neutral-systemd) has a simple for installing on [systemd](https://systemd.io/) based systems.

## Installing Polytect the Hard Way

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

### Placing polytect in a durable location

We recommend placing polytect in the `/usr/local/bin` directory. Specifically since polytect needs to run with higher privilege levels than a regular user, it is better to not have it under a user directory.

### Hooking into an init system

NOTE: for systemd, please refer to the [systemd recipe](./distro-neutral-systemd)

For other init systems, you want to ensure you run polytect with the proper configuration. While polytect does take command-line parameters (documented in the main [README.md](../README.md)), it is recommended to run polytect with

### Configuring with file

For stable installations it us recommended to run polytect with a configuration file located at `/etc/polytect/polytect.toml`, by telling it to load config from file:

```bash
polytect --configfile /etc/polytect/polytect.toml
```

When using a configuration file, no other command-line options are supported. To see all options available in a configuration file, read the [Reference polytect.toml file](../reference/polytect.toml).

### Recommendations for Running Polytect

For hosts/VMs, we recommend running polytect through the default init system. This may require creating the right configuration files.

Since Polytect detects side-effects from the kernel, it is sufficient to run a single instance of polytect for every Kernel. What this means is, traditional Linux "containers" (using cgroups and namespaces) do not need polytect whtin them so long as either the host is running it, or there's a single container running it.

However, "VM" containers such as Kata Containers, Firecracker VMs, and so forth will warrant a polytect instance per container, since they would not share the same kernel.
