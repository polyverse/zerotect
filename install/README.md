# Installing Polytect

## Table of Contents

* [systemd](#systemd)
* [Installing Polytect the Hard Way](#installing-polytect-the-hard-way)
  * [Compiling Polytect from source](#compiling-polytect-from-source)
  * [Downloading the latest polytect binary](#downloading-the-latest-polytect-binary)
  * [Configuring using the config file](#configuring-using-the-config-file)
  * [Recommendations for Running Polytect](#recommendations-for-running-polytect)

## SystemD

If your host/VM/container/device uses systemd, you may use the [Distribution-Neutral SystemD installer](./distro-neutral-systemd).

## Installing Polytect the Hard Way

This section deals with polytect installation primitives (including if necessary, compiling it from source yourself.) This is especially useful for security-conscious people and organizations to understand, as well as providing auditors with a complete trail of ownership.

### Compiling Polytect from source

Written in Rust, polytect is easy and simple to build. While the agent itself relies deeply on Linux as the underlying OS, it accesses the Linux kernel buffer through the virtual device `/dev/kmsg`. It means that polytect doesn't have any binary dependency on Linux.

To compile, simply clone this repository, and run `cargo build`.

Everything is plain simple Rust with no additional custom build scripts or interrupts. It should be possible to know the entire program source closure.

How to compile polytect to be completely statically linked is beyond the scope of this documentation. Please see the `.travis.yml` file at the root of this repository to see how we build it for release.

### Downloading the latest polytect binary

Polytect is frequently recompiled at the push of a new tag, and a [Github Release](https://github.com/polyverse/polytect/releases) is created for this repository.

You may download the latest polytect executable here: [https://github.com/polyverse/polytect/releases/latest/download/polytect](https://github.com/polyverse/polytect/releases/latest/download/polytect)

We compile polytect 100% statically-linked, even with the MUSL C library linked in. This allows it to portably deploy inside containers, VMs, hypervisors and IoT devices. So long as there's a modern-ish Linux kernel underneath, polytect will run.

### Configuring using the config file

For stable installations it us recommended to run polytect with a configuration file located at `/etc/polytect/polytect.toml`, by telling it to load config from file:

```bash
polytect --configfile /etc/polytect/polytect.toml
```

When using a configuration file, no other command-line options are supported. To see all options available in a configuration file, read the [Reference polytect.toml file](../reference/polytect.toml).

### Recommendations for Running Polytect

For hosts/VMs, we recommend running polytect through the default init system. This may require creating the right configuration files.

Since Polytect detects side-effects from the kernel, it is sufficient to run a single instance of polytect for every Kernel. What this means is, traditional Linux "containers" (using cgroups and namespaces) do not need polytect whtin them so long as either the host is running it, or there's a single container running it.

However, "VM" containers such as Kata Containers, Firecracker VMs, and so forth will warrant a polytect instance per container, since they would not share the same kernel.
