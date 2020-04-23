# Install Polytect on a [systemd](https://systemd.io) host

NOTE: If you don't like curl-pipe-bash, please read the detailed [installation document](../README.md) which breaks down all the options to install this in a trustworthy, verifiable, auditable way, right down to the source code.

To install polytect on systemd, run:

```.bash
curl -L https://github.com/polyverse/polytect/releases/latest/download/systemd-install.sh | sh -s <polycorder auth key> [optional nodeid]
```

To uninstall polutect:

```.bash
curl -L https://github.com/polyverse/polytect/releases/latest/download/systemd-install.sh | sh -s uninstall
```
