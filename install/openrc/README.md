# Install zerotect on a [OpenRC](https://wiki.gentoo.org/wiki/Project:OpenRC) host

NOTE: If you don't like curl-pipe-bash, please read the detailed [installation document](../README.md) which breaks down all the options to install this in a trustworthy, verifiable, auditable way, right down to the source code.

To install zerotect on OpenRC, run:

```.bash
curl -s -L https://github.com/polyverse/zerotect/releases/latest/download/openrc-install.sh | sh -s <polycorder auth key> [optional nodeid]
```

To uninstall zerotect:

```.bash
curl -s -L https://github.com/polyverse/zerotect/releases/latest/download/openrc-install.sh | sh -s uninstall
```
