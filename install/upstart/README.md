# Install Polytect on a [upstart](http://upstart.ubuntu.com/) host

NOTE: If you don't like curl-pipe-bash, please read the detailed [installation document](../README.md) which breaks down all the options to install this in a trustworthy, verifiable, auditable way, right down to the source code.

To install polytect on upstart, run:

```.bash
curl -s -L https://github.com/polyverse/polytect/releases/latest/download/upstart-install.sh | sh -s <polycorder auth key> [optional nodeid]
```

To uninstall polytect:

```.bash
curl -s -L https://github.com/polyverse/polytect/releases/latest/download/upstart-install.sh | sh -s uninstall
```