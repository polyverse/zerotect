#!/bin/sh

#docker run --rm -it -v $PWD:/zerotect --privileged rust bash

docker run -v /Users/archisgore/.rust_carco_cache:/root/.cargo/registry -v $PWD:/volume --rm -it --privileged polyverse/rust-dev-env
