#!/bin/sh

IMAGE="ghcr.io/polyverse/rust-dev-env"

docker run -v /Users/archisgore/.rust_carco_cache:/root/.cargo/registry -v $PWD:/volume --rm -it --privileged $IMAGE
