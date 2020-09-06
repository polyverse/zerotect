#!/bin/sh

#docker run --rm -it -v $PWD:/zerotect --privileged rust bash

docker run -v cargo-cache:/root/.cargo/registry -v $PWD:/volume --rm -it --privileged clux/muslrust /bin/bash -c "rustup component add clippy && cargo install cargo-bloat && bash" 
