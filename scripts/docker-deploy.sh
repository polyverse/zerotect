#!/bin/bash

echo "Deploy to github's docker package"

if [[ -z "$GITHUB_USER" ]]; then
    echo "Cannot deploy to github's docker package without \$GITHUB_USER set."
fi

if [[ -z "$GITHUB_TOKEN" ]]; then
    echo "Cannot deploy to github's docker package without \$GITHUB_TOKEN set (for the user set in \$GITHUB_USER)."
fi

if [[ -z "$1" ]]; then
    echo "No tag provided. This script requires one parameter - the release tag."
fi

echo "$GITHUB_TOKEN" | docker login docker.pkg.github.com -u $GITHUB_USER --password-stdin

# Build the image
docker build -t docker.pkg.github.com/polyverse/polytect/polytect:$1 .

# Also alias it to :latest
docker tag docker.pkg.github.com/polyverse/polytect/polytect:$1 docker.pkg.github.com/polyverse/polytect/polytect:latest

# Push both
docker push docker.pkg.github.com/polyverse/polytect/polytect:$1
docker push docker.pkg.github.com/polyverse/polytect/polytect:latest
