#!/bin/bash

YOUR="ghcr.io/igor-podpalchenko/kata-deploy:latest"
UP="ghcr.io/kata-containers/kata-deploy:latest"

docker pull "$YOUR"
docker pull "$UP"

docker image inspect "$YOUR" --format '{{.Size}}'
docker image inspect "$UP"   --format '{{.Size}}'

# show layers
docker history --no-trunc "$YOUR" | head -n 20
docker history --no-trunc "$UP"   | head -n 20

docker run --rm --entrypoint sh "$YOUR" -lc 'cd /opt/kata-artifacts && find . -type f | sort' > /tmp/kata-your.lst
docker run --rm --entrypoint sh "$UP"   -lc 'cd /opt/kata-artifacts && find . -type f | sort' > /tmp/kata-up.lst

echo "== Missing from YOUR (first 200) =="
comm -23 /tmp/kata-up.lst /tmp/kata-your.lst | head -n 200

echo
echo "== Extra in YOUR (first 200) =="
comm -13 /tmp/kata-up.lst /tmp/kata-your.lst | head -n 200

