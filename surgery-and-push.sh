#!/bin/bash

#mkdir -p ./patch/opt/kata-artifacts/scripts
#cp ./kata-deploy-dev.sh ./patch/opt/kata-artifacts/scripts/kata-deploy.sh
#chmod 0755 ./patch/opt/kata-artifacts/scripts/kata-deploy.sh

cat > Dockerfile.patch <<'EOF'
FROM ghcr.io/kata-containers/kata-deploy:latest
COPY --chmod=0755 kata-deploy-dev.sh /opt/kata-artifacts/scripts/kata-deploy.sh
EOF

# docker image ls --digests
UP="ghcr.io/kata-containers/kata-deploy@sha256:860a70e2339c79197c0d9860bf663242a34167a4173a9ba74e8ab13484211f4e"  # ideal
# or UP="ghcr.io/kata-containers/kata-deploy:latest"              # less ideal
sed -i "s|^FROM .*|FROM $UP|" Dockerfile.patch

OUT="ghcr.io/igor-podpalchenko/kata-deploy:latest"

docker buildx build \
  --platform linux/amd64 \
  -f Dockerfile.patch \
  -t "$OUT" \
  --push \
  .
