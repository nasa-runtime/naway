#!/usr/bin/env bash
# 构建 Naway 镜像。工程目录、构建产物、镜像和运行品牌统一为 naway/Naway。
set -euo pipefail

cd "$(dirname "$0")"

IMAGE="${NAWAY_IMAGE:-${GATEWAY_IMAGE:-naway}}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
DOCKER_BUILD_NETWORK="${NAWAY_DOCKER_BUILD_NETWORK:-${GATEWAY_DOCKER_BUILD_NETWORK:-host}}"

"$DOCKER_BIN" rmi "$IMAGE" >/dev/null 2>&1 || true
"$DOCKER_BIN" build \
  --network "$DOCKER_BUILD_NETWORK" \
  -t "$IMAGE" \
  -f Dockerfile \
  ..
