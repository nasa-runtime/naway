#!/usr/bin/env bash
# 以容器方式启动 Naway(host 网络,自动重启)。挂载外部配置目录即可热更。
set -euo pipefail

cd "$(dirname "$0")"

NAME="${NAWAY_CONTAINER_NAME:-${GATEWAY_CONTAINER_NAME:-naway}}"
IMAGE="${NAWAY_IMAGE:-${GATEWAY_IMAGE:-naway}}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
# 宿主机配置目录，1:1 挂进容器 /data/naway（新部署主文件为 naway.yml）。
CONFIG_DIR="${NAWAY_CONFIG_DIR:-${GATEWAY_CONFIG_DIR:-/data/naway}}"

DOCKER_ARGS=(
  -d
  --restart=always
  --name "$NAME"
  --network host
)

# 挂载外部配置固定目录(宿主 → 容器 /data/naway)；目录不存在则用镜像内置默认。
if [ -d "$CONFIG_DIR" ]; then
  DOCKER_ARGS+=(-v "$CONFIG_DIR:/data/naway")
fi

"$DOCKER_BIN" rm -f "$NAME" >/dev/null 2>&1 || true
"$DOCKER_BIN" run "${DOCKER_ARGS[@]}" "$IMAGE"
echo "Naway started as container '$NAME' (host network)."
