#!/usr/bin/env bash
# 以容器方式启动 Naway(host 网络,自动重启)。挂载外部配置目录即可热更。
set -euo pipefail

cd "$(dirname "$0")"

NAME="${NAWAY_CONTAINER_NAME:-${GATEWAY_CONTAINER_NAME:-naway}}"
IMAGE="${NAWAY_IMAGE:-${GATEWAY_IMAGE:-naway}}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
# 运行容器以 /etc/naway 为配置根，仍可挂载旧部署的宿主配置目录。
CONFIG_DIR="${NAWAY_CONFIG_DIR:-${GATEWAY_CONFIG_DIR:-/etc/naway}}"
if [ -z "${NAWAY_CONFIG_DIR:-${GATEWAY_CONFIG_DIR:-}}" ] && [ ! -d "$CONFIG_DIR" ] && [ -d /data/naway ]; then
  CONFIG_DIR=/data/naway
fi

DOCKER_ARGS=(
  -d
  --restart=always
  --name "$NAME"
  --network host
)

# 目录不存在时使用镜像内置配置。
if [ -d "$CONFIG_DIR" ]; then
  DOCKER_ARGS+=(-v "$CONFIG_DIR:/etc/naway")
fi

"$DOCKER_BIN" rm -f "$NAME" >/dev/null 2>&1 || true
"$DOCKER_BIN" run "${DOCKER_ARGS[@]}" "$IMAGE"
echo "Naway started as container '$NAME' (host network)."
