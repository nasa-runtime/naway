# syntax=docker/dockerfile:1.7
# Naway 多阶段构建。产品上下文为项目目录，组件依赖从 Cargo.lock 固定的 registry 获取。
ARG NAWAY_SOURCE_FINGERPRINT=unknown
FROM rust:1-bookworm AS builder

WORKDIR /work/naway
COPY Cargo.toml Cargo.lock README.md LICENSE-APACHE LICENSE-MIT ./
COPY src ./src
COPY zcf ./zcf
# 源码 COPY 会让这一层的普通 layer cache 失效；registry/git/target 改用 BuildKit 持久 cache，
# 修改业务源码时只重编受影响 crate。target cache 不会进入最终镜像，因此同一 RUN 必须把最终
# ELF 复制到普通 layer 路径；否则下一 stage 无法 COPY cache mount 内的文件。
RUN --mount=type=cache,id=naway-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=naway-cargo-git,target=/usr/local/cargo/git/db,sharing=locked \
    --mount=type=cache,id=naway-release-target,target=/work/naway/target,sharing=locked \
    cargo build --release --locked \
    && install -m 0755 target/release/naway /work/naway-bin

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && mkdir -p /data/naway \
    && rm -rf /var/lib/apt/lists/*

# 指纹只描述业务构建上下文，不应让每次源码改动都击穿昂贵且无关的 apt layer cache。
ARG NAWAY_SOURCE_FINGERPRINT
LABEL org.opencontainers.image.title="Naway" \
      org.opencontainers.image.naway-source-fingerprint=$NAWAY_SOURCE_FINGERPRINT

COPY --from=builder /work/naway-bin /usr/local/bin/naway
# 把仓库示例配置作为镜像内置默认放进 /data/naway；挂载外部同名目录即整体覆盖。
COPY --from=builder /work/naway/zcf/ /data/naway/

# 新部署使用 Naway 品牌变量；二进制仍接受旧 GW_* 变量，供滚动迁移。
ENV NAWAY_CONFIG_DIR=/data/naway
ENV NAWAY_PIDFILE=/var/run/naway.pid
VOLUME ["/data/naway"]

# 只暴露数据面端口;管理/观测面(/healthz /readyz /metrics)绑内网 18080,不对外暴露。
EXPOSE 8080

# 健康检查打【管理面 /healthz】(容器内回环可达);数据面 8080 无 `/` 路由会 404,不能用作 healthcheck。
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS "${NAWAY_HEALTH_URL:-${GW_HEALTH_URL:-http://127.0.0.1:18080/healthz}}" >/dev/null 2>&1 || exit 1

ENTRYPOINT ["naway"]
