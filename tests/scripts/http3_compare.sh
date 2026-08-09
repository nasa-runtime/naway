#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
image_name=${H3_IMAGE_NAME:-naway:h3-benchmark}
envoy_image=${H3_ENVOY_IMAGE:-envoyproxy/envoy:v1.35.3}
rounds=${H3_ROUNDS:-7}
requests=${H3_REQUESTS:-100000}
concurrency=${H3_CONCURRENCY:-64}
connections=${H3_CONNECTIONS:-8}
warmup=${H3_WARMUP:-5000}
max_cv=${H3_MAX_CV:-0.15}
min_ratio=${H3_MIN_RELATIVE_RPS:-0.90}
max_p99_ratio=${H3_MAX_P99_RATIO:-1.10}
report=${H3_REPORT:-$repo_dir/target/http3-envoy-formal.jsonl}
docker_cpus=$(docker info --format '{{.NCPU}}')
if [[ "$docker_cpus" -lt 10 ]]; then
  echo "HTTP/3 formal benchmark requires at least 10 Docker CPUs for backend/proxy/client isolation" >&2
  exit 2
fi
backend_cpuset=${H3_BACKEND_CPUSET:-0}
proxy_cpuset=${H3_PROXY_CPUSET:-1-5}
client_cpuset=${H3_CLIENT_CPUSET:-6-9}
proxy_workers=${H3_PROXY_WORKERS:-5}
run_id="$$-$(date +%s)"
network_name="naway-h3-bench-$run_id"
backend_name="naway-h3-backend-$run_id"
gateway_name="naway-h3-gateway-$run_id"
envoy_name="naway-h3-envoy-$run_id"
bench_tmp=$(mktemp -d "${TMPDIR:-/tmp}/naway-h3-bench.XXXXXX")

# 业务作用：无论脚本成功或失败，都只停止本轮精确命名的容器并回收专用 network，避免
# 端口、CPU 和 Docker DNS 状态污染下一轮；不匹配或删除用户其他容器。
cleanup() {
  local exit_code=$?
  if [[ "$exit_code" -ne 0 ]]; then
    echo "HTTP/3 benchmark failed; scoped container diagnostics follow" >&2
    docker logs "$gateway_name" 2>&1 | tail -80 >&2 || true
    docker logs "$envoy_name" 2>&1 | tail -80 >&2 || true
    docker logs "$backend_name" 2>&1 | tail -80 >&2 || true
  fi
  docker stop "$gateway_name" "$envoy_name" "$backend_name" >/dev/null 2>&1 || true
  docker rm "$gateway_name" "$envoy_name" "$backend_name" >/dev/null 2>&1 || true
  docker network rm "$network_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# 业务作用：计算奇数轮样本的中位数，正式门使用中位而不是最好一轮，抵抗单次调度噪声。
median() {
  sort -n | awk '{ values[NR]=$1 } END { if (NR % 2) print values[(NR+1)/2]; else print (values[NR/2]+values[NR/2+1])/2 }'
}

# 业务作用：计算样本总体变异系数；超过稳定线时必须判 INCONCLUSIVE，禁止引用偶然比例。
coefficient_of_variation() {
  awk '{ n+=1; sum+=$1; square+=$1*$1 } END { if (n == 0 || sum == 0) exit 2; mean=sum/n; variance=square/n-mean*mean; if (variance < 0) variance=0; printf "%.6f\n", sqrt(variance)/mean }'
}

if [[ "$rounds" -lt 7 || $((rounds % 2)) -eq 0 ]]; then
  echo "H3_ROUNDS must be an odd number >= 7" >&2
  exit 2
fi
if [[ "$connections" -lt 1 || "$connections" -gt "$concurrency" ]]; then
  echo "H3_CONNECTIONS must be between 1 and H3_CONCURRENCY" >&2
  exit 2
fi

source_fingerprint=$(git -C "$repo_dir" status --short | shasum -a 256 | awk '{print $1}')
if [[ "${H3_REBUILD:-0}" == "1" ]] || ! docker image inspect "$image_name" >/dev/null 2>&1; then
  docker build \
    --build-arg "NAWAY_SOURCE_FINGERPRINT=$source_fingerprint" \
    -f "$repo_dir/tests/Dockerfile.h3-benchmark" \
    -t "$image_name" \
    "$repo_dir/.."
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$bench_tmp/ca.key" \
  -out "$bench_tmp/ca.crt" \
  -days 1 -subj "/CN=Naway H3 Benchmark CA" \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$bench_tmp/server.key" \
  -out "$bench_tmp/server.csr" \
  -subj /CN=localhost >/dev/null 2>&1
cat >"$bench_tmp/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
EOF
openssl x509 -req -in "$bench_tmp/server.csr" \
  -CA "$bench_tmp/ca.crt" -CAkey "$bench_tmp/ca.key" -CAcreateserial \
  -out "$bench_tmp/server.crt" -days 1 -extfile "$bench_tmp/server.ext" >/dev/null 2>&1

cat >"$bench_tmp/interface-guard.yml" <<'YAML'
schema_version: 1
rules: []
YAML

cat >"$bench_tmp/sentinel-rules.yml" <<'YAML'
schema_version: 1
flow: []
degrade: []
YAML

cat >"$bench_tmp/gateway.yml" <<'YAML'
schema_version: 1
admin:
  listen: "127.0.0.1:9901"
  expose_metrics: true
interface_guard_file: "/work/interface-guard.yml"
sentinel_rules_file: "/work/sentinel-rules.yml"
access_log:
  enabled: false
proxies:
  - id: h3-benchmark
    listen: "0.0.0.0:8080"
    tls:
      listen: "0.0.0.0:8443"
      cert_file: "/work/server.crt"
      key_file: "/work/server.key"
    http3:
      enabled: true
      advertise_alt_svc: false
      retry: off
      max_connections: 4096
      max_connections_per_ip: 4096
      max_pending_handshakes: 1024
      max_pending_handshake_bytes: 16384
      max_bidi_streams_per_connection: 512
      max_request_header_bytes: 16384
      max_stream_buffer_bytes: 65536
    limits:
      upstream_pending_limit: 10000
      pool_max_per_upstream: 1024
      pool_max_connections_per_upstream: 1024
      keepalive_requests: 0
    routes:
      - id: benchmark
        uri: "lb://backend"
        predicates: ["Path=/"]
upstreams:
  services:
    backend:
      protocol: h1
      instances:
        - uri: "http://h3-backend:8080"
YAML

cat >"$bench_tmp/envoy.yaml" <<'YAML'
admin:
  address:
    socket_address: { protocol: TCP, address: 0.0.0.0, port_value: 9901 }
static_resources:
  listeners:
    - name: listener_udp
      address:
        socket_address: { protocol: UDP, address: 0.0.0.0, port_value: 8443 }
      udp_listener_config:
        quic_options: {}
        downstream_socket_config: { prefer_gro: true }
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.quic
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.quic.v3.QuicDownstreamTransport
              downstream_tls_context:
                common_tls_context:
                  tls_certificates:
                    - certificate_chain: { filename: /work/server.crt }
                      private_key: { filename: /work/server.key }
          filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                codec_type: HTTP3
                stat_prefix: ingress_http
                route_config:
                  name: benchmark
                  virtual_hosts:
                    - name: benchmark
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route: { cluster: backend }
                http3_protocol_options: {}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: backend
      connect_timeout: 3s
      type: STRICT_DNS
      dns_lookup_family: V4_ONLY
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: h3-backend, port_value: 8080 }
YAML

docker run --rm -v "$bench_tmp:/work:ro" "$envoy_image" \
  envoy --mode validate -c /work/envoy.yaml >/dev/null
docker network create "$network_name" >/dev/null
docker run -d --name "$backend_name" --network "$network_name" --network-alias h3-backend \
  --cpuset-cpus "$backend_cpuset" \
  "$image_name" local_h3_benchmark backend --listen 0.0.0.0:8080 >/dev/null
docker run -d --name "$gateway_name" --network "$network_name" --network-alias naway-h3 \
  --cpuset-cpus "$proxy_cpuset" -v "$bench_tmp:/work:ro" "$image_name" \
  naway --config /work/gateway.yml data >/dev/null
docker run -d --name "$envoy_name" --network "$network_name" --network-alias envoy-h3 \
  --cpuset-cpus "$proxy_cpuset" -v "$bench_tmp:/work:ro" "$envoy_image" \
  envoy -c /work/envoy.yaml --concurrency "$proxy_workers" --log-level warning >/dev/null

sleep 2
for readiness_attempt in $(seq 1 100); do
  if docker exec "$gateway_name" /usr/local/bin/local_h3_benchmark client \
    --target naway-h3:8443 --server-name localhost --ca /work/ca.crt \
    --requests 1 --concurrency 1 --connections 1 --warmup 1 --label readiness >/dev/null 2>&1 \
    && docker exec "$gateway_name" /usr/local/bin/local_h3_benchmark client \
      --target envoy-h3:8443 --server-name localhost --ca /work/ca.crt \
      --requests 1 --concurrency 1 --connections 1 --warmup 1 --label readiness >/dev/null 2>&1; then
    break
  fi
  if [[ "$readiness_attempt" -eq 100 ]]; then
    echo "HTTP/3 benchmark proxies did not become ready" >&2
    docker exec "$gateway_name" /usr/local/bin/local_h3_benchmark client \
      --target naway-h3:8443 --server-name localhost --ca /work/ca.crt \
      --requests 1 --concurrency 1 --connections 1 --warmup 1 --label readiness >&2 || true
    docker exec "$gateway_name" /usr/local/bin/local_h3_benchmark client \
      --target envoy-h3:8443 --server-name localhost --ca /work/ca.crt \
      --requests 1 --concurrency 1 --connections 1 --warmup 1 --label readiness >&2 || true
    exit 1
  fi
  sleep 0.1
done
mkdir -p "$(dirname "$report")"
: >"$report"

# 业务作用：运行单个实现的一轮独立 client container；计时在进程内部握手/预热后开始，
# container startup 不进样本，JSON 只有请求全部完成才写入正式报告。
run_case() {
  local label=$1
  local target=$2
  local round=$3
  local result
  result=$(docker run --rm --network "$network_name" --cpuset-cpus "$client_cpuset" \
    -v "$bench_tmp:/work:ro" \
    "$image_name" local_h3_benchmark client \
    --target "$target:8443" --server-name localhost --ca /work/ca.crt \
    --requests "$requests" --concurrency "$concurrency" --connections "$connections" \
    --warmup "$warmup" --label "$label")
  jq -c --argjson round "$round" '. + {round: $round}' <<<"$result" | tee -a "$report"
}

for round in $(seq 1 "$rounds"); do
  if (( round % 2 == 1 )); then
    run_case naway naway-h3 "$round"
    run_case envoy envoy-h3 "$round"
  else
    run_case envoy envoy-h3 "$round"
    run_case naway naway-h3 "$round"
  fi
done

naway_rps=$(jq -r 'select(.label == "naway") | .rps' "$report")
envoy_rps=$(jq -r 'select(.label == "envoy") | .rps' "$report")
naway_p99=$(jq -r 'select(.label == "naway") | .p99_us' "$report")
envoy_p99=$(jq -r 'select(.label == "envoy") | .p99_us' "$report")
naway_median_rps=$(median <<<"$naway_rps")
envoy_median_rps=$(median <<<"$envoy_rps")
naway_cv=$(coefficient_of_variation <<<"$naway_rps")
envoy_cv=$(coefficient_of_variation <<<"$envoy_rps")
naway_median_p99=$(median <<<"$naway_p99")
envoy_median_p99=$(median <<<"$envoy_p99")
ratio=$(awk -v gateway="$naway_median_rps" -v envoy="$envoy_median_rps" 'BEGIN { printf "%.6f", gateway/envoy }')
p99_ratio=$(awk -v gateway="$naway_median_p99" -v envoy="$envoy_median_p99" 'BEGIN { printf "%.6f", gateway/envoy }')

jq -n \
  --argjson rounds "$rounds" \
  --argjson connections "$connections" \
  --argjson naway_median_rps "$naway_median_rps" \
  --argjson envoy_median_rps "$envoy_median_rps" \
  --argjson ratio "$ratio" \
  --argjson naway_cv "$naway_cv" \
  --argjson envoy_cv "$envoy_cv" \
  --argjson naway_median_p99_us "$naway_median_p99" \
  --argjson envoy_median_p99_us "$envoy_median_p99" \
  --argjson p99_ratio "$p99_ratio" \
  '{summary: {rounds: $rounds, connections: $connections, naway_median_rps: $naway_median_rps, envoy_median_rps: $envoy_median_rps, ratio: $ratio, naway_cv: $naway_cv, envoy_cv: $envoy_cv, naway_median_p99_us: $naway_median_p99_us, envoy_median_p99_us: $envoy_median_p99_us, p99_ratio: $p99_ratio}}' \
  | tee -a "$report"

awk \
  -v naway_cv="$naway_cv" -v envoy_cv="$envoy_cv" -v max_cv="$max_cv" \
  -v ratio="$ratio" -v min_ratio="$min_ratio" \
  -v p99_ratio="$p99_ratio" -v max_p99_ratio="$max_p99_ratio" \
  'BEGIN {
    if (naway_cv > max_cv || envoy_cv > max_cv) {
      print "HTTP/3 benchmark INCONCLUSIVE: sample CV exceeds stability gate" > "/dev/stderr";
      exit 3;
    }
    if (ratio < min_ratio || p99_ratio > max_p99_ratio) {
      print "HTTP/3 benchmark FAIL: throughput or p99 gate missed" > "/dev/stderr";
      exit 4;
    }
    print "HTTP/3 benchmark PASS";
  }'
