-- 共享令牌以 Redis 时钟补充，不依赖不同网关节点的时钟一致性。
local cap = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local max_active = tonumber(ARGV[3])
local overflow_allowed = tonumber(ARGV[4])
local member = ARGV[5]
local cost = tonumber(ARGV[6])
local warmup_ms = tonumber(ARGV[8]) or 0
local cold_factor = tonumber(ARGV[9]) or 1
local cold_after_ms = tonumber(ARGV[10]) or 0
if warmup_ms ~= 0 and (warmup_ms < 1 or warmup_ms > 600000 or cold_factor < 2 or cold_factor > 1000 or cold_after_ms < 1 or cold_after_ms > 600000 or cost ~= 1) then
    return {
        0,
        0
    }
end
if cap == nil or refill == nil or cost == nil or cap <= 0 or refill <= 0 or cost <= 0 then
    return {
        1,
        9223372036854775807
    }
end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local ttl = math.ceil((cap / refill) * 1000) + 1000
if warmup_ms > 0 then
    ttl = math.max(ttl, warmup_ms + cold_after_ms)
end
local owner_limit = tonumber(ARGV[7]) or 0
if owner_limit > 0 then
    redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
    -- 工作区硬容量不能由流控规则的溢出放行策略绕过。
    if redis.call('ZSCORE', KEYS[3], KEYS[1]) == false and redis.call('ZCARD', KEYS[3]) >= owner_limit then
        return {
            0,
            0
        }
    end
end
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now - ttl)
-- 只对新维度执行活动键准入，既有维度继续使用同一余额，避免容量抖动重置额度。
if redis.call('ZSCORE', KEYS[2], member) == false then
    if max_active == nil or max_active <= 0 or redis.call('ZCARD', KEYS[2]) >= max_active then
        if overflow_allowed == 1 then
            return {
                1,
                9223372036854775807
            }
        end
        return {
            0,
            0
        }
    end
end
if owner_limit > 0 then
    redis.call('ZADD', KEYS[3], now + ttl, KEYS[1])
    if redis.call('PTTL', KEYS[3]) < ttl + 1000 then
        redis.call('PEXPIRE', KEYS[3], ttl + 1000)
    end
end
redis.call('ZADD', KEYS[2], now, member)
redis.call('PEXPIRE', KEYS[2], ttl + 1000)
local st
if warmup_ms > 0 then
    st = redis.call('HMGET', KEYS[1], 'tokens', 'ts', 'warm_start')
else
    st = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
end
local tokens = tonumber(st[1])
local ts = tonumber(st[2])
local warm_start = tonumber(st[3]) or now
if tokens == nil then
    tokens = cap
end
if ts == nil then
    ts = now
end
if warmup_ms > 0 then
    local cold_cap = math.max(1, cap / cold_factor)
    -- 首次出现或连续空闲时先恢复冷态容量，不能把等待期间当作已完成预热。
    if st[1] == false or now - ts >= cold_after_ms then
        warm_start = now
        ts = now
        tokens = math.min(tokens, cold_cap)
    end
    -- 时钟回退不产生额度；恢复后仍从最后一次已观察时刻继续推进。
    now = math.max(now, ts)
    local previous = math.max(0, ts - warm_start)
    local elapsed = math.max(0, now - warm_start)
    local a = math.min(previous, warmup_ms)
    local b = math.max(a, math.min(elapsed, warmup_ms))
    local cold = 1 / cold_factor
    local ramp = (b - a) * (cold + (1 - cold) * (a + b) / (2 * warmup_ms))
    local steady = math.max(0, elapsed - warmup_ms) - math.max(0, previous - warmup_ms)
    local current_cap = math.max(1, cap * (cold + (1 - cold) * math.min(1, elapsed / warmup_ms)))
    tokens = math.min(current_cap, tokens + refill * (ramp + steady) / 1000)
elseif now > ts then
    tokens = math.min(cap, tokens + ((now - ts) / 1000.0) * refill)
end
local allowed = 0
if tokens >= cost then
    tokens = tokens - cost
    allowed = 1
end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
if warmup_ms > 0 then
    redis.call('HSET', KEYS[1], 'warm_start', warm_start)
end
redis.call('PEXPIRE', KEYS[1], ttl)
return {
    allowed,
    math.floor(tokens)
}
