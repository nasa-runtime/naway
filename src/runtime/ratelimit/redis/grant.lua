-- 批次只是共享桶的预扣凭据；所有节点的未结算总额共同受同一个上限约束。
local cap = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local max_active = tonumber(ARGV[3])
local overflow = tonumber(ARGV[4])
local member = ARGV[5]
local owner_limit = tonumber(ARGV[6])
local batch = tonumber(ARGV[7])
local lease_ms = tonumber(ARGV[8])
local bound = tonumber(ARGV[9])
local policy = ARGV[10]
local id = ARGV[11]
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = math.ceil(cap / refill * 1000) + 1000
local entries = redis.call('HGETALL', KEYS[4])
local outstanding = 0
local count = 0
for i = 1, #entries, 2 do
    if string.sub(entries[i], 1, 1) ~= '@' then
        local amount, expiry = string.match(entries[i + 1], '^(%d+):(%d+)$')
        if not amount or not expiry then
            return redis.error_reply('invalid preallocation ledger')
        end
        if tonumber(expiry) <= now then
            -- 崩溃节点的实际消耗未知，过期只撤销权威，不猜测退款。
            redis.call('HDEL', KEYS[4], entries[i])
        else
            outstanding = outstanding + tonumber(amount)
            count = count + 1
        end
    end
end
-- 旧策略权威未到期前不混用新补充速率；更低上限不会追认旧额度为新额度。
if count > 0 and redis.call('HGET', KEYS[4], '@policy') ~= policy then
    return {
        0,
        0,
        0
    }
end
local existing = redis.call('HGET', KEYS[4], id)
if existing then
    local amount = string.match(existing, '^(%d+):')
    return {
        1,
        tonumber(amount),
        0
    }
end
if count >= 64 or outstanding >= bound then
    return {
        0,
        0,
        0
    }
end
if owner_limit > 0 then
    redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
    local needed = 0
    if not redis.call('ZSCORE', KEYS[3], KEYS[1]) then
        needed = needed + 1
    end
    if not redis.call('ZSCORE', KEYS[3], KEYS[4]) then
        needed = needed + 1
    end
    -- 桶和批次账本都计入工作区硬预算，任何放行策略都不能绕过。
    if redis.call('ZCARD', KEYS[3]) + needed > owner_limit then
        return {
            0,
            0,
            0
        }
    end
end
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now - ttl)
if not redis.call('ZSCORE', KEYS[2], member) and redis.call('ZCARD', KEYS[2]) >= max_active then
    if overflow == 1 then
        return {
            2,
            0,
            0
        }
    end
    return {
        0,
        0,
        0
    }
end
local state = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(state[1]) or cap
local timestamp = tonumber(state[2]) or now
tokens = math.min(cap, tokens + math.max(0, now - timestamp) * refill / 1000)
local grant = math.min(batch, bound - outstanding, math.max(0, math.floor(tokens)))
if grant < 1 then
    return {
        0,
        0,
        0
    }
end
-- 共享扣减、活动维度与批次权威在同一 slot 原子发布，不能先开放本地额度。
redis.call('HSET', KEYS[1], 'tokens', tokens - grant, 'ts', now)
redis.call('PEXPIRE', KEYS[1], ttl)
redis.call('HSET', KEYS[4], '@policy', policy, '@cap', cap, '@refill', refill,
    id, string.format('%.0f:%.0f', grant, now + lease_ms))
redis.call('PEXPIRE', KEYS[4], ttl)
redis.call('ZADD', KEYS[2], now, member)
redis.call('PEXPIRE', KEYS[2], ttl + 1000)
if owner_limit > 0 then
    redis.call('ZADD', KEYS[3], now + ttl, KEYS[1], now + ttl, KEYS[4])
    if redis.call('PTTL', KEYS[3]) < ttl + 1000 then
        redis.call('PEXPIRE', KEYS[3], ttl + 1000)
    end
end
return {
    1,
    grant,
    math.max(0,
    math.floor(tokens - grant))
}
