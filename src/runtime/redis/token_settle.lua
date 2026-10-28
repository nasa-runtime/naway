-- 结算标记与余额调整属于同一原子动作，重复回执不得重复归还预扣额度。
local cap = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local reserved = tonumber(ARGV[3])
local actual = tonumber(ARGV[4])
local ledger_ttl = tonumber(ARGV[5])
if cap == nil or refill == nil or reserved == nil or actual == nil or ledger_ttl == nil
or cap <= 0 or refill <= 0 or reserved < 0 or actual < 0 or ledger_ttl <= 0 then
    return redis.error_reply('invalid token settlement arguments')
end
if redis.call('EXISTS', KEYS[2]) == 1 then
    return 0
end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local ttl = math.ceil((cap / refill) * 1000) + 1000
local owner_limit = tonumber(ARGV[6]) or 0
if owner_limit > 0 then
    redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
    local needed = 0
    if redis.call('ZSCORE', KEYS[3], KEYS[1]) == false then
        needed = needed + 1
    end
    if redis.call('ZSCORE', KEYS[3], KEYS[2]) == false then
        needed = needed + 1
    end
    -- 先确认余额和结算凭据都可驻留，不能只落其中一半而丢失幂等证据。
    if redis.call('ZCARD', KEYS[3]) + needed > owner_limit then
        return redis.error_reply('workspace settlement capacity exhausted')
    end
    redis.call('ZADD', KEYS[3], now + ttl, KEYS[1], now + ledger_ttl, KEYS[2])
    local owner_ttl = math.max(ttl, ledger_ttl) + 1000
    if redis.call('PTTL', KEYS[3]) < owner_ttl then
        redis.call('PEXPIRE', KEYS[3], owner_ttl)
    end
end
redis.call('SET', KEYS[2], '1', 'PX', ledger_ttl)
local st = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(st[1])
local ts = tonumber(st[2])
if tokens == nil then
    tokens = cap
end
if ts == nil then
    ts = now
end
if now > ts then
    tokens = math.min(cap, tokens + ((now - ts) / 1000.0) * refill)
end
tokens = math.min(cap, math.max(- cap, tokens + reserved - actual))
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('PEXPIRE', KEYS[1], ttl)
return 1
