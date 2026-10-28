-- 先检查重放与工作区硬容量，再原子占位；拒绝不能产生新的有效 nonce。
if redis.call('EXISTS', KEYS[1]) == 1 then
    return 0
end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local ttl = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
if redis.call('ZSCORE', KEYS[2], KEYS[1]) == false and redis.call('ZCARD', KEYS[2]) >= limit then
    return 0
end
redis.call('ZADD', KEYS[2], now + ttl, KEYS[1])
if redis.call('PTTL', KEYS[2]) < ttl + 1000 then
    redis.call('PEXPIRE', KEYS[2], ttl + 1000)
end
redis.call('SET', KEYS[1], '1', 'PX', ttl)
return 1
