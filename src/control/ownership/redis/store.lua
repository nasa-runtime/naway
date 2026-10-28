-- 工作区容量索引与实体同 slot 原子发布，容量拒绝不得留下无归属的实体。
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local ttl = tonumber(ARGV[1])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
if not redis.call('ZSCORE', KEYS[2], KEYS[1]) and redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[2]) then
    return 0
end
redis.call('SET', KEYS[1], ARGV[3], 'PX', ttl)
redis.call('ZADD', KEYS[2], now + ttl, KEYS[1])
if redis.call('PTTL', KEYS[2]) < ttl + 1000 then
    redis.call('PEXPIRE', KEYS[2], ttl + 1000)
end
return 1
