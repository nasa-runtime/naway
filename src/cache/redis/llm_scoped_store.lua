-- 精确响应与可选索引共用工作区硬容量；先预留全部名额，避免仅提交半份缓存。
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local ttl = tonumber(ARGV[1])
local wanted = 0
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
if not redis.call('ZSCORE', KEYS[3], KEYS[1]) then
    wanted = wanted + 1
end
if ARGV[4] ~= '' and not redis.call('ZSCORE', KEYS[3], KEYS[2]) then
    wanted = wanted + 1
end
if redis.call('ZCARD', KEYS[3]) + wanted > tonumber(ARGV[2]) then
    return 0
end
redis.call('SET', KEYS[1], ARGV[3], 'PX', ttl)
redis.call('ZADD', KEYS[3], now + ttl, KEYS[1])
if ARGV[4] ~= '' then
    redis.call('LPUSH', KEYS[2], ARGV[4])
    redis.call('LTRIM', KEYS[2], 0, tonumber(ARGV[5]) - 1)
    redis.call('PEXPIRE', KEYS[2], ttl)
    redis.call('ZADD', KEYS[3], now + ttl, KEYS[2])
end
if redis.call('PTTL', KEYS[3]) < ttl + 1000 then
    redis.call('PEXPIRE', KEYS[3], ttl + 1000)
end
return 1
