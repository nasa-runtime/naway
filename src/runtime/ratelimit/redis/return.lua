-- 调用方必须先撤下本地凭据；只有仍有效且策略相同的唯一批次能归还已知未用余额。
local value = redis.call('HGET', KEYS[2], ARGV[1])
if not value or redis.call('HGET', KEYS[2], '@policy') ~= ARGV[3] then
    return 0
end
local granted, expiry = string.match(value, '^(%d+):(%d+)$')
if not granted or not expiry then
    return redis.error_reply('invalid preallocation ledger')
end
local unused = tonumber(ARGV[2])
if not unused or unused < 0 or unused > tonumber(granted) then
    return redis.error_reply('invalid preallocation return')
end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
redis.call('HDEL', KEYS[2], ARGV[1])
if tonumber(expiry) <= now or unused == 0 then
    return 0
end
local state = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(state[1])
local timestamp = tonumber(state[2])
-- 桶已消失时不创建新余额，避免退款把重建后的满桶再次充值。
if not tokens or not timestamp then
    return 0
end
local cap = tonumber(redis.call('HGET', KEYS[2], '@cap'))
local refill = tonumber(redis.call('HGET', KEYS[2], '@refill'))
tokens = math.min(cap, tokens + math.max(0, now - timestamp) * refill / 1000 + unused)
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
return unused
