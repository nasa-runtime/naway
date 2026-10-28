-- 过期或已经归零的计数按无占用处理，释放不产生负数名额。
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
if current <= 1 then
    redis.call('DEL', KEYS[1])
    return 0
end
current = redis.call('DECR', KEYS[1])
return current
