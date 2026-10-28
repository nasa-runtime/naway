-- 时间分桶只保留窗口内事实，单次提交同时汇总并淘汰过期桶。
local key = KEYS[1]
local ok = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local bucket_ms = tonumber(ARGV[3])
local t = redis.call('TIME')
local now_ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local ttl = window_ms + bucket_ms * 2
if KEYS[2] then
    redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms)
    -- 无法获得工作区状态名额时返回拒绝标记，不能把未记录事件伪装成零失败。
    if not redis.call('ZSCORE', KEYS[2], key) and redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[4]) then
        return {
            -1,
            -1
        }
    end
    redis.call('ZADD', KEYS[2], now_ms + ttl, key)
    if redis.call('PTTL', KEYS[2]) < ttl + 1000 then
        redis.call('PEXPIRE', KEYS[2], ttl + 1000)
    end
end
local cur = math.floor(now_ms / bucket_ms)
local min_bucket = cur - math.ceil(window_ms / bucket_ms)
redis.call('HINCRBY', key, 't:' .. cur, 1)
if ok == 0 then
    redis.call('HINCRBY', key, 'f:' .. cur, 1)
end
redis.call('PEXPIRE', key, ttl)
local total = 0
local fails = 0
local data = redis.call('HGETALL', key)
for i = 1, #data, 2 do
    local name = data[i]
    local val = tonumber(data[i + 1]) or 0
    local colon = string.find(name, ':')
    local b = tonumber(string.sub(name, colon + 1))
    if b == nil or b <= min_bucket then
        redis.call('HDEL', key, name)
    else
        local kind = string.sub(name, 1, colon - 1)
        if kind == 't' then
            total = total + val
        elseif kind == 'f' then
            fails = fails + val
        end
    end
end
return {
    total,
    fails
}
