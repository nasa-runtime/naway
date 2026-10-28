-- 严格登记只信任服务器时间；所有写权限与类型先复验，拒绝不得留下半份占位。
local ttl, limit, expires = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
if #KEYS ~= 2 or #ARGV ~= 3 or not ttl or ttl < 1 or ttl > 310000 or ttl ~= math.floor(ttl)
    or not expires or expires < 1 or expires >= 9007199254740992 or expires ~= math.floor(expires)
    or not limit or limit < 1 or limit > 4000000 or limit ~= math.floor(limit) then
    return redis.error_reply('invalid strict replay bounds')
end
local nonce_type, index_type = redis.call('TYPE', KEYS[1]).ok, redis.call('TYPE', KEYS[2]).ok
if (nonce_type ~= 'none' and nonce_type ~= 'string') or (index_type ~= 'none' and index_type ~= 'zset') then
    return redis.error_reply('invalid strict replay state type')
end
if redis.call('EXISTS', KEYS[1]) == 1 then
    return 0
end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
-- 所有节点在共享时钟上复验同一截止时间，慢时钟节点不能在消费证据回收后重新接受旧 nonce。
if expires <= now or expires > now + ttl - 1000 then
    return 0
end
if not redis.acl_check_cmd
    or not redis.acl_check_cmd('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
    or not redis.acl_check_cmd('ZADD', KEYS[2], now + ttl, KEYS[1])
    or not redis.acl_check_cmd('PEXPIRE', KEYS[2], ttl + 1000)
    or not redis.acl_check_cmd('SET', KEYS[1], '1', 'PX', ttl) then
    return redis.error_reply('strict replay write authority unavailable')
end
local count = redis.call('ZCARD', KEYS[2]) - redis.call('ZCOUNT', KEYS[2], '-inf', now)
if count >= limit then
    return 0
end
local remaining = redis.call('PTTL', KEYS[2])
-- 先完成全部可能拒绝的检查，再发布 nonce 与容量证据；仅过期记录可回收。
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
redis.call('SET', KEYS[1], '1', 'PX', ttl)
redis.call('ZADD', KEYS[2], now + ttl, KEYS[1])
if remaining < ttl + 1000 then
    redis.call('PEXPIRE', KEYS[2], ttl + 1000)
end
return 1
