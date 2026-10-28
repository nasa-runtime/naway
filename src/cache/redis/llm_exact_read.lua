-- 超大共享响应按未命中处理，实体检查与删除在 Redis 内原子完成。
local n = redis.call('STRLEN', KEYS[1]);
if n == 0 then
    return false
end;
if n > tonumber(ARGV[1]) then
    redis.call('DEL', KEYS[1]);
    return false
end;
return redis.call('GET', KEYS[1])
