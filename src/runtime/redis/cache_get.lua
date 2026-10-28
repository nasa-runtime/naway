-- 同一原子读内检查长度，避免并发替换把有界读取变为超大分配。
local n = redis.call('STRLEN', KEYS[1]);
if n == 0 or n > tonumber(ARGV[1]) then
    return false
end;
return redis.call('GET', KEYS[1])
