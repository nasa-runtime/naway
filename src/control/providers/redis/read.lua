-- 配置来源只有只读权威；长度与正文同次读取，超限不删除共享声明。
local n = redis.call('STRLEN', KEYS[1]);
if n == 0 then
    return nil
end;
if n > tonumber(ARGV[1]) then
    return redis.error_reply('provider document too large')
end;
return redis.call('GET', KEYS[1])
