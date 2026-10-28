-- 正文和剩余 TTL 来自同一读视图；超大共享实体直接淘汰，不下载到数据面。
local n = redis.call('STRLEN', KEYS[1]);
if n == 0 then
    return {
        false,
        -2
    }
end;
if n > tonumber(ARGV[1]) then
    redis.call('DEL', KEYS[1]);
    return {
        false,
        -2
    }
end;
return {
    redis.call('GET', KEYS[1]),
    redis.call('PTTL', KEYS[1])
}
