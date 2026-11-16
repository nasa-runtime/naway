-- 过期清理仅拥有读取原值的删除权；续期或重新封禁后必须保留新事实。
if redis.call('HGET', KEYS[1], ARGV[1]) ~= ARGV[2] then
    return 0
end
return redis.call('HDEL', KEYS[1], ARGV[1])
