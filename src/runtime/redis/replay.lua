-- nonce 占位与过期必须同时落地；仅首个申请获得本次请求的消费权。
if redis.call('SET', KEYS[1], '1', 'NX', 'PX', ARGV[1]) then
    return 1
else
    return 0
end
