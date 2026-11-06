CREATE TABLE naway_material_execution_schema (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    shape JSONB NOT NULL
);

CREATE TABLE naway_material_execution_fence (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    cluster_id TEXT COLLATE "C" NOT NULL REFERENCES naway_material_impact_owners(cluster_id),
    store_id TEXT COLLATE "C" NOT NULL CHECK (store_id ~ '^[0-9a-f]{64}$'),
    watermark BIGINT NOT NULL DEFAULT 0 CHECK (watermark >= 0),
    UNIQUE (cluster_id, store_id)
);

-- 业务作用：材料共享执行域只登记一次永久身份，水位只能保持或递增一次，不借配置执行计数授权。
-- 参数说明: 无；OLD 和 NEW 是数据库当前永久执行权威。
-- 返回：合法首次登记或同域单调后继继续；删除、换域、跳号和回退拒绝。
CREATE FUNCTION naway_material_execution_preserve_fence() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'material execution authority cannot be removed' USING ERRCODE = 'PN010';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.watermark <> 0 OR NOT EXISTS (
            SELECT 1 FROM naway_operation_namespace WHERE singleton AND cluster_id = NEW.cluster_id
        ) THEN
            RAISE EXCEPTION 'material execution namespace differs' USING ERRCODE = 'PN010';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.singleton, NEW.cluster_id, NEW.store_id)
        IS DISTINCT FROM ROW(OLD.singleton, OLD.cluster_id, OLD.store_id)
        OR NEW.watermark < OLD.watermark OR NEW.watermark::numeric > OLD.watermark::numeric + 1 THEN
        RAISE EXCEPTION 'material execution fence successor differs' USING ERRCODE = 'PN010';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER naway_material_execution_fence_change BEFORE INSERT OR UPDATE OR DELETE
    ON naway_material_execution_fence FOR EACH ROW EXECUTE FUNCTION naway_material_execution_preserve_fence();
CREATE TRIGGER naway_material_execution_fence_truncate BEFORE TRUNCATE
    ON naway_material_execution_fence FOR EACH STATEMENT EXECUTE FUNCTION naway_material_execution_preserve_fence();
