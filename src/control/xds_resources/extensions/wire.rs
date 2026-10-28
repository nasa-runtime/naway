use super::super::*;
use super::ECDS_TYPE_URL;

#[derive(Clone, PartialEq, Message)]
pub(in crate::control::xds_resources) struct ExtensionConfigSource {
    #[prost(message, optional, tag = "1")]
    config_source: Option<ConfigSource>,
    #[prost(string, repeated, tag = "4")]
    type_urls: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
struct TypedExtensionConfig {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "2")]
    typed_config: Option<Any>,
}

/// 业务作用：只允许当前 ADS 下的显式 Router 类型订阅，不允许默认配置跳过初始权威确认。
///
/// 参数说明：
/// - `bytes`：HttpFilter.config_discovery 的原始 protobuf 字节。
///
/// 返回：唯一 ADS 来源与类型字段通过；默认配置、超时、其它来源或未知字段拒绝。
pub(in crate::control::xds_resources) fn validate_source_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "ExtensionConfigSource.config_source")?;
            validate_config_source_wire(expect_bytes(value, "ExtensionConfigSource.config_source")?)
        }
        4 => expect_bytes(value, "ExtensionConfigSource.type_urls").map(|_| ()),
        other => bail!("unsupported ExtensionConfigSource field {other}"),
    })
}

/// 业务作用：将 HCM 的唯一终结器绑定静态 Router 或一个必须取得证明的命名 ECDS 资源。
///
/// 参数说明：
/// - `filter`：通过原始字段白名单的 HTTP filter。
///
/// 返回：静态空 Router 返回 None；合法命名订阅返回资源名；缺少配置或类型集合不精确时拒绝。
pub(in crate::control::xds_resources) fn translate_filter(
    filter: &HttpFilter,
) -> Result<Option<String>> {
    let Some(source) = &filter.config_discovery else {
        validate_static_router(filter)?;
        return Ok(None);
    };
    // 扩展名只标识订阅；实际执行器必须由精确 type_url 决定，不能由名字猜测或动态加载。
    anyhow::ensure!(
        filter.typed_config.is_none(),
        "HttpFilter has conflicting config sources"
    );
    validate_resource_name(&filter.name, "ECDS filter name")?;
    anyhow::ensure!(
        matches!(
            source
                .config_source
                .as_ref()
                .and_then(|source| source.config_source_specifier.as_ref()),
            Some(config_source::ConfigSourceSpecifier::Ads(_))
        ),
        "ECDS must use the current ADS source"
    );
    anyhow::ensure!(
        source.type_urls == [ROUTER_FILTER_TYPE_URL],
        "ECDS type_urls must contain only v3 Router"
    );
    Ok(Some(filter.name.clone()))
}

/// 业务作用：整批验证 ECDS 资源，只有无附加执行语义的空 Router 才能成为 listener 权威。
///
/// 参数说明：
/// - `resources`：同一 response 或 Delta 缓存中的全部正文。
/// - `allowed`：当前 LDS 派生的有界命名订阅。
/// - `limits`：bootstrap 的字节与资源数量硬预算。
///
/// 返回：全部资源通过后给出证明名集合；任何重复、未订阅、未知字段或执行器类型使整批拒绝。
pub(crate) fn translate_resources(
    resources: &[Any],
    allowed: &BTreeSet<String>,
    limits: &XdsLimitsCfg,
) -> Result<BTreeSet<String>> {
    ensure_resource_budget(resources, limits, "ECDS")?;
    let mut names = BTreeSet::new();
    for resource in resources {
        anyhow::ensure!(
            resource.type_url == ECDS_TYPE_URL,
            "ECDS Any type_url mismatch"
        );
        let mut singular = HashSet::new();
        walk_fields(&resource.value, |field, value| {
            mark_singular(&mut singular, field, "TypedExtensionConfig field")?;
            match field {
                1 => expect_bytes(value, "TypedExtensionConfig.name").map(|_| ()),
                2 => validate_any_wire(expect_bytes(value, "TypedExtensionConfig.typed_config")?),
                other => bail!("unsupported TypedExtensionConfig field {other}"),
            }
        })?;
        let extension = TypedExtensionConfig::decode(resource.value.as_slice())
            .context("decode ECDS resource")?;
        validate_resource_name(&extension.name, "ECDS resource name")?;
        anyhow::ensure!(
            allowed.contains(&extension.name),
            "ECDS resource is not subscribed"
        );
        let typed = extension
            .typed_config
            .context("ECDS typed_config is required")?;
        // 空 Router 与已有路由执行器等价；TypedStruct、Wasm、Lua 或任何额外参数都不能降级忽略。
        anyhow::ensure!(
            typed.type_url == ROUTER_FILTER_TYPE_URL && typed.value.is_empty(),
            "ECDS supports only an empty v3 Router"
        );
        anyhow::ensure!(names.insert(extension.name), "duplicate ECDS resource name");
    }
    Ok(names)
}
