use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct CatalogConfig {
    #[serde(alias = "maxAgeSeconds")]
    pub max_age_seconds: Option<i64>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct DenialConfig {
    #[serde(alias = "errorCode")]
    pub error_code: Option<i64>,
    #[serde(alias = "hint")]
    pub hint: Option<String>,
    #[serde(alias = "httpStatus")]
    pub http_status: Option<String>,
    #[serde(alias = "includeRequiredLevel")]
    pub include_required_level: Option<bool>,
    #[serde(alias = "revealGrantNames")]
    pub reveal_grant_names: Option<bool>,
    #[serde(alias = "style")]
    pub style: Option<String>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct Grants0Config {
    #[serde(alias = "attribute")]
    pub attribute: String,
    #[serde(alias = "level")]
    pub level: String,
}
#[derive(Deserialize, Clone, Debug)]
pub struct LimitsConfig {
    #[serde(alias = "maxBatchSize")]
    pub max_batch_size: Option<i64>,
    #[serde(alias = "maxCachedTools")]
    pub max_cached_tools: Option<i64>,
    #[serde(alias = "maxCatalogBytes")]
    pub max_catalog_bytes: Option<i64>,
    #[serde(alias = "maxCatalogs")]
    pub max_catalogs: Option<i64>,
    #[serde(alias = "maxListResponseBytes")]
    pub max_list_response_bytes: Option<i64>,
    #[serde(alias = "maxRequestBodyBytes")]
    pub max_request_body_bytes: Option<i64>,
    #[serde(alias = "maxToolNameBytes")]
    pub max_tool_name_bytes: Option<i64>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct LoggingConfig {
    #[serde(alias = "logAllowedCalls")]
    pub log_allowed_calls: Option<bool>,
    #[serde(alias = "logCallerAttributes")]
    pub log_caller_attributes: Option<bool>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct NameRules0Config {
    #[serde(alias = "class")]
    pub class: String,
    #[serde(alias = "pattern")]
    pub pattern: String,
}
#[derive(Deserialize, Clone, Debug)]
pub struct ToolOverrides0Config {
    #[serde(alias = "class")]
    pub class: String,
    #[serde(alias = "name")]
    pub name: String,
}
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "blockedTools")]
    pub blocked_tools: Option<Vec<String>>,
    #[serde(alias = "callerAttributeSeparator")]
    pub caller_attribute_separator: Option<String>,
    #[serde(
        alias = "callerAttributes",
        default,
        deserialize_with = "de_caller_attributes_0"
    )]
    pub caller_attributes: Option<pdk::script::Script>,
    #[serde(alias = "catalog")]
    pub catalog: Option<CatalogConfig>,
    #[serde(
        alias = "catalogPartition",
        default,
        deserialize_with = "de_catalog_partition_1"
    )]
    pub catalog_partition: Option<pdk::script::Script>,
    #[serde(alias = "defaultLevel")]
    pub default_level: Option<String>,
    #[serde(alias = "denial")]
    pub denial: Option<DenialConfig>,
    #[serde(alias = "filterToolsList")]
    pub filter_tools_list: Option<bool>,
    #[serde(alias = "grants")]
    pub grants: Option<Vec<Grants0Config>>,
    #[serde(alias = "limits")]
    pub limits: Option<LimitsConfig>,
    #[serde(alias = "logging")]
    pub logging: Option<LoggingConfig>,
    #[serde(alias = "mode")]
    pub mode: Option<String>,
    #[serde(alias = "nameRules")]
    pub name_rules: Option<Vec<NameRules0Config>>,
    #[serde(alias = "onUnknownTool")]
    pub on_unknown_tool: Option<String>,
    #[serde(alias = "strictContradictions")]
    pub strict_contradictions: Option<bool>,
    #[serde(alias = "toolOverrides")]
    pub tool_overrides: Option<Vec<ToolOverrides0Config>>,
    #[serde(alias = "unannotatedAs")]
    pub unannotated_as: Option<String>,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    abi.setup()?;
    Ok(())
}
fn de_caller_attributes_0<'de, D>(
    deserializer: D,
) -> Result<Option<pdk::script::Script>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let exp: Option<pdk::script::Expression> = serde::de::Deserialize::deserialize(
        deserializer,
    )?;
    exp.map(|exp| {
            pdk::script::ScriptingEngine::script(&exp)
                .input(pdk::script::Input::Attributes)
                .input(pdk::script::Input::Authentication)
                .compile()
                .map_err(serde::de::Error::custom)
        })
        .transpose()
}
fn de_catalog_partition_1<'de, D>(
    deserializer: D,
) -> Result<Option<pdk::script::Script>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let exp: Option<pdk::script::Expression> = serde::de::Deserialize::deserialize(
        deserializer,
    )?;
    exp.map(|exp| {
            pdk::script::ScriptingEngine::script(&exp)
                .input(pdk::script::Input::Attributes)
                .input(pdk::script::Input::Authentication)
                .compile()
                .map_err(serde::de::Error::custom)
        })
        .transpose()
}
