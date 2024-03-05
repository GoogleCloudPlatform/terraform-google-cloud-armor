# Upgrading to v2.1.0

The v2.1 release contains backwards-compatible. `preconfigured_waf_config_exclusion` is obsolete and will be removed in next major version.

## Preconfigured WAF Config
:bangbang: **NOTE:** `preconfigured_waf_config_exclusion` in `pre_configured_rules` and `custom_rules` is obsolete and available for backward compatibility only. Use `preconfigured_waf_config_exclusions` which allows multiple exclusions. They are mutually exclusive.

If you are migrating from `preconfigured_waf_config_exclusion` to `preconfigured_waf_config_exclusions` first remove `preconfigured_waf_config_exclusion` and apply the code, then add exclusions using `preconfigured_waf_config_exclusions`
