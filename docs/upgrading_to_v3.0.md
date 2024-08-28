# Upgrading to v3.0.0

The v3.0 release contains backwards-incompatible changes.

This update changed max provider version from `5.X` to `6.X`.

### TPG max version is bumped to 6.x
There is no known breaking change for Cloud Armor in 6.X.

### Remove preconfigured_waf_config_exclusion
`preconfigured_waf_config_exclusion` was deprecated in [v2.1](./upgrading_to_v2.1.md). It is now removed from the module. Before upgrading to 3.X move `preconfigured_waf_config_exclusion` settings to `preconfigured_waf_config_exclusions`. Here is an example:


    # preconfigured_waf_config_exclusion = optional(object({
    #   target_rule_set = string
    #   target_rule_ids = optional(list(string), [])
    #   request_header = optional(list(object({
    #     operator = string
    #     value    = optional(string)
    #   })))
    #   request_cookie = optional(list(object({
    #     operator = string
    #     value    = optional(string)
    #   })))
    #   request_uri = optional(list(object({
    #     operator = string
    #     value    = optional(string)
    #   })))
    #   request_query_param = optional(list(object({
    #     operator = string
    #     value    = optional(string)
    #   })))
    # }), { target_rule_set = null }) # Obsolete. Use preconfigured_waf_config_exclusions


```tf
"sqli_sensitivity_level_4" = {
  action            = "deny(502)"
  priority          = 1
  target_rule_set   = "sqli-v33-stable"
  sensitivity_level = 4
  description       = "sqli-v33-stable Sensitivity Level 4 and 2 preconfigured_waf_config_exclusions"

  preconfigured_waf_config_exclusion = {
      target_rule_set = "sqli-v33-stable"
      target_rule_ids = ["owasp-crs-v030301-id942120-sqli", "owasp-crs-v030301-id942130-sqli"]
      request_cookie = [
        {
          operator = "STARTS_WITH"
          value    = "abc"
        }
      ]
      request_header = [
        {
          operator = "STARTS_WITH"
          value    = "xyz"
        },
        {
          operator = "STARTS_WITH"
          value    = "uvw"
        }
      ]
  }
}
```

```tf
"sqli_sensitivity_level_4" = {
  action            = "deny(502)"
  priority          = 1
  target_rule_set   = "sqli-v33-stable"
  sensitivity_level = 4
  description       = "sqli-v33-stable Sensitivity Level 4 and 2 preconfigured_waf_config_exclusions"

  # 2 exclusions
  preconfigured_waf_config_exclusions = {
    exclusion_1 = {
      target_rule_set = "sqli-v33-stable"
      target_rule_ids = ["owasp-crs-v030301-id942120-sqli", "owasp-crs-v030301-id942130-sqli"]
      request_cookie = [
        {
          operator = "STARTS_WITH"
          value    = "abc"
        }
      ]
      request_header = [
        {
          operator = "STARTS_WITH"
          value    = "xyz"
        },
        {
          operator = "STARTS_WITH"
          value    = "uvw"
        }
      ]
    }
    exclusion_2 = {
      target_rule_set = "sqli-v33-stable"
      target_rule_ids = ["owasp-crs-v030301-id942150-sqli", "owasp-crs-v030301-id942180-sqli"]
      request_header = [
        {
          operator = "STARTS_WITH"
          value    = "lmn"
        },
        {
          operator = "ENDS_WITH"
          value    = "opq"
        }
      ]
      request_uri = [
        {
          operator = "CONTAINS"
          value    = "https://hashicorp.com"
        },
        {
          operator = "CONTAINS"
          value    = "https://xyz.com"
        },
      ]
    }

  }
}
```

