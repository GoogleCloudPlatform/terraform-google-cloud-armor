# Cloud Armor Terraform Module
This module makes it easy to setup [Cloud Armor Security Policy](https://cloud.google.com/armor/docs/cloud-armor-overview#security_policies) with Security rules. There are five type of rules you can create in each policy:
- [Pre-Configured Rules](#pre_configured_rules): These are based on [pre-configured waf rules](https://cloud.google.com/armor/docs/waf-rules).
- [Security Rules](#security_rules): Allow or Deny traffic from list of IP addresses or IP adress ranges.
- [Custom Rules](#custom_rules): You can create your own rules using [Common Expression Language (CEL)](https://cloud.google.com/armor/docs/rules-language-reference).
- [Threat Intelligence Rules](#threat_intelligence_rules): Add Rules based on [threat intelligence](https://cloud.google.com/armor/docs/threat-intelligence). [Managed protection plus](https://cloud.google.com/armor/docs/managed-protection-overview) subscription is needed to use this feature.
- [Automatically deploy Adaptive Protection suggested rules](#adaptive_protection_auto_deploy); When enable module will create a rule for automatically deploying the suggested rules that [Adaptive Protection generates](https://cloud.google.com/armor/docs/adaptive-protection-auto-deploy).


## Compatibility

This module is meant for use with Terraform 1.3+ and tested using Terraform 1.3+. If you find incompatibilities using Terraform >=1.3, please open an issue.

## Version

Current version is 1.0. Upgrade guides:

- [0.X -> 1.0.](/docs/upgrading_to_v1.0.md)

##  Module Format

```
module security_policy {
  source = "GoogleCloudPlatform/cloud-armor/google"

  project_id                           = "my-project-id"
  name                                 = "my-test-ca-policy"
  description                          = "Test Cloud Armor security policy with preconfigured rules, security rules and custom rules"
  default_rule_action                  = "deny(403)"
  type                                 = "CLOUD_ARMOR"
  layer_7_ddos_defense_enable          = true
  layer_7_ddos_defense_rule_visibility = "STANDARD"
  recaptcha_redirect_site_key          = google_recaptcha_enterprise_key.primary.name
  json_parsing                         = "STANDARD"
  log_level                            = "VERBOSE"

  pre_configured_rules                 = {}
  security_rules                       = {}
  custom_rules                         = {}
  threat_intelligence_rules            = {}
}
```

Rule details and Sample Code for each type of rule is available [here](#Rules)

## Usage
There are examples included in the [examples](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/tree/main/examples) folder but simple usage is as follows:

```
module "security_policy" {
  source = "GoogleCloudPlatform/cloud-armor/google"
  version = "~> 1.1"

  project_id                           = var.project_id
  name                                 = "my-test-security-policy"
  description                          = "Test Security Policy"
  recaptcha_redirect_site_key          = google_recaptcha_enterprise_key.primary.name
  default_rule_action                  = "allow"
  type                                 = "CLOUD_ARMOR"
  layer_7_ddos_defense_enable          = true
  layer_7_ddos_defense_rule_visibility = "STANDARD"

  # Pre-configured WAF Rules

  pre_configured_rules = {

    "sqli_sensitivity_level_4" = {
      action          = "deny(502)"
      priority        = 1
      target_rule_set = "sqli-v33-stable"
    }

    "xss-stable_level_2_with_exclude" = {
      action                  = "deny(502)"
      priority                = 2
      description             = "XSS Sensitivity Level 2 with excluded rules"
      preview                 = true
      target_rule_set         = "xss-v33-stable"
      sensitivity_level       = 2
      exclude_target_rule_ids = ["owasp-crs-v030301-id941380-xss", "owasp-crs-v030301-id941280-xss"]
      preconfigured_waf_config_exclusion = {
        target_rule_set = "xss-v33-stable"
        target_rule_ids = ["owasp-crs-v030301-id941140-xss", "owasp-crs-v030301-id941270-xss"]
        request_header = [
          {
            operator = "STARTS_WITH"
            value    = "abc"
          },
          {
            operator = "ENDS_WITH"
            value    = "xyz"
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

    "php-stable_level_0_with_include" = {
      action                  = "deny(502)"
      priority                = 3
      description             = "PHP Sensitivity Level 0 with included rules"
      target_rule_set         = "php-v33-stable"
      include_target_rule_ids = ["owasp-crs-v030301-id933190-php", "owasp-crs-v030301-id933111-php"]
    }

  }

  # Action against specific IP addresses or IP adress ranges

  security_rules = {

    "deny_project_bad_actor1" = {
      action        = "deny(502)"
      priority      = 11
      description   = "Deny Malicious IP address from project bad_actor1"
      src_ip_ranges = ["190.217.68.211/32", "45.116.227.68/32", "103.43.141.122", "123.11.215.36", "123.11.215.37", ]
      preview       = true
    }

    "redirect_project_rd" = {
      action        = "redirect"
      priority      = 12
      description   = "Redirect IP address from project RD"
      src_ip_ranges = ["190.217.68.215", "45.116.227.99", ]
      redirect_type = "EXTERNAL_302"
      redirect_target = "https://www.example.com"
    }

    "rate_ban_project_actor3" = {
      action        = "rate_based_ban"
      priority      = 14
      description   = "Rate based ban for address from project actor3 only if they cross banned threshold"
      src_ip_ranges = ["190.217.68.213", "45.116.227.70", ]
      rate_limit_options = {
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
        ban_duration_sec                     = 600
        ban_http_request_count               = 1000
        ban_http_request_interval_sec        = 300
        enforce_on_key                       = "ALL"
      }
    }

    "throttle_project_droptwenty" = {
      action        = "throttle"
      priority      = 15
      description   = "Throttle IP addresses from project droptwenty"
      src_ip_ranges = ["190.217.68.214", "45.116.227.71", ]

      rate_limit_options = {
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
        enforce_on_key_configs = [
          {
            enforce_on_key_type = "HTTP_PATH"
          },
          {
            enforce_on_key_type = "HTTP_COOKIE"
            enforce_on_key_name = "site_id"
          }
        ]
      }

    }
  }

  # Custom Rules using CEL

  custom_rules = {

    deny_specific_regions = {
      action      = "deny(502)"
      priority    = 21
      description = "Deny specific Regions"
      expression  = <<-EOT
        '[AU,BE]'.contains(origin.region_code)
      EOT
    }

    deny_specific_ip = {
      action      = "deny(502)"
      priority    = 22
      description = "Deny specific IP address in US Region"
      expression  = <<-EOT
        origin.region_code == "US" && inIpRange(origin.ip, '47.185.201.159/32')
      EOT
    }

    throttle_specific_ip_region = {
      action      = "throttle"
      priority    = 23
      description = "Throttle specific IP address in US Region"
      expression  = <<-EOT
        origin.region_code == "US" && inIpRange(origin.ip, '47.185.201.159/32')
      EOT
      rate_limit_options = {
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
      }
    }

    allow_path_token_header = {
      action      = "allow"
      priority    = 25
      description = "Allow path and token match with addition of header"

      expression = <<-EOT
        request.path.matches('/login.html') && token.recaptcha_session.score < 0.2
      EOT

      header_action = [
        {
          header_name  = "reCAPTCHA-Warning"
          header_value = "high"
        },
        {
          header_name  = "X-Resource"
          header_value = "test"
        }
      ]

    }

    deny_java_level3_with_exclude = {
      action      = "deny(502)"
      priority    = 100
      description = "Deny pre-configured rule java-v33-stable at sensitivity level 3"
      preview     = true
      expression  = <<-EOT
        evaluatePreconfiguredWaf('java-v33-stable', {'sensitivity': 3, 'opt_out_rule_ids': ['owasp-crs-v030301-id944240-java', 'owasp-crs-v030301-id944120-java']})
      EOT
    }

  }

  # Threat Intelligence Rules

  threat_intelligence_rules = {

    deny_malicious_ips = {
      action      = "deny(502)"
      priority    = 200
      description = "Deny IP addresses known to attack web applications"
      preview     = false
      feed        = "iplist-known-malicious-ips"
      exclude_ip  = "['47.100.100.100', '47.189.12.139']"
    }

    deny_tor_exit_ips = {
      action      = "deny(502)"
      priority    = 210
      description = "Deny Tor exit nodes IP addresses"
      preview     = false
      feed        = "iplist-tor-exit-nodes"
    }

  }

}
```


<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| adaptive\_protection\_auto\_deploy | Configuration for Automatically deploy Cloud Armor Adaptive Protection suggested rules. priority and action fields are required if enable is set to true | <pre>object({<br>    enable                      = bool<br>    priority                    = optional(number, null)<br>    action                      = optional(string, null)<br>    preview                     = optional(bool, false)<br>    description                 = optional(string, "Adaptive Protection auto-deploy")<br>    load_threshold              = optional(number, 0.1)<br>    confidence_threshold        = optional(number, 0.5)<br>    impacted_baseline_threshold = optional(number, 0.01)<br>    expiration_sec              = optional(number, 7200)<br>    redirect_type               = optional(string)<br>    redirect_target             = optional(string)<br><br>    rate_limit_options = optional(object({<br>      enforce_on_key      = optional(string)<br>      enforce_on_key_name = optional(string)<br><br>      enforce_on_key_configs = optional(list(object({<br>        enforce_on_key_name = optional(string)<br>        enforce_on_key_type = optional(string)<br>      })))<br><br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>    }), {})<br>  })</pre> | <pre>{<br>  "enable": false<br>}</pre> | no |
| custom\_rules | Custome security rules | <pre>map(object({<br>    action          = string<br>    priority        = number<br>    description     = optional(string)<br>    preview         = optional(bool, false)<br>    expression      = string<br>    redirect_type   = optional(string, null)<br>    redirect_target = optional(string, null)<br>    rate_limit_options = optional(object({<br>      enforce_on_key      = optional(string)<br>      enforce_on_key_name = optional(string)<br>      enforce_on_key_configs = optional(list(object({<br>        enforce_on_key_name = optional(string)<br>        enforce_on_key_type = optional(string)<br>      })))<br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>      }),<br>    {})<br>    header_action = optional(list(object({<br>      header_name  = optional(string)<br>      header_value = optional(string)<br>    })), [])<br>  }))</pre> | `{}` | no |
| default\_rule\_action | default rule that allows/denies all traffic with the lowest priority (2,147,483,647) | `string` | `"allow"` | no |
| description | An optional description of this security policy. Max size is 2048. | `string` | `null` | no |
| json\_custom\_config\_content\_types | A list of custom Content-Type header values to apply the JSON parsing. Only applicable when json\_parsing is set to STANDARD. Not supported for CLOUD\_ARMOR\_EDGE policy type | `list(string)` | `[]` | no |
| json\_parsing | Whether or not to JSON parse the payload body. Possible values are DISABLED and STANDARD. Not supported for CLOUD\_ARMOR\_EDGE policy type | `string` | `"DISABLED"` | no |
| layer\_7\_ddos\_defense\_enable | (Optional) If set to true, enables Cloud Armor Adaptive Protection for L7 DDoS detection. Cloud Armor Adaptive Protection is only supported in Global Security Policies of type CLOUD\_ARMOR | `bool` | `false` | no |
| layer\_7\_ddos\_defense\_rule\_visibility | (Optional) Rule visibility can be one of the following: STANDARD - opaque rules. PREMIUM - transparent rules. This field is only supported in Global Security Policies of type CLOUD\_ARMOR. | `string` | `"STANDARD"` | no |
| log\_level | Log level to use. Possible values are NORMAL and VERBOSE. Not supported for CLOUD\_ARMOR\_EDGE policy type | `string` | `"NORMAL"` | no |
| name | Name of the security policy. | `string` | n/a | yes |
| pre\_configured\_rules | Map of pre-configured rules Sensitivity levels | <pre>map(object({<br>    action                  = string<br>    priority                = number<br>    description             = optional(string)<br>    preview                 = optional(bool, false)<br>    redirect_type           = optional(string, null)<br>    redirect_target         = optional(string, null)<br>    target_rule_set         = string<br>    sensitivity_level       = optional(number, 4)<br>    include_target_rule_ids = optional(list(string), [])<br>    exclude_target_rule_ids = optional(list(string), [])<br>    rate_limit_options = optional(object({<br>      enforce_on_key      = optional(string)<br>      enforce_on_key_name = optional(string)<br>      enforce_on_key_configs = optional(list(object({<br>        enforce_on_key_name = optional(string)<br>        enforce_on_key_type = optional(string)<br>      })))<br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>    }), {})<br><br>    header_action = optional(list(object({<br>      header_name  = optional(string)<br>      header_value = optional(string)<br>    })), [])<br><br>    preconfigured_waf_config_exclusion = optional(object({<br>      target_rule_set = string<br>      target_rule_ids = optional(list(string), [])<br>      request_header = optional(list(object({<br>        operator = string<br>        value    = optional(string)<br>      })))<br>      request_cookie = optional(list(object({<br>        operator = string<br>        value    = optional(string)<br>      })))<br>      request_uri = optional(list(object({<br>        operator = string<br>        value    = optional(string)<br>      })))<br>      request_query_param = optional(list(object({<br>        operator = string<br>        value    = optional(string)<br>      })))<br>    }), { target_rule_set = null })<br><br>  }))</pre> | `{}` | no |
| project\_id | The project in which the resource belongs | `string` | n/a | yes |
| recaptcha\_redirect\_site\_key | reCAPTCHA site key to be used for all the rules using the redirect action with the redirect type of GOOGLE\_RECAPTCHA | `string` | `null` | no |
| security\_rules | Map of Security rules with list of IP addresses to block or unblock | <pre>map(object({<br>    action          = string<br>    priority        = number<br>    description     = optional(string)<br>    preview         = optional(bool, false)<br>    redirect_type   = optional(string, null)<br>    redirect_target = optional(string, null)<br>    src_ip_ranges   = list(string)<br>    rate_limit_options = optional(object({<br>      enforce_on_key      = optional(string)<br>      enforce_on_key_name = optional(string)<br>      enforce_on_key_configs = optional(list(object({<br>        enforce_on_key_name = optional(string)<br>        enforce_on_key_type = optional(string)<br>      })))<br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>      }),<br>    {})<br>    header_action = optional(list(object({<br>      header_name  = optional(string)<br>      header_value = optional(string)<br>    })), [])<br>  }))</pre> | `{}` | no |
| threat\_intelligence\_rules | Map of Threat Intelligence Feed rules | <pre>map(object({<br>    action      = string<br>    priority    = number<br>    description = optional(string)<br>    preview     = optional(bool, false)<br>    feed        = string<br>    exclude_ip  = optional(string)<br>    rate_limit_options = optional(object({<br>      enforce_on_key      = optional(string)<br>      enforce_on_key_name = optional(string)<br>      enforce_on_key_configs = optional(list(object({<br>        enforce_on_key_name = optional(string)<br>        enforce_on_key_type = optional(string)<br>      })))<br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>      }),<br>    {})<br>    header_action = optional(list(object({<br>      header_name  = optional(string)<br>      header_value = optional(string)<br>    })), [])<br>  }))</pre> | `{}` | no |
| type | Type indicates the intended use of the security policy. Possible values are CLOUD\_ARMOR and CLOUD\_ARMOR\_EDGE | `string` | `"CLOUD_ARMOR"` | no |

## Outputs

| Name | Description |
|------|-------------|
| policy | Security policy created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->



## Rules

[Pre-Configured Rules](#pre_configured_rules), [Security Rules](#security_rules), [Custom Rules](#custom_rules) and [Threat Intelligence Rules](#threat_intelligence_rules) are maps of rules. Each rule is a map which provides details about the rule. Here is an example of `pre_configured_rules`:

```
  "my_rule" = {
    action                             = "deny(502)"
    priority                           = 1
    description                        = "SQL Sensitivity Level 4"
    preview                            = false
    redirect_type                      = null
    redirect_target                    = null
    target_rule_set                    = "sqli-v33-stable"
    sensitivity_level                  = 4
    include_target_rule_ids            = []
    exclude_target_rule_ids            = []
    header_action                      = []
    rate_limit_options                 = {}
    preconfigured_waf_config_exclusion = {}
  }
```

`action, priority, description, preview, rate_limit_options, header_action, redirect_type and redirect_target` are common in all the rule types. Some of then are optional and some have default value see [Input](#Inputs).

## Rate limit
`rate_limit_options` is needed for the rules where action is set to `throttle` or `rate_based_ban`. `rate_limit_options` is a map of strings with following key pairs. You can find more details about rate limit [here](https://cloud.google.com/armor/docs/rate-limiting-overview).

```
rate_limit_options = {
  exceed_action                        = "deny(502)"
  rate_limit_http_request_count        = 10
  rate_limit_http_request_interval_sec = 60    # must be one of 60, 120, 180, 240, 300, 600, 900, 1200, 1800, 2700, 3600 seconds
  ban_duration_sec                     = 600   # needed only if action is rate_based_ban
  ban_http_request_count               = 1000  # needed only if action is rate_based_ban
  ban_http_request_interval_sec        = 300   # must be one of 60, 120, 180, 240, 300, 600, 900, 1200, 1800, 2700, 3600 seconds. needed only if action is rate_based_ban
  enforce_on_key                       = "ALL" # All is default value. If null is passed terraform will use ALL as the value. Will be set to "" when `enforce_on_key_configs` is not null

  enforce_on_key_configs = [
    {
      enforce_on_key_type = "HTTP_PATH"
    },
    {
      enforce_on_key_type = "HTTP_COOKIE"
      enforce_on_key_name = "site_id"
    }
  ]
}
```

## Preconfigured WAF Config
`preconfigured_waf_config_exclusion` is needed for custom application that might contain content in request fields (like headers, cookies, query parameters, or URIs) that matches signatures in preconfigured WAF rules, but which you know is legitimate. In this case, you can reduce false positives by excluding those request fields from inspection by associating a list of exclusions for request fields with the security policy rule. You can pass `request_header`, `request_uri`, `request_cookie` and `request_query_param`. It is available in [Pre-Configured Rules](#pre_configured_rules). You can find more details about `preconfigured_waf_config` [here](https://cloud.google.com/armor/docs/rule-tuning#exclude_request_fields_from_inspection)

```
preconfigured_waf_config_exclusion = {
  target_rule_set = "xss-v33-stable"
  target_rule_ids = ["owasp-crs-v030301-id941140-xss", "owasp-crs-v030301-id941270-xss"]
  request_header = [
    {
      operator = "STARTS_WITH"
      value    = "abc"
    },
    {
      operator = "ENDS_WITH"
      value    = "xyz"
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
```

## pre_configured_rules
List of preconfigured rules are available [here](https://cloud.google.com/armor/docs/waf-rules). Following is the key value pairs for setting up pre configured rules. `include_target_rule_ids` and `exclude_target_rule_ids` are mutually exclusive. If `include_target_rule_ids` is provided, sensitivity_level is automatically set to 0 by the module as it is a [requirement for opt in rule signature](https://cloud.google.com/armor/docs/rule-tuning#opt_in_rule_signatures). `exclude_target_rule_ids` is ignored when `include_target_rule_ids` is provided.

### Format:

```
  "sqli_sensitivity_level_4" = {
    action                             = "deny(502)"
    priority                           = 1
    description                        = "SQL Sensitivity Level 4"
    preview                            = false
    redirect_type                      = null
    redirect_target                    = null
    target_rule_set                    = "sqli-v33-stable"
    sensitivity_level                  = 4
    include_target_rule_ids            = []
    exclude_target_rule_ids            = []
    rate_limit_options                 = {}
    header_action                      = []
    preconfigured_waf_config_exclusion = {}
  }
```


### Sample:

```
pre_configured_rules = {

  "php-stable_level_1_with_include" = {
    action                  = "deny(502)"
    priority                = 3
    description             = "PHP Sensitivity Level 1 with included rules"
    target_rule_set         = "xss-v33-stable"
    sensitivity_level       = 0
    include_target_rule_ids = ["owasp-crs-v030301-id933190-php", "owasp-crs-v030301-id933111-php"]
  }

  "sqli_sensitivity_level_4" = {
    action            = "deny(502)"
    priority          = 1
    target_rule_set   = "sqli-v33-stable"
    sensitivity_level = 4

    preconfigured_waf_config_exclusion = {
      target_rule_set = "sqli-v33-stable"
      request_cookie = [
        {
          operator = "EQUALS_ANY"
        },
        {
          operator = "STARTS_WITH"
          value    = "abc"
        }
      ]
      request_header = [
        {
          operator = "STARTS_WITH"
          value    = "xyz"
        }
      ]
    }
  }

}
```


## security_rules:
Set of IP addresses or ranges (IPV4 or IPV6) in CIDR notation to match against inbound traffic. There is a limit of 10 IP ranges per rule.

### Format:
Each rule is key value pair where key is a unique name of the rule and value is the action associated with it.

```
"block_bad_actor_ip" = {
  action             = "deny(502)"
  priority           = 11
  description        = "Deny Malicious IP address"
  src_ip_ranges      = ["A..B.C.D", "W.X.Y.Z",]
  preview            = false
  redirect_type      = null
  redirect_target    = null
  rate_limit_options = {}
  header_action      = []
}
```

### Sample:

```
security_rules = {

  "deny_project_bad_actor" = {
    action             = "deny(502)"
    priority           = 11
    description        = "Deny Malicious IP address from project bad_actor"
    src_ip_ranges      = ["190.217.68.211/32", "45.116.227.68/32", "103.43.141.122", "123.11.215.36", ]
  }

  "throttle_project_droptwenty" = {
    action        = "throttle"
    priority      = 15
    description   = "Throttle IP addresses from project droptwenty"
    src_ip_ranges = ["190.217.68.214", "45.116.227.71", ]

    rate_limit_options = {
      exceed_action                        = "deny(502)"
      rate_limit_http_request_count        = 10
      rate_limit_http_request_interval_sec = 60
      enforce_on_key_configs = [
        {
          enforce_on_key_type = "HTTP_PATH"
        },
        {
          enforce_on_key_type = "HTTP_COOKIE"
          enforce_on_key_name = "site_id"
        }
      ]
    }

  }

}
```

## custom_rules:
Add Custom Rules using [Common Expression Language (CEL)](https://cloud.google.com/armor/docs/rules-language-reference)

### Format:
Each rule is key value pair where key is a unique name of the rule and value is the action associated with it.

```
allow_specific_regions = {
  action             = "allow"
  priority           = 21
  description        = "Allow specific Regions"
  preview            = false
  expression         = <<-EOT
    '[US,AU,BE]'.contains(origin.region_code)
  EOT
  redirect_type      = null
  redirect_target    = null
  rate_limit_options = {}
  header_action      = []
}
```

### Sample:

```
custom_rules = {

  allow_specific_regions = {
    action             = "allow"
    priority           = 21
    description        = "Allow specific Regions"
    preview            = true
    expression         = <<-EOT
      '[US,AU,BE]'.contains(origin.region_code)
    EOT
  }

  allow_path_token_header = {
    action      = "allow"
    priority    = 25
    description = "Allow path and token match with addition of header"

    expression = <<-EOT
      request.path.matches('/login.html') && token.recaptcha_session.score < 0.2
    EOT

    header_action = [
      {
        header_name  = "reCAPTCHA-Warning"
        header_value = "high"
      },
      {
        header_name  = "X-Resource"
        header_value = "test"
      }
    ]

  }

}
```

## threat_intelligence_rules:
Add Rules based on [threat intelligence](https://cloud.google.com/armor/docs/threat-intelligence). [Managed protection plus](https://cloud.google.com/armor/docs/managed-protection-overview) subscription is needed to use this feature.

### Format:
Each rule is key value pair where key is a unique name of the rule and value is the action associated with it. NOTE: `exclude_ip` is a string with IP addresse(s) in single quotes and enclused within a sqare bracket (You can find detail [here](https://cloud.google.com/armor/docs/threat-intelligence#configure-nti)).

```
threat_intelligence_rules = {
  deny_crawlers_ip = {
    action             = "deny(502)"
    priority           = 31
    description        = "Deny IP addresses of search engine crawlers"
    preview            = false
    feed               = "iplist-search-engines-crawlers"
    exclude_ip         = null
    rate_limit_options = {}
    header_action      = []
  }
}
```

### Sample:

```
threat_intelligence_rules = {

  deny_malicious_ips = {
    action      = "deny(502)"
    priority    = 31
    description = "Deny IP addresses known to attack web applications"
    preview     = true
    feed        = "iplist-known-malicious-ips"
    exclude_ip  = "['47.100.100.100', '47.189.12.139']"
  }

  deny_tor_exit_ips = {
    action      = "deny(502)"
    priority    = 31
    description = "Deny Tor exit nodes IP addresses"
    preview     = true
    feed        = "iplist-tor-exit-nodes"
  }

}
```

## adaptive_protection_auto_deploy:
Add a rule to [Automatically deploy Adaptive Protection suggested rules](https://cloud.google.com/armor/docs/adaptive-protection-auto-deploy). [Managed protection plus](https://cloud.google.com/armor/docs/managed-protection-overview) subscription is needed to use this feature. By default this feature is disabled. If `enable` is set to true you need to provide `priority` and `action` for this module to deploy auto deploy rule. Module will create a rule with expression `evaluateAdaptiveProtectionAutoDeploy()`.

### Format:
It is an object with key value pair.

```
adaptive_protection_auto_deploy = {
  enable                      = true
  action                      = "deny(502)"
  priority                    = 31
  description                 = "Automatically deploy Adaptive Protection suggested rules"
  preview                     = false
  load_threshold              = 0.1
  confidence_threshold        = 0.5
  impacted_baseline_threshold = 0.01
  expiration_sec              = 7200
  redirect_type               = null
  redirect_target             = null
  rate_limit_options          = {}
}
```

### Sample 1 (Deny):

```
adaptive_protection_auto_deploy = {
  enable   = true
  priority = 100000
  action   = "deny(403)"
}
```

### Sample 2 (redirect):

```
adaptive_protection_auto_deploy = {
  enable         = true
  priority       = 100000
  action         = "redirect"
  redirect_type  = "GOOGLE_RECAPTCHA"
}
```

### Sample 3 (throttle):

```
adaptive_protection_auto_deploy = {
  enable   = true
  priority = 100000
  action   = "throttle"

  rate_limit_options = {
    exceed_action                        = "deny(502)"
    rate_limit_http_request_count        = 500
    rate_limit_http_request_interval_sec = 120
    enforce_on_key                       = "IP"
  }
}
```

## Requirements

These sections describe requirements for using this module.

### Software

The following dependencies must be available:

- [Terraform][terraform] v1.3+
- [Terraform Provider for GCP][terraform-provider-gcp] plugin v4.39+

### Service Account

A service account with the following permission must be used to provision
the resources of this module:

- compute.securityPolicies.create
- compute.securityPolicies.delete
- compute.securityPolicies.get
- compute.securityPolicies.list
- compute.securityPolicies.use
- compute.securityPolicies.update
- recaptchaenterprise.keys.list
- recaptchaenterprise.keys.get

Following roles contain above mentioned permissions. You can either assing one of the following role or create custom roles with above permissions.

- Compute Organization Security Policy Admin: `roles/compute.orgSecurityPolicyAdmin`
- Compute Security Admin: `roles/compute.securityAdmin`
- reCAPTCHA Enterprise Admin: `roles/recaptchaenterprise.admin`

### Enable API's
In order to operate with the Service Account you must activate the following API on the project where the Service Account was created:

- Compute Engine API - compute.googleapis.com

## Contributing

Refer to the [contribution guidelines](./CONTRIBUTING.md) for
information on contributing to this module.
