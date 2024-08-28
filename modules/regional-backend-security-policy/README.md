# Cloud Armor Regional backend security policy module
This module makes it easy to setup [Cloud Armor Regional Backend Security Policy](https://cloud.google.com/armor/docs/security-policy-overview#expandable-2) with Security rules. You can attach the regional Security policy to the backend services exposed by the following load balancer types:
- regional external Application Load Balancer (HTTP/HTTPS)
- regional internal Application Load Balancer (HTTP/HTTPS)

There are `three` type of rules you can create in each policy:
1) [Pre-Configured Rules](#pre_configured_rules): These are based on [pre-configured waf rules](https://cloud.google.com/armor/docs/waf-rules).
2) [Security Rules](#security_rules): Allow or Deny traffic from list of IP addresses or IP address ranges.
3) [Custom Rules](#custom_rules): You can create your own rules using [Common Expression Language (CEL)](https://cloud.google.com/armor/docs/rules-language-reference).

##  Module Format

```
module security_policy {
  source = "GoogleCloudPlatform/cloud-armor/google"

  project_id  = var.project_id
  name        = "test-regional-external-sp-${random_id.suffix.hex}"
  description = "Test regional external Cloud Armor security policy with preconfigured rules, security rules and custom rules"
  region      = "us-central1"

  pre_configured_rules                 = {}
  security_rules                       = {}
  custom_rules                         = {}
}
```

Rule details and Sample Code for each type of rule is available [here](#Rules)

## Usage
There are examples included in the [examples](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/tree/main/examples) folder but simple usage is as follows:


```
module "cloud_armor_regional_security_policy" {
  source  = "GoogleCloudPlatform/cloud-armor/google"
  version = "~> 2.0"

  project_id  = var.project_id
  name        = "test-regional-external-sp-${random_id.suffix.hex}"
  description = "Test regional external Cloud Armor security policy with preconfigured rules, security rules and custom rules"
  type        = "CLOUD_ARMOR"
  region      = "us-central1"

  # pre-configured WAF rules

  pre_configured_rules = {

    "xss-stable_level_2_with_exclude" = {
      action                  = "deny(502)"
      priority                = 2
      preview                 = true
      target_rule_set         = "xss-v33-stable"
      sensitivity_level       = 2
      exclude_target_rule_ids = ["owasp-crs-v030301-id941380-xss", "owasp-crs-v030301-id941280-xss"]
    }

    "php-stable_level_0_with_include" = {
      action                  = "deny(502)"
      priority                = 3
      description             = "PHP Sensitivity Level 0 with included rules"
      target_rule_set         = "php-v33-stable"
      include_target_rule_ids = ["owasp-crs-v030301-id933190-php", "owasp-crs-v030301-id933111-php"]
    }

  }

  # Security Rules to block IP addreses

  security_rules = {

    "deny_project_honeypot" = {
      action        = "deny(502)"
      priority      = 11
      description   = "Deny Malicious IP address from project honeypot"
      src_ip_ranges = ["190.217.68.211/32", "45.116.227.68/32", "103.43.141.122/32", "123.11.215.36", "123.11.215.37", ]
      preview       = true
    }

    "rate_ban_project_dropthirty" = {
      action        = "rate_based_ban"
      priority      = 13
      description   = "Rate based ban for address from project dropthirty only if they cross banned threshold"
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
      priority      = 14
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

  # Custom Rules
  custom_rules = {

    deny_specific_regions = {
      action      = "deny(502)"
      priority    = 21
      description = "Deny specific Regions"

      expression = <<-EOT
        '[AU,BE]'.contains(origin.region_code)
      EOT

    }

    deny_specific_ip = {
      action      = "deny(502)"
      priority    = 22
      description = "Deny Specific IP address"

      expression = <<-EOT
        inIpRange(origin.ip, '47.185.201.155/32')
      EOT

    }

    throttle_specific_ip = {
      action      = "throttle"
      priority    = 23
      description = "Throttle specific IP address in US Region"

      expression = <<-EOT
        origin.region_code == "US" && inIpRange(origin.ip, '47.185.201.159/32')
      EOT

      rate_limit_options = {
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
      }

    }

    rate_ban_specific_ip = {
      action   = "rate_based_ban"
      priority = 24

      expression = <<-EOT
        inIpRange(origin.ip, '47.185.201.160/32')
      EOT

      rate_limit_options = {
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
        ban_duration_sec                     = 120
        ban_http_request_count               = 10000
        ban_http_request_interval_sec        = 600
        enforce_on_key                       = "ALL"
      }

    }

  }

}
```


<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| custom\_rules | Custome security rules | <pre>map(object({<br>    action      = string<br>    priority    = number<br>    description = optional(string)<br>    preview     = optional(bool, false)<br>    expression  = string<br>    rate_limit_options = optional(object({<br>      enforce_on_key      = optional(string)<br>      enforce_on_key_name = optional(string)<br>      enforce_on_key_configs = optional(list(object({<br>        enforce_on_key_name = optional(string)<br>        enforce_on_key_type = optional(string)<br>      })))<br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>      }),<br>    {})<br><br>    preconfigured_waf_config_exclusions = optional(map(object({<br>      target_rule_set = string<br>      target_rule_ids = optional(list(string), [])<br>      request_header = optional(list(object({<br>        operator = string<br>        value    = optional(string)<br>      })))<br>      request_cookie = optional(list(object({<br>        operator = string<br>        value    = optional(string)<br>      })))<br>      request_uri = optional(list(object({<br>        operator = string<br>        value    = optional(string)<br>      })))<br>      request_query_param = optional(list(object({<br>        operator = string<br>        value    = optional(string)<br>      })))<br>    })), null)<br><br>  }))</pre> | `{}` | no |
| description | An optional description of advanced network ddos protection security policy | `string` | `"CA Advance DDoS protection"` | no |
| name | Name of regional security policy. Name must be 1-63 characters long and match the regular expression a-z? which means the first character must be a lowercase letter, and all following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash | `string` | `"adv-network-ddos-protection"` | no |
| pre\_configured\_rules | Map of pre-configured rules with Sensitivity levels | <pre>map(object({<br>    action                  = string<br>    priority                = number<br>    description             = optional(string)<br>    preview                 = optional(bool, false)<br>    target_rule_set         = string<br>    sensitivity_level       = optional(number, 4)<br>    include_target_rule_ids = optional(list(string), [])<br>    exclude_target_rule_ids = optional(list(string), [])<br>    rate_limit_options = optional(object({<br>      enforce_on_key      = optional(string)<br>      enforce_on_key_name = optional(string)<br>      enforce_on_key_configs = optional(list(object({<br>        enforce_on_key_name = optional(string)<br>        enforce_on_key_type = optional(string)<br>      })))<br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>    }), {})<br><br>    preconfigured_waf_config_exclusions = optional(map(object({<br>      target_rule_set = string<br>      target_rule_ids = optional(list(string), [])<br>      request_header = optional(list(object({<br>        operator = string<br>        value    = optional(string)<br>      })))<br>      request_cookie = optional(list(object({<br>        operator = string<br>        value    = optional(string)<br>      })))<br>      request_uri = optional(list(object({<br>        operator = string<br>        value    = optional(string)<br>      })))<br>      request_query_param = optional(list(object({<br>        operator = string<br>        value    = optional(string)<br>      })))<br>    })), null)<br><br>  }))</pre> | `{}` | no |
| project\_id | The project in which the resource belongs. | `string` | n/a | yes |
| region | The region in which security policy is created | `string` | n/a | yes |
| security\_rules | Map of Security rules with list of IP addresses to block or unblock. | <pre>map(object({<br>    action        = string<br>    priority      = number<br>    description   = optional(string)<br>    preview       = optional(bool, false)<br>    src_ip_ranges = list(string)<br>    rate_limit_options = optional(object({<br>      enforce_on_key      = optional(string)<br>      enforce_on_key_name = optional(string)<br>      enforce_on_key_configs = optional(list(object({<br>        enforce_on_key_name = optional(string)<br>        enforce_on_key_type = optional(string)<br>      })))<br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>      }),<br>    {})<br>  }))</pre> | `{}` | no |
| type | Type indicates the intended use of the security policy. Possible values are CLOUD\_ARMOR and CLOUD\_ARMOR\_EDGE. | `string` | `"CLOUD_ARMOR"` | no |

## Outputs

| Name | Description |
|------|-------------|
| policy | Regional network Security policy created |
| security\_rules | Security policy rules created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

## Rules

[Pre-Configured Rules](#pre_configured_rules), [Security Rules](#security_rules) and [Custom Rules](#custom_rules) are maps of rules. Each rule is a map which provides details about the rule. Here is an example of `pre_configured_rules`:

```
  "my_rule" = {
    action                             = "deny(502)"
    priority                             = 1
    description                          = "SQL Sensitivity Level 4"
    preview                              = false
    target_rule_set                      = "sqli-v33-stable"
    sensitivity_level                    = 4
    include_target_rule_ids              = []
    exclude_target_rule_ids              = []
    rate_limit_options                   = {}
    preconfigured_waf_config_exclusions  = {}
  }
```

`action, priority, description, preview and rate_limit_options` are common in all the rule types. Some of then are optional and some have default value see [Input](#Inputs).

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

`preconfigured_waf_config_exclusions` is needed for custom application that might contain content in request fields (like headers, cookies, query parameters, or URIs) that matches signatures in preconfigured WAF rules, but which you know is legitimate. In this case, you can reduce false positives by excluding those request fields from inspection by associating a list of exclusions for request fields with the security policy rule. You can pass `request_header`, `request_uri`, `request_cookie` and `request_query_param`. It is available in [Pre-Configured Rules](#pre_configured_rules). You can find more details about `preconfigured_waf_config` [here](https://cloud.google.com/armor/docs/rule-tuning#exclude_request_fields_from_inspection)

```
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
```

## pre_configured_rules
List of preconfigured rules are available [here](https://cloud.google.com/armor/docs/waf-rules). Following is the key value pairs for setting up pre configured rules. `include_target_rule_ids` and `exclude_target_rule_ids` are mutually exclusive. If `include_target_rule_ids` is provided, sensitivity_level is automatically set to 0 by the module as it is a [requirement for opt in rule signature](https://cloud.google.com/armor/docs/rule-tuning#opt_in_rule_signatures). `exclude_target_rule_ids` is ignored when `include_target_rule_ids` is provided.

### Format:

```
  "sqli_sensitivity_level_4" = {
    action                               = "deny(502)"
    priority                             = 1
    description                          = "SQL Sensitivity Level 4"
    preview                              = false
    target_rule_set                      = "sqli-v33-stable"
    sensitivity_level                    = 4
    include_target_rule_ids              = []
    exclude_target_rule_ids              = []
    rate_limit_options                   = {}
    preconfigured_waf_config_exclusions  = {}
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
  }

}
```

## Requirements

These sections describe requirements for using this module.

### Software

The following dependencies must be available:

- [Terraform][terraform] v1.3+
- [Terraform Provider for GCP][terraform-provider-gcp] plugin v5.29+
