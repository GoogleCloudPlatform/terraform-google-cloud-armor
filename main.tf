/**
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

locals {
  ### find all the preconfigured rule with no include or exclude expression
  pre_configured_rules_no_cond_expr = { for name, policy in var.pre_configured_rules : name => {
    expression = "evaluatePreconfiguredWaf('${policy["target_rule_set"]}', {'sensitivity': ${policy["sensitivity_level"]}})"
    } if length(policy["include_target_rule_ids"]) == 0 && length(policy["exclude_target_rule_ids"]) == 0
  }

  ### find all the preconfigured rule with include (Opt In rules) expression
  pre_configured_rules_include = { for name, policy in var.pre_configured_rules : name => {
    target_rule_set         = policy.target_rule_set
    include_target_rule_ids = replace(join(",", policy.include_target_rule_ids), ",", "','")
    sensitivity_level       = policy.sensitivity_level
    action                  = policy.action
    priority                = 0
    description             = policy.description
    preview                 = policy.preview
    redirect_type           = policy.redirect_type
    redirect_target         = policy.redirect_target
    rate_limit_options      = policy.rate_limit_options
    } if length(policy["include_target_rule_ids"]) > 0
  }

  pre_configured_rules_include_expr = { for name, policy in local.pre_configured_rules_include : name => {
    expression = "evaluatePreconfiguredWaf('${policy["target_rule_set"]}', {'sensitivity': 0, 'opt_in_rule_ids': ['${policy.include_target_rule_ids}']})"
    }
  }

  ### find all the preconfigured rule with Exclude (Opt out rules) expression
  pre_configured_rules_exclude = { for name, policy in var.pre_configured_rules : name => {
    target_rule_set         = policy.target_rule_set
    exclude_target_rule_ids = replace(join(",", policy.exclude_target_rule_ids), ",", "','")
    sensitivity_level       = policy.sensitivity_level
    action                  = policy.action
    priority                = policy.priority
    description             = policy.description
    preview                 = policy.preview
    redirect_type           = policy.redirect_type
    redirect_target         = policy.redirect_target
    rate_limit_options      = policy.rate_limit_options
    } if length(policy["include_target_rule_ids"]) == 0 && length(policy["exclude_target_rule_ids"]) > 0
  }
  pre_configured_rules_exclude_expr = { for name, policy in local.pre_configured_rules_exclude : name => {
    expression = "evaluatePreconfiguredWaf('${policy["target_rule_set"]}', {'sensitivity': ${policy.sensitivity_level}, 'opt_out_rule_ids': ['${policy.exclude_target_rule_ids}']})"
    }
  }
  ## Combine all the preconfigured rules
  pre_configured_rules_expr = merge(local.pre_configured_rules_no_cond_expr, local.pre_configured_rules_include_expr, local.pre_configured_rules_exclude_expr)
}

resource "google_compute_security_policy" "policy" {
  provider    = google-beta
  name        = var.name
  description = var.description
  project     = var.project_id
  type        = var.type

  dynamic "recaptcha_options_config" {
    for_each = var.recaptcha_redirect_site_key == null ? [] : ["redirect_site_key"]
    content {
      redirect_site_key = var.recaptcha_redirect_site_key
    }
  }

  # Advanced options for Cloud Armor are currently only supported for security policies with CLOUD_ARMOR type
  dynamic "advanced_options_config" {
    for_each = var.type == "CLOUD_ARMOR" ? ["CLOUD_ARMOR"] : []
    content {
      json_parsing            = var.json_parsing
      log_level               = var.log_level
      user_ip_request_headers = var.user_ip_request_headers
      dynamic "json_custom_config" {
        for_each = var.json_parsing == "STANDARD" && length(var.json_custom_config_content_types) > 0 ? ["json_custom_config"] : []
        content {
          content_types = var.json_custom_config_content_types
        }
      }
    }
  }

  ##### Preconfigured WAF Rules

  dynamic "rule" {
    for_each = var.pre_configured_rules
    content {
      action      = rule.value["action"]
      priority    = rule.value["priority"]
      preview     = rule.value["preview"]
      description = rule.value["description"]

      match {
        expr {
          expression = local.pre_configured_rules_expr[rule.key].expression
        }
      }

      # Header Action Block. Only if header_action is provided
      dynamic "header_action" {
        for_each = length(rule.value["header_action"]) == 0 ? [] : ["header_action"]
        content {
          dynamic "request_headers_to_adds" {
            for_each = { for x in rule.value["header_action"] : x.header_name => x }
            content {
              header_name  = request_headers_to_adds.value.header_name
              header_value = request_headers_to_adds.value.header_value
            }
          }
        }
      }

      ### Redirect option
      dynamic "redirect_options" {
        for_each = rule.value["action"] == "redirect" ? ["redirect"] : []
        content {
          type   = rule.value["redirect_type"]
          target = rule.value["redirect_type"] == "EXTERNAL_302" ? rule.value["redirect_target"] : null
        }
      }

      ### Rate limit. Execute only if Action is "rate_based_ban" or "throttle"
      dynamic "rate_limit_options" {
        for_each = rule.value["action"] == "rate_based_ban" || rule.value["action"] == "throttle" ? ["rate_limits"] : []
        content {
          conform_action      = "allow"
          ban_duration_sec    = rule.value["action"] == "rate_based_ban" ? lookup(rule.value["rate_limit_options"], "ban_duration_sec") : null
          exceed_action       = lookup(rule.value["rate_limit_options"], "exceed_action")
          enforce_on_key      = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(rule.value["rate_limit_options"], "enforce_on_key", null) : ""
          enforce_on_key_name = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(rule.value["rate_limit_options"], "enforce_on_key_name", null) : null

          dynamic "enforce_on_key_configs" {
            for_each = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? {} : { for x in lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") : x.enforce_on_key_type => x }
            content {
              enforce_on_key_type = enforce_on_key_configs.value.enforce_on_key_type
              enforce_on_key_name = enforce_on_key_configs.value.enforce_on_key_name
            }
          }

          ## Required for all rate limit options
          dynamic "rate_limit_threshold" {
            for_each = rule.value["action"] == "rate_based_ban" || rule.value["action"] == "throttle" ? ["rate_limit_options"] : []
            content {
              count        = rule.value["rate_limit_options"].rate_limit_http_request_count
              interval_sec = rule.value["rate_limit_options"].rate_limit_http_request_interval_sec
            }
          }

          ## Optional. Can be provided for for rate based ban. Not needed for throttle
          dynamic "ban_threshold" {
            for_each = rule.value["action"] == "rate_based_ban" && lookup(rule.value["rate_limit_options"], "ban_http_request_count", null) != null && lookup(rule.value["rate_limit_options"], "ban_http_request_interval_sec", null) != null ? ["ban_threshold"] : []
            content {
              count        = lookup(rule.value["rate_limit_options"], "ban_http_request_count")
              interval_sec = lookup(rule.value["rate_limit_options"], "ban_http_request_interval_sec")
            }
          }

        }
      }

      # Optional preconfigured_waf_config Block if preconfigured_waf_config_exclusion is provided
      dynamic "preconfigured_waf_config" {
        for_each = rule.value.preconfigured_waf_config_exclusions == null ? [] : ["preconfigured_waf_config_exclusions"] #rule.value.preconfigured_waf_config_exclusions
        content {
          dynamic "exclusion" {
            for_each = rule.value.preconfigured_waf_config_exclusions
            content {
              target_rule_set = exclusion.value.target_rule_set
              target_rule_ids = exclusion.value.target_rule_ids
              dynamic "request_header" {
                for_each = exclusion.value.request_header == null ? {} : { for x in exclusion.value.request_header : "${x.operator}-${base64encode(coalesce(x.value, "test"))}" => x }
                content {
                  operator = request_header.value.operator
                  value    = request_header.value.operator == "EQUALS_ANY" ? null : request_header.value.value
                }
              }
              dynamic "request_cookie" {
                for_each = exclusion.value.request_cookie == null ? {} : { for x in exclusion.value.request_cookie : "${x.operator}-${base64encode(coalesce(x.value, "test"))}" => x }
                content {
                  operator = request_cookie.value.operator
                  value    = request_cookie.value.operator == "EQUALS_ANY" ? null : request_cookie.value.value
                }
              }
              dynamic "request_uri" {
                for_each = exclusion.value.request_uri == null ? {} : { for x in exclusion.value.request_uri : "${x.operator}-${base64encode(coalesce(x.value, "test"))}" => x }
                content {
                  operator = request_uri.value.operator
                  value    = request_uri.value.operator == "EQUALS_ANY" ? null : request_uri.value.value
                }
              }
              dynamic "request_query_param" {
                for_each = exclusion.value.request_query_param == null ? {} : { for x in exclusion.value.request_query_param : "${x.operator}-${base64encode(coalesce(x.value, "test"))}" => x }
                content {
                  operator = request_query_param.value.operator
                  value    = request_query_param.value.operator == "EQUALS_ANY" ? null : request_query_param.value.value
                }
              }
            }
          }

        }
      }

    }
  }


  ##### Security Rules IP

  dynamic "rule" {
    for_each = var.security_rules
    content {
      action      = rule.value["action"]
      priority    = rule.value["priority"]
      preview     = rule.value["preview"]
      description = rule.value["description"]
      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = rule.value["src_ip_ranges"]
        }
      }

      # Header Action Block. Only if header_action is provided
      dynamic "header_action" {
        for_each = length(rule.value["header_action"]) == 0 ? [] : ["header_action"]
        content {
          dynamic "request_headers_to_adds" {
            for_each = { for x in rule.value["header_action"] : x.header_name => x }
            content {
              header_name  = request_headers_to_adds.value.header_name
              header_value = request_headers_to_adds.value.header_value
            }
          }
        }
      }

      ### Redirect option. Execute only if Action is "redirect"
      dynamic "redirect_options" {
        for_each = rule.value["action"] == "redirect" ? ["redirect"] : []
        content {
          type   = rule.value["redirect_type"]
          target = rule.value["redirect_type"] == "EXTERNAL_302" ? rule.value["redirect_target"] : null
        }
      }

      ### Rate limit. Execute only if Action is "rate_based_ban" or "throttle"
      dynamic "rate_limit_options" {
        for_each = rule.value["action"] == "rate_based_ban" || rule.value["action"] == "throttle" ? ["rate_limits"] : []
        content {
          conform_action      = "allow"
          ban_duration_sec    = rule.value["action"] == "rate_based_ban" ? lookup(rule.value["rate_limit_options"], "ban_duration_sec") : null
          exceed_action       = lookup(rule.value["rate_limit_options"], "exceed_action")
          enforce_on_key      = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(rule.value["rate_limit_options"], "enforce_on_key", null) : ""
          enforce_on_key_name = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(rule.value["rate_limit_options"], "enforce_on_key_name", null) : null

          dynamic "enforce_on_key_configs" {
            for_each = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? {} : { for x in lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") : x.enforce_on_key_type => x }
            content {
              enforce_on_key_type = enforce_on_key_configs.value.enforce_on_key_type
              enforce_on_key_name = enforce_on_key_configs.value.enforce_on_key_name
            }
          }

          ## Required for all rate limit options
          dynamic "rate_limit_threshold" {
            for_each = rule.value["action"] == "rate_based_ban" || rule.value["action"] == "throttle" ? ["rate_limit_options"] : []
            content {
              count        = rule.value["rate_limit_options"].rate_limit_http_request_count
              interval_sec = rule.value["rate_limit_options"].rate_limit_http_request_interval_sec
            }
          }

          ## Optional. Can be provided for for rate based ban. Not needed for throttle
          dynamic "ban_threshold" {
            for_each = rule.value["action"] == "rate_based_ban" && lookup(rule.value["rate_limit_options"], "ban_http_request_count", null) != null && lookup(rule.value["rate_limit_options"], "ban_http_request_interval_sec", null) != null ? ["ban_threshold"] : []
            content {
              count        = lookup(rule.value["rate_limit_options"], "ban_http_request_count")
              interval_sec = lookup(rule.value["rate_limit_options"], "ban_http_request_interval_sec")
            }
          }

        }
      }

    }
  }

  ##### Custom Rules

  dynamic "rule" {
    for_each = var.custom_rules
    content {
      action      = rule.value["action"]
      priority    = rule.value["priority"]
      preview     = rule.value["preview"]
      description = rule.value["description"]

      match {
        expr {
          expression = rule.value["expression"]
        }
        dynamic "expr_options" {
          for_each = try(rule.value.recaptcha_action_token_site_keys, null) == null && try(rule.value.recaptcha_session_token_site_keys, null) == null ? [] : ["expr_options"]
          content {
            recaptcha_options {
              action_token_site_keys  = try(rule.value.recaptcha_action_token_site_keys, null)
              session_token_site_keys = try(rule.value.recaptcha_session_token_site_keys, null)
            }
          }
        }
      }

      # Header Action Block. Only if header_action is provided
      dynamic "header_action" {
        for_each = length(rule.value["header_action"]) == 0 ? [] : ["header_action"]
        content {
          dynamic "request_headers_to_adds" {
            for_each = { for x in rule.value["header_action"] : x.header_name => x }
            content {
              header_name  = request_headers_to_adds.value.header_name
              header_value = request_headers_to_adds.value.header_value
            }
          }
        }
      }

      # Redirect option block
      dynamic "redirect_options" {
        for_each = rule.value["action"] == "redirect" ? ["redirect"] : []
        content {
          type   = rule.value["redirect_type"]
          target = rule.value["redirect_type"] == "EXTERNAL_302" ? rule.value["redirect_target"] : null
        }
      }

      ### Rate limit. Execute only if Action is "rate_based_ban" or "throttle"
      dynamic "rate_limit_options" {
        for_each = rule.value["action"] == "rate_based_ban" || rule.value["action"] == "throttle" ? ["rate_limits"] : []
        content {
          conform_action      = "allow"
          ban_duration_sec    = rule.value["action"] == "rate_based_ban" ? lookup(rule.value["rate_limit_options"], "ban_duration_sec") : null
          exceed_action       = lookup(rule.value["rate_limit_options"], "exceed_action")
          enforce_on_key      = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(rule.value["rate_limit_options"], "enforce_on_key", null) : ""
          enforce_on_key_name = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(rule.value["rate_limit_options"], "enforce_on_key_name", null) : null

          dynamic "enforce_on_key_configs" {
            for_each = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? {} : { for x in lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") : x.enforce_on_key_type => x }
            content {
              enforce_on_key_type = enforce_on_key_configs.value.enforce_on_key_type
              enforce_on_key_name = enforce_on_key_configs.value.enforce_on_key_name
            }
          }

          ## Required for all rate limit options
          dynamic "rate_limit_threshold" {
            for_each = rule.value["action"] == "rate_based_ban" || rule.value["action"] == "throttle" ? ["rate_limit_options"] : []
            content {
              count        = rule.value["rate_limit_options"].rate_limit_http_request_count
              interval_sec = rule.value["rate_limit_options"].rate_limit_http_request_interval_sec
            }
          }

          ## Optional. Can be provided for for rate based ban. Not needed for throttle
          dynamic "ban_threshold" {
            for_each = rule.value["action"] == "rate_based_ban" && lookup(rule.value["rate_limit_options"], "ban_http_request_count", null) != null && lookup(rule.value["rate_limit_options"], "ban_http_request_interval_sec", null) != null ? ["ban_threshold"] : []
            content {
              count        = lookup(rule.value["rate_limit_options"], "ban_http_request_count")
              interval_sec = lookup(rule.value["rate_limit_options"], "ban_http_request_interval_sec")
            }
          }

        }
      }

      # Optional preconfigured_waf_config Block if preconfigured_waf_config_exclusion is provided
      dynamic "preconfigured_waf_config" {
        for_each = rule.value.preconfigured_waf_config_exclusions == null ? [] : ["preconfigured_waf_config_exclusions"] #rule.value.preconfigured_waf_config_exclusions
        content {
          dynamic "exclusion" {
            for_each = rule.value.preconfigured_waf_config_exclusions
            content {
              target_rule_set = exclusion.value.target_rule_set
              target_rule_ids = exclusion.value.target_rule_ids
              dynamic "request_header" {
                for_each = exclusion.value.request_header == null ? {} : { for x in exclusion.value.request_header : "${x.operator}-${base64encode(coalesce(x.value, "test"))}" => x }
                content {
                  operator = request_header.value.operator
                  value    = request_header.value.operator == "EQUALS_ANY" ? null : request_header.value.value
                }
              }
              dynamic "request_cookie" {
                for_each = exclusion.value.request_cookie == null ? {} : { for x in exclusion.value.request_cookie : "${x.operator}-${base64encode(coalesce(x.value, "test"))}" => x }
                content {
                  operator = request_cookie.value.operator
                  value    = request_cookie.value.operator == "EQUALS_ANY" ? null : request_cookie.value.value
                }
              }
              dynamic "request_uri" {
                for_each = exclusion.value.request_uri == null ? {} : { for x in exclusion.value.request_uri : "${x.operator}-${base64encode(coalesce(x.value, "test"))}" => x }
                content {
                  operator = request_uri.value.operator
                  value    = request_uri.value.operator == "EQUALS_ANY" ? null : request_uri.value.value
                }
              }
              dynamic "request_query_param" {
                for_each = exclusion.value.request_query_param == null ? {} : { for x in exclusion.value.request_query_param : "${x.operator}-${base64encode(coalesce(x.value, "test"))}" => x }
                content {
                  operator = request_query_param.value.operator
                  value    = request_query_param.value.operator == "EQUALS_ANY" ? null : request_query_param.value.value
                }
              }
            }
          }

        }
      }


    }
  }

  ##### Threat Intelligence Rules

  dynamic "rule" {
    for_each = var.threat_intelligence_rules
    content {
      action      = rule.value["action"]
      priority    = rule.value["priority"]
      preview     = rule.value["preview"]
      description = rule.value["description"]

      match {
        expr {
          expression = lookup(rule.value, "exclude_ip", null) == null ? "evaluateThreatIntelligence('${rule.value["feed"]}')" : "evaluateThreatIntelligence('${rule.value["feed"]}', ${rule.value["exclude_ip"]})"
        }
      }

      # Header Action Block. Only if header_action is provided
      dynamic "header_action" {
        for_each = length(rule.value["header_action"]) == 0 ? [] : ["header_action"]
        content {
          dynamic "request_headers_to_adds" {
            for_each = { for x in rule.value["header_action"] : x.header_name => x }
            content {
              header_name  = request_headers_to_adds.value.header_name
              header_value = request_headers_to_adds.value.header_value
            }
          }
        }
      }

      ### Rate limit. Execute only if Action is "rate_based_ban" or "throttle"
      dynamic "rate_limit_options" {
        for_each = rule.value["action"] == "rate_based_ban" || rule.value["action"] == "throttle" ? ["rate_limits"] : []
        content {
          conform_action      = "allow"
          ban_duration_sec    = rule.value["action"] == "rate_based_ban" ? lookup(rule.value["rate_limit_options"], "ban_duration_sec") : null
          exceed_action       = lookup(rule.value["rate_limit_options"], "exceed_action")
          enforce_on_key      = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(rule.value["rate_limit_options"], "enforce_on_key", null) : null
          enforce_on_key_name = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(rule.value["rate_limit_options"], "enforce_on_key_name", null) : null

          dynamic "enforce_on_key_configs" {
            for_each = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? {} : { for x in lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") : x.enforce_on_key_type => x }
            content {
              enforce_on_key_type = enforce_on_key_configs.value.enforce_on_key_type
              enforce_on_key_name = enforce_on_key_configs.value.enforce_on_key_name
            }
          }

          ## Required for all rate limit options
          dynamic "rate_limit_threshold" {
            for_each = rule.value["action"] == "rate_based_ban" || rule.value["action"] == "throttle" ? ["rate_limit_options"] : []
            content {
              count        = rule.value["rate_limit_options"].rate_limit_http_request_count
              interval_sec = rule.value["rate_limit_options"].rate_limit_http_request_interval_sec
            }
          }

          ## Optional. Can be provided for for rate based ban. Not needed for throttle
          dynamic "ban_threshold" {
            for_each = rule.value["action"] == "rate_based_ban" && lookup(rule.value["rate_limit_options"], "ban_http_request_count", null) != null && lookup(rule.value["rate_limit_options"], "ban_http_request_interval_sec", null) != null ? ["ban_threshold"] : []
            content {
              count        = lookup(rule.value["rate_limit_options"], "ban_http_request_count")
              interval_sec = lookup(rule.value["rate_limit_options"], "ban_http_request_interval_sec")
            }
          }

        }
      }
    }
  }


  ##### Default Rule
  rule {
    action      = var.default_rule_action
    priority    = "2147483647"
    description = "Default rule, higher priority overrides it"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }

  # Cloud Armor Adaptive Protection is currently not supported for edge or network policies
  dynamic "adaptive_protection_config" {
    for_each = var.type != "CLOUD_ARMOR_EDGE" ? ["adaptive_protection_config"] : []
    content {
      layer_7_ddos_defense_config {
        enable          = var.layer_7_ddos_defense_enable
        rule_visibility = var.layer_7_ddos_defense_rule_visibility
        dynamic "threshold_configs" {
          for_each = !var.layer_7_ddos_defense_enable && var.layer_7_ddos_defense_threshold_configs == null ? {} : { for x in var.layer_7_ddos_defense_threshold_configs : x.name => x }
          content {
            name                                    = threshold_configs.value["name"]
            auto_deploy_load_threshold              = threshold_configs.value["auto_deploy_load_threshold"]
            auto_deploy_confidence_threshold        = threshold_configs.value["auto_deploy_confidence_threshold"]
            auto_deploy_impacted_baseline_threshold = threshold_configs.value["auto_deploy_impacted_baseline_threshold"]
            auto_deploy_expiration_sec              = threshold_configs.value["auto_deploy_expiration_sec"]
            detection_load_threshold                = threshold_configs.value["detection_load_threshold"]
            detection_absolute_qps                  = threshold_configs.value["detection_absolute_qps"]
            detection_relative_to_baseline_qps      = threshold_configs.value["detection_relative_to_baseline_qps"]
            dynamic "traffic_granularity_configs" {
              for_each = threshold_configs.value["traffic_granularity_configs"] == null ? {} : { for x in threshold_configs.value["traffic_granularity_configs"] : x.type => x }
              content {
                type                     = traffic_granularity_configs.value["type"]
                value                    = traffic_granularity_configs.value["value"]
                enable_each_unique_value = traffic_granularity_configs.value["enable_each_unique_value"]
              }
            }
          }
        }
      }
      dynamic "auto_deploy_config" {
        for_each = var.adaptive_protection_auto_deploy.enable && (var.adaptive_protection_auto_deploy.load_threshold != null || var.adaptive_protection_auto_deploy.confidence_threshold != null || var.adaptive_protection_auto_deploy.impacted_baseline_threshold != null || var.adaptive_protection_auto_deploy.expiration_sec != null) ? { auto_deploy = var.adaptive_protection_auto_deploy } : {}
        content {
          load_threshold              = auto_deploy_config.value["load_threshold"]
          confidence_threshold        = auto_deploy_config.value["confidence_threshold"]
          impacted_baseline_threshold = auto_deploy_config.value["impacted_baseline_threshold"]
          expiration_sec              = auto_deploy_config.value["expiration_sec"]
        }

      }
    }
  }

  ##### Automatic Adaptive protection rule deploy

  dynamic "rule" {
    for_each = var.layer_7_ddos_defense_enable && var.adaptive_protection_auto_deploy.enable && var.type != "CLOUD_ARMOR_EDGE" ? { auto_deploy = var.adaptive_protection_auto_deploy } : {}
    content {
      action      = rule.value["action"]
      priority    = rule.value["priority"]
      preview     = rule.value["preview"]
      description = rule.value["description"]

      match {
        expr {
          expression = "evaluateAdaptiveProtectionAutoDeploy()"
        }
      }

      # Redirect option block
      dynamic "redirect_options" {
        for_each = rule.value["action"] == "redirect" ? ["redirect"] : []
        content {
          type   = rule.value["redirect_type"]
          target = rule.value["redirect_type"] == "EXTERNAL_302" ? rule.value["redirect_target"] : null
        }
      }

      ### Rate limit. Execute only if Action is "rate_based_ban" or "throttle"
      dynamic "rate_limit_options" {
        for_each = rule.value["action"] == "rate_based_ban" || rule.value["action"] == "throttle" ? ["rate_limits"] : []
        content {
          conform_action      = "allow"
          ban_duration_sec    = rule.value["action"] == "rate_based_ban" ? lookup(rule.value["rate_limit_options"], "ban_duration_sec") : null
          exceed_action       = lookup(rule.value["rate_limit_options"], "exceed_action")
          enforce_on_key      = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(rule.value["rate_limit_options"], "enforce_on_key", null) : ""
          enforce_on_key_name = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(rule.value["rate_limit_options"], "enforce_on_key_name", null) : null

          dynamic "enforce_on_key_configs" {
            for_each = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? {} : { for x in lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") : x.enforce_on_key_type => x }
            content {
              enforce_on_key_type = enforce_on_key_configs.value.enforce_on_key_type
              enforce_on_key_name = enforce_on_key_configs.value.enforce_on_key_name
            }
          }

          ## Required for all rate limit options
          dynamic "rate_limit_threshold" {
            for_each = rule.value["action"] == "rate_based_ban" || rule.value["action"] == "throttle" ? ["rate_limit_options"] : []
            content {
              count        = rule.value["rate_limit_options"].rate_limit_http_request_count
              interval_sec = rule.value["rate_limit_options"].rate_limit_http_request_interval_sec
            }
          }

          ## Optional. Can be provided for for rate based ban. Not needed for throttle
          dynamic "ban_threshold" {
            for_each = rule.value["action"] == "rate_based_ban" && lookup(rule.value["rate_limit_options"], "ban_http_request_count", null) != null && lookup(rule.value["rate_limit_options"], "ban_http_request_interval_sec", null) != null ? ["ban_threshold"] : []
            content {
              count        = lookup(rule.value["rate_limit_options"], "ban_http_request_count")
              interval_sec = lookup(rule.value["rate_limit_options"], "ban_http_request_interval_sec")
            }
          }

        }
      }

    }
  }

}
