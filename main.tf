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
  pre_configured_rules_expr = {
    for name, p in var.pre_configured_rules : name => (
      length(p.include_target_rule_ids) > 0
      ? "evaluatePreconfiguredWaf('${p.target_rule_set}', {'sensitivity': 0, 'opt_in_rule_ids': ['${join("','", p.include_target_rule_ids)}']})"
      : length(p.exclude_target_rule_ids) > 0
      ? "evaluatePreconfiguredWaf('${p.target_rule_set}', {'sensitivity': ${p.sensitivity_level}, 'opt_out_rule_ids': ['${join("','", p.exclude_target_rule_ids)}']})"
      : "evaluatePreconfiguredWaf('${p.target_rule_set}', {'sensitivity': ${p.sensitivity_level}})"
    )
  }

  # Normalize all 5 dynamic rule types into a single schema
  all_rules = merge(
    # 1. Preconfigured WAF Rules
    {
      for k, r in var.pre_configured_rules : "pre_configured/${k}" => {
        action                              = r.action
        priority                            = r.priority
        preview                             = r.preview
        description                         = r.description
        versioned_expr                      = null
        src_ip_ranges                       = null
        expression                          = local.pre_configured_rules_expr[k]
        recaptcha_action_token_site_keys    = null
        recaptcha_session_token_site_keys   = null
        header_action                       = r.header_action
        redirect_type                       = r.redirect_type
        redirect_target                     = r.redirect_target
        rate_limit_options                  = r.rate_limit_options
        preconfigured_waf_config_exclusions = r.preconfigured_waf_config_exclusions
      }
    },
    # 2. IP Security Rules
    {
      for k, r in var.security_rules : "security/${k}" => {
        action                              = r.action
        priority                            = r.priority
        preview                             = r.preview
        description                         = r.description
        versioned_expr                      = "SRC_IPS_V1"
        src_ip_ranges                       = r.src_ip_ranges
        expression                          = null
        recaptcha_action_token_site_keys    = null
        recaptcha_session_token_site_keys   = null
        header_action                       = r.header_action
        redirect_type                       = r.redirect_type
        redirect_target                     = r.redirect_target
        rate_limit_options                  = r.rate_limit_options
        preconfigured_waf_config_exclusions = null
      }
    },
    # 3. Custom CEL Expression Rules
    {
      for k, r in var.custom_rules : "custom/${k}" => {
        action                              = r.action
        priority                            = r.priority
        preview                             = r.preview
        description                         = r.description
        versioned_expr                      = null
        src_ip_ranges                       = null
        expression                          = r.expression
        recaptcha_action_token_site_keys    = try(r.recaptcha_action_token_site_keys, null)
        recaptcha_session_token_site_keys   = try(r.recaptcha_session_token_site_keys, null)
        header_action                       = r.header_action
        redirect_type                       = r.redirect_type
        redirect_target                     = r.redirect_target
        rate_limit_options                  = r.rate_limit_options
        preconfigured_waf_config_exclusions = r.preconfigured_waf_config_exclusions
      }
    },
    # 4. Threat Intelligence Rules
    {
      for k, r in var.threat_intelligence_rules : "threat_intel/${k}" => {
        action                              = r.action
        priority                            = r.priority
        preview                             = r.preview
        description                         = r.description
        versioned_expr                      = null
        src_ip_ranges                       = null
        expression                          = try(r.exclude_ip, null) == null ? "evaluateThreatIntelligence('${r.feed}')" : "evaluateThreatIntelligence('${r.feed}', ${r.exclude_ip})"
        recaptcha_action_token_site_keys    = null
        recaptcha_session_token_site_keys   = null
        header_action                       = r.header_action
        redirect_type                       = null
        redirect_target                     = null
        rate_limit_options                  = r.rate_limit_options
        preconfigured_waf_config_exclusions = null
      }
    },
    # 5. Adaptive Protection Auto-Deploy Rule
    var.layer_7_ddos_defense_enable && var.adaptive_protection_auto_deploy.enable && var.type != "CLOUD_ARMOR_EDGE" ? {
      "auto_deploy" = {
        action                              = var.adaptive_protection_auto_deploy.action
        priority                            = var.adaptive_protection_auto_deploy.priority
        preview                             = var.adaptive_protection_auto_deploy.preview
        description                         = var.adaptive_protection_auto_deploy.description
        versioned_expr                      = null
        src_ip_ranges                       = null
        expression                          = "evaluateAdaptiveProtectionAutoDeploy()"
        recaptcha_action_token_site_keys    = null
        recaptcha_session_token_site_keys   = null
        header_action                       = []
        redirect_type                       = var.adaptive_protection_auto_deploy.redirect_type
        redirect_target                     = var.adaptive_protection_auto_deploy.redirect_target
        rate_limit_options                  = var.adaptive_protection_auto_deploy.rate_limit_options
        preconfigured_waf_config_exclusions = null
      }
    } : {}
  )
}

resource "google_compute_security_policy" "policy" {
  provider    = google-beta
  name        = var.name
  description = var.description
  project     = var.project_id
  type        = var.type
  labels      = var.labels

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
      json_parsing                 = var.json_parsing
      log_level                    = var.log_level
      user_ip_request_headers      = var.user_ip_request_headers
      request_body_inspection_size = var.request_body_inspection_size

      dynamic "json_custom_config" {
        for_each = var.json_parsing == "STANDARD" && length(var.json_custom_config_content_types) > 0 ? ["json_custom_config"] : []
        content {
          content_types = var.json_custom_config_content_types
        }
      }
    }
  }

  ##### All Configured Rules (Preconfigured, IP, Custom, Threat Intel, Auto-Deploy)
  dynamic "rule" {
    for_each = local.all_rules
    content {
      action      = rule.value.action
      priority    = rule.value.priority
      preview     = rule.value.preview
      description = rule.value.description

      match {
        versioned_expr = rule.value.versioned_expr

        dynamic "config" {
          for_each = rule.value.src_ip_ranges != null ? ["config"] : []
          content {
            src_ip_ranges = rule.value.src_ip_ranges
          }
        }

        dynamic "expr" {
          for_each = rule.value.expression != null ? ["expr"] : []
          content {
            expression = rule.value.expression
          }
        }

        dynamic "expr_options" {
          for_each = rule.value.recaptcha_action_token_site_keys != null || rule.value.recaptcha_session_token_site_keys != null ? ["expr_options"] : []
          content {
            recaptcha_options {
              action_token_site_keys  = rule.value.recaptcha_action_token_site_keys
              session_token_site_keys = rule.value.recaptcha_session_token_site_keys
            }
          }
        }
      }

      # Header Action Block
      dynamic "header_action" {
        for_each = length(rule.value.header_action) > 0 ? ["header_action"] : []
        content {
          dynamic "request_headers_to_adds" {
            for_each = rule.value.header_action
            content {
              header_name  = request_headers_to_adds.value.header_name
              header_value = request_headers_to_adds.value.header_value
            }
          }
        }
      }

      # Redirect Options Block
      dynamic "redirect_options" {
        for_each = rule.value.action == "redirect" ? ["redirect"] : []
        content {
          type   = rule.value.redirect_type
          target = rule.value.redirect_type == "EXTERNAL_302" ? rule.value.redirect_target : null
        }
      }

      # Rate Limit Options Block
      dynamic "rate_limit_options" {
        for_each = contains(["rate_based_ban", "throttle"], rule.value.action) ? ["rate_limits"] : []
        content {
          conform_action      = "allow"
          ban_duration_sec    = rule.value.action == "rate_based_ban" ? try(rule.value.rate_limit_options.ban_duration_sec, null) : null
          exceed_action       = try(rule.value.rate_limit_options.exceed_action, null)
          enforce_on_key      = try(rule.value.rate_limit_options.enforce_on_key_configs, null) == null ? try(rule.value.rate_limit_options.enforce_on_key, null) : ""
          enforce_on_key_name = try(rule.value.rate_limit_options.enforce_on_key_configs, null) == null ? try(rule.value.rate_limit_options.enforce_on_key_name, null) : null

          dynamic "enforce_on_key_configs" {
            for_each = try(rule.value.rate_limit_options.enforce_on_key_configs, null) != null ? rule.value.rate_limit_options.enforce_on_key_configs : []
            content {
              enforce_on_key_type = enforce_on_key_configs.value.enforce_on_key_type
              enforce_on_key_name = try(enforce_on_key_configs.value.enforce_on_key_name, null)
            }
          }

          rate_limit_threshold {
            count        = rule.value.rate_limit_options.rate_limit_http_request_count
            interval_sec = rule.value.rate_limit_options.rate_limit_http_request_interval_sec
          }

          dynamic "ban_threshold" {
            for_each = (
              rule.value.action == "rate_based_ban" &&
              try(rule.value.rate_limit_options.ban_http_request_count, null) != null &&
              try(rule.value.rate_limit_options.ban_http_request_interval_sec, null) != null
            ) ? ["ban_threshold"] : []
            content {
              count        = rule.value.rate_limit_options.ban_http_request_count
              interval_sec = rule.value.rate_limit_options.ban_http_request_interval_sec
            }
          }

          dynamic "exceed_redirect_options" {
            for_each = try(rule.value.rate_limit_options.exceed_redirect_options, null) != null ? ["exceed_redirect_options"] : []
            content {
              type   = rule.value.rate_limit_options.exceed_redirect_options.type
              target = try(rule.value.rate_limit_options.exceed_redirect_options.target, null)
            }
          }
        }
      }

      # Preconfigured WAF Config Exclusions Block
      dynamic "preconfigured_waf_config" {
        for_each = rule.value.preconfigured_waf_config_exclusions != null ? ["preconfigured_waf_config"] : []
        content {
          dynamic "exclusion" {
            for_each = rule.value.preconfigured_waf_config_exclusions
            content {
              target_rule_set = exclusion.value.target_rule_set
              target_rule_ids = exclusion.value.target_rule_ids

              dynamic "request_header" {
                for_each = exclusion.value.request_header != null ? exclusion.value.request_header : []
                content {
                  operator = request_header.value.operator
                  value    = request_header.value.operator == "EQUALS_ANY" ? null : request_header.value.value
                }
              }
              dynamic "request_cookie" {
                for_each = exclusion.value.request_cookie != null ? exclusion.value.request_cookie : []
                content {
                  operator = request_cookie.value.operator
                  value    = request_cookie.value.operator == "EQUALS_ANY" ? null : request_cookie.value.value
                }
              }
              dynamic "request_uri" {
                for_each = exclusion.value.request_uri != null ? exclusion.value.request_uri : []
                content {
                  operator = request_uri.value.operator
                  value    = request_uri.value.operator == "EQUALS_ANY" ? null : request_uri.value.value
                }
              }
              dynamic "request_query_param" {
                for_each = exclusion.value.request_query_param != null ? exclusion.value.request_query_param : []
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


  ##### Default Rule
  rule {
    action      = var.default_rule_action
    priority    = 2147483647
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
          for_each = var.layer_7_ddos_defense_enable ? { for x in coalesce(var.layer_7_ddos_defense_threshold_configs, []) : x.name => x } : {}
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
}
