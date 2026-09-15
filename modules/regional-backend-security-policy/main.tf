/**
 * Copyright 2024 Google LLC
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
    for name, p in var.pre_configured_rules : name => {
      expression = (
        length(p.include_target_rule_ids) > 0
        ? "evaluatePreconfiguredWaf('${p.target_rule_set}', {'sensitivity': 0, 'opt_in_rule_ids': ['${join("','", p.include_target_rule_ids)}']})"
        : length(p.exclude_target_rule_ids) > 0
        ? "evaluatePreconfiguredWaf('${p.target_rule_set}', {'sensitivity': ${p.sensitivity_level}, 'opt_out_rule_ids': ['${join("','", p.exclude_target_rule_ids)}']})"
        : "evaluatePreconfiguredWaf('${p.target_rule_set}', {'sensitivity': ${p.sensitivity_level}})"
      )
    }
  }

  advanced_options_config_enable = var.json_parsing != null || var.log_level != null || var.request_body_inspection_size != null || length(var.user_ip_request_headers) > 0 || length(var.json_custom_content_types) > 0
}


resource "google_compute_region_security_policy" "security_policy" {
  provider    = google-beta
  project     = var.project_id
  name        = var.name
  description = var.description
  type        = var.type
  region      = var.region

  dynamic "advanced_options_config" {
    for_each = local.advanced_options_config_enable ? ["advanced_options_config"] : []
    content {
      json_parsing                 = var.json_parsing
      log_level                    = var.log_level
      request_body_inspection_size = var.request_body_inspection_size
      user_ip_request_headers      = length(var.user_ip_request_headers) > 0 ? var.user_ip_request_headers : null
      dynamic "json_custom_config" {
        for_each = length(var.json_custom_content_types) > 0 ? ["json_custom_config"] : []
        content {
          content_types = var.json_custom_content_types
        }
      }
    }
  }
}

##### Security Rules Block IP addresses

resource "google_compute_region_security_policy_rule" "security_rules" {
  provider        = google-beta
  for_each        = var.security_rules == null ? {} : { for x in var.security_rules : x.priority => x }
  project         = var.project_id
  region          = var.region
  security_policy = google_compute_region_security_policy.security_policy.name

  action      = each.value["action"]
  priority    = each.value["priority"]
  preview     = each.value["preview"]
  description = each.value["description"]
  match {
    versioned_expr = "SRC_IPS_V1"
    config {
      src_ip_ranges = each.value["src_ip_ranges"]
    }
  }

  ### Rate limit. Execute only if Action is "rate_based_ban" or "throttle"
  dynamic "rate_limit_options" {
    for_each = each.value["action"] == "rate_based_ban" || each.value["action"] == "throttle" ? ["rate_limits"] : []
    content {
      conform_action      = "allow"
      ban_duration_sec    = each.value["action"] == "rate_based_ban" ? lookup(each.value["rate_limit_options"], "ban_duration_sec") : null
      exceed_action       = lookup(each.value["rate_limit_options"], "exceed_action")
      enforce_on_key      = lookup(each.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(each.value["rate_limit_options"], "enforce_on_key", null) : ""
      enforce_on_key_name = lookup(each.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(each.value["rate_limit_options"], "enforce_on_key_name", null) : null

      dynamic "enforce_on_key_configs" {
        for_each = coalesce(try(each.value.rate_limit_options.enforce_on_key_configs, null), [])
        content {
          enforce_on_key_type = enforce_on_key_configs.value.enforce_on_key_type
          enforce_on_key_name = try(enforce_on_key_configs.value.enforce_on_key_name, null)
        }
      }

      ## Required for all rate limit options
      dynamic "rate_limit_threshold" {
        for_each = each.value["action"] == "rate_based_ban" || each.value["action"] == "throttle" ? ["rate_limit_options"] : []
        content {
          count        = each.value["rate_limit_options"].rate_limit_http_request_count
          interval_sec = each.value["rate_limit_options"].rate_limit_http_request_interval_sec
        }
      }

      ## Optional. Can be provided for for rate based ban. Not needed for throttle
      dynamic "ban_threshold" {
        for_each = each.value["action"] == "rate_based_ban" && lookup(each.value["rate_limit_options"], "ban_http_request_count", null) != null && lookup(each.value["rate_limit_options"], "ban_http_request_interval_sec", null) != null ? ["ban_threshold"] : []
        content {
          count        = lookup(each.value["rate_limit_options"], "ban_http_request_count")
          interval_sec = lookup(each.value["rate_limit_options"], "ban_http_request_interval_sec")
        }
      }
    }
  }
}


##### Custom Rules

resource "google_compute_region_security_policy_rule" "custom_rules" {
  provider        = google-beta
  for_each        = var.custom_rules == null ? {} : { for x in var.custom_rules : x.priority => x }
  project         = var.project_id
  region          = var.region
  security_policy = google_compute_region_security_policy.security_policy.name

  action      = each.value["action"]
  priority    = each.value["priority"]
  preview     = each.value["preview"]
  description = each.value["description"]
  match {
    expr {
      expression = each.value["expression"]
    }
  }

  ### Rate limit. Execute only if Action is "rate_based_ban" or "throttle"
  dynamic "rate_limit_options" {
    for_each = each.value["action"] == "rate_based_ban" || each.value["action"] == "throttle" ? ["rate_limits"] : []
    content {
      conform_action      = "allow"
      ban_duration_sec    = each.value["action"] == "rate_based_ban" ? lookup(each.value["rate_limit_options"], "ban_duration_sec") : null
      exceed_action       = lookup(each.value["rate_limit_options"], "exceed_action")
      enforce_on_key      = lookup(each.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(each.value["rate_limit_options"], "enforce_on_key", null) : ""
      enforce_on_key_name = lookup(each.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(each.value["rate_limit_options"], "enforce_on_key_name", null) : null

      dynamic "enforce_on_key_configs" {
        for_each = coalesce(try(each.value.rate_limit_options.enforce_on_key_configs, null), [])
        content {
          enforce_on_key_type = enforce_on_key_configs.value.enforce_on_key_type
          enforce_on_key_name = try(enforce_on_key_configs.value.enforce_on_key_name, null)
        }
      }

      ## Required for all rate limit options
      dynamic "rate_limit_threshold" {
        for_each = each.value["action"] == "rate_based_ban" || each.value["action"] == "throttle" ? ["rate_limit_options"] : []
        content {
          count        = each.value["rate_limit_options"].rate_limit_http_request_count
          interval_sec = each.value["rate_limit_options"].rate_limit_http_request_interval_sec
        }
      }

      ## Optional. Can be provided for for rate based ban. Not needed for throttle
      dynamic "ban_threshold" {
        for_each = each.value["action"] == "rate_based_ban" && lookup(each.value["rate_limit_options"], "ban_http_request_count", null) != null && lookup(each.value["rate_limit_options"], "ban_http_request_interval_sec", null) != null ? ["ban_threshold"] : []
        content {
          count        = lookup(each.value["rate_limit_options"], "ban_http_request_count")
          interval_sec = lookup(each.value["rate_limit_options"], "ban_http_request_interval_sec")
        }
      }
    }
  }
  # Optional preconfigured_waf_config Block if preconfigured_waf_config_exclusion is provided
  dynamic "preconfigured_waf_config" {
    for_each = each.value.preconfigured_waf_config_exclusions == null ? [] : ["preconfigured_waf_config_exclusions"] #each.value.preconfigured_waf_config_exclusions
    content {
      dynamic "exclusion" {
        for_each = each.value.preconfigured_waf_config_exclusions
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




##### Preconfigured WAF Rules

resource "google_compute_region_security_policy_rule" "pre_configured_rules" {
  provider        = google-beta
  for_each        = var.pre_configured_rules
  project         = var.project_id
  region          = var.region
  security_policy = google_compute_region_security_policy.security_policy.name

  action      = each.value["action"]
  priority    = each.value["priority"]
  preview     = each.value["preview"]
  description = each.value["description"]
  match {
    expr {
      expression = local.pre_configured_rules_expr[each.key].expression
    }
  }

  ### Rate limit. Execute only if Action is "rate_based_ban" or "throttle"
  dynamic "rate_limit_options" {
    for_each = each.value["action"] == "rate_based_ban" || each.value["action"] == "throttle" ? ["rate_limits"] : []
    content {
      conform_action      = "allow"
      ban_duration_sec    = each.value["action"] == "rate_based_ban" ? lookup(each.value["rate_limit_options"], "ban_duration_sec") : null
      exceed_action       = lookup(each.value["rate_limit_options"], "exceed_action")
      enforce_on_key      = lookup(each.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(each.value["rate_limit_options"], "enforce_on_key", null) : ""
      enforce_on_key_name = lookup(each.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(each.value["rate_limit_options"], "enforce_on_key_name", null) : null

      dynamic "enforce_on_key_configs" {
        for_each = coalesce(try(each.value.rate_limit_options.enforce_on_key_configs, null), [])
        content {
          enforce_on_key_type = enforce_on_key_configs.value.enforce_on_key_type
          enforce_on_key_name = try(enforce_on_key_configs.value.enforce_on_key_name, null)
        }
      }

      ## Required for all rate limit options
      dynamic "rate_limit_threshold" {
        for_each = each.value["action"] == "rate_based_ban" || each.value["action"] == "throttle" ? ["rate_limit_options"] : []
        content {
          count        = each.value["rate_limit_options"].rate_limit_http_request_count
          interval_sec = each.value["rate_limit_options"].rate_limit_http_request_interval_sec
        }
      }

      ## Optional. Can be provided for for rate based ban. Not needed for throttle
      dynamic "ban_threshold" {
        for_each = each.value["action"] == "rate_based_ban" && lookup(each.value["rate_limit_options"], "ban_http_request_count", null) != null && lookup(each.value["rate_limit_options"], "ban_http_request_interval_sec", null) != null ? ["ban_threshold"] : []
        content {
          count        = lookup(each.value["rate_limit_options"], "ban_http_request_count")
          interval_sec = lookup(each.value["rate_limit_options"], "ban_http_request_interval_sec")
        }
      }
    }
  }
  # Optional preconfigured_waf_config Block if preconfigured_waf_config_exclusion is provided
  dynamic "preconfigured_waf_config" {
    for_each = each.value.preconfigured_waf_config_exclusions == null ? [] : ["preconfigured_waf_config_exclusions"] #each.value.preconfigured_waf_config_exclusions
    content {
      dynamic "exclusion" {
        for_each = each.value.preconfigured_waf_config_exclusions
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

##### Default Rule

resource "google_compute_region_security_policy_rule" "default_rule" {
  provider        = google-beta
  region          = var.region
  project         = var.project_id
  security_policy = google_compute_region_security_policy.security_policy.name
  description     = "default rule"
  action          = var.default_rule_action
  priority        = 2147483647
  match {
    versioned_expr = "SRC_IPS_V1"
    config {
      src_ip_ranges = ["*"]
    }
  }
}
