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


resource "google_compute_region_security_policy" "security_policy" {
  provider    = google-beta
  project     = var.project_id
  name        = var.name
  description = var.description
  type        = var.type
  region      = var.region
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
        for_each = lookup(each.value["rate_limit_options"], "enforce_on_key_configs") == null ? {} : { for x in lookup(each.value["rate_limit_options"], "enforce_on_key_configs") : x.enforce_on_key_type => x }
        content {
          enforce_on_key_type = enforce_on_key_configs.value.enforce_on_key_type
          enforce_on_key_name = enforce_on_key_configs.value.enforce_on_key_name
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
        for_each = lookup(each.value["rate_limit_options"], "enforce_on_key_configs") == null ? {} : { for x in lookup(each.value["rate_limit_options"], "enforce_on_key_configs") : x.enforce_on_key_type => x }
        content {
          enforce_on_key_type = enforce_on_key_configs.value.enforce_on_key_type
          enforce_on_key_name = enforce_on_key_configs.value.enforce_on_key_name
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




##### Preconfigured WAF Rules

resource "google_compute_region_security_policy_rule" "pre_configured_rules" {
  provider        = google-beta
  for_each        = var.pre_configured_rules #var.pre_configured_rules == null ? {} : { for x in var.pre_configured_rules : x.priority => x }
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
        for_each = lookup(each.value["rate_limit_options"], "enforce_on_key_configs") == null ? {} : { for x in lookup(each.value["rate_limit_options"], "enforce_on_key_configs") : x.enforce_on_key_type => x }
        content {
          enforce_on_key_type = enforce_on_key_configs.value.enforce_on_key_type
          enforce_on_key_name = enforce_on_key_configs.value.enforce_on_key_name
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

# dynamic "rule" {
#   for_each = var.pre_configured_rules
#   content {
#     action      = rule.value["action"]
#     priority    = rule.value["priority"]
#     preview     = rule.value["preview"]
#     description = rule.value["description"]

#     match {
#       expr {
#         expression = local.pre_configured_rules_expr[rule.key].expression
#       }
#     }

#     # Header Action Block. Only if header_action is provided
#     dynamic "header_action" {
#       for_each = length(rule.value["header_action"]) == 0 ? [] : ["header_action"]
#       content {
#         dynamic "request_headers_to_adds" {
#           for_each = { for x in rule.value["header_action"] : x.header_name => x }
#           content {
#             header_name  = request_headers_to_adds.value.header_name
#             header_value = request_headers_to_adds.value.header_value
#           }
#         }
#       }
#     }

#     ### Redirect option
#     dynamic "redirect_options" {
#       for_each = rule.value["action"] == "redirect" ? ["redirect"] : []
#       content {
#         type   = rule.value["redirect_type"]
#         target = rule.value["redirect_type"] == "EXTERNAL_302" ? rule.value["redirect_target"] : null
#       }
#     }

#     ### Rate limit. Execute only if Action is "rate_based_ban" or "throttle"
#     dynamic "rate_limit_options" {
#       for_each = rule.value["action"] == "rate_based_ban" || rule.value["action"] == "throttle" ? ["rate_limits"] : []
#       content {
#         conform_action      = "allow"
#         ban_duration_sec    = rule.value["action"] == "rate_based_ban" ? lookup(rule.value["rate_limit_options"], "ban_duration_sec") : null
#         exceed_action       = lookup(rule.value["rate_limit_options"], "exceed_action")
#         enforce_on_key      = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(rule.value["rate_limit_options"], "enforce_on_key", null) : ""
#         enforce_on_key_name = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? lookup(rule.value["rate_limit_options"], "enforce_on_key_name", null) : null

#         dynamic "enforce_on_key_configs" {
#           for_each = lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") == null ? {} : { for x in lookup(rule.value["rate_limit_options"], "enforce_on_key_configs") : x.enforce_on_key_type => x }
#           content {
#             enforce_on_key_type = enforce_on_key_configs.value.enforce_on_key_type
#             enforce_on_key_name = enforce_on_key_configs.value.enforce_on_key_name
#           }
#         }

#         ## Required for all rate limit options
#         dynamic "rate_limit_threshold" {
#           for_each = rule.value["action"] == "rate_based_ban" || rule.value["action"] == "throttle" ? ["rate_limit_options"] : []
#           content {
#             count        = rule.value["rate_limit_options"].rate_limit_http_request_count
#             interval_sec = rule.value["rate_limit_options"].rate_limit_http_request_interval_sec
#           }
#         }

#         ## Optional. Can be provided for for rate based ban. Not needed for throttle
#         dynamic "ban_threshold" {
#           for_each = rule.value["action"] == "rate_based_ban" && lookup(rule.value["rate_limit_options"], "ban_http_request_count", null) != null && lookup(rule.value["rate_limit_options"], "ban_http_request_interval_sec", null) != null ? ["ban_threshold"] : []
#           content {
#             count        = lookup(rule.value["rate_limit_options"], "ban_http_request_count")
#             interval_sec = lookup(rule.value["rate_limit_options"], "ban_http_request_interval_sec")
#           }
#         }
#       }
#     }

#     # Optional preconfigured_waf_config Block if preconfigured_waf_config_exclusion is provided
#     dynamic "preconfigured_waf_config" {
#       for_each = rule.value.preconfigured_waf_config_exclusions == null ? [] : ["preconfigured_waf_config_exclusions"] #rule.value.preconfigured_waf_config_exclusions
#       content {
#         dynamic "exclusion" {
#           for_each = rule.value.preconfigured_waf_config_exclusions
#           content {
#             target_rule_set = exclusion.value.target_rule_set
#             target_rule_ids = exclusion.value.target_rule_ids
#             dynamic "request_header" {
#               for_each = exclusion.value.request_header == null ? {} : { for x in exclusion.value.request_header : "${x.operator}-${base64encode(coalesce(x.value, "test"))}" => x }
#               content {
#                 operator = request_header.value.operator
#                 value    = request_header.value.operator == "EQUALS_ANY" ? null : request_header.value.value
#               }
#             }
#             dynamic "request_cookie" {
#               for_each = exclusion.value.request_cookie == null ? {} : { for x in exclusion.value.request_cookie : "${x.operator}-${base64encode(coalesce(x.value, "test"))}" => x }
#               content {
#                 operator = request_cookie.value.operator
#                 value    = request_cookie.value.operator == "EQUALS_ANY" ? null : request_cookie.value.value
#               }
#             }
#             dynamic "request_uri" {
#               for_each = exclusion.value.request_uri == null ? {} : { for x in exclusion.value.request_uri : "${x.operator}-${base64encode(coalesce(x.value, "test"))}" => x }
#               content {
#                 operator = request_uri.value.operator
#                 value    = request_uri.value.operator == "EQUALS_ANY" ? null : request_uri.value.value
#               }
#             }
#             dynamic "request_query_param" {
#               for_each = exclusion.value.request_query_param == null ? {} : { for x in exclusion.value.request_query_param : "${x.operator}-${base64encode(coalesce(x.value, "test"))}" => x }
#               content {
#                 operator = request_query_param.value.operator
#                 value    = request_query_param.value.operator == "EQUALS_ANY" ? null : request_query_param.value.value
#               }
#             }
#           }
#         }

#       }
#     }

#   }
# }
