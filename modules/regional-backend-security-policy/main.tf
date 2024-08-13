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

### Adding custom rules to network dge security policies requires advanced network DDoS protection to be enabled in the region.

resource "google_compute_region_security_policy" "security_policy" {
  provider    = google-beta
  project     = var.project_id
  name        = var.policy_name
  description = var.policy_description
  type        = var.type
  region      = var.region
}

resource "google_compute_region_security_policy_rule" "security_rules" {
  provider        = google-beta
  for_each        = var.security_rules == null ? {} : { for x in var.security_rules : x.priority => x }
  project         = var.project_id
  region          = var.region
  security_policy = google_compute_region_security_policy.security_policy.name

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
