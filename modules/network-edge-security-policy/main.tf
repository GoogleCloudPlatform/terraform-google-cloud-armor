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
  provider = google-beta
  project  = var.project_id


  name        = var.policy_name
  description = var.policy_description
  type        = "CLOUD_ARMOR_NETWORK"
  region      = var.region

  dynamic "user_defined_fields" {
    for_each = var.policy_user_defined_fields == null ? [] : var.policy_user_defined_fields
    content {
      name   = lookup(user_defined_fields.value, "name", null)
      base   = user_defined_fields.value.base
      offset = lookup(user_defined_fields.value, "offset", null)
      size   = lookup(user_defined_fields.value, "size", null)
      mask   = lookup(user_defined_fields.value, "mask", null)
    }

  }
}

resource "google_compute_region_security_policy_rule" "policy_rules" {
  provider        = google-beta
  for_each        = var.policy_rules == null ? {} : { for x in var.policy_rules : x.priority => x }
  project         = var.project_id
  region          = var.region
  security_policy = google_compute_region_security_policy.security_policy.name
  description     = each.value.description
  priority        = each.value.priority
  network_match {
    src_ip_ranges    = lookup(each.value, "src_ip_ranges", [])
    src_ports        = lookup(each.value, "src_ports", [])
    src_asns         = lookup(each.value, "src_asns", [])
    src_region_codes = lookup(each.value, "src_region_codes", [])
    ip_protocols     = lookup(each.value, "ip_protocols", [])
    dest_ports       = lookup(each.value, "dest_ports", [])
    dest_ip_ranges   = lookup(each.value, "dest_ip_ranges", [])
    dynamic "user_defined_fields" {
      for_each = lookup(each.value, "user_defined_fields", null) == null ? [] : lookup(each.value, "user_defined_fields")
      content {
        name   = lookup(user_defined_fields.value, "name", null)
        values = lookup(user_defined_fields.value, "values", null)
      }
    }
  }
  action  = each.value.action
  preview = each.value.preview
}
