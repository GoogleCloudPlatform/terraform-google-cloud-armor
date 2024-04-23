/**
 * Copyright 2023 Google LLC
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

resource "google_compute_region_security_policy" "adv_ddos_protection" {
  provider = google-beta
  for_each = toset(var.regions)
  project  = var.project_id


  name        = "${var.policy_name}-${each.value}"
  description = "${var.policy_description} region: ${each.value}"
  type        = "CLOUD_ARMOR_NETWORK"
  region      = each.value

  ddos_protection_config {
    ddos_protection = var.ddos_protection_config
  }

}

resource "google_compute_network_edge_security_service" "adv_ddos_protection" {
  provider = google-beta
  for_each = toset(var.regions)
  project  = var.project_id

  name            = "${var.network_edge_security_service_name}-${each.value}"
  region          = each.value
  description     = "${var.network_edge_security_service_description} region: ${each.value}"
  security_policy = google_compute_region_security_policy.adv_ddos_protection[each.value].self_link
}
