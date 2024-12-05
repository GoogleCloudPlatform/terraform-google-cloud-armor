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
  primary_region   = "us-central1"
  secondary_region = "us-east1"
}

resource "random_id" "suffix" {
  byte_length = 4
}

module "advanced_network_ddos_protection" {
  source  = "GoogleCloudPlatform/cloud-armor/google//modules/advanced-network-ddos-protection"
  version = "~> 4.0"

  project_id                         = var.project_id
  regions                            = [local.primary_region, local.secondary_region]
  policy_name                        = "test-adv-network-ddos-protection-${random_id.suffix.hex}"
  network_edge_security_service_name = "test-network-edge-security-svc-${random_id.suffix.hex}"
}

module "network_edge_security_policy" {
  source  = "GoogleCloudPlatform/cloud-armor/google//modules/network-edge-security-policy"
  version = "~> 4.0"

  project_id  = var.project_id
  region      = local.primary_region
  policy_name = "test-nw-edge-security-policy-${random_id.suffix.hex}-${local.primary_region}"

  policy_rules = [
    {
      priority         = 100
      action           = "allow"
      preview          = false
      description      = "custom rule 100"
      src_ip_ranges    = ["70.119.66.60/32"]
      src_region_codes = ["US"]
      dest_ports       = [80]
    },
    {
      priority      = 2147483646
      action        = "deny"
      preview       = false
      src_ip_ranges = ["*"]
    },
  ]

  depends_on = [
    module.advanced_network_ddos_protection
  ]
}
