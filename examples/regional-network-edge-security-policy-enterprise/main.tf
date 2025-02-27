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

resource "random_id" "suffix" {
  byte_length = 4
}

module "network_edge_security_policy" {
  source  = "GoogleCloudPlatform/cloud-armor/google//modules/network-edge-security-policy"
  version = "~> 5.0"

  project_id  = var.project_id
  region      = "us-central1"
  policy_name = "test-nw-edge-security-policy-${random_id.suffix.hex}"

  policy_user_defined_fields = [
    {
      name   = "SIG1_AT_0"
      base   = "UDP"
      offset = 8
      size   = 2
      mask   = "0x8F00"
    },
    {
      name   = "SIG2_AT_8"
      base   = "TCP"
      offset = 16
      size   = 4
      mask   = "0xFFFFFFFF"
    },
    {
      name   = "IPv4-TTL"
      base   = "IPV4"
      offset = 8
      size   = 1
      mask   = "0xFF"
    },

  ]

  policy_rules = [
    {
      priority         = 100
      action           = "deny"
      preview          = true
      description      = "custom rule 100"
      src_ip_ranges    = ["10.10.0.0/16"]
      src_asns         = [15169]
      src_region_codes = ["AU"]
      ip_protocols     = ["TCP"]
      src_ports        = [80]
      dest_ports       = ["8080"]
      dest_ip_ranges   = ["10.100.0.0/16"]
      user_defined_fields = [
        {
          name   = "SIG1_AT_0"
          values = ["0x8F00"]
        },
      ]
    },
    {
      priority       = 200
      action         = "deny"
      preview        = false
      priority       = 200
      src_asns       = [15269]
      dest_ports     = ["80"]
      dest_ip_ranges = ["10.100.0.0/16"]
    },
  ]
}

module "network_edge_security_policy_no_rules" {
  source  = "GoogleCloudPlatform/cloud-armor/google//modules/network-edge-security-policy"
  version = "~> 5.0"

  project_id  = var.project_id
  region      = "us-central1"
  policy_name = "nw-edge-security-policy-no-rules${random_id.suffix.hex}"
}
