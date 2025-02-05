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

module "advanced_network_ddos_protection" {
  source  = "GoogleCloudPlatform/cloud-armor/google//modules/advanced-network-ddos-protection"
  version = "~> 5.0"

  project_id                         = var.project_id
  regions                            = ["us-central1", "us-east1"]
  policy_name                        = "test-adv-network-ddos-protection-${random_id.suffix.hex}"
  network_edge_security_service_name = "test-network-edge-security-svc-${random_id.suffix.hex}"
}
