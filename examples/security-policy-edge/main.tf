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

resource "random_id" "suffix" {
  byte_length = 4
}
module "cloud_armor" {
  source = "../../"

  project_id          = var.project_id
  name                = "test-casp-edge-policy-${random_id.suffix.hex}"
  description         = "Test Cloud Armor Edge security policy"
  default_rule_action = "deny(403)"
  type                = "CLOUD_ARMOR_EDGE"

  custom_rules = {
    allow_specific_regions = {
      action      = "allow"
      priority    = 1
      description = "Allow specific Regions"
      expression  = <<-EOT
        origin.region_code == "US"
      EOT
    }
  }

}
