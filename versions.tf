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

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.79, < 7"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 4.79, < 7"
    }
  }
  provider_meta "google" {
    module_name = "blueprints/terraform/terraform-google-cloud-armor/v2.2.0" # Does this need to be updated to 3.0 to support the regional backend service module (PR#126)?
  }
  provider_meta "google-beta" {
    module_name = "blueprints/terraform/terraform-google-cloud-armor/v2.2.0" # Does this need to be updated to 3.0 to support the regional backend service module (PR#126)?
  }
}
