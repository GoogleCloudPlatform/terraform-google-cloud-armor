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

############## Available Zones ####################

data "google_compute_zones" "available_primary" {
  project = var.project_id
  region  = local.primary_region
}

############## VM Images ####################

data "google_compute_image" "debian_image" {
  family  = "debian-12"
  project = "debian-cloud"
}

############## Service Account for the VM ####################

resource "google_service_account" "vm_service_account" {
  project      = var.project_id
  account_id   = "ca-web-svc-act"
  display_name = "ca Web server service account"
}

############## VM Instance ####################

resource "google_compute_instance" "ca_vm_1" {
  name                      = "ca-test-vm-${data.google_compute_zones.available_primary.names[0]}"
  machine_type              = "e2-micro"
  zone                      = data.google_compute_zones.available_primary.names[0]
  project                   = var.project_id
  allow_stopping_for_update = true

  metadata_startup_script = "apt-get update -y;apt-get install -y nginx;"

  boot_disk {
    initialize_params {
      image = data.google_compute_image.debian_image.self_link
    }
  }

  network_interface {
    subnetwork         = module.test_vpc.subnets_names[0]
    subnetwork_project = var.project_id
  }
  service_account {
    email = google_service_account.vm_service_account.email
    scopes = [
      "cloud-platform",
    ]
  }
}

############## Instance Group ####################

resource "google_compute_instance_group" "ca_vm_1_ig" {
  name        = "ca-ig-${data.google_compute_zones.available_primary.names[0]}"
  description = "Web Instance group zone ${data.google_compute_zones.available_primary.names[0]}"
  zone        = data.google_compute_zones.available_primary.names[0]
  project     = var.project_id

  instances = [
    google_compute_instance.ca_vm_1.self_link,
  ]
}
