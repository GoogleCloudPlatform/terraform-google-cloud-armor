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
  network_name        = "test-ca-regional-enterprise"
  rfc1918_cidr_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", ]
}

/******************************************
  Ranges for default firewall rules.
 *****************************************/

data "google_netblock_ip_ranges" "legacy_health_checkers" {
  range_type = "legacy-health-checkers"
}

data "google_netblock_ip_ranges" "health_checkers" {
  range_type = "health-checkers"
}

data "google_netblock_ip_ranges" "iap_forwarders" {
  range_type = "iap-forwarders"
}


module "test_vpc" {
  source       = "terraform-google-modules/network/google"
  version      = "~> 12.0"
  project_id   = var.project_id
  network_name = local.network_name

  subnets = [
    {
      subnet_name   = "subnet-100"
      subnet_ip     = "10.10.100.0/24"
      subnet_region = local.primary_region
    },
    {
      subnet_name   = "subnet-200"
      subnet_ip     = "10.10.200.0/24"
      subnet_region = local.secondary_region
    },
  ]
}

module "net_firewall" {
  source                  = "terraform-google-modules/network/google//modules/fabric-net-firewall"
  version                 = "~> 12.0"
  project_id              = module.test_vpc.project_id
  network                 = module.test_vpc.network_name
  ssh_source_ranges       = []
  http_source_ranges      = []
  https_source_ranges     = []
  internal_ranges_enabled = true
  internal_ranges         = local.rfc1918_cidr_ranges
  internal_allow = [
    {
      protocol = "all"
    },
  ]
  custom_rules = {
    ca-allow-ssh-from-iap = {
      description          = "Allow SSH access from IAP tunnel"
      direction            = "INGRESS"
      action               = "allow"
      ranges               = data.google_netblock_ip_ranges.iap_forwarders.cidr_blocks_ipv4
      sources              = []
      targets              = []
      use_service_accounts = false
      rules = [
        {
          protocol = "tcp"
          ports    = [22]
        },
      ]
      extra_attributes = {}
    }
    ca-allow-rdp-from-iap = {
      description          = "Allow RDP access from IAP tunnel"
      direction            = "INGRESS"
      action               = "allow"
      ranges               = data.google_netblock_ip_ranges.iap_forwarders.cidr_blocks_ipv4
      sources              = []
      targets              = []
      use_service_accounts = false
      rules = [
        {
          protocol = "tcp"
          ports    = [3389]
        },
        {
          protocol = "udp"
          ports    = [3389]
        },
      ]
      extra_attributes = {}
    }
    ca-allow-lb-healthcheck = {
      description          = "Allow Load balancer health check to all backends"
      direction            = "INGRESS"
      action               = "allow"
      ranges               = concat(data.google_netblock_ip_ranges.health_checkers.cidr_blocks_ipv4, data.google_netblock_ip_ranges.legacy_health_checkers.cidr_blocks_ipv4)
      sources              = []
      targets              = []
      use_service_accounts = false
      rules = [
        {
          protocol = "tcp"
          ports    = []
        },
      ]
      extra_attributes = {}
    }
    ca-all-ip-address = {
      description          = "Allow traffic from whitelisted CIDRs"
      direction            = "INGRESS"
      action               = "allow"
      ranges               = ["0.0.0.0/0"]
      sources              = []
      targets              = []
      use_service_accounts = false
      rules = [
        {
          protocol = "tcp"
          ports    = ["80", "443"]
        },
      ]
      extra_attributes = {}
    }
  }
}

module "cloud_router" {
  source  = "terraform-google-modules/cloud-router/google"
  version = "~> 7.0"

  name    = "test-ca-${local.primary_region}-cr"
  project = module.test_vpc.project_id
  region  = local.primary_region
  network = module.test_vpc.network_self_link
  nats = [{
    name                               = "test-ca-${local.primary_region}-nat"
    source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
    min_ports_per_vm                   = 4096
    log_config = {
      "filter" = "ERRORS_ONLY"
    }
    },
  ]
}
