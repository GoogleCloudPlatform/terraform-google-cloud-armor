# Cloud Armor Policy with rules supported by [Cloud Armor Enterprise](https://cloud.google.com/armor/docs/armor-enterprise-overview)

This example configures a single cloud armor policy with following types of rules which are only availalable to projects enrolled in [Cloud Armor Enterprise](https://cloud.google.com/armor/docs/armor-enterprise-overview):

- Threat Intelligence Rules
- Rule for Automatically deploying Adaptive Protection suggested rules


## Usage

To run this example you need to execute:

```bash
export TF_VAR_project_id="your_project_id"
```

```bash
terraform init
terraform plan
terraform apply
```

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| project\_id | The project in which the resource belongs | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| policy\_name | Security Policy name |
| project\_id | The project ID |
| security\_policy | Cloud Armor security policy created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

## For testing `redirect` and `throttle` policies replace `adaptive_protection_auto_deploy` with the following in `main.tf`

### Example 1 (redirect):

```
adaptive_protection_auto_deploy = {
  enable         = true
  priority       = 100000
  action         = "redirect"
  redirect_type  = "GOOGLE_RECAPTCHA"
}
```

### Example 2 (throttle):

```
adaptive_protection_auto_deploy = {
  enable   = true
  priority = 100000
  action   = "throttle"

  rate_limit_options = {
    exceed_action                        = "deny(502)"
    rate_limit_http_request_count        = 500
    rate_limit_http_request_interval_sec = 120
    enforce_on_key                       = "IP"
  }
}
```
