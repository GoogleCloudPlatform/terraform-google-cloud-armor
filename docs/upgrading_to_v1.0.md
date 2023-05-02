# Upgrading to v1.0.0

The v1.0 release contains backwards-incompatible changes.

This update requires upgrading the minimum provider version from `4.39` to `4.59`.

### [Terraform](https://www.terraform.io/downloads.html) >= 1.3.0 is required as `pre_configured_rules`, `security_rules`, `custom_rules` and its nested attributes and objects are made optional
Since [optional attributes](https://developer.hashicorp.com/terraform/language/expressions/type-constraints#optional-object-type-attributes) is a version 1.3 feature, the configuration will fail if the pinned version is < 1.3.
