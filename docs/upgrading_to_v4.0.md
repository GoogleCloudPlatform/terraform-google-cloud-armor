# Upgrading to v4.0.0

The v4.0 release contains backwards-incompatible changes.

### TPG max version is bumped to 6.10 for regional-backend-security-policy module
There is no known breaking change for Cloud Armor in 6.X.

### Added default rule at priority 2147483647
Before this version a default security rule with priority 2147483647 was created. This update will override that rule so users can manage it in terraform
