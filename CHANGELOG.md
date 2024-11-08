# Changelog

All notable changes to this project will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).
This changelog is generated automatically based on [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## [3.0.1](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/compare/v3.0.0...v3.0.1) (2024-11-08)


### Bug Fixes

* added example for address group in global security policy ([#138](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/138)) ([19305bd](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/19305bd5ffc35e37577c05f58c19138b3d0debc5))

## [3.0.0](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/compare/v2.2.0...v3.0.0) (2024-08-29)


### ⚠ BREAKING CHANGES

* add sub-module for regional backend security policy ([#126](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/126))

### Features

* add sub-module for regional backend security policy ([#126](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/126)) ([f9a6dd0](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/f9a6dd080df87acababfc2ece301bb69e237095a))

## [2.2.0](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/compare/v2.1.0...v2.2.0) (2024-04-23)


### Features

* added advanced network ddos protection & network edge security policy sub-modules ([#113](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/113)) ([8e1ecb5](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/8e1ecb5cd7df1371545d0ded157fea130dce8cb8))

## [2.1.0](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/compare/v2.0.1...v2.1.0) (2024-03-18)


### Features

* add preconfigured_waf_config_exclusions to allow multiple exclusions ([#105](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/105)) ([66f079f](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/66f079fdc8097a971cca2aeb1778d6af061fcaac))

## [2.0.1](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/compare/v2.0.0...v2.0.1) (2023-12-07)


### Bug Fixes

* add auto_deploy_config block ([#84](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/84)) ([468c904](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/468c9040c8dfdcae4c40d84c9a877f897843dd92))

## [2.0.0](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/compare/v1.2.0...v2.0.0) (2023-10-26)


### ⚠ BREAKING CHANGES

* **tpg v5:** rule.rate_limit_options.enforce_on_key has not default value ([#77](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/77))
* **TPG >= 4.79:** added preconfigured_waf_config block in custom_rule ([#71](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/71))

### Features

* **TPG >= 4.79:** added preconfigured_waf_config block in custom_rule ([#71](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/71)) ([56e9386](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/56e938658380f556c1dfe8dd7b169b1ab4449fbe))


### Bug Fixes

* rule set name for php ([#69](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/69)) ([de86b4d](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/de86b4d487c6160a67737d8f381af3ab6cc9d6b4))
* **tpg v5:** rule.rate_limit_options.enforce_on_key has not default value ([#77](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/77)) ([a9a0198](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/a9a01982c496779c863db6f1e146eb07871319d1))

## [1.2.0](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/compare/v1.1.0...v1.2.0) (2023-08-29)


### Features

* Add support for Automatically deploy Adaptive Protection suggested rules ([#61](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/61)) ([1dd4e0c](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/1dd4e0c397965999460f18fffa76fe5c6dc2802d))

## [1.1.0](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/compare/v1.0.0...v1.1.0) (2023-08-02)


### Features

* add exclude_ip filter for threat intelligence ([#55](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/55)) ([b92b9a3](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/b92b9a3ad21684ff5b19ae9966518bd47dda8fe6))


### Bug Fixes

* fixed exclude_ip variable and change threat_intelligence_rules to object ([#57](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/57)) ([e7c4219](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/e7c4219a62e61917da321fe8a5b884ddb9ee2a96))

## [1.0.0](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/compare/v0.3.0...v1.0.0) (2023-05-19)


### ⚠ BREAKING CHANGES

* **TPG >= 4.59:** added preconfigured_waf_config block ([#34](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/34))

### Features

* added support for rate limiting (rate_limit_options) on multiple keys (enforce_on_key_configs) ([#42](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/42)) ([189daa9](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/189daa9ec81734e87a24f496d4e6c55691343cf2))
* **TPG >= 4.59:** added preconfigured_waf_config block ([#34](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/34)) ([b43cfc9](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/b43cfc930920136113dadc5a9a4eab09fd857526))


### Bug Fixes

* added enforce_on_key_name variable ([#37](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/37)) ([cc7c56f](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/cc7c56f4de4a6c208e8de0f96ac338e72d58e082))
* make advanced_options_config optional for CLOUD_ARMOR_EDGE policy type ([#39](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/39)) ([c6ecc9e](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/c6ecc9e0823348cc4d407146b00219ce202d1986))

## [0.3.0](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/compare/v0.2.0...v0.3.0) (2023-03-16)


### Features

* added advanced_options_config ([#26](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/26)) ([af1d34e](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/af1d34e7405a05fef01783956c982432d5aed26a))

## [0.2.0](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/compare/v0.1.1...v0.2.0) (2023-03-07)


### Features

* add header_action block in rules ([#16](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/16)) ([9c2c3ec](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/9c2c3ec7d14c0954a9ff818cefc7f09b5899b317))
* Added recaptcha_redirect_site_key and fixed missing redirect_target parameter ([#13](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/13)) ([6ef7a65](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/6ef7a65072e3efc9eb33f76cafdd27970e3a3739))

## [0.1.1](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/compare/v0.1.0...v0.1.1) (2023-02-21)


### Bug Fixes

* add simple example and updated README ([#5](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/5)) ([d39b5ed](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/d39b5eda9dce99fb54e24cbc28a87c2f8b8aa316))

## 0.1.0 (2023-01-17)


### Bug Fixes

* Initial release ([#1](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/issues/1)) ([022f474](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/commit/022f474a8f11435b4309bad0fe8dd158b2cfc2fa))
