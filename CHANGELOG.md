# Changelog

All notable changes to this project will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).
This changelog is generated automatically based on [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

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
