// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package simple_example

import (
	"fmt"
	"testing"

	"github.com/GoogleCloudPlatform/cloud-foundation-toolkit/infra/blueprint-test/pkg/gcloud"
	"github.com/GoogleCloudPlatform/cloud-foundation-toolkit/infra/blueprint-test/pkg/tft"
	"github.com/stretchr/testify/assert"
)

func TestSimpleExample(t *testing.T) {
	casp := tft.NewTFBlueprintTest(t)

	casp.DefineVerify(func(assert *assert.Assertions) {
		casp.DefaultVerify(assert)

		projectId := casp.GetStringOutput("project_id")
		policyName := casp.GetStringOutput("policy_name")

		sp_name := gcloud.Run(t, fmt.Sprintf("compute security-policies describe %s --project %s", policyName, projectId))
		for _, sp := range sp_name.Array() {
			assert.Equal(policyName, sp.Get("name").String(), "has expected name")
			assert.Equal("STANDARD", sp.Get("advancedOptionsConfig.jsonParsing").String(), "has value STANDARD")
			assert.Equal("VERBOSE", sp.Get("advancedOptionsConfig.logLevel").String(), "has value VERBOSE")
			assert.Equal("STANDARD", sp.Get("adaptiveProtectionConfig.layer7DdosDefenseConfig.ruleVisibility").String(), "has value STANDARD")
			assert.True(sp.Get("adaptiveProtectionConfig.layer7DdosDefenseConfig.enable").Bool(), "layer7DdosDefenseConfig.enable set to True")
		}
	})
	casp.Test()
}
