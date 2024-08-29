// Copyright 2024 Google LLC
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

package security_policy_recaptcha

import (
	"fmt"
	"testing"

	"github.com/GoogleCloudPlatform/cloud-foundation-toolkit/infra/blueprint-test/pkg/gcloud"
	"github.com/GoogleCloudPlatform/cloud-foundation-toolkit/infra/blueprint-test/pkg/tft"
	"github.com/stretchr/testify/assert"
)

func TestGlobalSecurityPolicyRecaptcha(t *testing.T) {
	casp := tft.NewTFBlueprintTest(t)

	casp.DefineVerify(func(assert *assert.Assertions) {
		casp.DefaultVerify(assert)

		projectId := casp.GetTFSetupStringOutput("project_id")
		policyName := casp.GetStringOutput("policy_name")

		spName := gcloud.Run(t, fmt.Sprintf("compute security-policies describe %s --project %s", policyName, projectId))
		for _, sp := range spName.Array() {
			pname := sp.Get("name").String()
			assert.Equal(policyName, pname, "has expected name")
			assert.Equal("Test Cloud Armor security policy with Recaptcha Enterprise", sp.Get("description").String(), "has expected description")
			assert.Equal("CLOUD_ARMOR", sp.Get("type").String(), "has expected name")
		}
	})
	casp.Test()
}
