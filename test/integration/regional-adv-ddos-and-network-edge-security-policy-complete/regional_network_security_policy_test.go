// Copyright 2023 Google LLC
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

package network_security_policy

import (
	"fmt"
	"testing"

	"github.com/GoogleCloudPlatform/cloud-foundation-toolkit/infra/blueprint-test/pkg/gcloud"
	"github.com/GoogleCloudPlatform/cloud-foundation-toolkit/infra/blueprint-test/pkg/tft"
	"github.com/stretchr/testify/assert"
)

func TestRegionalNetworkEdgePolicy(t *testing.T) {
	casp := tft.NewTFBlueprintTest(t)

	casp.DefineVerify(func(assert *assert.Assertions) {
		// casp.DefaultVerify(assert)

		projectId := casp.GetStringOutput("project_id")
		policyName := casp.GetStringOutput("policy_name")
		region := casp.GetStringOutput("region")

		spName := gcloud.Run(t, fmt.Sprintf("compute security-policies describe %s --project %s --region %s", policyName, projectId, region))
		for _, sp := range spName.Array() {
			assert.Equal(policyName, sp.Get("name").String(), "mismatched name")
			assert.Equal("CA Advance DDoS protection", sp.Get("description").String(), "mismatched description")
			assert.Equal("CLOUD_ARMOR_NETWORK", sp.Get("type").String(), "mismatched type")
		}

		// 	Rule 100
		spRule1 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 100 --security-policy=%s --project %s --region %s", policyName, projectId, region))
		for _, sp := range spRule1.Array() {
			assert.Equal("allow", sp.Get("action").String(), "priority 100 rule has mismatched action")
			assert.Equal("custom rule 100", sp.Get("description").String(), "priority 1 rule has mismatched description")
			assert.False(sp.Get("preview").Bool(), "priority 1 rule Preview is set to true")
		}

	})
	casp.Test()
}
