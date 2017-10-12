// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package na

import (
	"encoding/json"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	cred "istio.io/auth/pkg/credential"
)

type awsPlatformImpl struct {
	fetcher *cred.AwsTokenFetcher
}

// This is extracted from the same function in gcp.go.
// Should put the common logic elsewhere in the future.
func (na *awsPlatformImpl) GetDialOptions(cfg *Config) ([]grpc.DialOption, error) {
	creds, err := credentials.NewClientTLSFromFile(cfg.RootCACertFile, "")
	if err != nil {
		return nil, err
	}

	options := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	return options, nil
}

func (na *awsPlatformImpl) IsProperPlatform() bool {
	return na.fetcher.IsOnAWS()
}

// Extract service identity from userdata. This function should be
// pluggable for different AWS deployments in the future.
func (na *awsPlatformImpl) GetServiceIdentity() (string, error) {
	userdata, err := na.fetcher.GetUserData()
	if err != nil {
		return "", fmt.Errorf("Failed to get EC2 user data: %v", err)
	}
	var dat map[string]string
	err = json.Unmarshal([]byte(userdata), &dat)
	if err != nil {
		return "", fmt.Errorf("Failed to get service identity: %v", err)
	}
	return dat["APIGEE_POD"], nil
}
