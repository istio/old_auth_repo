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

package credential

import (
	"encoding/json"
	"errors"
	"fmt"

	"cloud.google.com/go/compute/metadata"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
)

// TokenFetcher defines the interface to fetch token.
type TokenFetcher interface {
	FetchToken() (string, error)
}

// GcpTokenFetcher implements the token fetcher in GCP.
type GcpTokenFetcher struct {
	// aud is the unique URI agreed upon by both the instance and the system verifying the instance's identity.
	// For more info: https://cloud.google.com/compute/docs/instances/verifying-instance-identity
	Aud string
}

// AwsTokenFetcher implements the token fetcher in AWS.
// It gets the EC2 instance identity document as described
// in the doc: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
type AwsTokenFetcher struct {
}

// IsOnAWS returns if node agent is running on AWS EC2 instance
func (fetcher *AwsTokenFetcher) IsOnAWS() bool {
	sess := session.Must(session.NewSession())
	svc := ec2metadata.New(sess)
	return svc.Available()
}

// FetchToken fetches the instance identity document as a string
// Note: currently AWS Golang SDK does not verify the signature,
// so this function is not very secure. We expect this bug to
// be fixed in upstream.
func (fetcher *AwsTokenFetcher) FetchToken() (string, error) {
	sess := session.Must(session.NewSession())
	svc := ec2metadata.New(sess)
	if svc.Available() {
		doc, err := svc.GetInstanceIdentityDocument()
		if err == nil {
			bytes, _ := json.Marshal(doc)
			return string(bytes), nil
		}
		return "", fmt.Errorf("Failed to get EC2 instance identity document: %v", err)
	}
	return "", errors.New("Failed to connect to EC2 metadata service, please make sure this binary is running on an EC2 VM")
}

// GetUserData fetches the userdata for the current instance
func (fetcher *AwsTokenFetcher) GetUserData() (string, error) {
	sess := session.Must(session.NewSession())
	svc := ec2metadata.New(sess)
	return svc.GetUserData()
}

func (fetcher *GcpTokenFetcher) getTokenURI() string {
	// The GCE metadata service URI to get identity token of current (i.e., default) service account.
	return "instance/service-accounts/default/identity?audience=" + fetcher.Aud
}

// FetchToken fetches the GCE VM identity jwt token from its metadata server.
// Note: this function only works in a GCE VM environment.
func (fetcher *GcpTokenFetcher) FetchToken() (string, error) {
	return metadata.Get(fetcher.getTokenURI())
}
