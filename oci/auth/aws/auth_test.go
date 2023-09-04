/*
Copyright 2022 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package aws

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/jellydator/ttlcache/v3"
	. "github.com/onsi/gomega"
)

const (
	testValidECRImage = "012345678901.dkr.ecr.us-east-1.amazonaws.com/foo:v1"
)

func TestParseRegistry(t *testing.T) {
	tests := []struct {
		registry      string
		wantAccountID string
		wantRegion    string
		wantOK        bool
	}{
		{
			registry:      "012345678901.dkr.ecr.us-east-1.amazonaws.com/foo:v1",
			wantAccountID: "012345678901",
			wantRegion:    "us-east-1",
			wantOK:        true,
		},
		{
			registry:      "012345678901.dkr.ecr.us-east-1.amazonaws.com/foo",
			wantAccountID: "012345678901",
			wantRegion:    "us-east-1",
			wantOK:        true,
		},
		{
			registry:      "012345678901.dkr.ecr.us-east-1.amazonaws.com",
			wantAccountID: "012345678901",
			wantRegion:    "us-east-1",
			wantOK:        true,
		},
		{
			registry: "gcr.io/foo/bar:baz",
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.registry, func(t *testing.T) {
			g := NewWithT(t)

			accId, region, ok := ParseRegistry(tt.registry)
			g.Expect(ok).To(Equal(tt.wantOK), "unexpected OK")
			g.Expect(accId).To(Equal(tt.wantAccountID), "unexpected account IDs")
			g.Expect(region).To(Equal(tt.wantRegion), "unexpected regions")
		})
	}
}

func TestGetLoginAuth(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour * 12).Unix()
	tests := []struct {
		name           string
		responseBody   []byte
		statusCode     int
		wantErr        bool
		wantAuthConfig authn.AuthConfig
	}{
		{
			// NOTE: The authorizationToken is base64 encoded.
			name: "success",
			responseBody: []byte(`{
	"authorizationData": [
		{
			"authorizationToken": "c29tZS1rZXk6c29tZS1zZWNyZXQ=",
			"expiresAt": <expiresAt>
		}
	]
}`),
			statusCode: http.StatusOK,
			wantAuthConfig: authn.AuthConfig{
				Username: "some-key",
				Password: "some-secret",
			},
		},
		{
			name:       "fail",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
		{
			name: "invalid token",
			responseBody: []byte(`{
	"authorizationData": [
		{
			"authorizationToken": "c29tZS10b2tlbg=="
		}
	]
}`),
			statusCode: http.StatusOK,
			wantErr:    true,
		},
		{
			name: "invalid data",
			responseBody: []byte(`{
	"authorizationData": [
		{
			"foo": "bar"
		}
	]
}`),
			statusCode: http.StatusOK,
			wantErr:    true,
		},
		{
			name:         "invalid response",
			responseBody: []byte(`{}`),
			statusCode:   http.StatusOK,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			handler := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(strings.ReplaceAll(
					string(tt.responseBody), "<expiresAt>", fmt.Sprint(expiresAt)),
				))
			}
			srv := httptest.NewServer(http.HandlerFunc(handler))
			t.Cleanup(func() {
				srv.Close()
			})

			// Configure test client.
			ec := NewClient()
			cfg := aws.NewConfig()
			cfg.EndpointResolverWithOptions = aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{URL: srv.URL}, nil
			})
			// set the region in the config since we are not using the `LoadDefaultConfig` function that sets the region
			// by querying the instance metadata service(IMDS)
			cfg.Credentials = credentials.NewStaticCredentialsProvider("x", "y", "z")
			ec.WithConfig(cfg)

			a, expiresIn, err := ec.getLoginAuth(context.TODO(), "us-east-1")
			g.Expect(err != nil).To(Equal(tt.wantErr))
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(expiresIn.Round(time.Hour)).To(Equal(time.Hour * 12))

			}
			if tt.statusCode == http.StatusOK {
				g.Expect(a).To(Equal(tt.wantAuthConfig))
			}
		})
	}
}

func Test_getOrCacheLoginAuth(t *testing.T) {
	g := NewWithT(t)

	responseBody := `{
	"authorizationData": [
		{
			"authorizationToken": "c29tZS1rZXk6c29tZS1zZWNyZXQ=",
			"expiresAt": %v
		}
	]
}`

	min := time.Now().Add(time.Minute).Unix()
	expiresAt := &min
	var count int
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(responseBody, *expiresAt)))
		count += 1
	}
	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(func() {
		srv.Close()
	})

	// Configure test client.
	ec := NewClient()
	cfg := aws.NewConfig()
	cfg.EndpointResolverWithOptions = aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{URL: srv.URL}, nil
	})
	// set the region in the config since we are not using the `LoadDefaultConfig` function that sets the region
	// by querying the instance metadata service(IMDS)
	cfg.Credentials = credentials.NewStaticCredentialsProvider("x", "y", "z")
	ec.WithConfig(cfg)

	// init cache
	store := ttlcache.New[string, authn.AuthConfig](ttlcache.WithDisableTouchOnHit[string, authn.AuthConfig]())
	a, err := ec.getOrCacheLoginAuth(context.TODO(), "us-east-1", store)
	g.Expect(err).ToNot(HaveOccurred())
	authConfig := authn.AuthConfig{
		Username: "some-key",
		Password: "some-secret",
	}
	g.Expect(a).To(Equal(authConfig))
	g.Expect(count).To(Equal(1))

	// assert that auth config was cached
	item := store.Get("us-east-1")
	g.Expect(item).ToNot(BeNil())
	g.Expect(item.Value()).To(Equal(a))

	// modify the cached record in-place to assert that we hit the
	// cache when an unexpired entry exists.
	authConfig.Username = "some-other-key"
	authConfig.Password = "some-other-secret"
	store.Set("us-east-1", authConfig, time.Minute)

	a, err = ec.getOrCacheLoginAuth(context.TODO(), "us-east-1", store)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(a).To(Equal(authConfig))
	g.Expect(count).To(Equal(1))

	// insert a new record with a low expiration time to test
	// cache miss.
	sec := time.Now().Add(time.Second).Unix()
	expiresAt = &sec
	authConfig.Username = "some-key"
	authConfig.Password = "some-secret"
	a, err = ec.getOrCacheLoginAuth(context.TODO(), "us-west-1", store)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(a).To(Equal(authConfig))
	g.Expect(count).To(Equal(2))

	// assert that item was cached
	item = store.Get("us-west-1")
	g.Expect(item).ToNot(BeNil())
	g.Expect(item.IsExpired()).To(BeFalse())

	// wait for the record to expire
	time.Sleep(time.Second)
	// assert that we hit the server again after the cached item expires
	a, err = ec.getOrCacheLoginAuth(context.TODO(), "us-west-1", store)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(a).To(Equal(authConfig))
	g.Expect(count).To(Equal(3))
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name       string
		autoLogin  bool
		image      string
		statusCode int
		testOIDC   bool
		wantErr    bool
	}{
		{
			name:       "no auto login",
			autoLogin:  false,
			image:      testValidECRImage,
			statusCode: http.StatusOK,
			wantErr:    true,
		},
		{
			name:       "with auto login",
			autoLogin:  true,
			image:      testValidECRImage,
			statusCode: http.StatusOK,
			testOIDC:   true,
		},
		{
			name:       "login failure",
			autoLogin:  true,
			image:      testValidECRImage,
			statusCode: http.StatusInternalServerError,
			testOIDC:   true,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			cache.DeleteAll()

			handler := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(`{"authorizationData": [{"authorizationToken": "c29tZS1rZXk6c29tZS1zZWNyZXQ=", "expiresAt": 1257894000}]}`))
			}
			srv := httptest.NewServer(http.HandlerFunc(handler))
			t.Cleanup(func() {
				srv.Close()
			})

			// Configure test client.
			ecrClient := NewClient()
			cfg := aws.NewConfig()
			cfg.EndpointResolverWithOptions = aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{URL: srv.URL}, nil
			})
			cfg.Credentials = credentials.NewStaticCredentialsProvider("x", "y", "z")
			ecrClient.WithConfig(cfg)

			_, err := ecrClient.Login(context.TODO(), tt.autoLogin, tt.image)
			g.Expect(err != nil).To(Equal(tt.wantErr))

			if tt.testOIDC {
				_, err = ecrClient.OIDCLogin(context.TODO(), tt.image)
				g.Expect(err != nil).To(Equal(tt.wantErr))
			}
		})
	}
}
