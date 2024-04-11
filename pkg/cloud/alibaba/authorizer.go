package alibaba

import (
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth"
	"github.com/aliyun/credentials-go/credentials"
	"github.com/opencost/opencost/core/pkg/util/json"
	"github.com/opencost/opencost/pkg/cloud"
)

const AccessKeyAuthorizerType = "AlibabaAccessKey"

const OidcAuthorizerType = "AlibabaOidc"

// Authorizer provide *bssopenapi.Client for Alibaba cloud BOS for Billing related SDK calls
type Authorizer interface {
	cloud.Authorizer
	GetCredentials() (auth.Credential, error)
}

// SelectAuthorizerByType is an implementation of AuthorizerSelectorFn and acts as a register for Authorizer types
func SelectAuthorizerByType(typeStr string) (Authorizer, error) {
	switch typeStr {
	case AccessKeyAuthorizerType:
		return &AccessKey{}, nil
	case OidcAuthorizerType:
    return &Oidc{}, nil
	default:
		return nil, fmt.Errorf("alibaba: provider authorizer type '%s' is not valid", typeStr)
	}
}

// AccessKey holds Alibaba credentials parsing from the service-key.json file.
type AccessKey struct {
	AccessKeyID     string `json:"accessKeyID"`
	AccessKeySecret string `json:"accessKeySecret"`
}

// MarshalJSON custom json marshalling functions, sets properties as tagged in struct and sets the authorizer type property
func (ak *AccessKey) MarshalJSON() ([]byte, error) {
	fmap := make(map[string]any, 3)
	fmap[cloud.AuthorizerTypeProperty] = AccessKeyAuthorizerType
	fmap["accessKeyID"] = ak.AccessKeyID
	fmap["accessKeySecret"] = ak.AccessKeySecret
	return json.Marshal(fmap)
}

func (ak *AccessKey) Validate() error {
	if ak.AccessKeyID == "" {
		return fmt.Errorf("AccessKey: missing Access key ID")
	}
	if ak.AccessKeySecret == "" {
		return fmt.Errorf("AccessKey: missing Access Key secret")
	}
	return nil
}

func (ak *AccessKey) Equals(config cloud.Config) bool {
	if config == nil {
		return false
	}
	thatConfig, ok := config.(*AccessKey)
	if !ok {
		return false
	}

	if ak.AccessKeyID != thatConfig.AccessKeyID {
		return false
	}
	if ak.AccessKeySecret != thatConfig.AccessKeySecret {
		return false
	}
	return true
}

func (ak *AccessKey) Sanitize() cloud.Config {
	return &AccessKey{
		AccessKeyID:     ak.AccessKeyID,
		AccessKeySecret: cloud.Redacted,
	}
}

// GetCredentials creates a credentials object to authorize the use of service sdk calls
func (ak *AccessKey) GetCredentials() (auth.Credential, error) {
	err := ak.Validate()
	if err != nil {
		return nil, err
	}
	return &credentials.AccessKeyCredential{AccessKeyId: ak.AccessKeyID, AccessKeySecret: ak.AccessKeySecret}, nil
}

type Oidc struct {
	RoleArn           string `json:"roleArn"`
	OIDCProviderArn   string `json:"oidcProviderArn"`
	OIDCTokenFilePath string `json:"oidcTokenFilePath"`
}

// MarshalJSON custom json marshalling functions, sets properties as tagged in struct and sets the authorizer type property
func (o *Oidc) MarshalJSON() ([]byte, error) {
	fmap := make(map[string]any, 4)
	fmap[cloud.AuthorizerTypeProperty] = OidcAuthorizerType
	fmap["roleArn"] = o.RoleArn
	fmap["oidcProviderArn"] = o.OIDCProviderArn
	fmap["OIDCTokenFilePath"] = o.OIDCTokenFilePath
	return json.Marshal(fmap)
}

func (o *Oidc) Validate() error {
	if o.RoleArn == "" {
		return fmt.Errorf("RoleArn: missing role arn")
	}
	if o.OIDCProviderArn == "" {
		return fmt.Errorf("OidcProviderArn: missing oidc provider arn")
	}
	if o.OIDCTokenFilePath == "" {
		return fmt.Errorf("OIDCTokenFilePath: missing oidc token file path")
	}
	return nil
}

func (o *Oidc) Equals(config cloud.Config) bool {
	if config == nil {
		return false
	}
	thatConfig, ok := config.(*Oidc)
	if !ok {
		return false
	}

	if o.RoleArn != thatConfig.RoleArn {
		return false
	}
	if o.OIDCProviderArn != thatConfig.OIDCProviderArn {
		return false
	}
	if o.OIDCTokenFilePath != thatConfig.OIDCTokenFilePath {
		return false
	}
	return true
}

func (o *Oidc) Sanitize() cloud.Config {
	return &Oidc{
		RoleArn:         o.RoleArn,
		OIDCProviderArn: o.OIDCProviderArn,
		OIDCTokenFilePath:   o.OIDCTokenFilePath,
	}
}

// GetCredentials creates a credentials object to authorize the use of service sdk calls
func (o *Oidc) GetCredentials() (auth.Credential, error) {
	err := o.Validate()
	if err != nil {
		return nil, err
	}

	config := new(credentials.Config).
		SetType("oidc_role_arn").
		SetRoleArn(o.RoleArn).
		SetOIDCProviderArn(o.OIDCProviderArn).
		SetOIDCTokenFilePath(o.OIDCTokenFilePath).
		SetRoleSessionName("test-rrsa-oidc-token")

	cred, err := credentials.NewCredential(config)
	return cred, err
}
