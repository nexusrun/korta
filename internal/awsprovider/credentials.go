package cloud

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Credentials say how the manager signs in to one AWS account.
type Credentials struct {
	// Method is "environment" (the manager's AWS SDK chain: IAM role,
	// profile or variables), "access-key", or "assume-role".
	Method          string
	AccessKeyID     string
	SecretAccessKey string
	// RoleARN is assumed with the access key when one is set, otherwise
	// with the manager's environment.
	RoleARN    string
	ExternalID string
	// Region applies to roles and networks that name none.
	Region string
}

// awsConfig builds the SDK configuration for cred in region, or cred's
// region when region is empty.
func awsConfig(ctx context.Context, cred Credentials, region string) (aws.Config, error) {
	if region == "" {
		region = cred.Region
	}
	opts := []func(*config.LoadOptions) error{}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	if cred.Method != "environment" && cred.Method != "" && cred.AccessKeyID != "" {
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cred.AccessKeyID, cred.SecretAccessKey, "")))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS configuration: check the AWS environment, profile or IAM role")
	}
	if cred.Method == "assume-role" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), cred.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "korta"
			if cred.ExternalID != "" {
				o.ExternalID = aws.String(cred.ExternalID)
			}
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}
	return cfg, nil
}
