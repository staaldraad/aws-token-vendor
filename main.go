package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"go.mozilla.org/pkcs7"
)

const targetRole = "arn:aws:iam::611154891553:role/ec2_instance_role"

var certs []*x509.Certificate

var (
	stsClient *sts.Client
	ec2Client *ec2.Client
)

type TokenRequest struct {
	IdentityDocument string `json:"identity"`
	Duration         string `json:"duration,omitempty"`
}

type TokenResponse struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

type InstanceIdentityDocument struct {
	AvailabilityZone string      `json:"availabilityZone"`
	PrivateIP        string      `json:"privateIp"`
	Version          string      `json:"version"`
	InstanceID       string      `json:"instanceId"`
	BillingProducts  interface{} `json:"billingProducts"`
	InstanceType     string      `json:"instanceType"`
	AccountID        string      `json:"accountId"`
	ImageID          string      `json:"imageId"`
	PendingTime      time.Time   `json:"pendingTime"`
	Architecture     string      `json:"architecture"`
	KernelID         interface{} `json:"kernelId"`
	RamdiskID        interface{} `json:"ramdiskId"`
	Region           string      `json:"region"`
}

func init() {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		panic(err)
	}
	stsClient = sts.NewFromConfig(cfg)
	ec2Client = ec2.NewFromConfig(cfg)

	// eu-central-1 certificate
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html
	data := []byte(`-----BEGIN CERTIFICATE-----
MIIEEjCCAvqgAwIBAgIJAKD+v6LeR/WrMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV
BAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0
dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0xNTA4MTQw
OTA4MTlaGA8yMTk1MDExNzA5MDgxOVowXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgT
EFdhc2hpbmd0b24gU3RhdGUxEDAOBgNVBAcTB1NlYXR0bGUxIDAeBgNVBAoTF0Ft
YXpvbiBXZWIgU2VydmljZXMgTExDMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAka8FLhxs1cSJGK+Q+q/vTf8zVnDAPZ3U6oqppOW/cupCtpwMAQcky8DY
Yb62GF7+C6usniaq/9W6xPn/3o//wti0cNt6MLsiUeHqNl5H/4U/Q/fR+GA8pJ+L
npqZDG2tFi1WMvvGhGgIbScrjR4VO3TuKy+rZXMYvMRk1RXZ9gPhk6evFnviwHsE
jV5AEjxLz3duD+u/SjPp1vloxe2KuWnyC+EKInnka909sl4ZAUh+qIYfZK85DAjm
GJP4W036E9wTJQF2hZJrzsiB1MGyC1WI9veRISd30izZZL6VVXLXUtHwVHnVASrS
zZDVpzj+3yD5hRXsvFigGhY0FCVFnwIDAQABo4HUMIHRMAsGA1UdDwQEAwIHgDAd
BgNVHQ4EFgQUxC2l6pvJaRflgu3MUdN6zTuP6YcwgY4GA1UdIwSBhjCBg4AUxC2l
6pvJaRflgu3MUdN6zTuP6YehYKReMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBX
YXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6
b24gV2ViIFNlcnZpY2VzIExMQ4IJAKD+v6LeR/WrMBIGA1UdEwEB/wQIMAYBAf8C
AQAwDQYJKoZIhvcNAQELBQADggEBAIK+DtbUPppJXFqQMv1f2Gky5/82ZwgbbfXa
HBeGSii55b3tsyC3ZW5ZlMJ7Dtnr3vUkiWbV1EUaZGOUlndUFtXUMABCb/coDndw
CAr53XTv7UwGVNe/AFO/6pQDdPxXn3xBhF0mTKPrOGdvYmjZUtQMSVb9lbMWCFfs
w+SwDLnm5NF4yZchIcTs2fdpoyZpOHDXy0xgxO1gWhKTnYbaZOxkJvEvcckxVAwJ
obF8NyJla0/pWdjhlHafEXEN8lyxyTTyOa0BGTuYOBD2cTYYynauVKY4fqHUkr3v
Z6fboaHEd4RFamShM8uvSu6eEFD+qRmvqlcodbpsSOhuGNLzhOQ=
-----END CERTIFICATE-----
`)
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Printf("parsing cert: %w", err)
			return
		}
		certs = append(certs, cert)
	}
}

func handleRequest(ctx context.Context, req events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	method := strings.ToUpper(req.RequestContext.HTTP.Method)
	if method != "POST" {
		return events.LambdaFunctionURLResponse{
			StatusCode: 400,
			Headers:    jsonHeaders(),
			Body:       string("unsupported method"),
		}, nil
	}

	tokenRequest, err := parseBody(req)
	if err != nil {
		return events.LambdaFunctionURLResponse{
			StatusCode: 400,
			Headers:    jsonHeaders(),
			Body:       string(fmt.Sprintf("Failed to unmarshal event: %v", err)),
		}, nil
	}
	pemBytes, err := base64.StdEncoding.DecodeString(tokenRequest.IdentityDocument)
	if err != nil {
		return events.LambdaFunctionURLResponse{
			StatusCode: 400,
			Headers:    jsonHeaders(),
			Body:       string(fmt.Sprintf("identity is not valid base64: %v", err)),
		}, nil
	}
	// verify the instance document
	verified, err := verifyInstanceDocument(pemBytes)
	if err != nil {
		return events.LambdaFunctionURLResponse{
			StatusCode: 403,
			Headers:    jsonHeaders(),
			Body:       string(fmt.Sprintf("unverified instance document %s", err)),
		}, nil
	}
	// extract the instance id
	instanceDocument := &InstanceIdentityDocument{}
	if err := json.Unmarshal(verified, instanceDocument); err != nil {
		return events.LambdaFunctionURLResponse{
			StatusCode: 400,
			Headers:    jsonHeaders(),
			Body:       string(fmt.Sprintf("Failed to unmarshal identity document: %v", err)),
		}, nil
	}

	// fetch instance tags
	tags, err := fetchInstanceTags(ctx, instanceDocument.InstanceID)
	if err != nil {
		return events.LambdaFunctionURLResponse{
			StatusCode: 500,
			Headers:    jsonHeaders(),
			Body:       string(fmt.Sprintf("Failed to fetch instance tags: %v", err)),
		}, nil
	}

	if project, ok := tags["project"]; !ok || project == "" {
		return events.LambdaFunctionURLResponse{
			StatusCode: 500,
			Headers:    jsonHeaders(),
			Body:       string(fmt.Sprintf("project tag not set on: %s", instanceDocument.InstanceID)),
		}, nil
	} else {
		// dynamic policy with project_ref
		sessionPolicy := sessionPolicyTemplate(project)
		// mint token
		stsSession, err := mintSession(ctx, instanceDocument.InstanceID, sessionPolicy)
		if err != nil {
			return events.LambdaFunctionURLResponse{
				StatusCode: 500,
				Headers:    jsonHeaders(),
				Body:       string(fmt.Sprintf("Failed to fetch custom session: %v", err)),
			}, nil
		}
		fmt.Printf("Session created for %s(%s)\n", instanceDocument.InstanceID, project)
		// build custom response to match expected response from credential-process
		rsp := &TokenResponse{Version: 1, AccessKeyId: *stsSession.Credentials.AccessKeyId,
			SecretAccessKey: *stsSession.Credentials.SecretAccessKey, SessionToken: *stsSession.Credentials.SessionToken, Expiration: stsSession.Credentials.Expiration.Format(time.RFC3339)}
		c, _ := json.Marshal(rsp)
		return events.LambdaFunctionURLResponse{
			StatusCode: 200,
			Headers:    jsonHeaders(),
			Body:       string(c),
		}, nil
	}
}

// parseBody decodes the request body, handling base64 encoding that Lambda
// applies when the content is binary or the request comes via certain clients.
func parseBody(req events.LambdaFunctionURLRequest) (*TokenRequest, error) {
	raw := req.Body
	if req.IsBase64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, err
		}
		raw = string(decoded)
	}

	var r TokenRequest
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func jsonHeaders() map[string]string {
	return map[string]string{
		"Content-Type":                "application/json",
		"Access-Control-Allow-Origin": "*",
	}
}

func main() {
	lambda.Start(handleRequest)
}

func verifyInstanceDocument(document []byte) (verifiedInstanceDocument []byte, err error) {

	// --- Extract the DER-encoded PKCS#7 blob ---
	der, err := extractPKCS7(document, "PEM")
	if err != nil {
		return nil, fmt.Errorf("extracting PKCS#7 data: %v", err)
	}

	// --- Parse PKCS#7 ---
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#7: %v", err)
	}

	// only check against the region cert for aws
	p7.Certificates = certs
	// --- Verify ---
	pool := x509.NewCertPool()
	for _, c := range p7.Certificates {
		pool.AddCert(c)
	}
	// This checks: signature is valid against the embedded cert
	if err := p7.VerifyWithChain(pool); err != nil {
		fmt.Printf("Verification failed for %s\n", document)
		return nil, fmt.Errorf("verification failed: %v", err)
	}

	fmt.Println("Verification successful")

	content := p7.Content
	if len(content) == 0 {
		return nil, fmt.Errorf("no content extracted (detached signature?)")
	}
	return content, nil
}

func fetchInstanceTags(ctx context.Context, instanceID string) (tags map[string]string, err error) {
	result, err := ec2Client.DescribeTags(ctx, &ec2.DescribeTagsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("resource-id"),
				Values: []string{instanceID},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EC2 tags: %v", err)
	}

	tags = make(map[string]string, len(result.Tags))
	for _, tag := range result.Tags {
		tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return tags, nil
}

func mintSession(ctx context.Context, instanceID, sessionPolicy string) (role *sts.AssumeRoleOutput, err error) {
	return stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(targetRole),
		RoleSessionName: aws.String(fmt.Sprintf("temp-%s", instanceID)),
		Policy:          aws.String(sessionPolicy),
	})
}

func sessionPolicyTemplate(database string) string {
	// policy that provides a subset of the permissions
	// allowed by the assumed-role, in this case, limiting
	// s3 access to a resource path with a prefix
	return fmt.Sprintf(`{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:Get*",
                "s3:List*"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::staaldraad/",
                "arn:aws:s3:::staaldraad/%s/*"
            ]
        }
    ]
}`, database)
}

// extractPKCS7 pulls out raw DER bytes from PEM or raw DER input.
// It also handles full MIME email wrapping (Content-Type: application/pkcs7-mime).
func extractPKCS7(data []byte, inform string) ([]byte, error) {
	switch inform {
	case "DER":
		return data, nil

	case "PEM":
		// Try direct PEM decode first (bare -----BEGIN PKCS7-----)
		block, _ := pem.Decode(data)
		if block != nil {
			return block.Bytes, nil
		}

		// Try MIME email wrapping
		der, err := extractFromMIME(data)
		if err == nil {
			return der, nil
		}

		// Last resort: maybe it's raw base64 (no PEM headers)
		cleaned := strings.TrimSpace(string(data))
		decoded, err2 := base64.StdEncoding.DecodeString(cleaned)
		if err2 == nil {
			return decoded, nil
		}

		return nil, fmt.Errorf("could not decode PEM/MIME input (MIME error: %v)", err)

	default:
		return nil, fmt.Errorf("unknown -inform %q, use PEM or DER", inform)
	}
}

// extractFromMIME handles S/MIME wrapped in a proper email message.
func extractFromMIME(data []byte) ([]byte, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	ct := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return nil, err
	}

	switch {
	case strings.EqualFold(mediaType, "application/pkcs7-mime") ||
		strings.EqualFold(mediaType, "application/x-pkcs7-mime"):
		return readAndDecode(msg.Body, msg.Header.Get("Content-Transfer-Encoding"))

	case strings.EqualFold(mediaType, "multipart/signed"):
		// The signature is the last MIME part
		boundary := params["boundary"]
		if boundary == "" {
			return nil, fmt.Errorf("multipart/signed missing boundary")
		}
		mr := multipart.NewReader(msg.Body, boundary)
		var lastPart []byte
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(p)
			if err != nil {
				return nil, err
			}
			lastPart = b
			_ = textproto.MIMEHeader(p.Header) // just consume
		}
		// lastPart is the application/pkcs7-signature
		block, _ := pem.Decode(lastPart)
		if block != nil {
			return block.Bytes, nil
		}
		return base64.StdEncoding.DecodeString(strings.TrimSpace(string(lastPart)))

	default:
		return nil, fmt.Errorf("unsupported MIME type: %s", mediaType)
	}
}

func readAndDecode(r io.Reader, encoding string) ([]byte, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		cleaned := strings.ReplaceAll(string(body), "\n", "")
		cleaned = strings.ReplaceAll(cleaned, "\r", "")
		return base64.StdEncoding.DecodeString(cleaned)
	default:
		return body, nil
	}
}
