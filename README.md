# Lambda service for vending credentials

The service accepts connections and validates the instance-identity document that has been passed in. If the document has been signed by AWS (in the region), and the document is valid, the process will fetch the instance tags. The instance tags will be used in creating a dynamic policy that will be attached to the temporary session.

This allows giving a subset of permissions, but using a shared role, which is useful in the case of multi-tenant environments where there may be 1000s of tenants, easily exceeding the role limits in AWS.

Currently this hardcodes for eu-central-1 as a PoC. In a real-world this would likely not run as a Lambda (cost when lots of tenants) but in something like Fargate. The service will run per region, allowing for validation of requests within that region only, playing nicer with sts and providing per region segregation for security and blast radius control.

### Lambda permissions

The lambda (or ECS task) must have permission to assume the target role, for sts to work (trust-policy.json). And in this particular case requires `ec2:DescribeTags` for all target ec2 instances in the region.

## Credential process

Set the .aws/config to use a credential process

```
[profile default]
region = eu-central-1
credential_process = /home/ec2-user/.aws/credprocess.sh
```

The credential process will fetch the instance identity if it hasn't been fetched already, and save this for exchanging with the lambda / remote service.

Credentials will be fetched from the remote service and cached. Each time the credential process is called, it will check that the current set of credentials are not close to expiry (30 minutes). If they are expired or within the expiry window, fetch new credentials.

```bash
#!/bin/bash

if [ ! -f $HOME/.aws/id.rsa2048 ]; then
  echo "-----BEGIN PKCS7-----" > $HOME/.aws/id.rsa2048 && TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` && curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/dynamic/instance-identity/rsa2048 >> $HOME/.aws/id.rsa2048 && echo "" >> $HOME/.aws/id.rsa2048 && echo "-----END PKCS7-----" >> $HOME/.aws/id.rsa2048
fi

CREDS_FILE="${HOME}/.aws/cached"
EXPIRATION=$(jq -r '.Expiration' "$CREDS_FILE")

expiration_epoch=$(date -d "$EXPIRATION" +%s 2>/dev/null || date -jf "%Y-%m-%dT%H:%M:%SZ" "$EXPIRATION" +%s)
now_epoch=$(date +%s)
diff=$(( expiration_epoch - now_epoch ))
threshold=$(( 30 * 60 ))

if [ "$diff" -le "$threshold" ]; then
	resp=$(curl -XPOST https://l37paxo3ujcst2tn4scos2pcte0rrpfp.lambda-url.eu-central-1.on.aws --data "{\"identity\":\"$(base64 -w0 $HOME/.aws/id.rsa2048)\"}")

	echo "$resp" > "$CREDS_FILE"
fi

cat "${CREDS_FILE}"
```
