BINARY     = bootstrap
ZIP        = function.zip
REGION    ?= us-east-1
FUNC_NAME ?= my-lambda-function
ROLE_ARN  ?= arn:aws:iam::611154891553:role/lambda-execution-role

.PHONY: build zip deploy update invoke clean

## Build for Linux (required by Lambda)
build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(BINARY) .

## Package into a zip
zip: build
	zip $(ZIP) $(BINARY)

## Create function + function URL (first deploy)
deploy: zip
	aws lambda create-function \
		--function-name $(FUNC_NAME) \
		--runtime provided.al2023 \
		--handler bootstrap \
		--role $(ROLE_ARN) \
		--zip-file fileb://$(ZIP) \
		--region $(REGION)
	aws lambda create-function-url-config \
		--function-name $(FUNC_NAME) \
		--auth-type NONE \
		--region $(REGION)
	aws lambda add-permission \
		--function-name $(FUNC_NAME) \
		--statement-id FunctionURLAllowPublicAccess \
		--action lambda:InvokeFunctionUrl \
		--principal "*" \
		--function-url-auth-type NONE \
		--region $(REGION)
	aws lambda add-permission \
		--function-name $(FUNC_NAME) \
		--statement-id FunctionURLAllowInvokeAction \
		--action lambda:InvokeFunction \
		--principal "*" \
		--region $(REGION)
	@echo "Function URL:"
	@aws lambda get-function-url-config --function-name $(FUNC_NAME) --region $(REGION) \
		--query FunctionUrl --output text

## Update existing function code only
update: zip
	aws lambda update-function-code \
		--function-name $(FUNC_NAME) \
		--zip-file fileb://$(ZIP) \
		--region $(REGION)

## Get the function URL
url:
	@aws lambda get-function-url-config \
		--function-name $(FUNC_NAME) \
		--region $(REGION) \
		--query FunctionUrl --output text

## Test invoke via curl
invoke:
	curl -s "$$($(MAKE) -s url)" | jq .

clean:
	rm -f $(BINARY) $(ZIP)
