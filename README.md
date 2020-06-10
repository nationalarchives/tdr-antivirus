This is the code and configuration to carry out the antivirus checks on a single file from S3

## Building the lambda function

There will be a task to automatically build the virus definitions into the lambda but for now it's a manual process.
First, set $MANAGEMENT_ACCOUNT, STAGE and $YARA_VERSION. Current version as I write this is 4.0.0
```
export MANAGEMENT_ACCOUNT=managementaccount
export YARA_VERSION=4.0.0
export STAGE=intg
```

Build the base yara image
`docker build -f Dockerfile-yara --build-arg YARA_VERSION=$YARA_VERSION -t $MANAGEMENT_ACCOUNT.dkr.ecr.eu-west-2.amazonaws.com/yara:$STAGE .`

Build the dependencies image

`docker build -f Dockerfile-dependencies --build-arg YARA_VERSION=$YARA_VERSION -t $MANAGEMENT_ACCOUNT.dkr.ecr.eu-west-2.amazonaws.com/yara-dependencies:$STAGE .`

Build the rules file container

`docker build -f Dockerfile-compile -t yara-rules --build-arg STAGE=$STAGE --build-arg ACCOUNT_NUMBER=$MANAGEMENT_ACCOUNT .`

Run the dependencies container

`docker run -itd --rm --name dependencies $MANAGEMENT_ACCOUNT.dkr.ecr.eu-west-2.amazonaws.com/yara-dependencies:$STAGE`

Copy the dependencies zip locally

`docker cp dependencies:/lambda/dependencies.zip .`

Run the rules container

`docker run -itd --rm --name rules yara-rules`

Make a lambda directory

`mkdir lambda`

Copy the rules file into the lambda directory

`docker cp rules:/rules/output ./lambda`

Unzip the dependencies into the lambda directory

`unzip -q dependencies.zip -d ./lambda`

Copy the matcher file to the lambda directory

`cp src/matcher.py ./lambda`

Enter the lambda directory 

`cd lambda`

Zip the contents

`zip -r9 function.zip .`

Upload to an S3 bucket

`aws s3 cp function.zip s3://tdr-backend-code-mgmt/yara-av.zip`

Update the lambda function in the environment account. You will need credentials for whichever environment you're deploying to

`aws lambda update-function-code --function-name tdr-yara-av-$STAGE --s3-bucket tdr-backend-checks-$STAGE --s3-key yara-av.zip`

Publish a new lambda version. This is how we keep track of the database version 

`aws lambda publish-version --function-name tdr-yara-av-$STAGE`

Clean up
```
cd ..
rm -rf lambda dependencies.zip
docker stop rules dependencies
```

## Running locally
Create a virtual environment in the antivirus directory
`python3 -m venv venv`

Activate the environment

`source venv/bin/activate`

Install dependencies

`pip install -r requirements.txt`

To run it, you will need to add code to the matcher.py file at the bottom. 

```python
matcher_lambda_handler({
  "Records": [
    {
      "s3": {
        "bucket": {
          "name": "tdr-upload-files-dirty-staging"
        },
        "object": {
          "key": "cognitoId-1234/bf2181c7-70e4-448d-b122-be561d0e797a"
        }
      }
    }
  ]
}, None)
```

This is the minimum json you need but you can experiment with more records and different keys

Then either run this through the cli 

`python src/matcher.py`

or debug through Pycharm or the IDE of your choice. 

The following environment variables need to be set for this to work although the AWS ones are optional if you're using profiles.
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN

AWS_LAMBDA_FUNCTION_VERSION - This is the lambda function version. It's provided by the lambda and so needs to be set here. Set it to "$LATEST"
SQS_URL - This is the queue for the api updates. It's https://sqs.eu-west-2.amazonaws.com/${account_number}/tdr-api-update-$STAGE
ENVIRONMENT - intg, staging or prod 

## Running the tests

Normal run: `python -m pytest`

Run with coverage `python -m pytest --cov=src`

Run with coverage and missing lines `python -m pytest --cov-report term-missing --cov=src`

Run with coverage, missing lines and junit output `python -m pytest --cov-report term-missing --junitxml="result.xml" --cov=src`

 
