This is the code and configuration to carry out the antivirus checks on a single file from S3

## Building the lambda function

The lambda function is built by Jenkins. There are two Jenkins jobs in two Jenkinsfiles.

### Jenkinsfile-build
There are three docker images that are used to build the lambda. 

| File name               | Image Name        | Description                                                                                                               |
|-------------------------|-------------------|---------------------------------------------------------------------------------------------------------------------------|
| Dockerfile-yara         | yara              | Installs yara and some dependencies it needs like openssl on an alpine image.                                             |
| Dockerfile-compile      | yara-rules        | Uses yara as the base image. Gets the yara rules from github and compiles them into a single file for yara to use         |
| Dockerfile-dependencies | yara-dependencies | Installs necessary software on an amazon linux image and zips it up to be used by the lambda                              |

These images are built on every master build locally and are not stored in ECR. 

### Jenkinsfile-test 
This runs git secrets and runs the python tests. This is the standard multibranch pipeline job which runs on PRs and merge to master. If this runs on the master branch, it will rebuild the three Docker images locally and use them to build the lambda.

### Jenkinsfile-deploy
This updates the lambda with the zip file from S3.

## Running locally

Create a virtual environment in the antivirus directory
`python3 -m venv venv`

Activate the environment

`source venv/bin/activate`

Install dependencies

`pip install -r requirements.txt`

To run it, you will need to add code to the matcher.py file at the bottom. This will connect to the integration s3 dirty bucket so you will need to run it with integration credentials.

```python
matcher_lambda_handler({
  "Records": [
    {
      "body": {
        "userId": "7ad28066-7a76-4e07-b540-f005b6919328",
        "consignmentId": "bf2181c7-70e4-448d-b122-be561d0e797a",
        "fileId": "df216308-e78b-4328-90ef-8e4ebfef6b9d",
        "originalPath": "original/path",
        "dirtyBucketName" : "tdr-upload-files-cloudfront-dirty-intg"
      }
    }
  ]
}, None)
```

This is the minimum json you need but you can experiment with additional messages in the `Records` element

Then either run this through the cli

`python src/matcher.py`

or debug through Pycharm or the IDE of your choice.

The following environment variables need to be set for this to work although the AWS ones are optional if you're using profiles.
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN

AWS_LAMBDA_FUNCTION_VERSION - This is the lambda function version. It's provided by the lambda and so needs to be set here. Set it to "$LATEST"
OUTPUT_QUEUE - This is the queue for the api updates. It's https://sqs.eu-west-2.amazonaws.com/${account_number}/tdr-api-update-\$STAGE
ENVIRONMENT - intg, staging or prod
ROOT_DIRECTORY - This is the root directory for the EFS backend checks file system. It's /mnt/backend-checks

## Running the tests

Normal run: `python -m pytest`

Run with coverage `python -m pytest --cov=src`

Run with coverage and missing lines `python -m pytest --cov-report term-missing --cov=src`

Run with coverage, missing lines and junit output `python -m pytest --cov-report term-missing --junitxml="result.xml" --cov=src`

## Yara rules checks.

There is a Jenkins job run on a schedule from the Jenkinsfile-check-rules file. This carries out the following steps. 
* Builds the base yara image.
* Builds the rules yara image.
* Gets the most recent version from git.
* Downloads the lambda zip file from S3.
* Unzips the zip file and copies the exiting compiled rule file into the current directory.
* Downloads the test files from tdr-antivirus-test-files-mgmt in S3.
* Builds the docker image from the Dockerfile-run-tests file which copies the existing compiled rules and the test files to the container.
* Runs this docker image. This runs a python script which runs these steps:
    * Compares the rule identifiers in the old compiled rules file with the new one.
    * If there are new rules in the new compiled rules, it will run the checks against the files. It will not detect if rules have been removed and it won't check if they've been changed either. I tried to do it based on hashes but it's likely to bring up too many false positives.
    * Yara is run against the test files using the new rules. If it finds no matches, if returns exit code zero and the Jenkins job builds the Antivirus multibranch master branch job.
  
These steps can be run manually by copying the commands from the Jenkinsfile-check-rules.

Because this runs the master build job without any code changes, you end up with more than one version pointed to the same commit. We still have separate zip files stored in S3 for each version though so we can still roll back if necessary.
