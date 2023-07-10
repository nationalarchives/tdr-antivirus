This is the code and configuration to carry out the antivirus checks on a single file from S3

## Building the lambda function

The lambda function is built by GitHub actions. There are three actions in three yml files.

### test.yml 
This runs git secrets and runs the python tests. This is the standard multibranch pipeline job which runs on PRs and merge to master. If this runs on the master branch, it will rebuild the three Docker images locally and use them to build the lambda.

### build.yml
There are three docker images that are used to build the lambda.

| File name               | Image Name        | Description                                                                                                               |
|-------------------------|-------------------|---------------------------------------------------------------------------------------------------------------------------|
| Dockerfile-yara         | yara              | Installs yara and some dependencies it needs like openssl on an alpine image.                                             |
| Dockerfile-compile      | yara-rules        | Uses yara as the base image. Gets the yara rules from github and compiles them into a single file for yara to use         |
| Dockerfile-dependencies | yara-dependencies | Installs necessary software on an amazon linux image and zips it up to be used by the lambda                              |

These images are built on every master build locally and are not stored in ECR.

### deploy.yml
This deploys the lambda from S3

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
        "userId": "7ad28066-7a76-4e07-b540-f005b6919328",
        "consignmentId": "bf2181c7-70e4-448d-b122-be561d0e797a",
        "fileId": "df216308-e78b-4328-90ef-8e4ebfef6b9d",
        "originalPath": "original/path"
      }, None)
```


Then either run this through the cli

`python src/matcher.py`

or debug through Pycharm or the IDE of your choice.

The following environment variables need to be set for this to work although the AWS ones are optional if you're using profiles.
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN

AWS_LAMBDA_FUNCTION_VERSION - This is the lambda function version. It's provided by the lambda and so needs to be set here. Set it to "$LATEST"
ENVIRONMENT - intg, staging or prod
ROOT_DIRECTORY - This is the root directory for the file download in the lambda file system.

## Running the tests

Normal run: `python -m pytest`

Run with coverage `python -m pytest --cov=src`

Run with coverage and missing lines `python -m pytest --cov-report term-missing --cov=src`

Run with coverage, missing lines and junit output `python -m pytest --cov-report term-missing --junitxml="result.xml" --cov=src`

## Yara rules checks.

There is a GitHub actions job [TDR Check Antivirus Rules](https://github.com/nationalarchives/tdr-antivirus/actions/workflows/check_rules.yml) which is run on a schedule from the .github/workflows/check_rules file. This runs at 07:20 on a Monday. This carries out the following steps. 
* Builds the base yara image.
* Builds the rules yara image.
* Gets the highest version tag from git.
* Downloads the lambda zip file from S3.
* Unzips the zip file and copies the existing compiled rule file into the current directory.
* Downloads the tests file from the tdr-antivirus-test-files-mgmt S3 bucket.
* Builds the docker image from the Dockerfile-run-tests file which copies the existing compiled rules and the test files to the container.
* Runs this docker image. This runs a python script which runs these steps:
    * Compares the rule identifiers in the old compiled rules file with the new one.
    * If there are new yara rules in the new compiled rules, it will run the antivirus checks against the test files from the S3 bucket.
        * NOTE: It will not detect if rules have been removed, and it won't check if they've been changed either. I tried to do it based on hashes but it's likely to bring up too many false positives.
    * Yara is run against the test files using the new rules. If no matches are found after the new rules are run against the test files, it returns exit code zero and the GitHub actions job builds the Antivirus multibranch master branch job.
  
These steps can be run manually by copying the commands from the .github/workflows/check_rules.yml file.

Because this runs the master build job without any code changes, you end up with more than one version pointed to the same commit. We still have separate zip files stored in S3 for each version though so we can still roll back if necessary.

## Test files bucket terraform

**Important Note**: tdr-terraform-environments uses >= v1.5.0 of Terraform. Ensure that Terraform >= v1.5.0 is installed before proceeding.

In the terraform directory there are some terraform files which are used to create the bucket `tdr-antivirus-test-files-mgmt`. This bucket is used to store the files against which we run a periodic check of any new yara rules. This should almost never need to be updated.

To run the Terraform:

1. Navigate to the `terraform` directory:
    ```
   [location of project]: cd terraform
   ```
2. Clone the `tdr-terraform-modules` repository into the `terraform` directory
    ```
   [location of terraform directory]: git clone https://github.com/nationalarchives/tdr-terraform-modules.git
   ```
3. Initiate Terraform:
    ```
   [location of terraform directory]: terraform init
   ```
4. Select the `default` Terraform workspace`
    ```
   [location of terraform directory]: terraform workspace select default
   ```
5. Run Terraform `plan` / `apply` commands with AWS credentials that have access to the TDR management environment as needed:
    ```
   [location of terraform directory]: terraform {plan/apply}
   ```