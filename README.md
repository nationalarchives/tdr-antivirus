This is the code and configuration to carry out the antivirus checks on a single file from S3

## Building the lambda function

The lambda function is built by Jenkins. There are four Jenkins jobs in four Jenkinsfiles.

### Jenkinsfile-build
There are three docker images that are used to build the lambda. 

| File name               | Image Name        | Description                                                                                                               |
|-------------------------|-------------------|---------------------------------------------------------------------------------------------------------------------------|
| Dockerfile-yara         | yara              | Installs yara and some dependencies it needs like openssl on an alpine image.                                             |
| Dockerfile-compile      | yara-rules        | Uses yara as the base image. Gets the yara rules from github and compiles them into a single file for yara to use         |
| Dockerfile-dependencies | yara-dependencies | Installs necessary software on an amazon linux image and zips it up to be used by the lambda                              |

The build job rebuilds all of these images. This isn't necessary most of the time because the dependency versions and yara version don't change that often and so this job is only ever run manually when we need to update the dependencies.
The images are tagged with the jenkins build number and then tagged with the stage. This allows us to have different sets of dependencies for different stages. 

### Jenkinsfile-test 
This runs git secrets and runs the python tests. This is the standard multibranch pipeline job which runs on PRs and merge to master. If this runs on the master branch, it will trigger the bundle job.

### Jenkinsfile-bundle
This creates the lambda zip using the stored docker images that were built using the Dockerfile-build job and the latest python code from the project. The zip is uploaded to s3 and the deploy job is triggered.  

### Jenkinsfile-deploy
This updates the lambda with the zip file from S3.

## Deploying changes

There are two situations where the lambda will need to be redeployed.

### Docker image updates
If there are vulnerabilities in the current docker images and they need to be rebuilt or dependencies need to be updated, but there are no changes to the Jenkinsfile-build or the Dockerfiles themselves, then run the [build](https://jenkins.tdr-management.nationalarchives.gov.uk/job/TDR%20Antivirus%20Build/) job. This will rebuild all the images with the latest base images and the latest dependencies from the package managers.

If there are changes to the Dockerfile or Jenkinsfile-build, this will need to be reviewed and merged to master as normal, then the build job will need to be run again. 

The job will tag the images with the build number and the stage provided in the parameters. It will then run the bundle and deploy jobs to deploy the changes to the lambda.

### Python code updates
This includes our own custom code and any dependencies in requirements.txt This shouldn't need any manual intervention for the integration environment as it should trigger the [test](https://jenkins.tdr-management.nationalarchives.gov.uk/job/TDR%20Antivirus%20Test/) job which in turn runs the bundle and deploy jobs. The build number from the bundle job determines the version of the code bundle.
To deploy to other environments, run the [deploy](https://jenkins.tdr-management.nationalarchives.gov.uk/job/TDR%20Antivirus%20Deploy/) job with the right stage and deployment version.

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
      "body": {
        "cognitoId": "cognitoId1234",
        "consignmentId": "bf2181c7-70e4-448d-b122-be561d0e797a",
        "fileId": "df216308-e78b-4328-90ef-8e4ebfef6b9d",
        "originalPath": "original/path"
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
