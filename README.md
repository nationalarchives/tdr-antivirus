# TDR Antivirus

This is the code and configuration to carry out the antivirus checks on a single file from S3.

It checks the results of the AWS GuardDuty S3 malware protection

## Configuration Parameters

Lambda takes parameters to configure the scanning options.

| Parameter Name                  | Optional | Default Value                                         | Description                                                                                      | Example                     | 
|---------------------------------|----------|-------------------------------------------------------|--------------------------------------------------------------------------------------------------|-----------------------------|
| consignment_id                  | false    | N/A                                                   | TDR UUID for the consignment the object to scan belongs to                                       |                             |
| file_id                         | false    | N/A                                                   | Name of the object to scan                                                                       |                             |
| user_id                         | true     | `None`                                                | TDR UUID of the user who uploaded the object to scan                                             |                             |
| original_path                   | true     | `None`                                                | Original path to the object to scan. Used to create local version of object for scanning         |                             |
| scan_type                       | true     | N/A                                                   | **Deprecated**. Use combination of optional parameters to set configuration. Type of scan to run | `metadata` / `consignment`  |
| s3_source_bucket                | true     | `tdr-upload-files-cloudfront-dirty-{tdr environment}` | S3 bucket containing the object to scan                                                          | `{some AWS S3 bucket name}` |
| s3_source_bucket_key            | true     | `{user_id}/{consignment_id}/{file_id}`                | S3 bucket key of the object to scan                                                              |                             |
| s3_upload_bucket                | true     | `tdr-upload-files-{tdr environment}`                  | S3 bucket to copy clean objects to. If empty string then no copy occurs                          |                             |
| s3_upload_bucket_key            | true     | `{consignment_id}/{file_id}`                          | S3 bucket key of clean object. If empty value string no copy occurs                              |                             |
| s3_quarantine_bucket            | true     | `tdr-upload-files-quarantine-{tdr environment}`       | S3 bucket to copy infected objects to                                                            |                             |
| guard_duty_malware_scan_enabled | true     | True                                                  | Flag whether source s3 bucket has AWS GuardDuty malicious object scanning enabled.               |                             |

### Example Configuration

Object to scan details:
* **Consignment Id**: `bf2181c7-70e4-448d-b122-be561d0e797a`
* **File Id**: `myFileToScan.txt`
* **Original Path**: `identifier1/identifer2/myFileToScan.txt`
* **s3 Source bucket name**: `some-source-bucket`
* **s3 source object key**: same as original path
* **s3 clean bucket name**: `some-clean-bucket`
* **s3 clean object key**: same as s3 source object key
* **s3 quarantine bucket name**: `tdr-upload-files-quarantine-{tdr environment}`
* **AWS GuardDuty Malicious Scanning Enabled**: False

Event configuration to support the above would be as follows:

```json
    {
        "consignmentId": "bf2181c7-70e4-448d-b122-be561d0e797a",
        "fileId": "myFileToScan.txt",
        "originalPath": "identifier1/identifer2/myFileToScan.txt",
        "s3SourceBucket": "some-source-bucket",
        "s3SourceBucketKey": "identifier1/identifer2/myFileToScan.txt",
        "s3UploadBucket": "some-clean-bucket",
        "s3UploadBucketKey": "identifier1/identifer2/myFileToScan.txt",
        "guardDutyMalwareScanEnabled": False
   }
```

## Running locally

Create a virtual environment in the antivirus directory:

`python3 -m venv venv`

Activate the environment:

`source venv/bin/activate`

Install dependencies:

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
