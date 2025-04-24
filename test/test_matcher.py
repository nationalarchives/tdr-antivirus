import os

import boto3
import pytest
from botocore.errorfactory import ClientError
from moto import mock_aws

from src import matcher
from src.matcher import S3Location


@pytest.fixture(scope='function')
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'eu-west-2'


@pytest.fixture(scope='function')
def s3(aws_credentials):
    with mock_aws():
        yield boto3.resource('s3', region_name='eu-west-2')


@pytest.fixture(scope='function')
def s3_client(aws_credentials):
    with mock_aws():
        yield boto3.client('s3', region_name='eu-west-2')


@pytest.fixture(scope='function')
def s3_bucket(s3):
    s3.create_bucket(Bucket=metadata_source_location.bucket, CreateBucketConfiguration=location)
    return s3.Bucket(metadata_source_location.bucket)


class MockSettings:
    def __init__(self, tmpdir, bucket, key):
        self.local_download_location = os.path.join(tmpdir, "tests")
        self.s3_source_location = S3Location(bucket=bucket, key=key)

def get_consignment_event():
    return {
        "userId": "userId",
        "consignmentId": "consignmentId",
        "fileId": "fileId",
        "originalPath": "original/path"
    }


def get_metadata_event():
    return {
        "scanType": "metadata",
        "consignmentId": "consignmentId",
        "fileId": "draft-metadata.csv",
    }


dirty_s3_bucket = 'tdr-upload-files-cloudfront-dirty-intg'
quarantine_s3_bucket = 'tdr-upload-files-quarantine-intg'
metadata_source_location = S3Location(
    bucket='tdr-draft-metadata-intg',
    key='consignmentId/draft-metadata.csv'
)
clean_s3_bucket = 'tdr-upload-files-intg'
tdr_standard_dirty_key = "userId/consignmentId/fileId"
tdr_standard_copy_key = "consignmentId/fileId"
tdr_metadata_copy_key = "consignmentId/metadata/draft-metadata.csv"
location = {'LocationConstraint': 'eu-west-2'}


def mock_guard_duty_scan_complete(s3_client, dirty_bucket, object_key, scan_result = 'NO_THREATS_FOUND'):
    s3_client.put_object_tagging(
        Bucket=dirty_bucket,
        Key=object_key,
        Tagging={
            'TagSet': [
                {
                    'Key': 'GuardDutyMalwareScanStatus',
                    'Value': f'{scan_result}'
                },
            ]
        })


def set_environment(temp_directory):
    os.environ["ENVIRONMENT"] = "intg"
    os.environ["ROOT_DIRECTORY"] = str(temp_directory)
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"


def set_up(s3, s3_client, tmpdir, dirty_bucket = dirty_s3_bucket, object_key = tdr_standard_dirty_key, guard_duty_result = 'NO_THREATS_FOUND'):
    set_environment(tmpdir)
    s3.create_bucket(Bucket=dirty_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_bucket, object_key).put(Body="test")
    mock_guard_duty_scan_complete(s3_client, dirty_bucket, object_key, guard_duty_result)


def test_correct_output_guard_duty_scan_enabled(s3, s3_client, tmpdir):
    set_up(s3, s3_client, tmpdir)
    res = matcher.matcher_lambda_handler(get_consignment_event(), None)["antivirus"]
    assert res["software"] == "awsGuardDutyMalwareScan"
    assert res["softwareVersion"] == "AWSGuardDuty"
    assert res["databaseVersion"] == "1"
    assert res["result"] == ""


def test_correct_file_id_provided(s3, s3_client, tmpdir):
    set_up(s3, s3_client, tmpdir)
    res = matcher.matcher_lambda_handler(get_consignment_event(), None)["antivirus"]
    assert res["fileId"] == "fileId"


def test_guard_duty_threat_found(s3, tmpdir, s3_client):
    set_up(s3, s3_client, tmpdir, guard_duty_result='THREATS_FOUND')
    res = matcher.matcher_lambda_handler(get_consignment_event(), None)["antivirus"]
    assert res["result"] == "awsGuardDutyThreatFound"
    assert res["software"] == "awsGuardDutyMalwareScan"
    assert res["softwareVersion"] == "AWSGuardDuty"
    assert res["databaseVersion"] == "1"


def test_guard_duty_threat_found_metadata(s3, s3_client, tmpdir):
    set_up(s3, s3_client, tmpdir, dirty_bucket=metadata_source_location.bucket, object_key=metadata_source_location.key, guard_duty_result='THREATS_FOUND')
    res = matcher.matcher_lambda_handler(get_metadata_event(), None)["antivirus"]
    assert res["result"] == "awsGuardDutyThreatFound"


def test_bucket_not_found(s3, tmpdir):
    with pytest.raises(ClientError) as err:
        set_environment(tmpdir)
        s3.create_bucket(Bucket='anotherbucket', CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
        s3.Object("anotherbucket", tdr_standard_dirty_key).put(Body="test")
        matcher.matcher_lambda_handler(get_consignment_event(), None)
    assert err.typename == 'NoSuchBucket'


def test_key_not_found(s3, s3_client, tmpdir):
    with pytest.raises(ClientError) as err:
        set_environment(tmpdir)
        s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
        s3.Object(dirty_s3_bucket, "test0").put(Body="test")
        matcher.matcher_lambda_handler(get_consignment_event(), None)
    assert err.typename == 'NoSuchKey'


def test_copy_to_quarantine_with_threats_found(s3, s3_client, tmpdir):
    set_up(s3, s3_client, tmpdir, guard_duty_result='THREATS_FOUND')
    matcher.matcher_lambda_handler(get_consignment_event(), None)
    res = s3_client.get_object(Bucket=quarantine_s3_bucket, Key=tdr_standard_copy_key)
    assert res["Body"].read() == b"test"


def test_copy_to_quarantine_with_threats_found_metadata(s3, s3_client, tmpdir):
    set_up(s3, s3_client, tmpdir, dirty_bucket=metadata_source_location.bucket, object_key=metadata_source_location.key, guard_duty_result='THREATS_FOUND')
    matcher.matcher_lambda_handler(get_metadata_event(), None)
    res = s3_client.get_object(Bucket=quarantine_s3_bucket, Key=tdr_metadata_copy_key)
    assert res["Body"].read() == b"test"


def test_no_copy_to_quarantine_bucket_with_no_threats_found(s3, s3_client, tmpdir):
    with pytest.raises(ClientError) as err:
        set_up(s3, s3_client, tmpdir)
        matcher.matcher_lambda_handler(get_consignment_event(), None)
        s3_client.get_object(Bucket=quarantine_s3_bucket, Key="consignmentId")
    assert err.typename == 'NoSuchKey'


def test_copy_to_clean_bucket_with_no_threats_found(s3, s3_client, tmpdir):
    set_up(s3, s3_client, tmpdir)
    matcher.matcher_lambda_handler(get_consignment_event(), None)
    res = s3_client.get_object(Bucket=clean_s3_bucket, Key=tdr_standard_copy_key)
    assert res["Body"].read() == b"test"


def test_no_copy_to_clean_with_threats_found_metadata(s3, s3_client, tmpdir):
    with pytest.raises(ClientError) as err:
        set_up(s3, s3_client, tmpdir, dirty_bucket=metadata_source_location.bucket, object_key=metadata_source_location.key, guard_duty_result='THREATS_FOUND')
        matcher.matcher_lambda_handler(get_metadata_event(), None)
        s3_client.get_object(Bucket=clean_s3_bucket, Key="consignmentId")
    assert err.typename == 'NoSuchKey'


def test_no_copy_to_clean_with_threats_found(s3, s3_client, tmpdir):
    with pytest.raises(ClientError) as err:
        set_up(s3, s3_client, tmpdir, guard_duty_result='THREATS_FOUND')
        matcher.matcher_lambda_handler(get_consignment_event(), None)
        s3_client.get_object(Bucket=clean_s3_bucket, Key=tdr_standard_copy_key)
    assert err.typename == 'NoSuchKey'
