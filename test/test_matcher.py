import boto3
import pytest
from moto import mock_s3
import os
from src import matcher
import yara
from botocore.errorfactory import ClientError

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
    with mock_s3():
        yield boto3.resource('s3', region_name='eu-west-2')


@pytest.fixture(scope='function')
def s3_client(aws_credentials):
    with mock_s3():
        yield boto3.client('s3', region_name='eu-west-2')


class MockMatch:
    rule = "testmatch"


class MockRulesMatchFound:

    @staticmethod
    def match(data):
        return [MockMatch()]


class MockRulesMultipleMatchFound:

    @staticmethod
    def match(data):
        return [MockMatch(), MockMatch()]


class MockRulesNoMatch:

    @staticmethod
    def match(data):
        return []


class MockRulesMatchError:

    @staticmethod
    def match(data):
        raise yara.Error()


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
location = {'LocationConstraint': 'eu-west-2'}


def set_environment(temp_directory):
    os.environ["ENVIRONMENT"] = "intg"
    os.environ["ROOT_DIRECTORY"] = str(temp_directory)
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"


def test_load_is_called(s3, mocker, tmpdir):
    set_environment(tmpdir)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, tdr_standard_dirty_key).put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    matcher.matcher_lambda_handler(get_consignment_event(), None)
    yara.load.assert_called_once_with("output")


def test_correct_output(s3, mocker, tmpdir):
    set_environment(tmpdir)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, tdr_standard_dirty_key).put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    res = matcher.matcher_lambda_handler(get_consignment_event(), None)["antivirus"]
    assert res["software"] == "yara"
    assert res["softwareVersion"] == yara.__version__
    assert res["databaseVersion"] == "1"


def test_correct_file_id_provided(s3, mocker, tmpdir):
    set_environment(tmpdir)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, tdr_standard_dirty_key).put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    res = matcher.matcher_lambda_handler(get_consignment_event(), None)["antivirus"]
    assert res["fileId"] == "fileId"


def test_match_found(s3, mocker, tmpdir):
    set_environment(tmpdir)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, tdr_standard_dirty_key).put(Body="test")
    mocker.patch('yara.load')

    yara.load.return_value = MockRulesMatchFound()
    res = matcher.matcher_lambda_handler(get_consignment_event(), None)["antivirus"]
    assert res["result"] == "testmatch"


def test_no_match_found(s3, mocker, tmpdir):
    set_environment(tmpdir)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, tdr_standard_dirty_key).put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesNoMatch()
    res = matcher.matcher_lambda_handler(get_consignment_event(), None)["antivirus"]
    assert res["result"] == ""


def test_multiple_match_found(s3, mocker, tmpdir):
    set_environment(tmpdir)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, tdr_standard_dirty_key).put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMultipleMatchFound()
    res = matcher.matcher_lambda_handler(get_consignment_event(), None)["antivirus"]
    assert res["result"] == "testmatch\ntestmatch"


def test_match_found_metadata(s3, mocker, tmpdir):
    set_environment(tmpdir)
    s3.create_bucket(Bucket=metadata_source_location.bucket, CreateBucketConfiguration=location)
    s3.Object(metadata_source_location.bucket, metadata_source_location.key).put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    res = matcher.matcher_lambda_handler(get_metadata_event(), None)["antivirus"]
    assert res["result"] == "testmatch"


def test_no_match_found_metadata(s3, mocker, tmpdir):
    set_environment(tmpdir)
    s3.create_bucket(Bucket=metadata_source_location.bucket, CreateBucketConfiguration=location)
    s3.Object(metadata_source_location.bucket, metadata_source_location.key).put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesNoMatch()
    res = matcher.matcher_lambda_handler(get_metadata_event(), None)["antivirus"]
    assert res["result"] == ""


def test_multiple_match_found_metadata(s3, mocker, tmpdir):
    set_environment(tmpdir)
    s3.create_bucket(Bucket=metadata_source_location.bucket, CreateBucketConfiguration=location)
    s3.Object(metadata_source_location.bucket, metadata_source_location.key).put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMultipleMatchFound()
    res = matcher.matcher_lambda_handler(get_metadata_event(), None)["antivirus"]
    assert res["result"] == "testmatch\ntestmatch"


def test_bucket_not_found(s3, mocker, tmpdir):
    with pytest.raises(ClientError) as err:
        set_environment(tmpdir)
        s3.create_bucket(Bucket='anotherbucket', CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
        s3.Object("anotherbucket", tdr_standard_dirty_key).put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesNoMatch()
        matcher.matcher_lambda_handler(get_consignment_event(), None)
    assert err.typename == 'NoSuchBucket'


def test_key_not_found(s3, mocker, tmpdir):
    with pytest.raises(ClientError) as err:
        set_environment(tmpdir)
        s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
        s3.Object(dirty_s3_bucket, "test0").put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesNoMatch()
        matcher.matcher_lambda_handler(get_consignment_event(), None)
    assert err.typename == 'ClientError'


def test_match_fails(s3, mocker, tmpdir):
    with pytest.raises(yara.Error):
        set_environment(tmpdir)
        s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
        s3.Object(dirty_s3_bucket, tdr_standard_dirty_key).put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesMatchError()
        matcher.matcher_lambda_handler(get_consignment_event(), None)


def test_copy_to_quarantine(s3, s3_client, mocker, tmpdir):
    set_environment(tmpdir)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, tdr_standard_dirty_key).put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    matcher.matcher_lambda_handler(get_consignment_event(), None)
    res = s3_client.get_object(Bucket=quarantine_s3_bucket, Key=tdr_standard_copy_key)
    assert res["Body"].read() == b"test"


def test_no_copy_to_quarantine_with_match_metadata(s3, s3_client, mocker, tmpdir):
    with pytest.raises(ClientError) as err:
        set_environment(tmpdir)
        s3.create_bucket(Bucket=metadata_source_location.bucket, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
        s3.Object(metadata_source_location.bucket, metadata_source_location.key).put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesMatchFound()
        matcher.matcher_lambda_handler(get_metadata_event(), None)
        s3_client.get_object(Bucket=quarantine_s3_bucket, Key="consignmentId")
    assert err.typename == 'NoSuchKey'


def test_no_copy_to_quarantine_clean(s3, s3_client, mocker, tmpdir):
    with pytest.raises(ClientError) as err:
        set_environment(tmpdir)
        s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
        s3.Object(dirty_s3_bucket, tdr_standard_dirty_key).put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesNoMatch()
        matcher.matcher_lambda_handler(get_consignment_event(), None)
        s3_client.get_object(Bucket=quarantine_s3_bucket, Key="consignmentId")
    assert err.typename == 'NoSuchKey'


def test_copy_to_clean_bucket(s3, s3_client, mocker, tmpdir):
    set_environment(tmpdir)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, tdr_standard_dirty_key).put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesNoMatch()
    matcher.matcher_lambda_handler(get_consignment_event(), None)
    res = s3_client.get_object(Bucket=clean_s3_bucket, Key=tdr_standard_copy_key)
    assert res["Body"].read() == b"test"


def test_no_copy_to_clean_without_match_metadata(s3, s3_client, mocker, tmpdir):
    with pytest.raises(ClientError) as err:
        set_environment(tmpdir)
        s3.create_bucket(Bucket=metadata_source_location.bucket, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
        s3.Object(metadata_source_location.bucket, metadata_source_location.key).put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesNoMatch()
        matcher.matcher_lambda_handler(get_metadata_event(), None)
        s3_client.get_object(Bucket=clean_s3_bucket, Key="consignmentId")
    assert err.typename == 'NoSuchKey'


def test_no_copy_to_clean_with_match(s3, s3_client, mocker, tmpdir):
    with pytest.raises(ClientError) as err:
        set_environment(tmpdir)
        s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
        s3.Object(dirty_s3_bucket, tdr_standard_dirty_key).put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesMatchFound()
        matcher.matcher_lambda_handler(get_consignment_event(), None)
        s3_client.get_object(Bucket=clean_s3_bucket, Key=tdr_standard_copy_key)
    assert err.typename == 'NoSuchKey'
