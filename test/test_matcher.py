import boto3
import pytest
from moto import mock_s3, mock_sqs, mock_kms
import os
from src import matcher
import yara
import json
import base64
from botocore.errorfactory import ClientError


@pytest.fixture(scope='function')
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'


@pytest.fixture(scope='function')
def kms(aws_credentials):
    with mock_kms():
        yield boto3.client('kms', region_name='eu-west-2')


@pytest.fixture(scope='function')
def s3(aws_credentials):
    with mock_s3():
        yield boto3.resource('s3', region_name='eu-west-2')


@pytest.fixture(scope='function')
def s3_client(aws_credentials):
    with mock_s3():
        yield boto3.client('s3', region_name='eu-west-2')


@pytest.fixture(scope='function')
def sqs(aws_credentials):
    with mock_sqs():
        yield boto3.client('sqs', region_name='eu-west-2')


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


def get_records(num=1):
    records = []
    for i in range(num):
        body = {
            "cognitoId": "region%3AcognitoId",
            "consignmentId": "consignmentId",
            "fileId": "fileId" + str(i),
            "originalPath": "original/path"
        }

        message = {
            "body": json.dumps(body)
        }

        records.append(
            message
        )
    return {
        "Records": records
    }


output_sqs_queue = "tdr-api-update-intg"
dirty_s3_bucket = 'tdr-upload-files-dirty-intg'
quarantine_s3_bucket = 'tdr-upload-files-quarantine-intg'
clean_s3_bucket = 'tdr-upload-files-intg'
tdr_standard_dirty_key = "region:cognitoId/consignmentId/fileId"
tdr_standard_copy_key = "consignmentId/fileId"
location = {'LocationConstraint': 'eu-west-2'}
output_queue_url = "https://queue.amazonaws.com/aws_account_number/tdr-api-update-intg"


def encrypt(key, kms, value):
    return base64.b64encode(kms.encrypt(
        KeyId=key,
        Plaintext=bytearray(value, 'utf-8'),
        EncryptionContext={
            'LambdaFunctionName': 'test-function-name'
        }
    )['CiphertextBlob']).decode('utf-8')


def set_environment(kms):
    key = kms.create_key(
        Policy='string',
        Description='string',
    )['KeyMetadata']['KeyId']
    print(encrypt(key, kms, "intg"))
    os.environ["ENVIRONMENT"] = encrypt(key, kms, "intg")
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
    os.environ["AWS_LAMBDA_FUNCTION_NAME"] = "test-function-name"
    os.environ["OUTPUT_QUEUE"] = encrypt(key, kms, output_queue_url)
    os.environ["ROOT_DIRECTORY"] = encrypt(key, kms, "mnt/backend-checks")


def test_load_is_called(s3, sqs, mocker, kms):
    set_environment(kms)

    sqs.create_queue(QueueName=output_sqs_queue)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    matcher.matcher_lambda_handler(get_records(), None)
    yara.load.assert_called_once_with("output")


@pytest.mark.skip(reason="in this branch we generate random values to test the export")
def test_correct_output(s3, sqs, mocker, kms):
    set_environment(kms)
    sqs.create_queue(QueueName=output_sqs_queue)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    res = matcher.matcher_lambda_handler(get_records(), None)

    assert res[0]["software"] == "yara"
    assert res[0]["softwareVersion"] == yara.__version__
    assert res[0]["databaseVersion"] == "1"


def test_correct_file_id_provided(s3, sqs, mocker, kms):
    set_environment(kms)
    sqs.create_queue(QueueName=output_sqs_queue)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    res = matcher.matcher_lambda_handler(get_records(), None)

    assert res[0]["fileId"] == "fileId0"


def test_match_found(s3, sqs, mocker, kms):
    set_environment(kms)
    sqs.create_queue(QueueName=output_sqs_queue)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')

    yara.load.return_value = MockRulesMatchFound()
    res = matcher.matcher_lambda_handler(get_records(), None)

    assert res[0]["result"] == "testmatch"


def test_no_match_found(s3, sqs, mocker, kms):
    set_environment(kms)
    sqs.create_queue(QueueName=output_sqs_queue)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesNoMatch()
    res = matcher.matcher_lambda_handler(get_records(), None)
    assert res[0]["result"] == ""


def test_multiple_match_found(s3, sqs, mocker, kms):
    set_environment(kms)
    sqs.create_queue(QueueName=output_sqs_queue)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMultipleMatchFound()
    res = matcher.matcher_lambda_handler(get_records(), None)
    assert res[0]["result"] == "testmatch\ntestmatch"


def test_multiple_records(s3, sqs, mocker, kms):
    set_environment(kms)
    sqs.create_queue(QueueName=output_sqs_queue)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}0").put(Body="test")
    s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}1").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    res = matcher.matcher_lambda_handler(get_records(2), None)
    assert len(res) == 2
    assert res[0]["result"] == "testmatch"
    assert res[1]["result"] == "testmatch"


def test_bucket_not_found(s3, s3_client, sqs, mocker, kms):
    with pytest.raises(ClientError) as err:
        set_environment(kms)
        sqs.create_queue(QueueName=output_sqs_queue)
        s3.create_bucket(Bucket='anotherbucket', CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
        s3.Object("anotherbucket", f"{tdr_standard_dirty_key}0").put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesNoMatch()
        matcher.matcher_lambda_handler(get_records(), None)
    assert err.typename == 'NoSuchBucket'


def test_key_not_found(s3, sqs, mocker, kms):
    with pytest.raises(ClientError) as err:
        set_environment(kms)
        sqs.create_queue(QueueName=output_sqs_queue)
        s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
        s3.Object(dirty_s3_bucket, "test0").put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesNoMatch()
        matcher.matcher_lambda_handler(get_records(), None)
    assert err.typename == 'ClientError'


def test_match_fails(s3, sqs, mocker, kms):
    with pytest.raises(yara.Error):
        set_environment(kms)
        sqs.create_queue(QueueName=output_sqs_queue)
        s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
        s3.Object(dirty_s3_bucket, "test0").put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesMatchError()
        matcher.matcher_lambda_handler(get_records(), None)


def test_no_records():
    res = matcher.matcher_lambda_handler([], None)
    assert res == []


def test_output_sent_to_queue(s3, sqs, mocker, kms):
    set_environment(kms)
    sqs.create_queue(QueueName=output_sqs_queue)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    matcher.matcher_lambda_handler(get_records(), None)
    res = sqs.receive_message(QueueUrl=output_queue_url)
    print(res["Messages"])
    assert len(res["Messages"]) == 1


def test_output_sent_to_queue_multiple_records(s3, sqs, mocker, kms):
    set_environment(kms)
    sqs.create_queue(QueueName=output_sqs_queue)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}0").put(Body="test")
    s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}1").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    matcher.matcher_lambda_handler(get_records(2), None)
    res = sqs.receive_message(QueueUrl=output_queue_url, MaxNumberOfMessages=10)
    messages = res["Messages"]
    assert len(messages) == 2


def test_copy_to_quarantine(s3, sqs, s3_client, mocker, kms):
    set_environment(kms)
    sqs.create_queue(QueueName=output_sqs_queue)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    matcher.matcher_lambda_handler(get_records(), None)
    res = s3_client.get_object(Bucket=quarantine_s3_bucket, Key=f"{tdr_standard_copy_key}0")
    assert res["Body"].read() == b"test"


def test_no_copy_to_quarantine_clean(s3, sqs, s3_client, mocker, kms):
    with pytest.raises(ClientError) as err:
        set_environment(kms)
        sqs.create_queue(QueueName=output_sqs_queue)
        s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
        s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}0").put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesNoMatch()
        matcher.matcher_lambda_handler(get_records(), None)
        s3_client.get_object(Bucket=quarantine_s3_bucket, Key="consignmentId")
    assert err.typename == 'NoSuchKey'


def test_copy_to_clean_bucket(s3, sqs, s3_client, mocker, kms):
    set_environment(kms)
    sqs.create_queue(QueueName=output_sqs_queue)
    s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
    s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesNoMatch()
    matcher.matcher_lambda_handler(get_records(), None)
    res = s3_client.get_object(Bucket=clean_s3_bucket, Key=f"{tdr_standard_copy_key}0")
    assert res["Body"].read() == b"test"


def test_no_copy_to_clean_with_match(s3, sqs, s3_client, mocker, kms):
    with pytest.raises(ClientError) as err:
        set_environment(kms)
        sqs.create_queue(QueueName=output_sqs_queue)
        s3.create_bucket(Bucket=dirty_s3_bucket, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=quarantine_s3_bucket, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=clean_s3_bucket, CreateBucketConfiguration=location)
        s3.Object(dirty_s3_bucket, f"{tdr_standard_dirty_key}0").put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesMatchFound()
        matcher.matcher_lambda_handler(get_records(), None)
        s3_client.get_object(Bucket=clean_s3_bucket, Key=f"{tdr_standard_copy_key}0")
    assert err.typename == 'NoSuchKey'
