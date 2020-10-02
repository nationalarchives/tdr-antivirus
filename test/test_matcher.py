import boto3
import pytest
from moto import mock_s3, mock_sqs
import os
from src import matcher
import yara
from botocore.errorfactory import ClientError


@pytest.fixture(scope='function')
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'


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


def get_upload_events(num=1):
    events = []
    for i in range(num):
        events.append(
            {
                "cognitoId": "cognitoId",
                "consignmentId": "consignmentId",
                "fileId": "fileId" +str(i),
                "originalPath": "original/path"
            }
        )
    return events


tdr_standard_dirty_key = "cognitoId/consignmentId/fileId"
tdr_standard_clean_key = "consignmentId/fileId"
location = {'LocationConstraint': 'eu-west-2'}


def test_load_is_called(s3, sqs, mocker):
    os.environ["ENVIRONMENT"] = "intg"
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
    os.environ["SQS_URL"] = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
    os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
    sqs.create_queue(QueueName="tdr-api-update-intg")
    s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
    s3.create_bucket(Bucket='tdr-upload-files-quarantine-intg', CreateBucketConfiguration=location)
    s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    matcher.matcher_lambda_handler(get_upload_events(), None)
    yara.load.assert_called_once_with("output")


def test_correct_output(s3, sqs, mocker):
    os.environ["ENVIRONMENT"] = "intg"
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
    os.environ["SQS_URL"] = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
    os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
    sqs.create_queue(QueueName="tdr-api-update-intg")
    s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
    s3.create_bucket(Bucket='tdr-upload-files-quarantine-intg', CreateBucketConfiguration=location)
    s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    res = matcher.matcher_lambda_handler(get_upload_events(), None)

    assert res[0]["software"] == "yara"
    assert res[0]["softwareVersion"] == yara.__version__
    assert res[0]["databaseVersion"] == "1"


def test_correct_file_id_provided(s3, sqs, mocker):
    os.environ["ENVIRONMENT"] = "intg"
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
    os.environ["SQS_URL"] = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
    os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
    sqs.create_queue(QueueName="tdr-api-update-intg")
    s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
    s3.create_bucket(Bucket='tdr-upload-files-quarantine-intg', CreateBucketConfiguration=location)
    s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    res = matcher.matcher_lambda_handler(get_upload_events(), None)

    assert res[0]["fileId"] == "fileId0"


def test_match_found(s3, sqs, mocker):
    os.environ["ENVIRONMENT"] = "intg"
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
    os.environ["SQS_URL"] = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
    os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
    sqs.create_queue(QueueName="tdr-api-update-intg")
    s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
    s3.create_bucket(Bucket='tdr-upload-files-quarantine-intg', CreateBucketConfiguration=location)
    s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')

    yara.load.return_value = MockRulesMatchFound()
    res = matcher.matcher_lambda_handler(get_upload_events(), None)

    assert res[0]["result"] == "testmatch"


def test_no_match_found(s3, sqs, mocker):
    os.environ["ENVIRONMENT"] = "intg"
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
    os.environ["SQS_URL"] = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
    os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
    sqs.create_queue(QueueName="tdr-api-update-intg")
    s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
    s3.create_bucket(Bucket='tdr-upload-files-intg', CreateBucketConfiguration=location)
    s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesNoMatch()
    res = matcher.matcher_lambda_handler(get_upload_events(), None)
    assert res[0]["result"] == ""


def test_multiple_match_found(s3, sqs, mocker):
    os.environ["ENVIRONMENT"] = "intg"
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
    os.environ["SQS_URL"] = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
    os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
    sqs.create_queue(QueueName="tdr-api-update-intg")
    s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
    s3.create_bucket(Bucket='tdr-upload-files-quarantine-intg', CreateBucketConfiguration=location)
    s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMultipleMatchFound()
    res = matcher.matcher_lambda_handler(get_upload_events(), None)
    assert res[0]["result"] == "testmatch\ntestmatch"


def test_multiple_records(s3, sqs, mocker):
    os.environ["ENVIRONMENT"] = "intg"
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
    os.environ["SQS_URL"] = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
    os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
    sqs.create_queue(QueueName="tdr-api-update-intg")
    s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
    s3.create_bucket(Bucket='tdr-upload-files-quarantine-intg', CreateBucketConfiguration=location)
    s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}0").put(Body="test")
    s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}1").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    res = matcher.matcher_lambda_handler(get_upload_events(2), None)
    assert len(res) == 2
    assert res[0]["result"] == "testmatch"
    assert res[1]["result"] == "testmatch"


def test_bucket_not_found(s3, s3_client, sqs, mocker):
    with pytest.raises(ClientError) as err:
        os.environ["ENVIRONMENT"] = "intg"
        os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
        os.environ["SQS_URL"] = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
        os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
        sqs.create_queue(QueueName="tdr-api-update-intg")
        s3.create_bucket(Bucket='anotherbucket', CreateBucketConfiguration=location)
        s3.create_bucket(Bucket='tdr-upload-files-intg', CreateBucketConfiguration=location)
        s3.Object("anotherbucket", f"{tdr_standard_dirty_key}0").put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesNoMatch()
        matcher.matcher_lambda_handler(get_upload_events(), None)
    assert err.typename == 'NoSuchBucket'


def test_key_not_found(s3, sqs, mocker):
    with pytest.raises(ClientError) as err:
        os.environ["ENVIRONMENT"] = "intg"
        os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
        os.environ["SQS_URL"] = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
        os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
        sqs.create_queue(QueueName="tdr-api-update-intg")
        s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
        s3.create_bucket(Bucket='tdr-upload-files-intg', CreateBucketConfiguration=location)
        s3.Object("tdr-upload-files-dirty-intg", "test0").put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesNoMatch()
        matcher.matcher_lambda_handler(get_upload_events(), None)
    assert err.typename == 'ClientError'


def test_match_fails(s3, sqs, mocker):
    with pytest.raises(yara.Error):
        os.environ["ENVIRONMENT"] = "intg"
        os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
        os.environ["SQS_URL"] = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
        os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
        sqs.create_queue(QueueName="tdr-api-update-intg")
        s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
        s3.Object("tdr-upload-files-dirty-intg", "test0").put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesMatchError()
        matcher.matcher_lambda_handler(get_upload_events(), None)


def test_no_records():
    res = matcher.matcher_lambda_handler([], None)
    assert res == []


def test_output_sent_to_queue(s3, sqs, mocker):
    os.environ["ENVIRONMENT"] = "intg"
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
    os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
    queue_url = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
    os.environ["SQS_URL"] = queue_url
    sqs.create_queue(QueueName="tdr-api-update-intg")
    s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
    s3.create_bucket(Bucket='tdr-upload-files-quarantine-intg', CreateBucketConfiguration=location)
    s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    matcher.matcher_lambda_handler(get_upload_events(), None)
    res = sqs.receive_message(QueueUrl=queue_url)
    print(res["Messages"])
    assert len(res["Messages"]) == 1


def test_output_sent_to_queue_multiple_records(s3, sqs, mocker):
    os.environ["ENVIRONMENT"] = "intg"
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
    os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
    queue_url = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
    os.environ["SQS_URL"] = queue_url
    sqs.create_queue(QueueName="tdr-api-update-intg")
    s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
    s3.create_bucket(Bucket='tdr-upload-files-quarantine-intg', CreateBucketConfiguration=location)
    s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}0").put(Body="test")
    s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}1").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    matcher.matcher_lambda_handler(get_upload_events(2), None)
    res = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10)
    messages = res["Messages"]
    assert len(messages) == 2


def test_copy_to_quarantine(s3, sqs, s3_client, mocker):
    os.environ["ENVIRONMENT"] = "intg"
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
    os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
    queue_url = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
    os.environ["SQS_URL"] = queue_url
    quarantine = 'tdr-upload-files-quarantine-intg'
    sqs.create_queue(QueueName="tdr-api-update-intg")
    s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=quarantine, CreateBucketConfiguration=location)
    s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesMatchFound()
    matcher.matcher_lambda_handler(get_upload_events(), None)
    res = s3_client.get_object(Bucket=quarantine, Key=f"consignmentId")
    assert res["Body"].read() == b"test"


def test_no_copy_to_quarantine_clean(s3, sqs, s3_client, mocker):
    with pytest.raises(ClientError) as err:
        os.environ["ENVIRONMENT"] = "intg"
        os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
        queue_url = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
        os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
        os.environ["SQS_URL"] = queue_url
        quarantine = 'tdr-upload-files-quarantine-intg'
        sqs.create_queue(QueueName="tdr-api-update-intg")
        s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=quarantine, CreateBucketConfiguration=location)
        s3.create_bucket(Bucket='tdr-upload-files-intg', CreateBucketConfiguration=location)
        s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}0").put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesNoMatch()
        matcher.matcher_lambda_handler(get_upload_events(), None)
        s3_client.get_object(Bucket=quarantine, Key="consignmentId")
    assert err.typename == 'NoSuchKey'


def test_copy_to_clean_bucket(s3, sqs, s3_client, mocker):
    os.environ["ENVIRONMENT"] = "intg"
    os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
    os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
    queue_url = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
    os.environ["SQS_URL"] = queue_url
    clean = 'tdr-upload-files-intg'
    sqs.create_queue(QueueName="tdr-api-update-intg")
    s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
    s3.create_bucket(Bucket=clean, CreateBucketConfiguration=location)
    s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}0").put(Body="test")
    mocker.patch('yara.load')
    yara.load.return_value = MockRulesNoMatch()
    matcher.matcher_lambda_handler(get_upload_events(), None)
    res = s3_client.get_object(Bucket=clean, Key="consignmentId")
    assert res["Body"].read() == b"test"


def test_no_copy_to_clean_with_match(s3, sqs, s3_client, mocker):
    with pytest.raises(ClientError) as err:
        os.environ["ENVIRONMENT"] = "intg"
        os.environ["AWS_LAMBDA_FUNCTION_VERSION"] = "1"
        os.environ["ROOT_DIRECTORY"] = "mnt/backend-checks"
        queue_url = "https://queue.amazonaws.com/123456789012/tdr-api-update-intg"
        os.environ["SQS_URL"] = queue_url
        clean = 'tdr-upload-files-intg'
        sqs.create_queue(QueueName="tdr-api-update-intg")
        s3.create_bucket(Bucket='tdr-upload-files-dirty-intg', CreateBucketConfiguration=location)
        s3.create_bucket(Bucket='tdr-upload-files-quarantine-intg', CreateBucketConfiguration=location)
        s3.create_bucket(Bucket=clean, CreateBucketConfiguration=location)
        s3.Object("tdr-upload-files-dirty-intg", f"{tdr_standard_dirty_key}0").put(Body="test")
        mocker.patch('yara.load')
        yara.load.return_value = MockRulesMatchFound()
        matcher.matcher_lambda_handler(get_upload_events(), None)
        s3_client.get_object(Bucket=clean, Key=f"{tdr_standard_clean_key}0")
    assert err.typename == 'NoSuchKey'
