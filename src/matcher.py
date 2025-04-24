import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import boto3


scan_complete_tag_key = 'GuardDutyMalwareScanStatus'
threat_found = 'THREATS_FOUND'
threat_found_result = 'awsGuardDutyThreatFound'
await_delay_secs = os.getenv('POLL_MALWARE_SCAN_COMPLETE_AWAIT_SECS', 5)
FORMAT = '%(asctime)-15s %(message)s'
INFO = 20


logging.basicConfig(format=FORMAT)
logger = logging.getLogger('matcher')
logger.setLevel(INFO)


# def download_file_if_not_already_present(settings):
#     if not exists(settings.local_download_location):
#         download_file(settings.s3_source_location.bucket, settings.s3_source_location.key, settings.local_download_location)
#     else:
#         s3_client = boto3.client("s3")
#         s3_mtime = s3_client.head_object(Bucket=settings.s3_source_location.bucket, Key=settings.s3_source_location.key)['LastModified'].timestamp()
#         local_mtime = os.stat(settings.local_download_location).st_mtime
#         if local_mtime > s3_mtime:
#             print(f"File {settings.local_download_location} already exists in local storage, using this instead of downloading from S3.")
#         else:
#             download_file(settings.s3_source_location.bucket, settings.s3_source_location.key, settings.local_download_location)


# def download_file(bucket, key, location):
#     s3_client = boto3.client("s3")
#     download_directory = "/".join(location.split("/")[:-1])
#     os.makedirs(download_directory, exist_ok=True)
#     print(f"Downloading object s3://{bucket}/{key} to {location}.")
#     s3_client.download_file(bucket, key, location)


def get_object_tagging(s3_client, bucket, object_key):
        return s3_client.get_object_tagging(
            Bucket=f'{bucket}',
            Key=f'{object_key}'
        )['TagSet']


def poll_guard_duty_scan_complete(s3_client, bucket, object_key):
    print(f'Polling for GuardDuty scan result: {object_key}')
    while True:
        tag_set = get_object_tagging(s3_client, bucket, object_key)
        for tag in tag_set:
            tag_key = tag['Key']
            if tag_key == scan_complete_tag_key:
                scan_result = tag['Value']
                print(f'Polling for GuardDuty scan result completed: {object_key}')
                return scan_result
        time.sleep(await_delay_secs)


def guard_duty_threat_found(s3_client, bucket, object_key):
    scan_result = poll_guard_duty_scan_complete(s3_client, bucket, object_key)
    threats = []
    if scan_result == threat_found:
        threats = [threat_found_result]
    return threats


def matcher_lambda_handler(event, lambda_context):
    handler_trigger_time = datetime.today().replace(tzinfo=timezone.utc).timestamp() * 1000
    print(event)
    s3_client = boto3.client("s3")

    settings = build_settings(event)
    aws_guard_duty_threat_found = (
        guard_duty_threat_found(s3_client, settings.s3_source_location.bucket, settings.s3_source_location.key))

    if len(aws_guard_duty_threat_found) > 0:
        if settings.s3_quarantine_location is not None:
            s3_client.copy(
                settings.s3_source_location.as_dict(),
                settings.s3_quarantine_location.bucket,
                settings.s3_quarantine_location.key
            )
    else:
        if settings.s3_upload_location is not None:
            s3_client.copy(
                settings.s3_source_location.as_dict(),
                settings.s3_upload_location.bucket,
                settings.s3_upload_location.key
            )

    logger.info("Key %s processed", settings.s3_source_location.key)
    results = aws_guard_duty_threat_found

    return antivirus_results_dict(settings.file_id, results, handler_trigger_time)


@dataclass(frozen=True)
class S3Location:
    bucket: str
    key: str

    def as_dict(self) -> object: return {
        "Bucket": self.bucket,
        "Key": self.key
    }


@dataclass(frozen=True)
class VirusCheckSettings:
    file_id: str
    s3_source_location: S3Location
    s3_quarantine_location: Optional[S3Location]
    s3_upload_location: Optional[S3Location]


class ScanType(Enum):
    metadata = 1
    consignment = 2


def build_settings(event: dict) -> VirusCheckSettings:
    # TDR environment
    environment = os.environ["ENVIRONMENT"]
    # TDR UUID for the consignment the object to scan belongs to
    consignment_id = event["consignmentId"]
    # TDR UUID of the object to scan
    file_id = event["fileId"]
    # Original path to the object
    original_path = event.get("originalPath", None)
    # UUID of the user who uploaded the object to scan
    user_id = event.get("userId", None)
    # Type of scan: deprecated should use optional parameters
    scan_type = ScanType[event.get("scanType", "consignment")]
    # S3 bucket containing the object to scan
    s3_source_bucket = event.get("s3SourceBucket", "tdr-upload-files-cloudfront-dirty-" + environment)
    # S3 bucket key of the object to scan
    s3_source_bucket_key = event.get("s3SourceBucketKey", f"{user_id}/{consignment_id}/{file_id}")
    # S3 bucket to copy clean objects to
    s3_upload_bucket = event.get("s3UploadBucket", "tdr-upload-files-" + environment)
    # S3 bucket key of clean object
    s3_upload_bucket_key = event.get("s3UploadBucketKey", f"{consignment_id}/{file_id}")
    # S3 bucket to copy infected objects to
    s3_quarantine_bucket = event.get("s3QuarantineBucket", "tdr-upload-files-quarantine-" + environment)
    # S3 bucket key of infected object
    s3_quarantine_bucket_key = event.get("s3QuarantineBucketKey", f"{consignment_id}/{file_id}")

    if scan_type == ScanType.metadata:
        return VirusCheckSettings(
            file_id=file_id,
            s3_source_location=S3Location(
                bucket="tdr-draft-metadata-" + environment,
                key=f"{consignment_id}/{file_id}"
            ),
            s3_quarantine_location=S3Location(
                bucket="tdr-upload-files-quarantine-" + environment,
                key=f"{consignment_id}/metadata/{file_id}"
            ),
            s3_upload_location=None
        )
    else:
        return VirusCheckSettings(
            file_id=file_id,
            s3_source_location=S3Location(
                bucket=s3_source_bucket,
                key=s3_source_bucket_key
            ),
            s3_quarantine_location=S3Location(
                bucket=s3_quarantine_bucket,
                key=s3_quarantine_bucket_key
            ),
            s3_upload_location=s3_location(s3_upload_bucket, s3_upload_bucket_key)
        )


def s3_location(s3_bucket, s3_bucket_key):
    if s3_bucket != "" and s3_bucket_key != "":
        return S3Location(
            bucket=s3_bucket,
            key=s3_bucket_key
        )
    else:
        None


def antivirus_results_dict(file_id, results, handler_trigger_time):
    software = "awsGuardDutyMalwareScan"
    software_version = "AWSGuardDuty"
    return {
        "antivirus":
            {
                "software": software,
                "softwareVersion": software_version,
                "databaseVersion": os.environ["AWS_LAMBDA_FUNCTION_VERSION"],
                "result": "\n".join(results),
                "datetime": int(handler_trigger_time),
                "fileId": file_id
            }
    }
