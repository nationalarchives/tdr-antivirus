import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import boto3
import yara

from src.download_file import download_file_if_not_already_present
from src.guard_duty_malware_scan import guard_duty_threat_found

FORMAT = '%(asctime)-15s %(message)s'
INFO = 20
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('matcher')
logger.setLevel(INFO)


def matcher_lambda_handler(event, lambda_context):
    handler_trigger_time = datetime.today().replace(tzinfo=timezone.utc).timestamp() * 1000
    print(event)
    s3_client = boto3.client("s3")

    settings = build_settings(event)
    guard_duty_scan_enabled = settings.guard_duty_malware_scan_enabled
    download_file_if_not_already_present(settings)
    rules = yara.load("output")
    matched_antivirus_rules = [x.rule for x in rules.match(settings.local_download_location)]
    aws_guard_duty_threat_found = (
        guard_duty_threat_found(s3_client, settings.s3_source_location.bucket, settings.s3_source_location.key)) if guard_duty_scan_enabled else []

    if len(matched_antivirus_rules) > 0 or len(aws_guard_duty_threat_found) > 0:
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
    results = matched_antivirus_rules + aws_guard_duty_threat_found

    return antivirus_results_dict(settings.file_id, results, handler_trigger_time, guard_duty_scan_enabled)


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
    local_download_location: str
    guard_duty_malware_scan_enabled: bool


class ScanType(Enum):
    metadata = 1
    consignment = 2


def build_settings(event: dict) -> VirusCheckSettings:
    # TDR environment
    environment = os.environ["ENVIRONMENT"]
    # AWS EFS root directory where object to scan is copied to for scanning
    efs_root_location = os.environ["ROOT_DIRECTORY"]
    # TDR UUID for the consignment the object to scan belongs to
    guard_duty_malware_scan_enabled = event.get("guardDutyMalwareScanEnabled", True)
    consignment_id = event["consignmentId"]
    # TDR UUID of the object to scan
    file_id = event["fileId"]
    # Local path for copying object to scan
    root_path = f"{efs_root_location}/{consignment_id}"

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
            s3_upload_location=None,
            local_download_location=f"{root_path}/metadata/{file_id}",
            guard_duty_malware_scan_enabled=guard_duty_malware_scan_enabled
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
            s3_upload_location=s3_location(s3_upload_bucket, s3_upload_bucket_key),
            local_download_location=f"{root_path}/{original_path}",
            guard_duty_malware_scan_enabled=guard_duty_malware_scan_enabled
        )


def s3_location(s3_bucket, s3_bucket_key):
    if s3_bucket != "" and s3_bucket_key != "":
        return S3Location(
            bucket=s3_bucket,
            key=s3_bucket_key
        )
    else:
        None


def antivirus_results_dict(file_id, results, handler_trigger_time, guard_duty_scan_enabled):
    software = "yara|awsGuardDutyMalwareScan" if guard_duty_scan_enabled else "yara"
    return {
        "antivirus":
            {
                "software": software,
                "softwareVersion": yara.__version__,
                "databaseVersion": os.environ["AWS_LAMBDA_FUNCTION_VERSION"],
                "result": "\n".join(results),
                "datetime": int(handler_trigger_time),
                "fileId": file_id
            }
    }
