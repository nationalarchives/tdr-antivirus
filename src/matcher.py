import yara
import boto3
import logging
from datetime import datetime, timezone
import os
from os.path import exists
from dataclasses import dataclass
from typing import Optional
from enum import Enum

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
    download_file_if_not_already_present(settings)
    rules = yara.load("output")
    matched_antivirus_rules = [x.rule for x in rules.match(settings.local_download_location)]

    if len(matched_antivirus_rules) > 0:
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

    return antivirus_results_dict(settings.file_id, matched_antivirus_rules, handler_trigger_time)


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


class ScanType(Enum):
    metadata = 1
    consignment = 2


def build_settings(event: dict) -> VirusCheckSettings:
    scan_type = ScanType[event.get("scanType", "consignment")]
    consignment_id = event["consignmentId"]
    file_id = event["fileId"]

    environment = os.environ["ENVIRONMENT"]
    efs_root_location = os.environ["ROOT_DIRECTORY"]
    root_path = f"{efs_root_location}/{consignment_id}"
    if scan_type == ScanType.consignment:
        user_id = event["userId"]
        original_path = event["originalPath"]
        return VirusCheckSettings(
            file_id=file_id,
            s3_source_location=S3Location(
                bucket="tdr-upload-files-cloudfront-dirty-" + environment,
                key=f"{user_id}/{consignment_id}/{file_id}"
            ),
            s3_quarantine_location=S3Location(
                bucket="tdr-upload-files-quarantine-" + environment,
                key=f"{consignment_id}/{file_id}"
            ),
            s3_upload_location=S3Location(
                bucket="tdr-upload-files-" + environment,
                key=f"{consignment_id}/{file_id}"
            ),
            local_download_location=f"{root_path}/{original_path}"
        )
    elif scan_type == ScanType.metadata:
        return VirusCheckSettings(
            file_id=file_id,
            s3_source_location=S3Location(
                bucket="tdr-draft-metadata-" + environment,
                key=f"{consignment_id}/{file_id}"
            ),
            s3_quarantine_location=None,
            s3_upload_location=None,
            local_download_location=f"{root_path}/metadata/{file_id}"
        )


def download_file_if_not_already_present(settings):
    s3_resource = boto3.resource("s3")
    download_directory = "/".join(settings.local_download_location.split("/")[:-1])
    if not exists(download_directory):
        os.makedirs(download_directory)
    if not exists(settings.local_download_location):
        bucket = s3_resource.Bucket(settings.s3_source_location.bucket)
        bucket.download_file(settings.s3_source_location.key, settings.local_download_location)


def antivirus_results_dict(file_id, results, time):
    return {
        "antivirus":
            {
                "software": "yara", "softwareVersion": yara.__version__,
                "databaseVersion": os.environ["AWS_LAMBDA_FUNCTION_VERSION"],
                "result": "\n".join(results),
                "datetime": int(time),
                "fileId": file_id
            }
    }
