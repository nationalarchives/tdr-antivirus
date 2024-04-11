import yara
import boto3
import logging
from datetime import datetime, timezone
import os
from os.path import exists
from dataclasses import dataclass
from typing import Optional

FORMAT = '%(asctime)-15s %(message)s'
INFO = 20
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('matcher')
logger.setLevel(INFO)


def matcher_lambda_handler(event, lambda_context):
    time = datetime.today().replace(tzinfo=timezone.utc).timestamp() * 1000
    print(event)
    check_type = event["checkType"]
    file_id = event["fileId"]
    user_id = event["userId"]
    original_path = event["originalPath"]
    consignment_id = event["consignmentId"]
    environment = os.environ["ENVIRONMENT"]
    s3_client = boto3.client("s3")
    s3_resource = boto3.resource("s3")
    efs_root_location = os.environ["ROOT_DIRECTORY"]
    root_path = f"{efs_root_location}/{consignment_id}"

    settings = VirusCheckSettings(
        s3_source_location=S3Location(
            bucket="tdr-upload-files-cloudfront-dirty-" + environment,
            key=f"{user_id}/{consignment_id}/{file_id}"
        ),
        s3_quarantine_location=S3Location(
            bucket="tdr-upload-files-quarantine-" + environment,
            key=f"{consignment_id}/{file_id}"
        ),
        local_download_location=f"{root_path}/{original_path}"
    ) if check_type == "consignment" else VirusCheckSettings(
        s3_source_location=S3Location(
            bucket="",
            key=""
        ),
        s3_quarantine_location=None,
        local_download_location=""
    )

    rules = yara.load("output")
    download_directory = "/".join(settings.local_download_location.split("/")[:-1])
    if not exists(download_directory):
        os.makedirs(download_directory)
    if not exists(settings.local_download_location):
        bucket = s3_resource.Bucket(settings.s3_source_location.bucket)
        bucket.download_file(settings.s3_source_location.key, settings.local_download_location)

    match = rules.match(settings.local_download_location)
    results = [x.rule for x in match]

    copy_s3_key = f"{consignment_id}/{file_id}"

    if settings.s3_quarantine_location is not None:
        if len(results) > 0:
            s3_client.copy(
                settings.s3_source_location.as_dict(),
                settings.s3_quarantine_location.bucket,
                settings.s3_quarantine_location.key
            )
        else:
            # TODO: Add s3_upload_location
            s3_client.copy(settings.s3_source_location.as_dict(), "tdr-upload-files-" + environment, copy_s3_key)

    result = "\n".join(results)

    logger.info("Key %s processed", f"{consignment_id}/{file_id}")

    return {
        "antivirus":
            {"software": "yara", "softwareVersion": yara.__version__,
             "databaseVersion": os.environ["AWS_LAMBDA_FUNCTION_VERSION"],
             "result": result,
             "datetime": int(time),
             "fileId": file_id}
    }


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
    s3_source_location: S3Location
    s3_quarantine_location: Optional[S3Location]
    local_download_location: str
