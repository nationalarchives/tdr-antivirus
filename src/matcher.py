import boto3
import logging
from datetime import datetime, timezone
import os
from os.path import exists
import subprocess

FORMAT = '%(asctime)-15s %(message)s'
INFO = 20
MAX_BYTES = 4000000000
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('matcher')
logger.setLevel(INFO)


def scan(download_path):
    subprocess.run("freshclam")
    command = [
        "clamscan",
        "--stdout",
        f"--max-scansize={MAX_BYTES}",
        f"{download_path}",
    ]
    scan_summary = subprocess.run(
        command,
        stderr=subprocess.STDOUT,
        stdout=subprocess.PIPE,
    )
    print("Scan complete")
    print(scan_summary.stdout)
    print(scan_summary.stderr)
    return scan_summary.returncode


def matcher_lambda_handler(event, lambda_context):
    time = datetime.today().replace(tzinfo=timezone.utc).timestamp() * 1000
    print(event)
    file_id = event["fileId"]
    user_id = event["userId"]
    original_path = event["originalPath"]
    consignment_id = event["consignmentId"]
    environment = os.environ["ENVIRONMENT"]
    dirty_bucket_name = f"tdr-upload-files-cloudfront-dirty-{environment}"
    s3_client = boto3.client("s3")
    s3_resource = boto3.resource("s3")

    efs_root_location = os.environ["ROOT_DIRECTORY"]

    root_path = f"{efs_root_location}"
    file_path = f"{root_path}/{original_path}"
    download_directory = "/".join(file_path.split("/")[:-1])
    if not exists(download_directory):
        os.makedirs(download_directory)
    if not exists(file_path):
        bucket = s3_resource.Bucket(dirty_bucket_name)
        bucket.download_file(f"{user_id}/{consignment_id}/{file_id}", file_path)

    exit_code = scan(file_path)
    original_s3_key = f"{user_id}/{consignment_id}/{file_id}"
    copy_s3_key = f"{consignment_id}/{file_id}"

    copy_source = {
        "Bucket": dirty_bucket_name,
        "Key": original_s3_key
    }

    if exit_code != 0:
        s3_client.copy(
            copy_source,
            "tdr-upload-files-quarantine-" + environment,
            copy_s3_key
        )
    else:
        s3_client.copy(copy_source, "tdr-upload-files-" + environment, copy_s3_key)

    logger.info("Key %s processed", f"{consignment_id}/{file_id}")

    return {
        "antivirus":
            {"software": "yara", "softwareVersion": "1",
             "databaseVersion": os.environ["AWS_LAMBDA_FUNCTION_VERSION"],
             "result": exit_code,
             "datetime": int(time),
             "fileId": file_id}
    }
