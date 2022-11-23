import yara
import boto3
import logging
from datetime import datetime, timezone
import os

FORMAT = '%(asctime)-15s %(message)s'
INFO = 20
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('matcher')
logger.setLevel(INFO)


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

    rules = yara.load("output")
    efs_root_location = os.environ["ROOT_DIRECTORY"]

    root_path = f"{efs_root_location}/{consignment_id}"
    file_path = f"{root_path}/{original_path}"
    os.makedirs("/".join(file_path.split("/")[:-1]))
    bucket = s3_resource.Bucket(dirty_bucket_name)
    bucket.download_file(f"{user_id}/{consignment_id}/{file_id}", file_path)

    match = rules.match(f"{root_path}/{original_path}")
    results = [x.rule for x in match]

    original_s3_key = f"{user_id}/{consignment_id}/{file_id}"
    copy_s3_key = f"{consignment_id}/{file_id}"

    copy_source = {
        "Bucket": dirty_bucket_name,
        "Key": original_s3_key
    }

    if len(results) > 0:
        s3_client.copy(
            copy_source,
            "tdr-upload-files-quarantine-" + environment,
            copy_s3_key
        )
    else:
        s3_client.copy(copy_source, "tdr-upload-files-" + environment, copy_s3_key)

    result = "\n".join(results)

    logger.info("Key %s processed", f"{consignment_id}/{file_id}")

    return {"software": "yara", "softwareVersion": yara.__version__,
            "databaseVersion": os.environ["AWS_LAMBDA_FUNCTION_VERSION"],
            "result": result,
            "datetime": int(time),
            "fileId": file_id}
