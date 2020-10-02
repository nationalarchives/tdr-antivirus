import yara
import boto3
import json
import logging
from datetime import datetime, timezone
import os


FORMAT = '%(asctime)-15s %(message)s'
INFO = 20
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('matcher')
logger.setLevel(INFO)


def matcher_lambda_handler(events, lambda_context):
    print(events)
    outputs = []
    if not events:
        logger.info("Message does not contain any records")
        return []
    else:
        s3_client = boto3.client("s3")
        sqs_client = boto3.client("sqs")
        rules = yara.load("output")
        efs_root_location = os.environ["ROOT_DIRECTORY"]
        for event in events:
            print(event)
            cognito_id = event["cognitoId"]
            consignment_id = event["consignmentId"]
            consignment_path = f"${efs_root_location}/${consignment_id}"
            file_id = event["fileId"]
            match = rules.match(f"${consignment_path}/${file_id}")
            results = [x.rule for x in match]

            original_s3_key = f"{cognito_id}/{consignment_id}/{file_id}"

            copy_source = {
                "Bucket": "tdr-upload-files-dirty-" + os.environ["ENVIRONMENT"],
                "Key": original_s3_key
            }

            if len(results) > 0:
                s3_client.copy(copy_source, "tdr-upload-files-quarantine-" + os.environ["ENVIRONMENT"], consignment_id)
            else:
                s3_client.copy(copy_source, "tdr-upload-files-" + os.environ["ENVIRONMENT"], consignment_id)

            result = "\n".join(results)
            time = int(datetime.today().replace(tzinfo=timezone.utc).timestamp()) * 1000
            output = {"software": "yara", "softwareVersion": yara.__version__,
                "databaseVersion": os.environ["AWS_LAMBDA_FUNCTION_VERSION"],
                "result": result,
                "datetime": time,
                "fileId": file_id}
            outputs.append(output)
            sqs_client.send_message(QueueUrl=os.environ["SQS_URL"], MessageBody=json.dumps(output))
            logger.info("Key %s processed", f"${consignment_id}/${file_id}")

        return outputs
