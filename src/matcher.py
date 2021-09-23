import yara
import boto3
import json
import logging
from datetime import datetime, timezone
import os
import urllib.parse
from base64 import b64decode

FORMAT = '%(asctime)-15s %(message)s'
INFO = 20
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('matcher')
logger.setLevel(INFO)


def decrypt(value):
    return boto3.client('kms').decrypt(
        CiphertextBlob=b64decode(value),
        EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
    )['Plaintext'].decode('utf-8')


def matcher_lambda_handler(event, lambda_context):
    print(event)
    successful_receipt_handles = []
    outputs = []
    if "Records" in event:
        s3_client = boto3.client("s3")
        sqs_client = boto3.client("sqs")
        rules = yara.load("output")
        efs_root_location = decrypt(os.environ["ROOT_DIRECTORY"])
        environment = decrypt(os.environ["ENVIRONMENT"])
        output_queue = decrypt(os.environ["OUTPUT_QUEUE"])
        input_queue = decrypt(os.environ["INPUT_QUEUE"])
        records = event['Records']
        failures = []
        for record in records:
            receipt_handle = record['receiptHandle']
            try:
                message_body = json.loads(record['body'])
                user_id = message_body['userId']
                consignment_id = message_body["consignmentId"]
                original_path = message_body["originalPath"]
                dirty_bucket_name = message_body["dirtyBucketName"]
                root_path = f"{efs_root_location}/{consignment_id}"
                file_id = message_body["fileId"]
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
                time = int(datetime.today().replace(tzinfo=timezone.utc).timestamp()) * 1000
                output = {"software": "yara", "softwareVersion": yara.__version__,
                          "databaseVersion": os.environ["AWS_LAMBDA_FUNCTION_VERSION"],
                          "result": result,
                          "datetime": time,
                          "fileId": file_id}
                outputs.append(output)
                sqs_client.send_message(QueueUrl=output_queue, MessageBody=json.dumps(output))
                logger.info("Key %s processed", f"{consignment_id}/{file_id}")
                successful_receipt_handles.append(receipt_handle)
            except Exception as ex:
                failures.append(ex)
                logger.error(ex)
                sqs_client.change_message_visibility(
                    QueueUrl=input_queue,
                    ReceiptHandle=receipt_handle,
                    VisibilityTimeout=0
                )

        if len(failures) > 0:
            for successful_receipt_handle in successful_receipt_handles:
                sqs_client.delete_message(
                    QueueUrl=input_queue,
                    ReceiptHandle=successful_receipt_handle
                )
            for failure in failures:
                logging.exception(failure)

            raise failures[0]  # We've logged the exceptions and now need the lambda to fail.
        return outputs
    else:
        logger.info("Message does not contain any records")
        return []
