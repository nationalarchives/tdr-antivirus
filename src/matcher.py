import yara
import boto3
import json
import logging
from datetime import datetime, timezone
import os
import urllib.parse

FORMAT = '%(asctime)-15s %(message)s'
INFO = 20
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('matcher')
logger.setLevel(INFO)


def matcher_lambda_handler(event, lambda_context):
    print(event)
    outputs = []
    if "Records" in event:
        sqs_client = boto3.client("sqs")
        s3_client = boto3.client("s3")
        for record in event["Records"]:
            message = json.loads(record['body'])['Message']
            s3_records = json.loads(message)['Records']
            for s3_record in s3_records:
                s3 = s3_record["s3"]
                bucket = s3["bucket"]["name"]

                key = urllib.parse.unquote(s3["object"]["key"])
                logger.info("Object %s found", key)
                logger.info("Bucket " + bucket)
                s3_object = s3_client.get_object(Bucket=bucket, Key=key)
                streaming_body = s3_object["Body"]

                rules = yara.load("output")
                match = rules.match(data=streaming_body.read())
                results = [x.rule for x in match]

                copy_source = {
                    "Bucket": bucket,
                    "Key": key
                }
                if len(results) > 0:
                    s3_client.copy(copy_source, "tdr-upload-files-quarantine-" + os.environ["ENVIRONMENT"], key)
                else:
                    s3_client.copy(copy_source, "tdr-upload-files-" + os.environ["ENVIRONMENT"], key)

                result = "\n".join(results)
                time = int(datetime.today().replace(tzinfo=timezone.utc).timestamp()) * 1000
                output = {"software": "yara", "softwareVersion": yara.__version__,
                          "databaseVersion": os.environ["AWS_LAMBDA_FUNCTION_VERSION"],
                          "result": result,
                          "datetime": time,
                          "fileId": key.split("/")[-1] }
                outputs.append(output)
                sqs_client.send_message(QueueUrl=os.environ["SQS_URL"], MessageBody=json.dumps(output))
                logger.info("Key %s processed", key)

        return outputs
    else:
        logger.info("Message does not contain any records")
        return []
