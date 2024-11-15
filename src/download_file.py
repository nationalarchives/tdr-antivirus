import os
import boto3
from os.path import exists


def download_file_if_not_already_present(settings):
    if not exists(settings.local_download_location):
        download_file(settings.s3_source_location.bucket, settings.s3_source_location.key, settings.local_download_location)
    else:
        s3_client = boto3.client("s3")
        s3_mtime = s3_client.head_object(Bucket=settings.s3_source_location.bucket, Key=settings.s3_source_location.key)['LastModified'].timestamp()
        local_mtime = os.stat(settings.local_download_location).st_mtime
        if local_mtime > s3_mtime:
            print(f"File {settings.local_download_location} already exists in local storage, using this instead of downloading from S3.")
        else:
            download_file(settings.s3_source_location.bucket, settings.s3_source_location.key, settings.local_download_location)


def download_file(bucket, key, location):
    s3_client = boto3.client("s3")
    download_directory = "/".join(location.split("/")[:-1])
    os.makedirs(download_directory, exist_ok=True)
    print(f"Downloading object s3://{bucket}/{key} to {location}.")
    s3_client.download_file(bucket, key, location)
