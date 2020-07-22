import boto3
import base64
import getopt
import sys
from configuration import Configuration
from encryption_manager import EncryptionManager


def push_sqs_message(message):
    print(f'Starting push_sqs_message')
    print(f'Encrypting message')
    cipher_bytes = EncryptionManager.encrypt_message(message)
    print(f'Completed encrypting message')
    print(f'Pushing message: {message} - to queue: {Configuration.SQS_URL}')
    session = boto3.Session(profile_name=Configuration.PROFILE)
    sqs_client = session.client('sqs', region_name=Configuration.REGION)
    sqs_client.send_message(MessageBody=base64.b64encode(cipher_bytes).decode('utf-8'), QueueUrl=Configuration.SQS_URL)
    print(f'Completed pushing message')
    print(f'Finished push_sqs_message')

if __name__ == "__main__":
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv,"m:",["message="])
    for opt, arg in opts:
      if opt == '-h':
         print('push_sqs_message.py -m message')
         sys.exit()
      elif opt in ("-m", "--message"):
         message = arg
    push_sqs_message(message)