import boto3
import base64
import getopt
import sys
from configuration import Configuration
from encryption_manager import EncryptionManager

# TODO update to pull messages in batches
def process_sqs_message(number_of_messages):
    print(f'Starting process_sqs_message')
    session = boto3.Session(profile_name=Configuration.PROFILE)
    sqs_client = session.client('sqs', region_name=Configuration.REGION)
    response = sqs_client.receive_message(QueueUrl=Configuration.SQS_URL)
    if 'Messages' in response:
        for message in response['Messages']:
            message_body = message['Body'] #.encode('utf-8')
            cipher_bytes = base64.b64decode(message_body)
            plain_text = EncryptionManager.decrypt_message(cipher_bytes) 
            print (f'Message from queue, decrypted: {plain_text}')
            sqs_client.delete_message(QueueUrl=Configuration.SQS_URL, ReceiptHandle=message['ReceiptHandle'])
    else:
        print('No messages to process')

    print(f'Finished process_sqs_message')

if __name__ == "__main__":
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv,"n:",["number="])
    for opt, arg in opts:
      if opt == '-h':
         print('process_sqs_message.py -n number of messages')
         sys.exit()
      elif opt in ("-n", "--number"):
         number_of_messages = arg
    process_sqs_message(number_of_messages)