import json
import boto3
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

PROFILE = 't6'
REGION = 'us-east-2'
BLOCK_SIZE = 16 # Bytes
SQS_URL = 'https://sqs.us-east-2.amazonaws.com/108110259026/kms_aes_poc'

def get_encryption_key():
    with open("data_key.json") as data_key_file:
        kms_data_key_dict = json.loads(data_key_file.read())
    key_blob = kms_data_key_dict['CiphertextBlob']
    session = boto3.Session(profile_name=PROFILE)
    client = session.client('kms', region_name=REGION)
    response = client.decrypt(
        CiphertextBlob=bytes(base64.b64decode(key_blob))
    )
    return response['Plaintext']

def encrypt_message(message):
    key = get_encryption_key()
    encryption_suite = AES.new(key, AES.MODE_CBC)
    cipher_bytes = encryption_suite.encrypt(pad(message.encode("utf-8"),BLOCK_SIZE))
    return cipher_bytes

def decrypt_message(ciphertext):
    key = get_encryption_key()
    decryption_suite = AES.new(key, AES.MODE_CBC)
    text = decryption_suite.decrypt(ciphertext)
    return text

def push_sqs_message(message):
    cipher_bytes = encrypt_message(message)
    session = boto3.Session(profile_name=PROFILE)
    sqs_client = session.client('sqs', region_name=REGION)
    sqs_client.send_message(MessageBody=base64.b64encode(cipher_bytes).decode('utf-8'), QueueUrl=SQS_URL)

def process_sqs_message():
    session = boto3.Session(profile_name=PROFILE)
    sqs_client = session.client('sqs', region_name=REGION)
    response = sqs_client.receive_message(QueueUrl=SQS_URL)
    if 'Messages' in response:
        for message in response['Messages']:
            message_body = message['Body'].encode('utf-8')
            print (message_body)
            cipher_bytes = base64.b64decode(message_body)
            plain_text = decrypt_message(cipher_bytes) 
            # .decode('utf-8')
            print ('Message from queue, decrypted:')
            print (plain_text)
            sqs_client.delete_message(QueueUrl=SQS_URL, ReceiptHandle=message['ReceiptHandle'])
    else:
        print('No messages to process')

if __name__ == "__main__":    
    push_sqs_message("here is a secret message for you .... ")
    process_sqs_message()