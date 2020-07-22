import json
import boto3
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from configuration import Configuration


class EncryptionManager():

    @staticmethod
    def get_encryption_key():
        with open(Configuration.KMS_DATA_KEY) as data_key_file:
            kms_data_key_dict = json.loads(data_key_file.read())
        key_blob = kms_data_key_dict['CiphertextBlob']
        session = boto3.Session(profile_name=Configuration.PROFILE)
        client = session.client('kms', region_name=Configuration.REGION)
        response = client.decrypt(
            CiphertextBlob=bytes(base64.b64decode(key_blob))
        )
        return response['Plaintext']

    @staticmethod
    def encrypt_message(message):
        key = EncryptionManager.get_encryption_key()
        encryption_suite = AES.new(key, AES.MODE_CBC)
        cipher_bytes = encryption_suite.encrypt(pad(message.encode("utf-8"),Configuration.BLOCK_SIZE))
        return cipher_bytes

    @staticmethod
    def decrypt_message(ciphertext):
        key = EncryptionManager.get_encryption_key()
        decryption_suite = AES.new(key, AES.MODE_CBC)
        text = decryption_suite.decrypt(ciphertext)
        return text