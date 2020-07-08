
    # session = boto3.Session(profile_name=PROFILE)
    # sqs_client = session.client('sqs', region_name=REGION)
    # sqs_client.send_message(MessageBody=ciphertext, QueueUrl=SQS_URL)

    # key = get_encryption_key()
    # encryption_suite = AES.new(key, AES.MODE_ECB)
    # cipher_text = encryption_suite.encrypt(pad(message.encode('utf-8'),BLOCK_SIZE))

    # cipher_text = x(message)
    # plain_text = z(cipher_text)

    # Decryption
    # key = get_encryption_key()
    # decryption_suite = AES.new(key, AES.MODE_ECB)
    # plain_text = decryption_suite.decrypt(cipher_text)