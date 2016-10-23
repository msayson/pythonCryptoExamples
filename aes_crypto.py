from Crypto.Cipher import AES
import random
import hashlib

MESSAGE_OK_CODE = 0        # Message matches hash
MESSAGE_MISMATCH_CODE = -1 # Message doesn't match hash

# Returns IV + h(M) + E(M, k)
# * IV:      initialization vector
# * h(M):    hash of message
# * E(M, k): message encrypted with AES and key k
def encryptMessageWithAES(key, message):
  IV = generateIV()
  messageHash = hashSHA256(message)
  cipherText = computeCiphertextAES(key, IV, message)

  fullText = (IV, messageHash, cipherText)
  return ''.join(fullText)

# Returns plainText, errorStatus
def decryptMessageWithAES(key, ciphertext):
  IV = ciphertext[0:16]
  hash = ciphertext[16:80]
  plainText = computePlaintextAES(key, IV, ciphertext[80:len(ciphertext)])
  if(hashSHA256(plainText) == hash):
    return plainText, MESSAGE_OK_CODE
  else:
    return "Error: Message does not match hash", MESSAGE_MISMATCH_CODE

# Returns AES-encrypted message
def computeCiphertextAES(key, iv, message):
  paddedMessage = padMessageForAES(message)
  encryptor = AES.new(key, AES.MODE_CBC, iv)
  return encryptor.encrypt(paddedMessage)

# Returns AES-decrypted message
def computePlaintextAES(key, iv, cipherText):
  decryptor = AES.new(key, AES.MODE_CBC, iv)
  decryptedWithPadding = decryptor.decrypt(cipherText)
  return extractMessage(decryptedWithPadding)

# Returns a random 16-character(128 bits) IV
def generateIV():
  return ''.join(chr(random.randint(0, 0xFF)) for i in range(16))

# Returns the SHA256 hash of s, where s must be encoded with ASCII code
def hashSHA256(s):
  return hashlib.sha256(s).hexdigest()

# Returns a message padded with 0s, up to the
# shortest message length divisible by 16
#
# AES messages must be divisible into 16-character blocks
def padMessageForAES(message):
  paddingLabelLength = 3 # "\d\d:" indicates padding length btw 0-15
  lenBeforePadding = len(message) + paddingLabelLength # start of message is ##:
  paddingRequired = (16 - (lenBeforePadding % 16)) if (lenBeforePadding % 16 > 0) else 0
  formattedLengthStr = str(lenBeforePadding + paddingRequired)
  paddedMessage = ('{:0<' + formattedLengthStr + '}').format(('%02d:' % paddingRequired) + message)
  return paddedMessage

# Return message from padded text
# eg. "02:Hi bob!00" -> "Hi bob!"
#
# paddedMessage has form "\d\d:MessageWithPadding",
# where padding is at most 15 characters.
def extractMessage(paddedMessage):
  paddingAmount = int(paddedMessage[0:2])
  return paddedMessage[3:len(paddedMessage) - paddingAmount]
