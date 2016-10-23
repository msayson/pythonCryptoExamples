# Crypto tests

import unittest
import aes_crypto

SHARED_SECRET = "SharedSecret3456"

class TestAESCrypto(unittest.TestCase):

  # Encrypting and decrypting a 16-character
  # message should return the original message
  def test_computePlaintextAES_16CharMsg(self):
    originalMessage = "See you later B!"
    iv = "1234567890123456"
    cipherText = aes_crypto.computeCiphertextAES(SHARED_SECRET, iv, originalMessage)
    decryptedText = aes_crypto.computePlaintextAES(SHARED_SECRET, iv, cipherText)
    self.assertEqual(decryptedText, originalMessage)

  # Encrypting and decrypting a message with a
  # length not divisible by 16 should return
  # the original message padded by zeros
  def test_computePlaintextAES_17CharMsg(self):
    originalMessage = "Hello Bob01234567"
    iv = "1234567890123456"
    cipherText = aes_crypto.computeCiphertextAES(SHARED_SECRET, iv, originalMessage)
    decryptedText = aes_crypto.computePlaintextAES(SHARED_SECRET, iv, cipherText)
    self.assertEqual(decryptedText, originalMessage)

  # Test that decryption works when using our IV generator
  def test_computePlaintextAES_RandomIV(self):
    originalMessage = "Hello Bob"
    iv = aes_crypto.generateIV()
    cipherText = aes_crypto.computeCiphertextAES(SHARED_SECRET, iv, originalMessage)
    decryptedText = aes_crypto.computePlaintextAES(SHARED_SECRET, iv, cipherText)
    self.assertEqual(decryptedText, originalMessage)

  # Test that decryption does not return the original
  # message when the incorrect IV is used 
  def test_computePlaintextAES_RequiresCorrectIV(self):
    originalMessage = "Hello Bob"
    cipherText = aes_crypto.computeCiphertextAES(SHARED_SECRET, aes_crypto.generateIV(), originalMessage)
    with self.assertRaises(ValueError):
      aes_crypto.computePlaintextAES(SHARED_SECRET, aes_crypto.generateIV(), cipherText)

  def test_padMessageForAES(self):
    message = "Hello alice"
    expected = "02:Hello alice00"
    paddedMessage = aes_crypto.padMessageForAES(message)
    self.assertEqual(paddedMessage, expected)

  def test_extractMessage(self):
    paddedMessage = "02:Hello alice00"
    expected = "Hello alice"
    extracted = aes_crypto.extractMessage(paddedMessage)
    self.assertEqual(extracted, expected)

  def test_generateIV_Yields16CharString(self):
    iv = aes_crypto.generateIV()
    self.assertEqual(len(iv), 16)

  def test_generateIV_MultRunsYieldDiffIVs(self):
    iv1 = aes_crypto.generateIV()
    iv2 = aes_crypto.generateIV()
    self.assertNotEqual(iv1, iv2)

  def test_hashSHA256_SameInputsYieldSameHash(self):
    message1 = "Hi, it's Alice!0"
    message2 = "Hi, it's Alice!" + "0"
    hash1 = aes_crypto.hashSHA256(message1)
    hash2 = aes_crypto.hashSHA256(message2)
    self.assertEqual(hash1, hash2)

  def test_hashSHA256_DiffInputsYieldDiffHash(self):
    message1 = "Hi, it's Alice!0"
    message2 = "Hi, it's Alice!"
    hash1 = aes_crypto.hashSHA256(message1)
    hash2 = aes_crypto.hashSHA256(message2)
    self.assertNotEqual(hash1, hash2)

if __name__ == '__main__':
  unittest.main()
