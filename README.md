# pythonCryptoExamples

This repository contains sample code for encrypting/decrypting messages using PythonCrypto's implementation of AES.

Disclaimer: This code was written for exploratory purposes only.

See PythonCrypto's website for more information on their packages:
https://www.dlitz.net/software/pycrypto/

### Set up instructions:
1. Install Python 2.7
2. Install Python's Crypto package
    * Debian or Ubuntu Linux: ```sudo aptitude install python-crypto```
    * Windows: ```pip install pycrypto```

### Running unit tests:

* All tests in the current directory: ```python -m unittest discover```
* All tests in a given file: ```python TEST_FILE_PATH```
    * eg. ```python test_aes_crypto.py```
* A specific test: ```python TEST_FILE_PATH TEST_CLASS TEST_NAME```
    * eg. ```python test_aes_crypto.py TestAESCrypto.test_padMessageForAES```
