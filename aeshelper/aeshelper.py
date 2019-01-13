#!/usr/bin/env python3.6

import base64
import zlib
from enum import Enum
from hashlib import sha256
from json import dumps
from time import time

try:
    from Crypto.Cipher import AES
except ImportError:
    import sys

    print('Crypto package is required to run this script')
    sys.exit(1)


class OutputFmt(Enum):
    RAW_CIPHER = 0
    BASE64_CIPHER = 1
    PLAIN_COMPRESSED_BASE64_CIPHER = 2


def output_decorator(fun):
    def func_wrapper(*args, **kwargs):
        if AesHelper.enc_out_fmt == OutputFmt.RAW_CIPHER:
            return fun(*args, **kwargs)
        return base64.b64encode(fun(*args, **kwargs)).decode()

    return func_wrapper


class AesHelper:
    enc_out_fmt = OutputFmt.BASE64_CIPHER

    def __init__(self, key_str: str):
        """
        Sets the default data for AES encryption
        :param key_str: AES key
        """
        self.aes_mode = AES.MODE_CFB
        self.key = self.hash_key(key_str)
        self.init_vector = None

    @classmethod
    def get_output_fmt(cls):
        return cls.enc_out_fmt

    @output_decorator
    def encrypt_str(self, plain_str: str, iv_concat=False) -> bytes or str:
        """
        Encrypts string to AES, then encodes it according to Output Format
        :param plain_str: text to encrypt
        :param iv_concat: if true, concatenates IV to encrypted data
        :return: encrypted data according to Output Format
        """
        if not plain_str:
            raise ValueError('String is empty')

        cipher = AES.new(self.key, self.aes_mode)

        self.init_vector = cipher.iv

        if self.get_output_fmt() != OutputFmt.PLAIN_COMPRESSED_BASE64_CIPHER:
            data_bytes = plain_str.encode()
        else:
            data_bytes = zlib.compress(plain_str.encode())

        if not iv_concat:
            return cipher.encrypt(data_bytes)
        return self.init_vector + cipher.encrypt(data_bytes)

    def encrypt_json(self, json_data: dict, iv_concat=False) -> bytes or str:
        """
        Dumps dictionary to JSON string, then encrypts it and encodes according to Output Format
        :param json_data: json data to encrypt
        :param iv_concat: if true, concatenates IV to encrypted data
        :return: encrypted data according to Output Format
        """
        if not json_data:
            raise ValueError('Dictionary is empty')

        return self.encrypt_str(dumps(json_data), iv_concat)

    def decrypt(self, encrypted: bytes or str, contains_iv=False) -> str or None:
        """
        Decrypts AES data
        :param encrypted: encrypted raw/base64/compressed data
        :param contains_iv: if true, separates IV from encrypted data
        :return: decrypted data string
        """
        encrypted_raw = self.get_raw_encrypted(encrypted)

        if encrypted_raw is None or len(encrypted_raw) < 1:
            return None

        if contains_iv and len(encrypted_raw) > AES.block_size:
            self.init_vector = encrypted_raw[0:AES.block_size]
            to_decrypt = encrypted_raw[AES.block_size:]
        else:
            to_decrypt = encrypted_raw

        if self.init_vector is None:
            raise ValueError('IV is NOT set')

        cipher = AES.new(self.key, self.aes_mode, self.init_vector)

        try:
            if self.get_output_fmt() != OutputFmt.PLAIN_COMPRESSED_BASE64_CIPHER:
                return cipher.decrypt(to_decrypt).decode()
            return zlib.decompress(cipher.decrypt(to_decrypt)).decode()
        except (UnicodeDecodeError, TypeError, zlib.error, base64.binascii.Error):
            return f'{time()} | decryption error'

    @staticmethod
    def get_raw_encrypted(encrypted: str or bytes) -> str or bytes:
        """
        Gets raw encrypted data for decryption
        :param encrypted: encrypted data
        :return: base64 decoded and/or uncompressed AES encrypted data
        """
        if isinstance(encrypted, bytes):
            return encrypted

        try:
            return base64.b64decode(encrypted)
        except base64.binascii.Error:
            return None

    def set_key(self, aes_key: str):
        """
        Sets the AES key for encryption/decryption
        :param aes_key: AES key for data encryption or decryption
        """
        self.key = self.hash_key(aes_key)

    @staticmethod
    def hash_key(aes_key: str) -> bytes:
        """
        Hashes string AES key to SHA256 hex string
        :param aes_key: AES key string
        :return: SHA256 digest
        """
        return sha256(aes_key.encode()).digest()

    @output_decorator
    def get_iv_by_format(self) -> bytes or str:
        """
        Returns IV for AES (from last encryption), according to Output Format
        :return: IV bytes according to Output Format
        """
        return self.init_vector
