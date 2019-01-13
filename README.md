# aeshelper
It is the Python tool for string or json data encryption (AES-256 CFB).
It requires **Crypto** package installed (you can install it with pip)

Can be used for preparing the encrypted API data for the server.

There are three output data format defined:
* RAW_CIPHER - encrypted data as byte array
* BASE64_CIPHER - encrypted data as base64 string
* PLAIN_COMPRESSED_BASE64_CIPHER - zlib compressed plain text encrypted data as base64 string

See the examples in the unit tests.

# unittest run
> python -m unittest -v test.test_aeshelper
