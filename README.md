# OPENSSL EVP ECDH EXAMPLE(C)

Demonstration of Simple ECDH Using OpenSSL's EVP Library.

# Code Build
1. Install build-essential and libssl
  sudo apt-get install build-essential libssl-dev

2. Use GCC to build code. The code needs to be linked to libcrypto
   gcc -w  main.c -o ecdh-sample -lcrypto
