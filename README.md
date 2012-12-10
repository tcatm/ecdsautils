ECDSA Util
==========

Requirements
------------

  * libuecc: http://git.universe-factory.net/libuecc

Building
--------

    mkdir build
    cd build
    cmake ..
    make

Binaries will be in `build/src`.

Utilities
---------

### ecdsakeygen

#### Generate a new private key

The secret is written to stdout.

    % ecdsakeygen -s > secret
    % cat secret
    68b12c0eaf88bf17fbcdf560780136b9cc4be352fb8aa7148215fbd65887db7b

#### Calculate public key given a private key

The secret should be supplied on stdin. The public key will be written to
stdout.

    % ecdsakeygen -p < secret
    1f63ef7450760af9062ff697995eb536eef25a555822087fa4cfd9a82d9faa79

### ecdsasign  
    Given a private key signs a 256-bit number.

### ecdsaverify  
    Given a public key and a 256-bit number a signature is verified.  
    Exits with 0 on success.  

Signature Format
----------------

concat $ map tohexstring [r, s]

