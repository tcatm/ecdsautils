ECDSA Util
==========

based on libuecc[1]

[1]: http://git.universe-factory.net/libuecc

Building
--------

    mkdir build
    cd build
    cmake ..
    make

Binaries will be in `build/src`.

Signature Format
----------------

concat . map tohexstring [r, s]

Utilities
---------

  * ecdsakeygen  
    Generates a new key pair  
    TODO Given a private key, generate public key  
    TODO Write and read private key to/from file  
    TODO Output public key in machine readable format  

  * ecdsasign  
    Given a private key signs a 256-bit number.

  * ecdsaverify  
    Given a public key and a 256-bit number a signature is verified.  
    Exits with 0 on success.  
