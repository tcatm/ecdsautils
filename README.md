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

Binary will be in `build/src`.

Utilities
---------

### generate-key

The secret is written to stdout.

    % ecdsautil generate-key > secret
    % cat secret
    68b12c0eaf88bf17fbcdf560780136b9cc4be352fb8aa7148215fbd65887db7b

### show-key

The secret should be supplied on stdin. The public key will be written to
stdout.

    % ecdsautil show-key < secret
    1f63ef7450760af9062ff697995eb536eef25a555822087fa4cfd9a82d9faa79

### sign

If you have followed the previous examples you should have a file called
`secret` containing the private key. Using a secret you can sign a file like
this:

    % ecdsautil sign somefile < secret
    da967af925168d8eb113bc79a60717b444d24c0dab449a90b1360dc849d1150fc6fe5e6656966d2fc88e67d81108deb13836ed66308cf897dd1b8815f6422802

### verify

`ecdsautil verify` is quite powerful utility for verification of signatures. You can
verify a simple signature like this:

    % ecdsautil verify -s da967...802 -p 1f63ef7450760af9062ff697995eb536eef25a555822087fa4cfd9a82d9faa79 somefile
    % echo $?
    0

Usually, there is no output except the return code. A return code of 0 denotes
a correct signature. If the signature is invalid, 1 is returned.

#### n-of-m verification

Multiple signatures and public keys may be supplied to facilitate n-of-m
verifications:

    % ecdsautil verify -s signature1 -s signature2 ... -p pubkey1 -p pubkey2 ... somefile

In this mode it is checked whether any supplied public key can be used to
verify any supplied signature. This can be used in cases where multiple
parties (each with their own private key) are allowed to sign a file. This is
called 1-of-m verification.

This can further be expanded into n-of-m verification using the `-n` switch:

    % ecdsautil verify -s sig1 -s sig2 -s sig3 -p pub1 -p pub2 -p pub3 -p pub4 -n 2

In this case at least two pairs of public key and signature must match.

Signature Format
----------------

concat $ map tohexstring [r, s]


libecdsautil
------------

ecdsautil can easily be embedded into other applications. A pkg-config file
called `ecdsautil.pc` is provided for easy compiling and linking against
libecdsautil.

For API documentation see the public header file `<ecdsautil/ecdsa.h>` (and
`<ecdsautil/sha256.h>` for the included SHA256 implementation). If you have
installed Doxygen, `make doxygen` can be used to generated HTML documentation
of libecdsautil.

libecdsautil does not provide functions for the generate-key and show-key commands,
as these are already provided by libuecc (see `ecc_25519_gf_sanitize_secret` and
`ecc_25519_scalarmult_base`).


Release precedure
-----------------

- [ ] update debian/changelog
- [ ] create debian package
- [ ] update AUR package
