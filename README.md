# Iso_mdoc
ISO/IEC 18013-5 describes datastructures to represent a digital drivers-licenses and other documents
and protocols and datastructures to present these documents to verifiers.
This library implements all datastructures and security mechanisms described in the specification.
ISO/IEC 18013-7 describes extension to ISO/IEC 18013-5, e.g. reverse engagement, online presentation using OID4VP.
It is WIP to add these additions to this library.

## Usage
It is RECOMMENDED to have knowledge of ISO/IEC 18013-5 when using this library. The datastructures 
are named the same as in the specification.

For concrete usage instructions please consult the examples. You will find a scripted document 
exchange in [example/presentation.dart](./example/presentation.dart).

## Cryptography support
Beside algorithms using ed448 and X448 all algorithms and curves named in ISO/IEC 18013-5 are
supported.

## Extensibility
All crypto-Algorithms are supported in their platform independent form using e.g. pointyCastle.
If you prefer to use for example hardware based or platform-dependent cryptography, this is possible be extending 
the base classes for KeyAgreement, MacGeneration and Signing (KeyAgreement, MacGenerator, SignatureGenerator).
You will find these base-classes and implementations in [lib/src/crypto_generator.dart](./lib/src/crypto_generator.dart).