import 'dart:async';
import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:elliptic/ecdh.dart' as ecdh;
import 'package:elliptic/elliptic.dart' as elliptic;

import 'cose_objects.dart';
import 'private_util.dart';

abstract class SignatureGenerator {
  final int supportedCoseAlgorithm;

  SignatureGenerator(this.supportedCoseAlgorithm);

  factory SignatureGenerator.get(CoseKey key) {
    if (key.crv == CoseCurve.ed25519) {
      return Ed25519Signer(key);
    } else if (key.crv == CoseCurve.p256) {
      return Es256Signer(key);
    } else if (key.crv == CoseCurve.p384) {
      return Es384Signer(key);
    } else if (key.crv == CoseCurve.p521) {
      return Es512Signer(key);
    } else {
      throw Exception('Unsupported Curve: ${key.crv}');
    }
  }
  FutureOr<List<int>> generate(List<int> data);
  FutureOr<bool> verify(List<int> data, List<int> toVerify);
}

class Ed25519Signer extends SignatureGenerator {
  CoseKey key;

  Ed25519Signer(this.key) : super(CoseAlgorithm.edDSA);

  @override
  List<int> generate(List<int> data) {
    ed.PrivateKey privateKey;
    if (key.d!.length == 32) {
      privateKey = ed.newKeyFromSeed(Uint8List.fromList(key.d!));
    } else {
      privateKey = ed.PrivateKey(key.d!);
    }
    var signature = ed.sign(privateKey, Uint8List.fromList(data));

    return signature.toList();
  }

  @override
  bool verify(List<int> data, List<int> toVerify) {
    return ed.verify(ed.PublicKey(key.x!), Uint8List.fromList(data),
        Uint8List.fromList(toVerify));
  }
}

class Es256Signer extends SignatureGenerator {
  CoseKey key;

  Es256Signer(this.key) : super(CoseAlgorithm.es256);

  @override
  List<int> generate(List<int> data) {
    var private = EcPrivateKey(
        eccPrivateKey: bytesToUnsignedInt(key.d!), curve: curves.p256);

    var signer = private.createSigner(algorithms.signing.ecdsa.sha256);
    return signer.sign(data).data.toList();
  }

  @override
  bool verify(List<int> data, List<int> toVerify) {
    var pubKey = EcPublicKey(
        xCoordinate: bytesToUnsignedInt(key.x!),
        yCoordinate: bytesToUnsignedInt(key.y!),
        curve: curves.p256);
    var verifier = pubKey.createVerifier(algorithms.signing.ecdsa.sha256);
    return verifier.verify(
        Uint8List.fromList(data), Signature(Uint8List.fromList(toVerify)));
  }
}

class Es384Signer extends SignatureGenerator {
  CoseKey key;

  Es384Signer(this.key) : super(CoseAlgorithm.es384);

  @override
  List<int> generate(List<int> data) {
    var private = EcPrivateKey(
        eccPrivateKey: bytesToUnsignedInt(key.d!), curve: curves.p384);

    var signer = private.createSigner(algorithms.signing.ecdsa.sha384);
    return signer.sign(data).data.toList();
  }

  @override
  bool verify(List<int> data, List<int> toVerify) {
    var pubKey = EcPublicKey(
        xCoordinate: bytesToUnsignedInt(key.x!),
        yCoordinate: bytesToUnsignedInt(key.y!),
        curve: curves.p384);
    var verifier = pubKey.createVerifier(algorithms.signing.ecdsa.sha384);
    return verifier.verify(
        Uint8List.fromList(data), Signature(Uint8List.fromList(toVerify)));
  }
}

class Es512Signer extends SignatureGenerator {
  CoseKey key;

  Es512Signer(this.key) : super(CoseAlgorithm.es512);

  @override
  List<int> generate(List<int> data) {
    var private = EcPrivateKey(
        eccPrivateKey: bytesToUnsignedInt(key.d!), curve: curves.p521);

    var signer = private.createSigner(algorithms.signing.ecdsa.sha512);
    return signer.sign(data).data.toList();
  }

  @override
  bool verify(List<int> data, List<int> toVerify) {
    var pubKey = EcPublicKey(
        xCoordinate: bytesToUnsignedInt(key.x!),
        yCoordinate: bytesToUnsignedInt(key.y!),
        curve: curves.p521);
    var verifier = pubKey.createVerifier(algorithms.signing.ecdsa.sha512);
    return verifier.verify(
        Uint8List.fromList(data), Signature(Uint8List.fromList(toVerify)));
  }
}

abstract class KeyAgreement {
  factory KeyAgreement(
      {required CoseKey publicKey, required CoseKey privateKey}) {
    if (publicKey.crv == CoseCurve.x25519 &&
        privateKey.crv == CoseCurve.x25519) {
      return X25519KeyAgreement(publicKey: publicKey, privateKey: privateKey);
    } else if (publicKey.crv == CoseCurve.p256 &&
        privateKey.crv == CoseCurve.p256) {
      return P256KeyAgreement(publicKey: publicKey, privateKey: privateKey);
    } else if (publicKey.crv == CoseCurve.p384 &&
        privateKey.crv == CoseCurve.p384) {
      return P384KeyAgreement(publicKey: publicKey, privateKey: privateKey);
    } else if (publicKey.crv == CoseCurve.p521 &&
        privateKey.crv == CoseCurve.p521) {
      return P521KeyAgreement(publicKey: publicKey, privateKey: privateKey);
    } else {
      throw Exception(
          'Unsupported curve or different curves in keys (Public: ${publicKey.crv}, private: ${privateKey.crv}');
    }
  }

  FutureOr<List<int>> generateSymmetricKey();
}

class X25519KeyAgreement implements KeyAgreement {
  CoseKey publicKey, privateKey;

  X25519KeyAgreement({required this.publicKey, required this.privateKey});

  @override
  Future<List<int>> generateSymmetricKey() async {
    var generator = crypto.X25519();
    var private = crypto.SimpleKeyPairData(privateKey.d!,
        publicKey: crypto.SimplePublicKey(privateKey.x!,
            type: crypto.KeyPairType.x25519),
        type: crypto.KeyPairType.x25519);
    var public =
        crypto.SimplePublicKey(publicKey.x!, type: crypto.KeyPairType.x25519);
    var s = await generator.sharedSecretKey(
        keyPair: private, remotePublicKey: public);
    return s.extractBytes();
  }
}

class P256KeyAgreement implements KeyAgreement {
  CoseKey publicKey, privateKey;

  P256KeyAgreement({required this.publicKey, required this.privateKey});

  @override
  List<int> generateSymmetricKey() {
    return ecdh.computeSecret(
        elliptic.PrivateKey(elliptic.getP256(),
            bytesToUnsignedInt(Uint8List.fromList(privateKey.d!))),
        elliptic.PublicKey(
            elliptic.getP256(),
            bytesToUnsignedInt(Uint8List.fromList(publicKey.x ?? [])),
            bytesToUnsignedInt(Uint8List.fromList(publicKey.y ?? []))));
  }
}

class P384KeyAgreement implements KeyAgreement {
  CoseKey publicKey, privateKey;

  P384KeyAgreement({required this.publicKey, required this.privateKey});

  @override
  List<int> generateSymmetricKey() {
    return ecdh.computeSecret(
        elliptic.PrivateKey(elliptic.getP384(),
            bytesToUnsignedInt(Uint8List.fromList(privateKey.d!))),
        elliptic.PublicKey(
            elliptic.getP384(),
            bytesToUnsignedInt(Uint8List.fromList(publicKey.x ?? [])),
            bytesToUnsignedInt(Uint8List.fromList(publicKey.y ?? []))));
  }
}

class P521KeyAgreement implements KeyAgreement {
  CoseKey publicKey, privateKey;

  P521KeyAgreement({required this.publicKey, required this.privateKey});

  @override
  List<int> generateSymmetricKey() {
    return ecdh.computeSecret(
        elliptic.PrivateKey(elliptic.getP521(),
            bytesToUnsignedInt(Uint8List.fromList(privateKey.d!))),
        elliptic.PublicKey(
            elliptic.getP521(),
            bytesToUnsignedInt(Uint8List.fromList(publicKey.x ?? [])),
            bytesToUnsignedInt(Uint8List.fromList(publicKey.y ?? []))));
  }
}
