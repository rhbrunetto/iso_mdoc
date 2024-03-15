import 'dart:async';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:pointycastle/export.dart' as pc;
import 'package:x25519/x25519.dart' as x25519;

import 'cose_objects.dart';
import 'private_util.dart';

abstract class SignatureGenerator {
  final int supportedCoseAlgorithm;

  SignatureGenerator(this.supportedCoseAlgorithm);

  factory SignatureGenerator.get(CoseKey key) {
    if (key.crv == CoseCurve.ed25519) {
      return Ed25519Signer(key);
    } else if (key.crv == CoseCurve.p256 ||
        key.crv == CoseCurve.brainpoolP256r1) {
      return Es256Signer(key);
    } else if (key.crv == CoseCurve.p384 ||
        key.crv == CoseCurve.brainpoolP384r1 ||
        key.crv == CoseCurve.brainpoolP320r1) {
      return Es384Signer(key);
    } else if (key.crv == CoseCurve.p521 ||
        key.crv == CoseCurve.brainpoolP512r1) {
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
  pc.ECDomainParameters curve;
  final _generator = pc.ECDSASigner(pc.SHA256Digest(), null);
  static final _curveParams = {
    CoseCurve.p256: pc.ECCurve_secp256r1(),
    CoseCurve.brainpoolP256r1: pc.ECCurve_brainpoolp256r1()
  };

  Es256Signer(this.key)
      : curve = _curveParams.containsKey(key.crv)
            ? _curveParams[key.crv]!
            : throw ArgumentError(),
        super(CoseAlgorithm.es256);

  @override
  List<int> generate(List<int> data) {
    var private = pc.ECPrivateKey(bytesToUnsignedInt(key.d!), curve);

    _generator.init(
        true,
        pc.ParametersWithRandom(
            pc.PrivateKeyParameter<pc.ECPrivateKey>(private),
            getSecureRandom()));

    var sig = _generator.generateSignature(Uint8List.fromList(data))
        as pc.ECSignature;
    return unsignedIntToBytes(sig.r).toList() +
        unsignedIntToBytes(sig.s).toList();
  }

  @override
  bool verify(List<int> data, List<int> toVerify) {
    var pubKey = pc.ECPublicKey(
        curve.curve.createPoint(
            bytesToUnsignedInt(key.x!), bytesToUnsignedInt(key.y!)),
        curve);

    var s = toVerify.length ~/ 2;

    _generator.init(
      false,
      pc.PublicKeyParameter<pc.PublicKey>(pubKey),
    );
    return _generator.verifySignature(
        Uint8List.fromList(data),
        pc.ECSignature(bytesToUnsignedInt(toVerify.sublist(0, s)),
            bytesToUnsignedInt(toVerify.sublist(s))));
  }
}

class Es384Signer extends SignatureGenerator {
  CoseKey key;
  pc.ECDomainParameters curve;
  final _generator = pc.ECDSASigner(pc.SHA384Digest(), null);
  static final _curveParams = {
    CoseCurve.p384: pc.ECCurve_secp384r1(),
    CoseCurve.brainpoolP384r1: pc.ECCurve_brainpoolp384r1(),
    CoseCurve.brainpoolP320r1: pc.ECCurve_brainpoolp320r1()
  };

  Es384Signer(this.key)
      : curve = _curveParams.containsKey(key.crv)
            ? _curveParams[key.crv]!
            : throw ArgumentError(),
        super(CoseAlgorithm.es384);

  @override
  List<int> generate(List<int> data) {
    var private = pc.ECPrivateKey(bytesToUnsignedInt(key.d!), curve);

    _generator.init(
        true,
        pc.ParametersWithRandom(
            pc.PrivateKeyParameter<pc.ECPrivateKey>(private),
            getSecureRandom()));

    var sig = _generator.generateSignature(Uint8List.fromList(data))
        as pc.ECSignature;
    var rList = unsignedIntToBytes(sig.r).toList();
    while (rList.length < 48) {
      rList = [0] + rList;
    }
    var sList = unsignedIntToBytes(sig.s).toList();
    while (sList.length < 48) {
      sList = [0] + sList;
    }
    return rList + sList;
  }

  @override
  bool verify(List<int> data, List<int> toVerify) {
    var pubKey = pc.ECPublicKey(
        curve.curve.createPoint(
            bytesToUnsignedInt(key.x!), bytesToUnsignedInt(key.y!)),
        curve);

    var s = toVerify.length ~/ 2;

    _generator.init(
      false,
      pc.PublicKeyParameter<pc.PublicKey>(pubKey),
    );
    return _generator.verifySignature(
        Uint8List.fromList(data),
        pc.ECSignature(bytesToUnsignedInt(toVerify.sublist(0, s)),
            bytesToUnsignedInt(toVerify.sublist(s))));
  }
}

class Es512Signer extends SignatureGenerator {
  CoseKey key;
  pc.ECDomainParameters curve;
  final _generator = pc.ECDSASigner(pc.SHA512Digest(), null);
  static final _curveParams = {
    CoseCurve.p521: pc.ECCurve_secp521r1(),
    CoseCurve.brainpoolP512r1: pc.ECCurve_brainpoolp512r1()
  };

  Es512Signer(this.key)
      : curve = _curveParams.containsKey(key.crv)
            ? _curveParams[key.crv]!
            : throw ArgumentError(),
        super(CoseAlgorithm.es512);

  @override
  List<int> generate(List<int> data) {
    var private = pc.ECPrivateKey(bytesToUnsignedInt(key.d!), curve);

    _generator.init(
        true,
        pc.ParametersWithRandom(
            pc.PrivateKeyParameter<pc.ECPrivateKey>(private),
            getSecureRandom()));

    var sig = _generator.generateSignature(Uint8List.fromList(data))
        as pc.ECSignature;
    var rList = unsignedIntToBytes(sig.r).toList();
    while (rList.length < 66) {
      rList = [0] + rList;
    }
    var sList = unsignedIntToBytes(sig.s).toList();
    while (sList.length < 66) {
      sList = [0] + sList;
    }
    return rList + sList;
  }

  @override
  bool verify(List<int> data, List<int> toVerify) {
    var pubKey = pc.ECPublicKey(
        curve.curve.createPoint(
            bytesToUnsignedInt(key.x!), bytesToUnsignedInt(key.y!)),
        curve);

    var s = toVerify.length ~/ 2;

    _generator.init(
      false,
      pc.PublicKeyParameter<pc.PublicKey>(pubKey),
    );
    return _generator.verifySignature(
        Uint8List.fromList(data),
        pc.ECSignature(bytesToUnsignedInt(toVerify.sublist(0, s)),
            bytesToUnsignedInt(toVerify.sublist(s))));
  }
}

abstract class KeyAgreement {
  factory KeyAgreement(
      {required CoseKey publicKey, required CoseKey privateKey}) {
    if (publicKey.crv == CoseCurve.x25519 &&
        privateKey.crv == CoseCurve.x25519) {
      return X25519KeyAgreement(publicKey: publicKey, privateKey: privateKey);
    } else {
      return PointyCastleKeyAgreement(
          publicKey: publicKey, privateKey: privateKey);
    }
  }

  FutureOr<List<int>> generateSymmetricKey();
}

class X25519KeyAgreement implements KeyAgreement {
  CoseKey publicKey, privateKey;

  X25519KeyAgreement({required this.publicKey, required this.privateKey});

  @override
  Future<List<int>> generateSymmetricKey() async {
    return x25519.X25519(privateKey.d!, publicKey.x!);
  }
}

class PointyCastleKeyAgreement implements KeyAgreement {
  CoseKey publicKey, privateKey;

  PointyCastleKeyAgreement({required this.publicKey, required this.privateKey});

  @override
  List<int> generateSymmetricKey() {
    if (publicKey.crv != privateKey.crv) {
      throw ArgumentError('Keys have different curves');
    }
    var curve = coseCurveToPointyCastleCurve[privateKey.crv];
    if (curve == null) {
      throw UnsupportedError('Unsupported Curve: ${privateKey.crv}');
    }
    var private = pc.ECPrivateKey(bytesToUnsignedInt(privateKey.d!), curve);
    var pubKey = pc.ECPublicKey(
        curve.curve.createPoint(
            bytesToUnsignedInt(publicKey.x!), bytesToUnsignedInt(publicKey.y!)),
        curve);
    var agree = pc.ECDHBasicAgreement();
    agree.init(private);
    var secret = agree.calculateAgreement(pubKey);
    return unsignedIntToBytes(secret);
  }
}

abstract class MacGenerator {
  int supportedCoseAlgorithm;
  MacGenerator(this.supportedCoseAlgorithm);

  factory MacGenerator.get(int coseAlgorithm, Uint8List macKey) {
    if (coseAlgorithm == CoseAlgorithm.hmac256) {
      return HMacSha256Generator(macKey);
    } else {
      throw UnsupportedError('Unsupported Algorithm: $coseAlgorithm');
    }
  }
  List<int> generate(List<int> data);
  bool verify(List<int> data, List<int> macToVerify);
}

class HMacSha256Generator extends MacGenerator {
  Uint8List macKey;
  final pc.HMac _hmac = pc.HMac(pc.SHA256Digest(), 64);

  HMacSha256Generator(this.macKey) : super(CoseAlgorithm.hmac256);

  @override
  List<int> generate(List<int> data) {
    _hmac.init(pc.KeyParameter(macKey));
    return _hmac.process(Uint8List.fromList(data)).toList();
  }

  @override
  bool verify(List<int> data, List<int> macToVerify) {
    var generated = generate(data);
    return listEquals(generated, macToVerify);
  }
}
