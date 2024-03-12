import 'dart:async';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:pointycastle/export.dart' as pc;
import 'package:x25519/x25519.dart' as x25519;
import 'package:x509b/x509.dart';

import 'crypto_generator.dart';
import 'private_util.dart';

class CoseKey {
  int kty;
  List<int>? kid;
  dynamic alg;
  List<int>? keyOps;
  List<int>? baseIV;
  int? crv;
  List<int>? x, y, d;
  Map<int, dynamic>? additionalData;
  CborBytes? _keyBytes;

  CoseKey(
      {required this.kty,
      this.kid,
      this.alg,
      this.keyOps,
      this.baseIV,
      this.crv,
      this.x,
      this.y,
      this.d,
      this.additionalData,
      CborBytes? keyBytes})
      : _keyBytes = keyBytes;

  factory CoseKey.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    CborValue decoded;
    CborBytes? keyBytesTmp;

    if (cborData is CborBytes && cborData.tags.contains(24)) {
      keyBytesTmp = cborData;
      decoded = cborDecode(cborData.bytes);
    } else {
      decoded = cborData is CborValue
          ? cborData
          : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    }
    var asMap = CborMap.of(decoded as CborMap);

    var ktyTmp = asMap.remove(CborSmallInt(1));
    var kidTmp = asMap.remove(CborSmallInt(2)) as CborBytes?;
    var algTmp = asMap.remove(CborSmallInt(3)) as CborSmallInt?;
    var keyOpsTmp = asMap.remove(CborSmallInt(4)) as CborList?;
    var baseIvTmp = asMap.remove(CborSmallInt(5)) as CborBytes?;
    var crvTmp = asMap.remove(CborSmallInt(-1)) as CborSmallInt?;
    var xTmp = asMap.remove(CborSmallInt(-2)) as CborBytes?;
    var yTmp = asMap.remove(CborSmallInt(-3)) as CborBytes?;
    var dTmp = asMap.remove(CborSmallInt(-4)) as CborBytes?;

    return CoseKey(
        kty: ktyTmp is CborSmallInt
            ? ktyTmp.value
            : int.parse((ktyTmp as CborString).toString()),
        kid: kidTmp?.bytes,
        alg: algTmp?.value,
        keyOps: keyOpsTmp?.map((e) => (e as CborSmallInt).value).toList(),
        baseIV: baseIvTmp?.bytes,
        crv: crvTmp?.value,
        x: xTmp?.bytes,
        y: yTmp?.bytes,
        d: dTmp?.bytes,
        additionalData: asMap.isNotEmpty
            ? asMap.map((key, value) =>
                MapEntry((key as CborSmallInt).value, value.toObject()))
            : null,
        keyBytes: keyBytesTmp);
  }

  factory CoseKey.fromCertificate(String x509Certificate) {
    var certIt = parsePem(
        '-----BEGIN CERTIFICATE-----\n$x509Certificate\n-----END CERTIFICATE-----');
    var cert = certIt.first as X509Certificate;

    CoseKey tmp;
    if (cert.publicKey.algorithm == 'ecPublicKey') {
      var oid = cert.publicKey.parameters as ObjectIdentifier;
      tmp = CoseKey(kty: CoseKeyType.ec2);
      if (oid.name == 'prime256v1') {
        tmp.crv = CoseCurve.p256;
        tmp.x = cert.publicKey.publicKeyDer.sublist(1, 33);
        tmp.y = cert.publicKey.publicKeyDer.sublist(33);
      } else if (oid.name == 'secp384r1') {
        tmp.crv = CoseCurve.p384;
        tmp.x = cert.publicKey.publicKeyDer.sublist(1, 49);
        tmp.y = cert.publicKey.publicKeyDer.sublist(49);
      } else if (oid.name == 'secp521r1') {
        tmp.crv = CoseCurve.p521;
        tmp.x = cert.publicKey.publicKeyDer.sublist(2, 67);
        tmp.y = cert.publicKey.publicKeyDer.sublist(68);
      } else {
        throw Exception('Unknown or unsupported curve');
      }
    } else if (cert.publicKey.algorithm == 'Ed25519') {
      tmp = CoseKey(
          kty: CoseKeyType.octetKeyPair,
          crv: CoseCurve.ed25519,
          x: cert.publicKey.publicKeyDer);
    } else {
      throw Exception('Unsupported Algorithm: ${cert.publicKey.algorithm}');
    }

    return tmp;
  }

  factory CoseKey.generate(int curve) {
    CoseKey tmp;
    if (curve == CoseCurve.ed25519) {
      var key = ed.generateKey();
      tmp = CoseKey(
          kty: CoseKeyType.octetKeyPair,
          crv: CoseCurve.ed25519,
          x: key.publicKey.bytes,
          d: key.privateKey.bytes);
    } else if (curve == CoseCurve.x25519) {
      var key = x25519.generateKeyPair();
      tmp = CoseKey(
          kty: CoseKeyType.octetKeyPair,
          crv: CoseCurve.x25519,
          d: key.privateKey,
          x: key.publicKey);
    } else {
      final curveMap = {
        CoseCurve.p256: pc.ECCurve_secp256r1(),
        CoseCurve.p384: pc.ECCurve_secp384r1(),
        CoseCurve.p521: pc.ECCurve_secp521r1(),
        CoseCurve.brainpoolP256r1: pc.ECCurve_brainpoolp256r1(),
        CoseCurve.brainpoolP320r1: pc.ECCurve_brainpoolp320r1(),
        CoseCurve.brainpoolP384r1: pc.ECCurve_brainpoolp384r1(),
        CoseCurve.brainpoolP512r1: pc.ECCurve_brainpoolp512r1()
      };
      var pcCurve = curveMap[curve];
      if (pcCurve == null) {
        throw Exception('Unsupported curve: $curve');
      }
      var keyGen = pc.ECKeyGenerator();
      keyGen.init(pc.ParametersWithRandom(
          pc.ECKeyGeneratorParameters(pcCurve), getSecureRandom()));
      var newKey = keyGen.generateKeyPair();
      tmp = CoseKey(
          kty: CoseKeyType.ec2,
          crv: curve,
          x: unsignedIntToBytes(
                  (newKey.publicKey as pc.ECPublicKey).Q!.x!.toBigInteger()!)
              .toList(),
          y: unsignedIntToBytes(
                  (newKey.publicKey as pc.ECPublicKey).Q!.y!.toBigInteger()!)
              .toList(),
          d: unsignedIntToBytes((newKey.privateKey as pc.ECPrivateKey).d!)
              .toList());
    }

    return tmp;
  }

  CoseKey toPublicKey() {
    if (d == null) {
      return this;
    } else if (x != null) {
      return CoseKey(
          kty: kty,
          crv: crv,
          x: x,
          y: y,
          alg: alg,
          keyOps: keyOps,
          kid: kid,
          additionalData: additionalData,
          baseIV: baseIV);
    } else {
      throw UnimplementedError();
    }
  }

  CborBytes toCoseKeyBytes() {
    return _keyBytes ?? CborBytes(toEncodedCbor(), tags: [24]);
  }

  CborMap toCbor() {
    var data = <CborSmallInt, CborValue>{CborSmallInt(1): CborSmallInt(kty)};
    if (kid != null) {
      data[CborSmallInt(2)] = CborBytes(kid!);
    }
    if (alg != null) {
      data[CborSmallInt(3)] = CborSmallInt(alg!);
    }
    if (keyOps != null && keyOps!.isNotEmpty) {
      data[CborSmallInt(4)] =
          CborList(keyOps!.map((e) => CborSmallInt(e)).toList());
    }
    if (baseIV != null) {
      data[CborSmallInt(5)] = CborBytes(baseIV!);
    }
    if (crv != null) {
      data[CborSmallInt(-1)] = CborSmallInt(crv!);
    }
    if (x != null) {
      data[CborSmallInt(-2)] = CborBytes(x!);
    }
    if (y != null) {
      data[CborSmallInt(-3)] = CborBytes(y!);
    }
    if (d != null) {
      data[CborSmallInt(-4)] = CborBytes(d!);
    }

    if (additionalData != null && additionalData!.isNotEmpty) {
      data.addAll(additionalData!
          .map((key, value) => MapEntry(CborSmallInt(key), CborValue(value))));
    }

    return CborMap(data);
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  @override
  String toString() {
    return 'CoseKey{kty: $kty, kid: $kid, alg: $alg, keyOps: $keyOps, baseIV: $baseIV, crv: $crv, x: $x, y: $y, d: $d, additionalData: $additionalData}';
  }
}

class CoseMac0 {
  CoseHeader protected;
  CoseHeader unprotected;
  dynamic payload;
  List<int>? mac;

  CoseMac0(
      {required this.protected,
      required this.unprotected,
      this.payload,
      this.mac});

  factory CoseMac0.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    var asList = decoded as CborList;

    var protected = cborDecode((asList[0] as CborBytes).bytes);

    return CoseMac0(
        protected: CoseHeader.fromCbor(protected),
        unprotected: CoseHeader.fromCbor(asList[1]),
        payload: asList[2].toObject(),
        mac: (asList[3] as CborBytes).bytes);
  }

  List<int> generateMacStructure(
      {List<int>? externalAad, dynamic externalPayload}) {
    externalAad ??= [];
    var macStructure = CborList([
      CborString('MAC0'),
      CborBytes(protected.toEncodedCbor()),
      CborBytes(externalAad),
      externalPayload is List<int>
          ? CborBytes(externalPayload)
          : CborValue(externalPayload ?? payload)
    ]);

    return cborEncode(macStructure);
  }

  CborList toCbor() {
    return CborList([
      CborBytes(protected.toEncodedCbor()),
      unprotected.toCbor(),
      payload == null ? CborNull() : CborValue(payload),
      CborBytes(mac ?? [])
    ]);
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  @override
  String toString() {
    return 'CoseMac0{protected: $protected, unprotected: $unprotected, payload: $payload, mac: $mac}';
  }
}

class CoseSign1 {
  CoseHeader protected;
  CoseHeader unprotected;
  dynamic payload;
  List<int>? signature;
  List<int>? protectedEncoded;

  CoseSign1(
      {required this.protected,
      required this.unprotected,
      required this.payload,
      this.signature,
      this.protectedEncoded});

  factory CoseSign1.fromCbor(dynamic cborData) {
    assert(cborData is String || cborData is List<int> || cborData is CborList);
    CborList asList;
    if (cborData is CborList) {
      asList = cborData;
    } else {
      var decoded =
          cborDecode(cborData is String ? hex.decode(cborData) : cborData);
      asList = decoded as CborList;
    }

    var protected = cborDecode((asList[0] as CborBytes).bytes);

    return CoseSign1(
        protected: CoseHeader.fromCbor(protected),
        unprotected: CoseHeader.fromCbor(asList[1]),
        payload: asList[2],
        signature: (asList[3] as CborBytes).bytes,
        protectedEncoded: (asList[0] as CborBytes).bytes);
  }

  String generateIntermediate({dynamic externalPayload}) {
    var protectedEnc = protectedEncoded ?? protected.toEncodedCbor();
    var data = [
      'Signature1',
      CborBytes(protectedEnc),
      CborBytes([]),
      externalPayload ?? payload
    ];
    return hex.encode(Uint8List.fromList(cborEncode(CborValue(data))));
  }

  Future<void> sign(SignatureGenerator signer,
      {dynamic externalPayload}) async {
    var intermediate = generateIntermediate(externalPayload: externalPayload);

    if (signer.supportedCoseAlgorithm != protected.algorithm) {
      throw Exception(
          'Selected CryptoGenerator not applicable for this Object. Different Algorithm values: ${signer.supportedCoseAlgorithm} != ${protected.algorithm}');
    }

    signature = await signer.generate(hex.decode(intermediate));
  }

  FutureOr<bool> verify(SignatureGenerator verifier,
      {dynamic externalPayload}) {
    var intermediate = generateIntermediate(externalPayload: externalPayload);
    if (verifier.supportedCoseAlgorithm != protected.algorithm) {
      throw Exception(
          'Selected CryptoGenerator not applicable for this Object. Different Algorithm values');
    }

    if (signature == null) {
      throw Exception('There is no signature to verify');
    }

    return verifier.verify(hex.decode(intermediate), signature!);
  }

  CborList toCbor() {
    var object = CborList([
      CborBytes(protectedEncoded ?? protected.toEncodedCbor()),
      unprotected.toCbor(),
      CborValue(payload)
    ]);

    if (signature != null) {
      object.add(CborBytes(signature!));
    }

    return object;
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  @override
  String toString() {
    return 'CoseSign1{protected: $protected, unprotected: $unprotected, payload: $payload, signature: $signature}';
  }
}

class CoseHeader {
  int? algorithm;
  List<int>? critical;
  int? contentType;
  List<int>? keyIdentifier;
  List<int>? iv;
  List<int>? partialIv;
  List<int>? x509chain;

  static final int algorithmParameter = 1;
  static final int criticalParameter = 2;
  static final int contentTypeParameter = 3;
  static final int keyIdParameter = 4;
  static final int ivParameter = 5;
  static final int partialIvParameter = 6;
  static final int x509ChainParameter = 33;

  CoseHeader(
      {this.algorithm,
      this.critical,
      this.contentType,
      this.keyIdentifier,
      this.iv,
      this.partialIv,
      this.x509chain});

  factory CoseHeader.fromCbor(dynamic cborData) {
    assert(cborData is String || cborData is List<int> || cborData is CborMap);
    CborMap asMap;
    if (cborData is CborMap) {
      asMap = cborData;
    } else {
      var decoded =
          cborDecode(cborData is String ? hex.decode(cborData) : cborData);
      asMap = decoded as CborMap;
    }

    List<int>? x509chainTmp;
    int? algTmp;
    if (asMap.containsKey(CborSmallInt(x509ChainParameter))) {
      x509chainTmp =
          (asMap[CborSmallInt(x509ChainParameter)] as CborBytes).bytes;
    }

    if (asMap.containsKey(CborSmallInt(algorithmParameter))) {
      algTmp = (asMap[CborSmallInt(algorithmParameter)] as CborSmallInt).value;
    }

    return CoseHeader(algorithm: algTmp, x509chain: x509chainTmp);
  }

  CborMap toCbor() {
    var object = CborMap({});
    if (algorithm != null) {
      object[CborSmallInt(algorithmParameter)] = CborSmallInt(algorithm!);
    }
    if (x509chain != null) {
      object[CborSmallInt(x509ChainParameter)] = CborBytes(x509chain!);
    }
    return object;
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }
}

class CoseAlgorithm {
  static final int aes128kw = -3;
  static final int aes192kw = -4;
  static final int aes256kw = -5;

  static final int edDSA = -8;

  static final int es256 = -7;
  static final int es384 = -35;
  static final int es512 = -36;

  static final int aes128gcm = 1;
  static final int aes192gcm = 2;
  static final int aes256gcm = 3;

  static final int hmac256truncated = 4;
  static final int hmac256 = 5;
  static final int hmac384 = 6;
  static final int hmac512 = 7;

  static final int aesMac128with64 = 14;
  static final int aesMac256with64 = 15;
  static final int aesMac128with128 = 25;
  static final int aesMac256with128 = 26;

  static final int chaCha30poly1305 = 24;
}

class CoseKeyType {
  static final int octetKeyPair = 1;
  static final int ec2 = 2;
  static final int symmetric = 4;
}

class CoseCurve {
  static final int p256 = 1;
  static final int p384 = 2;
  static final int p521 = 3;

  static final int x25519 = 4;
  static final int x448 = 5;

  static final int ed25519 = 6;
  static final int ed448 = 7;

  static final int secp256k1 = 8;

  static final int brainpoolP256r1 = 256;
  static final int brainpoolP320r1 = 257;
  static final int brainpoolP384r1 = 258;
  static final int brainpoolP512r1 = 259;
}
