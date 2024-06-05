import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:pointycastle/asn1.dart' as asn1;
import 'package:pointycastle/export.dart' as pc;
import 'package:x25519/x25519.dart' as x25519;

import 'crypto_generator.dart';
import 'private_util.dart';

/// Cose Key Object
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

  /// Parse cbor encoded key
  ///
  /// [cborData] is allowed to be
  /// - a hex encoded string containing cbor encoded data
  /// - a List<int> of cbor encoded data
  /// - a CborMap
  /// - CborBytes with tag 24, which means that these bytes are a cbor encoded value
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

  /// Parse a public key from a X509 certificate
  ///
  /// [x509Certificate] is the base64 encoded certificate WITHOUT the
  /// ----- BEGIN Certificate ----- and ----- END CERTIFICATE ------ marker.
  factory CoseKey.fromCertificate(String x509Certificate) {
    var p = asn1.ASN1Parser(base64Decode(x509Certificate));
    var certSequence = p.nextObject() as asn1.ASN1Sequence;
    var tbsCert = certSequence.elements!.first as asn1.ASN1Sequence;
    var pubKeyIndex = 5;
    // check if there is explicit version
    if (tbsCert.elements!.first.tag == 160) {
      pubKeyIndex = 6;
    }
    var pubKeyFromCert = asn1.ASN1SubjectPublicKeyInfo.fromSequence(
        tbsCert.elements![pubKeyIndex] as asn1.ASN1Sequence);
    var pubKeyBytes = pubKeyFromCert.subjectPublicKey.valueBytes!;
    var pubKeyAlgorithm = pubKeyFromCert.algorithm.algorithm;

    CoseKey tmp;
    if (pubKeyAlgorithm.readableName == 'ecPublicKey') {
      var pubKeyParameter =
          pubKeyFromCert.algorithm.parameters as asn1.ASN1ObjectIdentifier;
      var compression = pubKeyBytes[1];
      if (compression != 4) {
        throw UnsupportedError(
            'only uncompressed keys are supported: current compression: $compression');
      }
      tmp = CoseKey(kty: CoseKeyType.ec2);
      if (pubKeyParameter.readableName == 'prime256v1') {
        tmp.crv = CoseCurve.p256;
        tmp.x = pubKeyBytes.sublist(2, 34);
        tmp.y = pubKeyBytes.sublist(34);
      } else if (pubKeyParameter.readableName == 'secp384r1') {
        tmp.crv = CoseCurve.p384;
        tmp.x = pubKeyBytes.sublist(2, 50);
        tmp.y = pubKeyBytes.sublist(50);
      } else if (pubKeyParameter.readableName == 'secp521r1') {
        tmp.crv = CoseCurve.p521;
        tmp.x = pubKeyBytes.sublist(2, 68);
        tmp.y = pubKeyBytes.sublist(68);
      } else if (pubKeyParameter.readableName == 'brainpoolP256r1') {
        tmp.crv = CoseCurve.brainpoolP256r1;
        tmp.x = pubKeyBytes.sublist(2, 34);
        tmp.y = pubKeyBytes.sublist(34);
      } else if (pubKeyParameter.readableName == 'brainpoolP320r1') {
        tmp.crv = CoseCurve.brainpoolP320r1;
        tmp.x = pubKeyBytes.sublist(2, 42);
        tmp.y = pubKeyBytes.sublist(42);
      } else if (pubKeyParameter.readableName == 'brainpoolP384r1') {
        tmp.crv = CoseCurve.brainpoolP384r1;
        tmp.x = pubKeyBytes.sublist(2, 50);
        tmp.y = pubKeyBytes.sublist(50);
      } else if (pubKeyParameter.readableName == 'brainpoolP512r1') {
        tmp.crv = CoseCurve.brainpoolP512r1;
        tmp.x = pubKeyBytes.sublist(2, 66);
        tmp.y = pubKeyBytes.sublist(66);
      } else {
        throw Exception('Unknown or unsupported curve');
      }
    } else if (pubKeyAlgorithm.objectIdentifierAsString == '1.3.101.112') {
      tmp = CoseKey(
          kty: CoseKeyType.octetKeyPair,
          crv: CoseCurve.ed25519,
          x: pubKeyBytes.sublist(1));
    } else {
      throw Exception(
          'Unsupported Algorithm: ${pubKeyAlgorithm.readableName}/${pubKeyAlgorithm.objectIdentifierAsString}');
    }

    return tmp;
  }

  /// Generates a new private key with the given elliptic curve
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
      var pcCurve = coseCurveToPointyCastleCurve[curve];
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

  /// Turns a private key into an public key
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
      if (crv == CoseCurve.ed25519) {
        var private = ed.newKeyFromSeed(Uint8List.fromList(d!));
        return CoseKey(
            kty: kty,
            crv: crv,
            x: ed.public(private).bytes,
            alg: alg,
            keyOps: keyOps,
            kid: kid,
            additionalData: additionalData,
            baseIV: baseIV);
      } else {
        var curve = coseCurveToPointyCastleCurve[crv];
        if (curve == null) {
          throw UnsupportedError('Unsupported Curve: $crv');
        }
        var private =
            pc.ECPrivateKey(bytesToUnsignedInt(Uint8List.fromList(d!)), curve);
        var q = curve.G * private.d;
        return CoseKey(
            kty: kty,
            crv: crv,
            x: unsignedIntToBytes(q!.x!.toBigInteger()!),
            y: unsignedIntToBytes(q.y!.toBigInteger()!),
            alg: alg,
            keyOps: keyOps,
            kid: kid,
            additionalData: additionalData,
            baseIV: baseIV);
      }
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

/// Cose Mac0 Structure
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

  /// Parse cbor encoded mac
  ///
  /// [cborData] is allowed to be
  /// - a hex encoded string containing cbor encoded data
  /// - a List<int> of cbor encoded data
  /// - a CborList
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

  /// Generates the macStructure over which the MAC is computed
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

  void generateMac(MacGenerator generator,
      {List<int>? externalAad, dynamic externalPayload}) {
    if (generator.supportedCoseAlgorithm != protected.algorithm) {
      throw Exception(
          'Algorithm value in Header does not match supported algorithm of Mac-Generator');
    }
    mac = generator.generate(generateMacStructure(
        externalPayload: externalPayload, externalAad: externalAad));
  }

  bool verify(MacGenerator generator,
      {List<int>? externalAad, dynamic externalPayload}) {
    if (generator.supportedCoseAlgorithm != protected.algorithm) {
      throw Exception(
          'Algorithm value in Header does not match supported algorithm of Mac-Generator');
    }
    if (mac == null) {
      throw Exception('There is no mac to verify');
    }
    return generator.verify(
        generateMacStructure(
            externalPayload: externalPayload, externalAad: externalAad),
        mac!);
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

/// Cose Sign1 Structure
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

  /// Parse cbor encoded signature object
  ///
  /// [cborData] is allowed to be
  /// - a hex encoded string containing cbor encoded data
  /// - a List<int> of cbor encoded data
  /// - a CborList
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

  /// Generates the intermediate data over which the signature is computed
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

/// Cose Header for signature and mac
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

  /// Parse cbor encoded key
  ///
  /// [cborData] is allowed to be
  /// - a hex encoded string containing cbor encoded data
  /// - a List<int> of cbor encoded data
  /// - a CborMap
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

  @override
  String toString() {
    return 'CoseHeader{algorithm: $algorithm, critical: $critical, contentType: $contentType, keyIdentifier: $keyIdentifier, iv: $iv, partialIv: $partialIv, x509chain: $x509chain}';
  }
}

/// Helper class listing cose algorithm values (used in alg header parameter)
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

/// Helper class listing cose keytypes (used in kty header parameter)
class CoseKeyType {
  static final int octetKeyPair = 1;
  static final int ec2 = 2;
  static final int symmetric = 4;
}

/// Helper class listing cose elliptic curves (used in crv header parameter)
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
