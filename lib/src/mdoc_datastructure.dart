import 'dart:async';
import 'dart:convert';

import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:uuid/uuid.dart';

import 'cose_objects.dart';
import 'crypto_generator.dart';
import 'mdoc_request.dart';
import 'private_util.dart';

Map<String, List<IssuerSignedItem>> getDataToReveal(
    ItemsRequest requestedData, IssuerSignedObject data) {
  if (MobileSecurityObject.fromCbor(data.issuerAuth.payload).docType !=
      requestedData.docType) {
    throw Exception('DocType does not match. No chance to find requested Data');
  }
  var toReveal = <String, List<IssuerSignedItem>>{};
  for (var nameSpace in requestedData.nameSpaces.keys) {
    var requestPerNameSpace = requestedData.nameSpaces[nameSpace];
    var dataPerNameSpace = data.items[nameSpace];
    if (dataPerNameSpace == null || dataPerNameSpace.isEmpty) {
      continue;
    }
    var valuesFound = <IssuerSignedItem>[];
    for (var property in requestPerNameSpace!.keys) {
      IssuerSignedItem? found;
      try {
        found = dataPerNameSpace
            .firstWhere((element) => element.dataElementIdentifier == property);
      } catch (_) {}

      if (found != null) {
        valuesFound.add(found);
      }
    }

    if (valuesFound.isNotEmpty) {
      toReveal[nameSpace] = valuesFound;
    }
  }
  return toReveal;
}

FutureOr<bool> verifyMso(IssuerSignedObject signed) {
  var mso = MobileSecurityObject.fromCbor(signed.issuerAuth.payload);

  // compare hashes
  bool equal = true;
  signed.items.forEach((key, value) {
    for (var i in value) {
      var expectedHash = mso.valueDigest[key]?[i.digestId];
      if (expectedHash != null) {
        var hash = sha256.convert(cborEncode(i.toIssuerSignedItemBytes()));
        if (!listEquals(expectedHash, hash.bytes)) {
          equal = false;
          print('hash not match, key: ${i.digestId}');
        }
      }
    }
  });

  if (!equal) {
    print('hash not match');
    return false;
  }

  var issuerPublicKey = CoseKey.fromCertificate(
      base64Encode(signed.issuerAuth.unprotected.x509chain!));

  return signed.issuerAuth.verify(SignatureGenerator.get(issuerPublicKey));
}

Future<IssuerSignedObject> buildMso(
    SignatureGenerator signer,
    String issuerCert,
    Map<String, List<IssuerSignedItem>> inputData,
    String hashAlg,
    CoseKey deviceKey,
    String docType) async {
  Hash hasher;
  if (hashAlg.toLowerCase() == 'sha-256') {
    hasher = sha256;
  } else if (hashAlg.toLowerCase() == 'sha-384') {
    hasher = sha384;
  } else if (hashAlg.toLowerCase() == 'sha-512') {
    hasher = sha512;
  } else {
    hasher = sha256;
  }

  Map<String, Map<int, List<int>>> valueDigest = inputData.map((key, value) =>
      MapEntry(
          key,
          value.asMap().map((key, value) => MapEntry(
              value.digestId,
              hasher
                  .convert(cborEncode(value.toIssuerSignedItemBytes()))
                  .bytes))));

  var mso = MobileSecurityObject(
      version: '1.0',
      digestAlgorithm: hashAlg,
      valueDigest: valueDigest,
      deviceKeyInfo: DeviceKeyInfo(deviceKey: deviceKey),
      docType: docType,
      validityInfo: ValidityInfo(
          signed: DateTime.now(),
          validFrom: DateTime.now(),
          validUntil: DateTime.now().add(Duration(days: 356))));

  var msoBytes = mso.toMobileSecurityObjectBytes();

  var unprotected = CoseHeader(x509chain: base64Decode(issuerCert));
  var protected = CoseHeader(algorithm: signer.supportedCoseAlgorithm);

  var cs = CoseSign1(
      protected: protected,
      unprotected: unprotected,
      payload: hex.decode(msoBytes));
  cs.sign(signer);

  var issAuth = IssuerSignedObject(issuerAuth: cs, items: inputData);

  return issAuth;
}

class MobileSecurityObject {
  // "1.0"
  String version;
  // "SHA-256" , "SHA-384" , "SHA-512"
  String digestAlgorithm;
  //{
  // 'namespace1' : {0: [1, 2], 1: [3, 4]},
  // 'namespace2' : {0: [4, 6], 1: [7, 8]}
  // }
  Map<String, Map<int, List<int>>> valueDigest;
  DeviceKeyInfo deviceKeyInfo;
  String docType;
  ValidityInfo validityInfo;
  String? itemBytes;

  MobileSecurityObject(
      {required this.version,
      required this.digestAlgorithm,
      required this.valueDigest,
      required this.deviceKeyInfo,
      required this.docType,
      required this.validityInfo,
      this.itemBytes});

  factory MobileSecurityObject.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);
    CborMap asMap;
    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    String? issuerSignedItemBytes;
    if (decoded.tags.contains(24)) {
      issuerSignedItemBytes =
          cborData is String ? cborData : hex.encode(cborData);

      asMap = cbor.decode((decoded as CborBytes).bytes) as CborMap;
    } else if (decoded is CborBytes) {
      var d2 = cbor.decode(decoded.bytes);
      if (d2.tags.contains(24)) {
        issuerSignedItemBytes = hex.encode(decoded.bytes);
        asMap = cbor.decode((d2 as CborBytes).bytes) as CborMap;
      } else {
        asMap = d2 as CborMap;
        issuerSignedItemBytes = hex.encode(decoded.bytes);
      }
    } else {
      asMap = decoded as CborMap;
    }

    var valueDigestUncasted = asMap[CborValue('valueDigests')] as CborMap;
    var v = valueDigestUncasted.map((key, value) => MapEntry(
        key.toString(),
        (value as CborMap).map((key, value) =>
            MapEntry((key as CborInt).toInt(), (value as CborBytes).bytes))));

    return MobileSecurityObject(
        itemBytes: issuerSignedItemBytes,
        version: (asMap[CborValue('version')] as CborString).toString(),
        digestAlgorithm:
            (asMap[CborValue('digestAlgorithm')] as CborString).toString(),
        valueDigest: v,
        deviceKeyInfo:
            DeviceKeyInfo.fromCbor(asMap[CborValue('deviceKeyInfo')]),
        docType: (asMap[CborValue('docType')] as CborString).toString(),
        validityInfo: ValidityInfo.fromCbor(asMap[CborValue('validityInfo')]));
  }

  CborMap toCbor() {
    return CborMap({
      CborString('version'): CborString(version),
      CborString('digestAlgorithm'): CborString(digestAlgorithm),
      CborString('valueDigests'): CborMap(valueDigest.map((key, value) =>
          MapEntry(
              CborString(key),
              CborMap(value.map((key, value) =>
                  MapEntry(CborSmallInt(key), CborBytes(value))))))),
      CborString('deviceKeyInfo'): deviceKeyInfo.toCbor(),
      CborString('docType'): CborString(docType),
      CborString('validityInfo'): validityInfo.toCbor()
    });
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  String toMobileSecurityObjectBytes() {
    return itemBytes ??
        hex.encode(cborEncode(CborBytes(toEncodedCbor(), tags: [24])));
  }

  @override
  String toString() {
    return 'MobileSecurityObject{version: $version, digestAlgorithm: $digestAlgorithm, valueDigest: $valueDigest, deviceKeyInfo: $deviceKeyInfo, docType: $docType, validityInfo: $validityInfo, itemBytes: $itemBytes}';
  }
}

class ValidityInfo {
  DateTime signed, validFrom, validUntil;
  DateTime? expectedUpdate;

  ValidityInfo(
      {required this.signed,
      required this.validFrom,
      required this.validUntil,
      this.expectedUpdate});

  factory ValidityInfo.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    var asMap = decoded as CborMap;

    return ValidityInfo(
        signed: (asMap[CborValue('signed')] as CborDateTime).toDateTime(),
        validFrom: (asMap[CborValue('validFrom')] as CborDateTime).toDateTime(),
        validUntil:
            (asMap[CborValue('validUntil')] as CborDateTime).toDateTime(),
        expectedUpdate: asMap.containsKey(CborValue('expectedUpdate'))
            ? (asMap[CborValue('expectedUpdate')] as CborDateTime).toDateTime()
            : null);
  }

  CborMap toCbor() {
    var object = CborMap({
      CborString('signed'): CborDateTimeString(signed),
      CborString('validFrom'): CborDateTimeString(validFrom),
      CborString('validUntil'): CborDateTimeString(validUntil)
    });
    if (expectedUpdate != null) {
      object[CborString('expectedUpdate')] =
          CborDateTimeString(expectedUpdate!);
    }
    return object;
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  @override
  String toString() {
    return 'ValidityInfo{signed: $signed, validFrom: $validFrom, validUntil: $validUntil, expectedUpdate: $expectedUpdate}';
  }
}

class DeviceKeyInfo {
  //COSE Key
  CoseKey deviceKey;
  List<String>? authorizedNameSpaces;
  Map<String, List<String>>? authorizedDataElements;
  Map<int, dynamic>? keyInfo;

  DeviceKeyInfo(
      {required this.deviceKey,
      this.authorizedNameSpaces,
      this.authorizedDataElements,
      this.keyInfo});

  factory DeviceKeyInfo.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);
    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);

    var asMap = decoded as CborMap;

    var deviceKeyU = asMap[CborValue('deviceKey')] as Map;
    var deviceKey = CoseKey.fromCbor(deviceKeyU);

    List<String>? nameSpaces;
    Map<String, List<String>>? dataElements;
    if (asMap.containsKey(CborValue('keyAuthorizations'))) {
      var keyAuth = asMap[CborValue('keyAuthorizations')] as CborMap;
      if (keyAuth.containsKey(CborValue('nameSpaces'))) {
        var tmp = keyAuth[CborValue('nameSpaces')] as CborList;
        nameSpaces = tmp.map((e) => e.toString()).toList();
      }
      if (keyAuth.containsKey(CborValue('dataElements'))) {
        var tmp = keyAuth[CborValue('dataElements')] as CborMap;
        dataElements = tmp.map((key, value) => MapEntry(
            key.toString(), (value.toObject() as List).cast<String>()));
      }
    }

    Map<int, dynamic>? info;
    if (asMap.containsKey(CborValue('keyInfo'))) {
      info = (asMap[CborValue('keyInfo')] as CborMap).map(
          (key, value) => MapEntry((key as CborInt).toInt(), value.toObject()));
    }
    return DeviceKeyInfo(
        deviceKey: deviceKey,
        authorizedNameSpaces: nameSpaces,
        authorizedDataElements: dataElements,
        keyInfo: info);
  }

  CborMap toCbor() {
    var object = <CborString, CborValue>{
      CborString('deviceKey'): deviceKey.toCbor()
    };

    if (authorizedNameSpaces != null || authorizedDataElements != null) {
      var auth = <CborString, CborValue>{};
      if (authorizedNameSpaces != null) {
        auth[CborString('nameSpaces')] =
            CborList(authorizedNameSpaces!.map((e) => CborString(e)).toList());
      }
      if (authorizedDataElements != null) {
        auth[CborString('dataElements')] = CborMap(authorizedDataElements!.map(
            (key, value) => MapEntry(CborString(key),
                CborList(value.map((e2) => CborString(e2)).toList()))));
      }
      object[CborString('keyAuthorizations')] = CborMap(auth);
    }

    if (keyInfo != null) {
      object[CborString('keyInfo')] = CborMap(keyInfo!
          .map((key, value) => MapEntry(CborSmallInt(key), CborValue(value))));
    }

    return CborMap(object);
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }
}

class IssuerSignedItem {
  int digestId;
  List<int> random;
  String dataElementIdentifier;
  dynamic dataElementValue;
  //internal-> not part of structure
  CborBytes? issuerSignedItemBytes;

  IssuerSignedItem(
      {required this.digestId,
      List<int>? random,
      required this.dataElementIdentifier,
      required this.dataElementValue,
      this.issuerSignedItemBytes})
      : random = random ?? ascii.encode(Uuid().v4());

  /// [cborData] might be a List<int> or a hex-String
  factory IssuerSignedItem.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);
    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    CborBytes? issuerSignedItemBytes;
    cborData is List<int> ? cborData : null;
    if (decoded.tags.contains(24)) {
      issuerSignedItemBytes = cborData;
      decoded = cbor.decode(decoded.toObject() as List<int>);
    }

    Map<dynamic, dynamic> asMap = decoded.toObject() as Map;

    return IssuerSignedItem(
        digestId: asMap['digestID'],
        random: asMap['random'],
        dataElementIdentifier: asMap['elementIdentifier'],
        dataElementValue: asMap['elementValue'],
        issuerSignedItemBytes: issuerSignedItemBytes);
  }

  CborMap toCbor() {
    return CborMap({
      CborString('digestID'): CborSmallInt(digestId),
      CborString('random'): CborBytes(random),
      CborString('elementIdentifier'): CborString(dataElementIdentifier),
      CborString('elementValue'): CborValue(dataElementValue)
    });
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  CborBytes toIssuerSignedItemBytes() {
    return issuerSignedItemBytes ?? CborBytes(toEncodedCbor(), tags: [24]);
  }

  @override
  String toString() {
    return 'IssuerSignedItem{digestId: $digestId, random: $random, dataElementIdentifier: $dataElementIdentifier, dataElementValue: $dataElementValue, issuerSignedItemBytes: $issuerSignedItemBytes}';
  }
}

class IssuerSignedObject {
  CoseSign1 issuerAuth;
  Map<String, List<IssuerSignedItem>> items;

  IssuerSignedObject({required this.issuerAuth, required this.items});

  factory IssuerSignedObject.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);

    CborMap asMap = decoded as CborMap;

    var auth = asMap[CborValue('issuerAuth')];

    var items = asMap[CborValue('nameSpaces')] as CborMap;
    var l = items.map((key, value) => MapEntry(
        key.toString(),
        (value as CborList).map((e) {
          return IssuerSignedItem.fromCbor(e);
        }).toList()));

    return IssuerSignedObject(issuerAuth: CoseSign1.fromCbor(auth), items: l);
  }

  CborMap toCbor() {
    return CborMap({
      CborString('issuerAuth'): issuerAuth.toCbor(),
      CborString('nameSpaces'): CborMap(items.map((key, value) => MapEntry(
          CborString(key),
          CborList(value.map((e) => e.toIssuerSignedItemBytes()).toList()))))
    });
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  @override
  String toString() {
    return 'IssuerSignedObject{issuerAuth: $issuerAuth, items: $items}';
  }
}
