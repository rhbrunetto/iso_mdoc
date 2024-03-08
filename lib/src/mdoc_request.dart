import 'dart:async';
import 'dart:convert';

import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';

import 'cose_objects.dart';
import 'crypto_generator.dart';
import 'mdoc_response.dart';

FutureOr<bool> verifyDocRequestSignature(
    DocRequest docRequest, SessionTranscript sessionTranscript) {
  var readerAuth = ReaderAuth(
      sessionTranscript: sessionTranscript,
      itemsRequestBytes: docRequest.itemsRequest.toItemsRequestBytes());

  var enc = CborBytes(cborEncode(readerAuth.toReaderAuthBytes()));

  var issuerPublicKey = CoseKey.fromCertificate(
      base64Encode(docRequest.readerAuthSignature!.unprotected.x509chain!));

  return docRequest.readerAuthSignature!
      .verify(SignatureGenerator.get(issuerPublicKey), externalPayload: enc);
}

class SessionEstablishment {
  CoseKey eReaderKey;
  List<int> encryptedRequest;

  SessionEstablishment(
      {required this.eReaderKey, required this.encryptedRequest});

  factory SessionEstablishment.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    var asMap = decoded as CborMap;

    return SessionEstablishment(
        eReaderKey: CoseKey.fromCbor(asMap[CborString('eReaderKey')]),
        encryptedRequest: (asMap[(CborString('data'))] as CborBytes).bytes);
  }

  CborMap toCbor() {
    return CborMap({
      CborString('eReaderKey'): eReaderKey.toCoseKeyBytes(),
      CborString('data'): CborBytes(encryptedRequest)
    });
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  @override
  String toString() {
    return 'SessionEstablishment{eReaderKey: $eReaderKey, encryptedRequest: $encryptedRequest}';
  }
}

class DeviceRequest {
  String version;
  List<DocRequest> docRequests;

  DeviceRequest({this.version = '1.0', required this.docRequests});

  factory DeviceRequest.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    var asMap = decoded as CborMap;

    var versionTmp = asMap[CborString('version')];
    if (versionTmp != CborString('1.0')) {
      throw Exception(
          'Unsupported version $versionTmp. Only support version 1.0');
    }

    return DeviceRequest(
        docRequests: (asMap[CborString('docRequests')] as CborList)
            .map((e) => DocRequest.fromCbor(e))
            .toList());
  }

  CborMap toCbor() {
    var m = <CborString, CborValue>{
      CborString('version'): CborString(version),
      CborString('docRequests'):
          CborList(docRequests.map((e) => e.toCbor()).toList())
    };
    return CborMap(m);
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  @override
  String toString() {
    return 'DeviceRequest{version: $version, docRequests: $docRequests}';
  }
}

class DocRequest {
  ItemsRequest itemsRequest;
  CoseSign1? readerAuthSignature;

  DocRequest({required this.itemsRequest, this.readerAuthSignature});

  factory DocRequest.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    var asMap = decoded as CborMap;

    return DocRequest(
        itemsRequest: ItemsRequest.fromCbor(
            (asMap[CborString('itemsRequest')] as CborBytes).bytes),
        readerAuthSignature:
            CoseSign1.fromCbor(asMap[CborString('readerAuth')]));
  }

  CborMap toCbor() {
    var m = <CborString, CborValue>{
      CborString('itemsRequest'): itemsRequest.toItemsRequestBytes()
    };
    if (readerAuthSignature != null) {
      m[CborString('readerAuth')] = readerAuthSignature!.toCbor();
    }
    return CborMap(m);
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  @override
  String toString() {
    return 'DocRequest{itemsRequest: $itemsRequest, readerAuthSignature: $readerAuthSignature}';
  }
}

class ItemsRequest {
  String docType;
  // {'nameSpace' : {'dataElementIdentifier' : intentToRetain}}
  Map<String, Map<String, bool>> nameSpaces;
  Map<String, dynamic>? requesterInfo;

  ItemsRequest(
      {required this.docType, required this.nameSpaces, this.requesterInfo});

  factory ItemsRequest.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    var asMap = decoded as CborMap;

    var nameSpacesTmp = asMap[CborString('nameSpaces')] as CborMap;

    return ItemsRequest(
        docType: (asMap[CborString('docType')] as CborString).toString(),
        nameSpaces: nameSpacesTmp.map((key, value) => MapEntry(
            (key as CborString).toString(),
            (value as CborMap).map((key, value) => MapEntry(
                (key as CborString).toString(), (value as CborBool).value)))));
  }

  CborBytes toItemsRequestBytes() {
    return CborBytes(toEncodedCbor(), tags: [24]);
  }

  CborMap toCbor() {
    var m = <CborString, CborValue>{
      CborString('docType'): CborString(docType),
      CborString('nameSpaces'): CborMap(nameSpaces.map((key, value) => MapEntry(
          CborString(key),
          CborMap(value.map(
              (key, value) => MapEntry(CborString(key), CborBool(value)))))))
    };
    if (requesterInfo != null) {
      m[CborString('requesterInfo')] = CborMap(requesterInfo!
          .map((key, value) => MapEntry(CborString(key), CborValue(value))));
    }
    return CborMap(m);
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  @override
  String toString() {
    return 'ItemsRequest{docType: $docType, nameSpaces: $nameSpaces, requesterInfo: $requesterInfo}';
  }
}

class ReaderAuth {
  SessionTranscript sessionTranscript;
  CborBytes itemsRequestBytes;

  ReaderAuth(
      {required this.sessionTranscript, required this.itemsRequestBytes});

  CborBytes toReaderAuthBytes() {
    return CborBytes(toEncodedCbor(), tags: [24]);
  }

  CborList toCbor() {
    return CborList([
      CborString('ReaderAuthentication'),
      sessionTranscript.toCbor(),
      itemsRequestBytes
    ]);
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  @override
  String toString() {
    return 'ReaderAuth{sessionTranscript: $sessionTranscript, itemsRequestBytes: $itemsRequestBytes}';
  }
}
