import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:cryptography/cryptography.dart';

import 'cose_objects.dart';
import 'crypto_generator.dart';
import 'mdoc_datastructure.dart';
import 'mdoc_response.dart';
import 'private_util.dart';

enum MdocRole { mdocHolder, mdocReader }

class SessionEncryptor {
  final algorithm = AesGcm.with256bits(nonceLength: 12);
  MdocRole mdocRole;
  int counterEncrypt, counterDecrypt;
  // Ephemeral Keys
  CoseKey myPrivateKey, otherPublicKey;
  List<int>? encryptionKey, decryptionKey;

  SessionEncryptor(
      {required this.mdocRole,
      required this.myPrivateKey,
      required this.otherPublicKey})
      : counterDecrypt = 1,
        counterEncrypt = 1;

  Future<void> generateKeys(List<int> sessionTranscriptBytes) async {
    var keyAgreement =
        KeyAgreement(privateKey: myPrivateKey, publicKey: otherPublicKey);
    var secret = await keyAgreement.generateSymmetricKey();

    final kdf = Hkdf(
      hmac: Hmac.sha256(),
      outputLength: 32,
    );

    final readerKey = await kdf.deriveKey(
        secretKey: SecretKey(secret),
        nonce: sessionTranscriptBytes,
        info: utf8.encode('SKReader'));

    final deviceKey = await kdf.deriveKey(
        secretKey: SecretKey(secret),
        nonce: sessionTranscriptBytes,
        info: utf8.encode('SKDevice'));

    if (mdocRole == MdocRole.mdocReader) {
      encryptionKey = readerKey.bytes;
      decryptionKey = deviceKey.bytes;
    } else {
      encryptionKey = deviceKey.bytes;
      decryptionKey = readerKey.bytes;
    }
  }

  Future<List<int>> decrypt(List<int> encryptedData) async {
    var iv = Uint8List.fromList([
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      mdocRole == MdocRole.mdocReader ? 1 : 0,
      0,
      0,
      0,
      counterDecrypt
    ]);

    var ciphertext = encryptedData.sublist(0, encryptedData.length - 16);
    var mac = encryptedData.sublist(encryptedData.length - 16);
    var d2 = SecretBox(ciphertext, nonce: iv, mac: Mac(mac));

    if (decryptionKey == null) {
      throw Exception(
          'No decryption Key generated. Use generateKeys() beforehand.');
    }

    var cleartext =
        await algorithm.decrypt(d2, secretKey: SecretKey(decryptionKey!));

    counterDecrypt++;

    return cleartext;
  }

  Future<List<int>> encrypt(List<int> data) async {
    var iv = Uint8List.fromList([
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      mdocRole == MdocRole.mdocReader ? 0 : 1,
      0,
      0,
      0,
      counterEncrypt
    ]);

    if (encryptionKey == null) {
      throw Exception(
          'No encryption Key generated. Use generateKeys() beforehand.');
    }

    var ciphertext = await algorithm.encrypt(data,
        secretKey: SecretKey(encryptionKey!), nonce: iv);

    counterEncrypt++;

    return ciphertext.concatenation(nonce: false);
  }
}

Future<bool> verifyDeviceResponse(
    DeviceResponse response, SessionTranscript sessionTranscript,
    {CoseKey? readerPrivateKey}) async {
  var msoValid = await verifyMso(response.documents!.first.issuerSigned);
  if (!msoValid) {
    throw Exception('Invalid Mobile Security Object (Issuer Signed)');
  }

  var mso = MobileSecurityObject.fromCbor(
      response.documents!.first.issuerSigned.issuerAuth.payload);
  var sDeviceKey = mso.deviceKeyInfo.deviceKey;

  var deviceMac = response.documents!.first.deviceSigned.deviceMac;
  var deviceAuth = DeviceAuth(
      sessionTranscript: sessionTranscript,
      docType: response.documents!.first.docType,
      nameSpaceBytes: response.documents!.first.deviceSigned.nameSpaceBytes);

  var encDevAuth = cborEncode(deviceAuth.toDeviceAuthBytes());
  if (deviceMac != null) {
    if (readerPrivateKey == null) {
      throw Exception('Reader-Private Key needed to verify Mac');
    }

    var keyAgreement =
        KeyAgreement(privateKey: readerPrivateKey, publicKey: sDeviceKey);
    var macSecret = await keyAgreement.generateSymmetricKey();

    final kdf = Hkdf(
      hmac: Hmac.sha256(),
      outputLength: 32,
    );

    final macKey = await kdf.deriveKey(
        secretKey: SecretKey(macSecret),
        nonce: cborEncode(sessionTranscript.toSessionTranscriptBytes()),
        info: utf8.encode('EMacKey'));

    var macStructure =
        deviceMac.generateMacStructure(externalPayload: encDevAuth);

    var macAlgo = Hmac.sha256();

    var calculatedMac =
        await macAlgo.calculateMac(macStructure, secretKey: macKey);
    return listEquals(calculatedMac.bytes, deviceMac.mac!);
  } else {
    return response.documents!.first.deviceSigned.deviceSignature!.verify(
        SignatureGenerator.get(sDeviceKey),
        externalPayload: encDevAuth);
  }
}

Future<DeviceSignedObject> generateDeviceSignature(
    Map<String, Map<String, dynamic>> revealedData,
    String docType,
    SessionTranscript transcript,
    CoseKey devicePrivateKey,
    {CoseKey? readerEphemeralKey}) async {
  var signedData = DeviceSignedObject(nameSpaces: revealedData);
  var deviceAuth = DeviceAuth(
      sessionTranscript: transcript,
      docType: docType,
      nameSpaceBytes: signedData.nameSpaceBytes);

  var encDevAuth = cborEncode(deviceAuth.toDeviceAuthBytes());

  if (readerEphemeralKey != null) {
    // we assume, we should generate Mac
    var keyAgreement = KeyAgreement(
        privateKey: devicePrivateKey, publicKey: readerEphemeralKey);
    var macSecret = await keyAgreement.generateSymmetricKey();

    final kdf = Hkdf(
      hmac: Hmac.sha256(),
      outputLength: 32,
    );

    final macKey = await kdf.deriveKey(
        secretKey: SecretKey(macSecret),
        nonce: cborEncode(transcript.toSessionTranscriptBytes()),
        info: utf8.encode('EMacKey'));

    var macStructure = CborList([
      CborString('MAC0'),
      CborBytes(cborEncode(CborMap({1: 5}
          .map((key, value) => MapEntry(CborValue(key), CborValue(value)))))),
      CborBytes([]),
      CborBytes(encDevAuth)
    ]);

    var macAlgo = Hmac.sha256();

    var calculatedMac =
        await macAlgo.calculateMac(cborEncode(macStructure), secretKey: macKey);
    signedData.deviceMac = CoseMac0(
        protected: CoseHeader(algorithm: CoseAlgorithm.hmac256),
        unprotected: CoseHeader(),
        mac: calculatedMac.bytes);

    return signedData;
  } else {
    var signer = SignatureGenerator.get(devicePrivateKey);
    var sig = CoseSign1(
        protected: CoseHeader(algorithm: signer.supportedCoseAlgorithm),
        unprotected: CoseHeader(),
        payload: null);
    sig.sign(signer, externalPayload: encDevAuth);
    signedData.deviceSignature = sig;
    return signedData;
  }
}
