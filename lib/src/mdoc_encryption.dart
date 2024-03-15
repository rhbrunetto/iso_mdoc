import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'cose_objects.dart';
import 'crypto_generator.dart';

enum MdocRole { mdocHolder, mdocReader }

class SessionEncryptor {
  final algorithm = pc.GCMBlockCipher(pc.AESEngine());
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

    var hkdfReader = pc.HKDFKeyDerivator(pc.SHA256Digest());
    hkdfReader.init(pc.HkdfParameters(Uint8List.fromList(secret), 32,
        Uint8List.fromList(sessionTranscriptBytes), utf8.encode('SKReader')));
    var r = hkdfReader.process(Uint8List.fromList([]));

    var hkdfDevice = pc.HKDFKeyDerivator(pc.SHA256Digest());
    hkdfDevice.init(pc.HkdfParameters(Uint8List.fromList(secret), 32,
        Uint8List.fromList(sessionTranscriptBytes), utf8.encode('SKDevice')));
    var d = hkdfDevice.process(Uint8List.fromList([]));

    if (mdocRole == MdocRole.mdocReader) {
      encryptionKey = r.toList();
      decryptionKey = d.toList();
    } else {
      encryptionKey = d.toList();
      decryptionKey = r.toList();
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

    if (decryptionKey == null) {
      throw Exception(
          'No decryption Key generated. Use generateKeys() beforehand.');
    }

    algorithm.init(
        false,
        pc.AEADParameters(
          pc.KeyParameter(Uint8List.fromList(decryptionKey!)),
          128,
          iv,
          Uint8List(0),
        ));

    counterDecrypt++;

    return algorithm.process(Uint8List.fromList(encryptedData)).toList();
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

    algorithm.init(
        true,
        pc.AEADParameters(
          pc.KeyParameter(Uint8List.fromList(encryptionKey!)),
          128,
          iv,
          Uint8List(0),
        ));

    counterEncrypt++;

    return algorithm.process(Uint8List.fromList(data));
  }
}
