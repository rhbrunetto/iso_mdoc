import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'cose_objects.dart';
import 'crypto_generator.dart';

enum MdocRole { mdocHolder, mdocReader }

/// Encrypt and decrypt all messages in one session
class SessionEncryptor {
  final _algorithm = pc.GCMBlockCipher(pc.AESEngine());
  final MdocRole _mdocRole;
  int _counterEncrypt, _counterDecrypt;
  // Ephemeral Keys
  final CoseKey _myPrivateKey, _otherPublicKey;
  List<int>? _encryptionKey, _decryptionKey;

  SessionEncryptor(
      {required MdocRole mdocRole,
      required CoseKey myPrivateKey,
      required CoseKey otherPublicKey})
      : _otherPublicKey = otherPublicKey,
        _myPrivateKey = myPrivateKey,
        _mdocRole = mdocRole,
        _counterDecrypt = 1,
        _counterEncrypt = 1;

  /// Derive symmetric keys to encrypt and decrypt messages.
  ///
  /// Call this method before starting encrypting or decryption messages.
  Future<void> generateKeys(List<int> sessionTranscriptBytes) async {
    var keyAgreement =
        KeyAgreement.get(privateKey: _myPrivateKey, publicKey: _otherPublicKey);
    var secret = await keyAgreement.generateSymmetricKey();

    var hkdfReader = pc.HKDFKeyDerivator(pc.SHA256Digest());
    hkdfReader.init(pc.HkdfParameters(Uint8List.fromList(secret), 32,
        Uint8List.fromList(sessionTranscriptBytes), utf8.encode('SKReader')));
    var r = hkdfReader.process(Uint8List.fromList([]));

    var hkdfDevice = pc.HKDFKeyDerivator(pc.SHA256Digest());
    hkdfDevice.init(pc.HkdfParameters(Uint8List.fromList(secret), 32,
        Uint8List.fromList(sessionTranscriptBytes), utf8.encode('SKDevice')));
    var d = hkdfDevice.process(Uint8List.fromList([]));

    if (_mdocRole == MdocRole.mdocReader) {
      _encryptionKey = r.toList();
      _decryptionKey = d.toList();
    } else {
      _encryptionKey = d.toList();
      _decryptionKey = r.toList();
    }
  }

  /// Decrypts the message in [encryptedData]
  Future<List<int>> decrypt(List<int> encryptedData) async {
    var iv = Uint8List.fromList([
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      _mdocRole == MdocRole.mdocReader ? 1 : 0,
      0,
      0,
      0,
      _counterDecrypt
    ]);

    if (_decryptionKey == null) {
      throw Exception(
          'No decryption Key generated. Use generateKeys() beforehand.');
    }

    _algorithm.init(
        false,
        pc.AEADParameters(
          pc.KeyParameter(Uint8List.fromList(_decryptionKey!)),
          128,
          iv,
          Uint8List(0),
        ));

    _counterDecrypt++;

    return _algorithm.process(Uint8List.fromList(encryptedData)).toList();
  }

  /// Encrypts the message in [data].
  Future<List<int>> encrypt(List<int> data) async {
    var iv = Uint8List.fromList([
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      _mdocRole == MdocRole.mdocReader ? 0 : 1,
      0,
      0,
      0,
      _counterEncrypt
    ]);

    if (_encryptionKey == null) {
      throw Exception(
          'No encryption Key generated. Use generateKeys() beforehand.');
    }

    _algorithm.init(
        true,
        pc.AEADParameters(
          pc.KeyParameter(Uint8List.fromList(_encryptionKey!)),
          128,
          iv,
          Uint8List(0),
        ));

    _counterEncrypt++;

    return _algorithm.process(Uint8List.fromList(data));
  }

  List<int>? get encryptionKey => _encryptionKey;

  List<int>? get decryptionKey => _decryptionKey;

  MdocRole get mdocRole => _mdocRole;
}
