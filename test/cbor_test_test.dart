import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';
import 'package:iso_mdoc/iso_mdoc.dart';
import 'package:test/test.dart';

import '../example/example_keys.dart';
import 'data.dart';

void main() {
  test('generate SessionTranscript', () {
    var stb = cborDecode(hex.decode(sessionTranscriptBytes)) as CborBytes;
    var stbEnc = cborDecode(stb.bytes) as CborList;
    var devEng = DeviceEngagement.fromCbor((stbEnc.first as CborBytes).bytes);
    var se = SessionEstablishment.fromCbor(sessionEsrablishment);

    var st = SessionTranscript(
        deviceEngagementBytes: devEng.toDeviceEngagementBytes(),
        keyBytes: se.eReaderKey.toCoseKeyBytes(),
        handover: Handover(
            handoverSelectMessage: hex.decode(handoverSelect),
            handoverRequestMessage: hex.decode(handoverRequest)));

    var gen = hex
        .encode(Uint8List.fromList(cborEncode(st.toSessionTranscriptBytes())));
    expect(gen.toLowerCase(), sessionTranscriptBytes);
  });

  test('encrypt/Decrypt with example Data', () async {
    var deviceEncryptor = SessionEncryptor(
        mdocRole: MdocRole.mdocHolder,
        myPrivateKey: device,
        otherPublicKey: reader);
    await deviceEncryptor.generateKeys(hex.decode(sessionTranscriptBytes));
    expect(deviceEncryptor.decryptionKey, isNotNull);
    expect(deviceEncryptor.encryptionKey, isNotNull);

    var readerEncryptor = SessionEncryptor(
        mdocRole: MdocRole.mdocReader,
        myPrivateKey: reader,
        otherPublicKey: device);
    await readerEncryptor.generateKeys(hex.decode(sessionTranscriptBytes));
    expect(readerEncryptor.decryptionKey, isNotNull);
    expect(readerEncryptor.encryptionKey, isNotNull);

    var dataToEncrypt = hex.decode(mdocRequestHex);

    var selfEncryptedRequest = await readerEncryptor.encrypt(dataToEncrypt);
    var cleartext = await deviceEncryptor.decrypt(selfEncryptedRequest);
    expect(dataToEncrypt, cleartext);

    var request = DeviceRequest.fromCbor(cleartext);
    expect(
        verifyDocRequestSignature(request.docRequests.first,
            SessionTranscript.fromCbor(sessionTranscriptBytes)),
        isTrue);

    var selfEncryptedResponse =
        await deviceEncryptor.encrypt(hex.decode(response));
    var data = SessionData.fromCbor(hex.decode(sessionData));
    expect(selfEncryptedResponse, data.encryptedData);

    var cleartext2 = await readerEncryptor.decrypt(data.encryptedData!);

    expect(
        await verifyDeviceResponse(DeviceResponse.fromCbor(cleartext2),
            SessionTranscript.fromCbor(sessionTranscriptBytes),
            readerPrivateKey: reader),
        isTrue);
  });

  test('verify given mso', () {
    var decoded = hex.decode(response);
    var asMap = cbor.decode(decoded);

    var doc = (((asMap as CborMap)[CborValue('documents')] as CborList).first
        as CborMap)[CborValue('issuerSigned')];
    var iss = IssuerSignedObject.fromCbor(doc);

    expect(verifyMso(iss), isTrue);
  });

  test('whole Process with signature, fixed Holder curve', () async {
    var curves = [CoseCurve.p256, CoseCurve.p384, CoseCurve.p521];

    for (var c in curves) {
      await _runPresentationProcess(c, CoseCurve.p256, false);
    }
  });

  test('whole Process with signature, varying Holder curve', () async {
    var curves = [
      CoseCurve.p256,
      CoseCurve.p384,
      CoseCurve.p521,
      CoseCurve.ed25519,
      CoseCurve.brainpoolP256r1,
      CoseCurve.brainpoolP384r1,
      CoseCurve.brainpoolP320r1,
      CoseCurve.brainpoolP512r1
    ];

    for (var c in curves) {
      await _runPresentationProcess(CoseCurve.p256, c, false);
    }
  });

  test('whole Process with mac', () async {
    var curves = [
      CoseCurve.p256,
      CoseCurve.p384,
      CoseCurve.p521,
      CoseCurve.x25519
    ];

    for (var c in curves) {
      await _runPresentationProcess(c, c, true);
    }
  });
}

_runPresentationProcess(
    int curveEphemeral, int curveHolder, bool useMac) async {
  // ----- MDoc-Holder -------
  // Generate Ephemeral Key. Feel free to experiment with the used curve
  var deviceEphemeralCosePriv = CoseKey.generate(curveEphemeral);
  var deviceEphemeralCosePub = deviceEphemeralCosePriv.toPublicKey();

  // Generate DeviceEngagement
  var bleEngagement = DeviceEngagement(
      security: Security(
          deviceKeyBytes: deviceEphemeralCosePub.toCoseKeyBytes().bytes),
      deviceRetrievalMethods: [
        DeviceRetrievalMethod(
            type: 2,
            options: BLEOptions(
                supportPeripheralServerMode: false,
                supportCentralClientMode: true,
                centralClientModeId: [1, 4, 8, 0]))
      ]);

  // Encode for Qr-Code
  var qrData = bleEngagement.toUri();

  // ----- MDOC - Reader ------

  // decode Engagement
  var decodedEngagement = DeviceEngagement.fromUri(qrData);

  // check used Curve and generate Ephemeral Key
  var readerEphemeralCosePriv =
      CoseKey.generate(decodedEngagement.security.deviceKey!.crv!);
  var readerEphemeralCosePub = readerEphemeralCosePriv.toPublicKey();

  // Generate SessionTranscript
  var transcript = SessionTranscript(
      deviceEngagementBytes: decodedEngagement.toDeviceEngagementBytes(),
      keyBytes: readerEphemeralCosePub.toCoseKeyBytes());

  // Generate ItemsRequest
  var items = ItemsRequest(docType: 'docType', nameSpaces: {
    'org.iso.18013.5.1': {'family_name': true}
  });

  // Generate Reader-Auth. Feel free to also use the other provided certificates
  var unprotected = CoseHeader(x509chain: base64Decode(readerCertEd25519));
  var protected = CoseHeader(algorithm: CoseAlgorithm.edDSA);

  var cs = CoseSign1(
    protected: protected,
    unprotected: unprotected,
    payload: null,
  );

  var readerAuth = ReaderAuth(
      sessionTranscript: transcript,
      itemsRequestBytes: items.toItemsRequestBytes());

  var enc = CborBytes(cborEncode(readerAuth.toReaderAuthBytes()));
  // If you try other certificates, change the used key according to used certificate
  cs.sign(SignatureGenerator.get(readerKeyEd25519), externalPayload: enc);

  // Generate Request
  var request = DeviceRequest(
      docRequests: [DocRequest(itemsRequest: items, readerAuthSignature: cs)]);

  // Encrypt Request
  var readerEncryptor = SessionEncryptor(
      mdocRole: MdocRole.mdocReader,
      myPrivateKey: readerEphemeralCosePriv,
      otherPublicKey: decodedEngagement.security.deviceKey!);
  await readerEncryptor
      .generateKeys(cborEncode(transcript.toSessionTranscriptBytes()));
  var requestCipher = await readerEncryptor.encrypt(request.toEncodedCbor());

  // Generate SessionEstablishment
  var establishment = SessionEstablishment(
      eReaderKey: readerEphemeralCosePub, encryptedRequest: requestCipher);
  var encodedEstablishment = establishment.toCbor();

  // ---- MDoc - Holder

  // Decrypt Request
  var decodedEstablishment =
      SessionEstablishment.fromCbor(encodedEstablishment);
  var transcriptHolder = SessionTranscript(
      deviceEngagementBytes: bleEngagement.toDeviceEngagementBytes(),
      keyBytes: decodedEstablishment.eReaderKey.toCoseKeyBytes());
  var holderEncryptor = SessionEncryptor(
      mdocRole: MdocRole.mdocHolder,
      myPrivateKey: deviceEphemeralCosePriv,
      otherPublicKey: decodedEstablishment.eReaderKey);
  await holderEncryptor
      .generateKeys(cborEncode(transcriptHolder.toSessionTranscriptBytes()));

  var decryptedRequest =
      await holderEncryptor.decrypt(decodedEstablishment.encryptedRequest);
  var decodedRequest = DeviceRequest.fromCbor(decryptedRequest);

  // Check Signature
  expect(
      verifyDocRequestSignature(
          decodedRequest.docRequests.first, transcriptHolder),
      isTrue);

  // Search Credential (or generate ;) )
  var givenName = IssuerSignedItem(
      digestId: 1,
      dataElementIdentifier: 'given_name',
      dataElementValue: 'Max');
  var familyName = IssuerSignedItem(
      digestId: 2,
      dataElementIdentifier: 'family_name',
      dataElementValue: 'Mustermann');
  var birthDate = IssuerSignedItem(
      digestId: 3,
      dataElementIdentifier: 'birth_date',
      dataElementValue: DateTime(1992, 3, 15).toUtc());
  var issueDate = IssuerSignedItem(
      digestId: 4,
      dataElementIdentifier: 'issue_date',
      dataElementValue: DateTime.now().toUtc());
  var expiryDate = IssuerSignedItem(
      digestId: 5,
      dataElementIdentifier: 'expiry_date',
      dataElementValue: DateTime.now().add(Duration(days: 365)).toUtc());

  var holderKey = CoseKey.generate(curveHolder);

  var sig = await buildMso(
      SignatureGenerator.get(issuerP521Key),
      issuerP521Cert,
      {
        'org.iso.18013.5.1': [
          givenName,
          familyName,
          birthDate,
          issueDate,
          expiryDate
        ]
      },
      'SHA-256',
      holderKey.toPublicKey(),
      'docType');

  expect(verifyMso(sig), isTrue);
  var c = sig.toCbor();

  var i = IssuerSignedObject.fromCbor(c);
  var m = MobileSecurityObject.fromCbor(i.issuerAuth.payload);

  Map<String, List<IssuerSignedItem>> revealedData =
      getDataToReveal(decodedRequest.docRequests.first.itemsRequest, i);

  i.items = revealedData;

  // Generate DeviceAuth (Mac / Signature)
  var signedData = await generateDeviceSignature({},
      decodedRequest.docRequests.first.itemsRequest.docType,
      transcriptHolder,
      holderKey,
      readerEphemeralKey: useMac ? decodedEstablishment.eReaderKey : null);
  var docToSend =
      Document(docType: m.docType, issuerSigned: i, deviceSigned: signedData);

  // Generate Response
  var response = DeviceResponse(status: 1, documents: [docToSend]);

  // Encrypt Response
  var encryptedResponse =
      await holderEncryptor.encrypt(response.toEncodedCbor());
  var responseToSend = SessionData(encryptedData: encryptedResponse).toCbor();

  // ---- MDoc - Reader -----
  // Decrypt Response
  var responseData = SessionData.fromCbor(responseToSend);
  var decryptedResponse =
      await readerEncryptor.decrypt(responseData.encryptedData!);
  var decodedResponse = DeviceResponse.fromCbor(decryptedResponse);

  // Verify Response
  expect(
      await verifyDeviceResponse(decodedResponse, transcript,
          readerPrivateKey: readerEphemeralCosePriv),
      isTrue);
}
