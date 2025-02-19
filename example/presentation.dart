import 'dart:convert';

import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';
import 'package:iso_mdoc/iso_mdoc.dart';

import 'example_keys.dart';

void main() async {
  // ----- MDoc-Holder -------
  // Generate Ephemeral Key. Feel free to experiment with the used curve
  var deviceEphemeralCosePriv = CoseKey.generate(CoseCurve.x25519);
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

  print(hex.encode(bleEngagement.toEncodedCbor()));

  // Encode for Qr-Code
  var qrData = bleEngagement.toUri();

  // ----- MDOC - Reader ------

  // decode Engagement
  var decodedEngagement = DeviceEngagement.fromUri(qrData);

  // check used Curve and generate Ephemeral Key
  var readerEphemeralCosePriv =
      CoseKey.generate(decodedEngagement.security.deviceKey!.crv!);
  print(hex.encode(readerEphemeralCosePriv.toEncodedCbor()));
  var readerEphemeralCosePub = readerEphemeralCosePriv.toPublicKey();

  // Generate SessionTranscript
  var transcript = SessionTranscript(
      deviceEngagementBytes: decodedEngagement.toDeviceEngagementBytes(),
      keyBytes: readerEphemeralCosePub.toCoseKeyBytes());

  // Generate ItemsRequest
  var items = ItemsRequest(docType: MobileDriversLicense.docType, nameSpaces: {
    MobileDriversLicense.namespace: {
      MobileDriversLicense.familyNameIdentifier: true
    }
  });

  // Generate Reader-Auth (Optional). Feel free to also use the other provided certificates
  var unprotected =
      CoseHeader(x509chain: [base64Decode(readerCertBrainpoolP256r1).toList()]);
  var protected = CoseHeader(algorithm: CoseAlgorithm.es256);

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
  await cs.sign(SignatureGenerator.get(readerKeyBrainpoolP256r1),
      externalPayload: enc);

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
  for (var docRequest in decodedRequest.docRequests) {
    if (docRequest.readerAuthSignature != null) {
      print(
          '''Is DocRequest correct: ${verifyDocRequestSignature(docRequest, transcriptHolder)}''');
    } else {
      print('No reader signature');
    }
  }

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
      dataElementValue: FullDate(1992, 3, 15));
  var issueDate = IssuerSignedItem(
      digestId: 4,
      dataElementIdentifier: 'issue_date',
      dataElementValue: FullDate.fromDateTime(DateTime.now()));
  var expiryDate = IssuerSignedItem(
      digestId: 5,
      dataElementIdentifier: 'expiry_date',
      dataElementValue:
          FullDate.fromDateTime(DateTime.now().add(Duration(days: 365))));

  var holderKey = CoseKey.generate(CoseCurve.x25519);

  var sig = await buildMso(
      SignatureGenerator.get(issuerP521Key),
      issuerP521Cert,
      {
        MobileDriversLicense.namespace: [
          givenName,
          familyName,
          birthDate,
          issueDate,
          expiryDate
        ]
      },
      'SHA-256',
      holderKey.toPublicKey(),
      MobileDriversLicense.docType);

  print('Is issued credential correct: ${verifyMso(sig)}');
  var c = sig.toCbor();

  var i = IssuerSignedObject.fromCbor(c);
  var m = MobileSecurityObject.fromCbor(i.issuerAuth.payload);

  Map<String, List<IssuerSignedItem>> revealedData =
      getDataToReveal(decodedRequest.docRequests.first.itemsRequest, i);
  print('Data to reveal: $revealedData');
  i.items = revealedData;

  // Generate DeviceAuth (Mac / Signature)
  // var signer = SignatureGenerator.get(holderKey);
  var keyAgreement = KeyAgreement.get(
      publicKey: decodedEstablishment.eReaderKey, privateKey: holderKey);
  var signedData = await generateDeviceSignature({},
      decodedRequest.docRequests.first.itemsRequest.docType, transcriptHolder,
      // signer: signer,
      keyAgreement: keyAgreement);
  var docToSend =
      Document(docType: m.docType, issuerSigned: i, deviceSigned: signedData);

  // Generate Response
  var response = DeviceResponse(status: 1, documents: [docToSend]);

  // Encrypt Response
  var encryptedResponse =
      await holderEncryptor.encrypt(response.toEncodedCbor());
  var responseToSend = SessionData(encryptedData: encryptedResponse).toCbor();
  print(hex
      .encode(SessionData(encryptedData: encryptedResponse).toEncodedCbor()));

  // ---- MDoc - Reader -----
  // Decrypt Response
  var responseData = SessionData.fromCbor(responseToSend);
  var decryptedResponse =
      await readerEncryptor.decrypt(responseData.encryptedData!);
  var decodedResponse = DeviceResponse.fromCbor(decryptedResponse);

  // Verify Response
  print(
      ''' Is Device Response correct: ${await verifyDeviceResponse(decodedResponse, transcript, readerPrivateKey: readerEphemeralCosePriv)}''');

  print(
      'Received Data: ${decodedResponse.documents!.first.issuerSigned.items}');
  // Session Termination
}
