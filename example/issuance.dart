import 'dart:math';

import 'package:iso_mdoc/iso_mdoc.dart';

import 'example_keys.dart';

void main() async {
  //---- 1 Issue using basic classes -----
  // The claims to include
  var random = Random.secure();
  var givenName = IssuerSignedItem(
      digestId: random.nextInt(2 ^ 31 - 1),
      dataElementIdentifier: 'given_name',
      dataElementValue: 'Max');
  var familyName = IssuerSignedItem(
      digestId: random.nextInt(2 ^ 31 - 1),
      dataElementIdentifier: 'family_name',
      dataElementValue: 'Mustermann');
  var birthDate = IssuerSignedItem(
      digestId: random.nextInt(2 ^ 31 - 1),
      dataElementIdentifier: 'birth_date',
      dataElementValue: FullDate(1992, 3, 15));

  // sign the claims
  var signed = await buildMso(
      SignatureGenerator.get(issuerP521Key),
      issuerP521Cert,
      {
        MobileDriversLicense.namespace: [givenName, familyName, birthDate]
      },
      'SHA-256',
      CoseKey.generate(CoseCurve.p521),
      MobileDriversLicense.docType);

  print(signed);

  // The IssuerSignedObject is cbor-encoded and transported to the holder,
  // e.g. using OpenId-Connect for Verifiable Credentials
  // (Issuance is not part of ISO/IEC 18013-5)
  var encodedIssuerSignedObject = signed.toCbor();

  // The holder can decode the signed data and verify the signature
  var decodedIssuerSignedObject =
      IssuerSignedObject.fromCbor(encodedIssuerSignedObject);
  var m = MobileSecurityObject.fromCbor(
      decodedIssuerSignedObject.issuerAuth.payload);
  print(verifyMso(decodedIssuerSignedObject));

  print(m);

  //----- 2 Issue using predefined data classes -----
  var mdl = MobileDriversLicense(
      givenName: 'Max',
      familyName: 'Mustermann',
      birthDate: FullDate(1992, 3, 15));
  mdl.generateAgeOverNN([16, 18, 21, 65, 67]);

  var signed2 = await mdl.generateIssuerSignedObject(
      SignatureGenerator.get(issuerP521Key),
      issuerP521Cert,
      CoseKey.generate(CoseCurve.p521));

  var encodedIssuerSignedObject2 = signed2.toCbor();
  var decodedIssuerSignedObject2 =
      IssuerSignedObject.fromCbor(encodedIssuerSignedObject2);
  print(verifyMso(decodedIssuerSignedObject));

  var decodedMdl = MobileDriversLicense.fromIssuerSignedItems(
      decodedIssuerSignedObject2.items);
  print(decodedMdl);
}
