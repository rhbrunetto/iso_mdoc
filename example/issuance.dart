import 'package:iso_mdoc/iso_mdoc.dart';

import 'example_keys.dart';

void main() async {
  // The claims to include
  var givenName = IssuerSignedItem(
      digestId: 1,
      dataElementIdentifier: 'given_name',
      dataElementValue: 'Max');
  var familyName = IssuerSignedItem(
      digestId: 2,
      dataElementIdentifier: 'family_name',
      dataElementValue: 'Mustermann');

  // sign the claims
  var signed = await buildMso(
      SignatureGenerator.get(issuerP521Key),
      issuerP521Cert,
      {
        mdlNamespace: [givenName, familyName]
      },
      'SHA-256',
      CoseKey.generate(CoseCurve.p521),
      mdlDocType);

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
}
