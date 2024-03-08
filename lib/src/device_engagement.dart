import 'dart:convert';

import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';

import 'cose_objects.dart';
import 'private_util.dart';

class DeviceEngagement {
  String version;
  Security security;
  List<DeviceRetrievalMethod>? deviceRetrievalMethods;
  ServerRetrievalMethod? serverRetrievalMethods;
  // reserved for future use
  dynamic protocolInfo;
  Map<int, dynamic>? additionalProperties;
  CborBytes? _deviceEngagementBytes;

  DeviceEngagement(
      {this.version = '1.0',
      required this.security,
      this.deviceRetrievalMethods,
      this.serverRetrievalMethods,
      this.protocolInfo,
      this.additionalProperties,
      CborBytes? bytes})
      : _deviceEngagementBytes = bytes;

  factory DeviceEngagement.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    CborBytes? bytes;
    if (cborData is String) {
      bytes = CborBytes(hex.decode(cborData), tags: [24]);
    } else if (cborData is List<int>) {
      bytes = CborBytes(cborData, tags: [24]);
    }
    var asMap = CborMap.of(decoded as CborMap);

    CborString version = asMap.remove(CborSmallInt(0)) as CborString;
    if (version != CborString('1.0')) {
      throw Exception(
          'version $version is not supported. Only support version 1.0');
    }
    Security sec = Security.fromCbor(asMap.remove(CborSmallInt(1)));
    var device = asMap.remove(CborSmallInt(2)) as CborList?;
    var server = asMap.remove(CborSmallInt(3));
    CborValue? protocolInfoTmp = asMap.remove(CborSmallInt(4));

    return DeviceEngagement(
        security: sec,
        deviceRetrievalMethods:
            device?.map((e) => DeviceRetrievalMethod.fromCbor(e)).toList(),
        serverRetrievalMethods:
            server != null ? ServerRetrievalMethod.fromCbor(server) : null,
        protocolInfo: protocolInfoTmp?.toObject(),
        additionalProperties: asMap.isNotEmpty
            ? asMap.map((key, value) =>
                MapEntry((key as CborSmallInt).value, value.toObject()))
            : null,
        bytes: bytes);
  }

  factory DeviceEngagement.fromUri(String uri) {
    if (!uri.startsWith('mdoc:')) {
      throw Exception('Usi must start with mdoc:');
    }
    return DeviceEngagement.fromCbor(
        base64Decode(addPaddingToBase64(uri.replaceAll('mdoc:', ''))));
  }

  CborBytes toDeviceEngagementBytes() {
    return _deviceEngagementBytes ?? CborBytes(toEncodedCbor(), tags: [24]);
  }

  CborMap toCbor() {
    var data = {
      CborSmallInt(0): CborString(version),
      CborSmallInt(1): security.toCbor()
    };

    if (deviceRetrievalMethods != null && deviceRetrievalMethods!.isNotEmpty) {
      data[CborSmallInt(2)] = CborList(deviceRetrievalMethods!
          .map((e) => cborDecode(e.toCbor()) as CborList)
          .toList());
    }

    if (serverRetrievalMethods != null) {
      data[CborSmallInt(3)] =
          cborDecode(serverRetrievalMethods!.toCbor()) as CborMap;
    }

    if (protocolInfo != null) {
      data[CborSmallInt(4)] = CborValue(protocolInfo);
    }

    if (additionalProperties != null && additionalProperties!.isNotEmpty) {
      data.addAll(additionalProperties!
          .map((key, value) => MapEntry(CborSmallInt(key), CborValue(value))));
    }

    return CborMap(data);
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  String toUri() {
    return 'mdoc:${removePaddingFromBase64(base64UrlEncode(toEncodedCbor()))}';
  }

  @override
  String toString() {
    return 'DeviceEngagement{version: $version, security: $security, deviceRetrievalMethods: $deviceRetrievalMethods, serverRetrievalMethods: $serverRetrievalMethods, protocolInfo: $protocolInfo, additionalProperties: $additionalProperties}';
  }
}

class Security {
  int cipherSuiteIdentifier;
  List<int> deviceKeyBytes;
  CoseKey? deviceKey;

  Security(
      {this.cipherSuiteIdentifier = 1,
      required this.deviceKeyBytes,
      this.deviceKey});

  factory Security.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    var asList = decoded as CborList;

    var cipherSuiteId = (asList.first as CborSmallInt).value;
    if (cipherSuiteId != 1) {
      throw Exception(
          'Unsupported CipherSuite: $cipherSuiteId. Only CipherSuite 1 (as per Iso/IEC 18013-5 section 9.1.5.2) is supported');
    }

    return Security(
        cipherSuiteIdentifier: (asList.first as CborSmallInt).value,
        deviceKeyBytes: (asList.last as CborBytes).bytes,
        deviceKey: CoseKey.fromCbor((asList.last as CborBytes).bytes));
  }

  CborList toCbor() {
    return CborList([
      CborSmallInt(cipherSuiteIdentifier),
      CborBytes(deviceKeyBytes, tags: [24])
    ]);
  }

  List<int> toEncodedCbor() {
    return cborEncode(toCbor());
  }

  @override
  String toString() {
    return 'Security{cipherSuiteIdentifier: $cipherSuiteIdentifier, deviceKeyBytes: $deviceKeyBytes, deviceKey: $deviceKey}';
  }
}

// type: 1 = NFC, 2 = BLE, 3 = WiFi Aware
class DeviceRetrievalMethod {
  int type;
  int version;
  RetrievalOptions options;

  DeviceRetrievalMethod(
      {required this.type, this.version = 1, required this.options});

  factory DeviceRetrievalMethod.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    var asList = decoded as CborList;

    var type = (asList.first as CborSmallInt).value;
    var version = (asList[1] as CborSmallInt).value;

    if (version != 1) {
      throw Exception(
          'Unsupported version $version for DeviceRetrievalMethod. Only support version 1');
    }

    return DeviceRetrievalMethod(
        type: type,
        options: RetrievalOptions.fromCborAndType(type, asList.last));
  }

  List<int> toCbor() {
    return cborEncode(CborList([
      CborSmallInt(type),
      CborSmallInt(version),
      cborDecode(options.toCbor()) as CborMap
    ]));
  }

  @override
  String toString() {
    return 'DeviceRetrievalMethod{type: $type, version: $version, options: $options}';
  }
}

abstract class RetrievalOptions {
  List<int> toCbor();

  RetrievalOptions();

  factory RetrievalOptions.fromCborAndType(int type, dynamic cborData) {
    switch (type) {
      case 1:
        return NfcOptions.fromCbor(cborData);
      case 2:
        return BLEOptions.fromCbor(cborData);
      case 3:
        return WifiOptions.fromCbor(cborData);
      default:
        throw Exception('Unknown type $type');
    }
  }
}

class WifiOptions extends RetrievalOptions {
  String? passPhraseInfo;
  int? channelInfoOperatingClass;
  int? channelInfoChannelNumber;
  List<int>? bandInfo;

  WifiOptions(
      {this.passPhraseInfo,
      this.channelInfoOperatingClass,
      this.channelInfoChannelNumber,
      this.bandInfo});

  factory WifiOptions.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    var asMap = decoded as CborMap;

    return WifiOptions(
        passPhraseInfo: (asMap[CborSmallInt(0)] as CborString?)?.toString(),
        channelInfoOperatingClass:
            (asMap[CborSmallInt(1)] as CborSmallInt?)?.value,
        channelInfoChannelNumber:
            (asMap[CborSmallInt(2)] as CborSmallInt?)?.value,
        bandInfo: (asMap[CborSmallInt(3)] as CborBytes?)?.bytes);
  }

  @override
  List<int> toCbor() {
    var m = <CborSmallInt, CborValue>{};

    if (passPhraseInfo != null) {
      m[CborSmallInt(0)] = CborString(passPhraseInfo!);
    }
    if (channelInfoOperatingClass != null) {
      m[CborSmallInt(1)] = CborSmallInt((channelInfoOperatingClass!));
    }
    if (channelInfoChannelNumber != null) {
      m[CborSmallInt(2)] = CborSmallInt((channelInfoChannelNumber!));
    }
    if (bandInfo != null) {
      m[CborSmallInt(3)] = CborBytes(bandInfo!);
    }

    return cborEncode(CborMap(m));
  }

  @override
  String toString() {
    return 'WifiOptions{passPhraseInfo: $passPhraseInfo, channelInfoOperatingClass: $channelInfoOperatingClass, channelInfoChannelNumber: $channelInfoChannelNumber, bandInfo: $bandInfo}';
  }
}

class BLEOptions extends RetrievalOptions {
  bool supportPeripheralServerMode;
  bool supportCentralClientMode;
  List<int>? peripheralModeId;
  List<int>? centralClientModeId;
  List<int>? peripheralModeDeviceAddress;

  BLEOptions(
      {required this.supportPeripheralServerMode,
      required this.supportCentralClientMode,
      this.peripheralModeId,
      this.centralClientModeId,
      this.peripheralModeDeviceAddress});

  factory BLEOptions.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    var asMap = decoded as CborMap;

    return BLEOptions(
        supportPeripheralServerMode: (asMap[CborSmallInt(0)] as CborBool).value,
        supportCentralClientMode: (asMap[CborSmallInt(1)] as CborBool).value,
        peripheralModeId: (asMap[CborSmallInt(10)] as CborBytes?)?.bytes,
        centralClientModeId: (asMap[CborSmallInt(11)] as CborBytes?)?.bytes,
        peripheralModeDeviceAddress:
            (asMap[CborSmallInt(20)] as CborBytes?)?.bytes);
  }

  @override
  List<int> toCbor() {
    var m = <CborSmallInt, CborValue>{
      CborSmallInt(0): CborBool(supportPeripheralServerMode),
      CborSmallInt(1): CborBool(supportCentralClientMode)
    };

    if (peripheralModeId != null) {
      m[CborSmallInt(10)] = CborBytes(peripheralModeId!);
    }
    if (centralClientModeId != null) {
      m[CborSmallInt(11)] = CborBytes(centralClientModeId!);
    }
    if (peripheralModeDeviceAddress != null) {
      m[CborSmallInt(20)] = CborBytes(peripheralModeDeviceAddress!);
    }

    return cborEncode(CborMap(m));
  }

  @override
  String toString() {
    return 'BLEOptions{supportPeripheralServerMode: $supportPeripheralServerMode, supportCentralClientMode: $supportCentralClientMode, peripheralModeId: $peripheralModeId, centralClientModeId: $centralClientModeId, peripheralModeDeviceAddress: $peripheralModeDeviceAddress}';
  }
}

class NfcOptions extends RetrievalOptions {
  int maxLengthCommand;
  int maxLengthResponse;

  NfcOptions({required this.maxLengthCommand, required this.maxLengthResponse});

  factory NfcOptions.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    var asMap = decoded as CborMap;

    return NfcOptions(
        maxLengthCommand: (asMap[CborSmallInt(0)] as CborSmallInt).value,
        maxLengthResponse: (asMap[CborSmallInt(1)] as CborSmallInt).value);
  }

  @override
  List<int> toCbor() {
    return cborEncode(CborMap({
      CborSmallInt(0): CborSmallInt(maxLengthCommand),
      CborSmallInt(1): CborSmallInt(maxLengthResponse)
    }));
  }

  @override
  String toString() {
    return 'NfcOptions{maxLengthCommand: $maxLengthCommand, maxLengthResponse: $maxLengthResponse}';
  }
}

class ServerRetrievalMethod {
  ApiInfo? webApi;
  ApiInfo? oidc;

  ServerRetrievalMethod({this.webApi, this.oidc});

  factory ServerRetrievalMethod.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    var asMap = decoded as CborMap;

    return ServerRetrievalMethod(
        webApi: asMap.containsKey(CborString('webApi'))
            ? ApiInfo.fromCbor(asMap[CborString('webApi')])
            : null,
        oidc: asMap.containsKey(CborString('oidc'))
            ? ApiInfo.fromCbor(asMap[CborString('oidc')])
            : null);
  }

  List<int> toCbor() {
    var m = <CborString, CborValue>{};
    if (webApi != null) {
      m[CborString('webApi')] = cborDecode(webApi!.toCbor());
    }
    if (oidc != null) {
      m[CborString('oidc')] = cborDecode(oidc!.toCbor());
    }

    return cborEncode(CborMap(m));
  }

  @override
  String toString() {
    return 'ServerRetrievalMethod{webApi: $webApi, oidc: $oidc}';
  }
}

class ApiInfo {
  int version;
  String issuerUrl;
  String serverRetrievalToken;

  ApiInfo(
      {required this.version,
      required this.issuerUrl,
      required this.serverRetrievalToken});

  factory ApiInfo.fromCbor(dynamic cborData) {
    assert(
        cborData is String || cborData is List<int> || cborData is CborValue);

    var decoded = cborData is CborValue
        ? cborData
        : cborDecode(cborData is String ? hex.decode(cborData) : cborData);
    var asList = decoded as CborList;

    return ApiInfo(
        version: (asList.first as CborSmallInt).value,
        issuerUrl: (asList[1] as CborString).toString(),
        serverRetrievalToken: (asList.last as CborString).toString());
  }

  List<int> toCbor() {
    return cborEncode(CborList([
      CborSmallInt(version),
      CborString(issuerUrl),
      CborString(serverRetrievalToken)
    ]));
  }

  @override
  String toString() {
    return 'ApiInfo{version: $version, issuerUrl: $issuerUrl, serverRetrievalToken: $serverRetrievalToken}';
  }
}
