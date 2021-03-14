import 'package:hash_identifier/hash_identifier.dart';
import 'package:test/test.dart';

void main() {
  group('Identify', () {
    test('Identifies simple crc-16', () {
      var prototypes = getDefaultPrototypes();

      expect(Identify('abcd', prototypes).map((hm) => getName(hm.id)),
          equals(['CRC-16', 'CRC-16-CCITT', 'FCS-16', 'Cisco Type 7']));
    });
  });
}
