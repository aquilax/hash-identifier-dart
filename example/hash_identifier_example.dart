import 'package:hash_identifier/hash_identifier.dart';

main() {
  var prototypes = getDefaultPrototypes();
  var candidates = Identify("abcd", prototypes);
  print(candidates);
}