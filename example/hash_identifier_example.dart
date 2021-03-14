import 'package:hash_identifier/hash_identifier.dart';

void main() {
  var prototypes = getDefaultPrototypes();
  var candidates = Identify('abcd', prototypes);
  print(candidates);
}
