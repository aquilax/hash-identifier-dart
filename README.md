# Library for identifying different hashes

## Usage

A simple usage example:

```dart
import 'package:hash_identifier/hash_identifier.dart';

main() {
  var prototypes = getDefaultPrototypes();
  var candidates = Identify("abcd", prototypes);
  print(candidates);
}
```

Dart port of [hashId](https://pypi.org/project/hashID/)
