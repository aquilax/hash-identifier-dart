# Library for identifying different hashes

[![Build Status](https://travis-ci.org/aquilax/hash-identifier-dart.svg?branch=master)](https://travis-ci.org/aquilax/hash-identifier-dart)

This library in dart.pub: https://pub.dev/packages/hash_identifier

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
Go version [hash-identifier](https://github.com/aquilax/hash-identifier)