import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';

class FilesProviderNotifier extends StateNotifier<List<File>> {
  FilesProviderNotifier() : super([]);

  void addFile(File file) {
    state = [...state, file];
  }

  void removeFile(String filePath) {
    state = state.where((element) => element.path != filePath).toList();
  }

  void clearFiles() {
    state = [];
  }
}

final filesProvider = StateNotifierProvider<FilesProviderNotifier, List<File>>(
    (ref) => FilesProviderNotifier());
