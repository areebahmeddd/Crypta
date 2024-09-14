import 'package:flutter_riverpod/flutter_riverpod.dart';

class FilesMetadataNotifier extends StateNotifier<List<Map<String, String>>> {
  FilesMetadataNotifier() : super([]);

  void addFileMetadata(Map<String, String> fileMetadata) {
    state = [...state, fileMetadata];
  }

  void removeFileMetadata(String filePath) {
    state = state.where((element) => element['path'] != filePath).toList();
  }

  void clearFilesMetadata() {
    state = [];
  }
}

final filesMetadataProvider =
    StateNotifierProvider<FilesMetadataNotifier, List<Map<String, String>>>(
        (ref) => FilesMetadataNotifier());