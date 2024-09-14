import 'package:flutter_riverpod/flutter_riverpod.dart';

class AnalysisProviderNotifer extends StateNotifier<Map<String, dynamic>> {
  AnalysisProviderNotifer() : super({});

  void saveAnalysis(Map<String, dynamic> analysis) {
    state = analysis;
  }

  void clearAnalysis() {
    state = {};
  }
}

final analysisProvider =
    StateNotifierProvider<AnalysisProviderNotifer, Map<String, dynamic>>(
        (ref) => AnalysisProviderNotifer());