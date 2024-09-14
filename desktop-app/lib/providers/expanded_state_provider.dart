import 'package:flutter_riverpod/flutter_riverpod.dart';

class ExpandedStateNotifier extends StateNotifier<List<bool>> {
  ExpandedStateNotifier(int length) : super(List.generate(length, (_) => false));

  void toggle(int index) {
    state = [
      for (int i = 0; i < state.length; i++)
        if (i == index) !state[i] else state[i],
    ];
  }
}

final expandedStateProvider = StateNotifierProvider.family<ExpandedStateNotifier, List<bool>, int>((ref, length) {
  return ExpandedStateNotifier(length);
});
