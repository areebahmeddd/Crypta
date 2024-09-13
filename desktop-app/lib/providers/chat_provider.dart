import 'dart:convert';
import 'dart:developer';

import 'package:crypta/model/message.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:http/http.dart' as http;

class ChatsNotifier extends StateNotifier<List<dynamic>> {
  ChatsNotifier() : super([]);
  bool _isLoading = false;
  bool get isLoading => _isLoading;

  Future<Message?> getResponse(String prompt) async {
    try {
      _isLoading = true;
      state = [...state];
      String url = '';

      final response = await http.post(
        Uri.parse(url),
        body: json.encode(''),
        headers: {
          "Content-Type": "application/json",
        },
      );

      log('got response');

      if (response.statusCode == 200) {
        var data = json.decode(response.body);

        final result = data['response'];
        log(result);

        final chat = Message(text: result, isUser: false);

        state = [...state, chat];
        _isLoading = false;
        state = [...state];
        return chat;
      } else {
        log(response.body);
        return null;
      }
    } catch (e) {
      log(e.toString());
      return null;
    }
  }
}

final chatsProvider = StateNotifierProvider<ChatsNotifier, List<dynamic>>(
    (ref) => ChatsNotifier());
