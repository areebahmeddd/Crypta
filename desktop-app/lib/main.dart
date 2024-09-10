import 'dart:io';

import 'package:crypta/screens/home_page.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:window_manager/window_manager.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await windowManager.ensureInitialized();
  WindowOptions windowOptions = const WindowOptions(
    center: true,
  );
  windowManager.waitUntilReadyToShow(windowOptions, () async {
    await windowManager.show();
    await windowManager.focus();
  });
  if (Platform.isWindows) {
    windowManager.setMinimumSize(const Size(1000, 800));
  }
  runApp(const ProviderScope(child: MyApp()));
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'File Upload App',
      theme: theme,
      debugShowCheckedModeBanner: false,
      home: const HomePage(),
    );
  }
}

final theme = ThemeData().copyWith(
  scaffoldBackgroundColor: const Color.fromARGB(255, 238, 238, 238),
);
