import 'dart:developer';
import 'dart:io';

import 'package:crypta/providers/files_provider.dart';
import 'package:crypta/screens/dashboard_page.dart';
import 'package:crypta/utils/hexcolor.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:gap/gap.dart';

class UploadRulesPage extends ConsumerStatefulWidget {
  const UploadRulesPage({super.key});

  @override
  ConsumerState<UploadRulesPage> createState() {
    return _UploadRulesPageState();
  }
}

class _UploadRulesPageState extends ConsumerState<UploadRulesPage> {
  PlatformFile? selectedFile;
  Future<void> pickFile() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles();

    if (result != null) {
      setState(() {
        selectedFile = result.files.first;
        val = 0;
      });
    }
  }

  var val = 0;

  @override
  void initState() {
    super.initState();
    final files = ref.read(filesProvider);
    for (int i = 0; i < files.length; i++) {
      log(files[i].path);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Stack(
          children: [
            Center(
              child: Container(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    // Title
                    Container(
                      width: 600,
                      height: 550,
                      padding: const EdgeInsets.all(32),
                      decoration: const BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.all(
                          Radius.circular(10),
                        ),
                      ),
                      child: Column(
                        children: [
                          const Align(
                            alignment: Alignment.centerLeft,
                            child: Text(
                              'Upload YARA Rules',
                              style: TextStyle(
                                fontSize: 24,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                          const SizedBox(height: 30),
                          Container(
                            width: 500,
                            height: 200,
                            decoration: BoxDecoration(
                              border: Border.all(color: Colors.grey),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                const Icon(
                                  Icons.upload_rounded,
                                  size: 50,
                                  color: Colors.grey,
                                ),
                                const SizedBox(height: 8),
                                const Text(
                                  'Drag and drop a file here or',
                                  style: TextStyle(color: Colors.grey),
                                ),
                                TextButton(
                                  onPressed: pickFile,
                                  child: const Text(
                                    'Choose file',
                                    style: TextStyle(
                                      color: Colors.blue,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),

                          const SizedBox(height: 30),

                          // OR divider
                          const Text('--OR--'),

                          const SizedBox(height: 30),

                          // Default Rules
                          Padding(
                            padding: const EdgeInsets.only(left: 70),
                            child: Row(
                              mainAxisAlignment: MainAxisAlignment.start,
                              children: [
                                const Icon(
                                  Icons.insert_drive_file,
                                  size: 35,
                                  color: Colors.grey,
                                ),
                                const Gap(15),
                                Column(
                                  mainAxisAlignment: MainAxisAlignment.start,
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Row(
                                      children: [
                                        GestureDetector(
                                          onTap: () {
                                            setState(() {
                                              selectedFile = null;
                                              val == 0 ? val = 1 : val = 0;
                                            });
                                          },
                                          child: Container(
                                            width: 15,
                                            height: 15,
                                            decoration: BoxDecoration(
                                              shape: BoxShape.circle,
                                              border: Border.all(
                                                  color: Colors.grey),
                                            ),
                                            child: val == 0
                                                ? Container()
                                                : Center(
                                                    child: Container(
                                                      width: 10,
                                                      height: 10,
                                                      decoration:
                                                          const BoxDecoration(
                                                        shape: BoxShape.circle,
                                                        color: Colors.green,
                                                      ),
                                                    ),
                                                  ),
                                          ),
                                        ),
                                        const Gap(15),
                                        const SizedBox(width: 6),
                                        const Text(
                                          'Default Rules',
                                          style: TextStyle(
                                              fontSize: 16,
                                              fontWeight: FontWeight.bold),
                                        ),
                                      ],
                                    ),
                                    const SizedBox(width: 8),
                                    const Text(
                                      'security.yara',
                                      style: TextStyle(
                                          fontSize: 14,
                                          color:
                                              Color.fromARGB(255, 94, 93, 93),
                                          fontWeight: FontWeight.bold),
                                    ),
                                  ],
                                )
                              ],
                            ),
                          ),

                          const SizedBox(height: 40),

                          // Back and Analyze Buttons
                          Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              ElevatedButton(
                                onPressed: () {
                                  Navigator.pop(context);
                                },
                                style: ElevatedButton.styleFrom(
                                  backgroundColor:
                                      const Color.fromARGB(255, 203, 203, 203),
                                  padding: const EdgeInsets.symmetric(
                                      horizontal: 100, vertical: 25),
                                  shape: RoundedRectangleBorder(
                                    borderRadius: BorderRadius.circular(8),
                                  ),
                                ),
                                child: const Text(
                                  'Back',
                                  style: TextStyle(color: Colors.black),
                                ),
                              ),
                              const SizedBox(width: 20),
                              ElevatedButton(
                                onPressed: () {
                                  // Analyze action
                                  Navigator.push(
                                        context,
                                        MaterialPageRoute(
                                          builder: (context) =>
                                              const DashboardPage(),
                                        ),
                                      );
                                },
                                style: ElevatedButton.styleFrom(
                                  backgroundColor: myColorFromHex('#457d58'),
                                  padding: const EdgeInsets.symmetric(
                                      horizontal: 100, vertical: 25),
                                  shape: RoundedRectangleBorder(
                                    borderRadius: BorderRadius.circular(8),
                                  ),
                                ),
                                child: const Text(
                                  'Analyze',
                                  style: TextStyle(color: Colors.white),
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 30),

                    // File Info
                    val == 0
                        ? selectedFile == null
                            ? Container()
                            : Container(
                                width: 600,
                                padding: const EdgeInsets.all(16.0),
                                decoration: BoxDecoration(
                                  color: Colors.white,
                                  borderRadius: BorderRadius.circular(8),
                                ),
                                child: Row(
                                  mainAxisAlignment:
                                      MainAxisAlignment.spaceAround,
                                  children: [
                                    // Name
                                    Column(
                                      children: [
                                        const Text(
                                          'Name:',
                                          style: TextStyle(
                                              fontWeight: FontWeight.bold),
                                        ),
                                        Text(selectedFile!.name),
                                      ],
                                    ),
                                    // Size
                                    Column(
                                      children: [
                                        const Text(
                                          'Size:',
                                          style: TextStyle(
                                              fontWeight: FontWeight.bold),
                                        ),
                                        Text('${selectedFile!.size} KB'),
                                      ],
                                    ),
                                    // Type
                                    Column(
                                      children: [
                                        const Text(
                                          'Type:',
                                          style: TextStyle(
                                              fontWeight: FontWeight.bold),
                                        ),
                                        Text(selectedFile!.extension!),
                                      ],
                                    ),
                                    // Last Modified
                                    const Column(
                                      children: [
                                         Text(
                                          'Last Modified:',
                                          style: TextStyle(
                                              fontWeight: FontWeight.bold),
                                        ),
                                      ],
                                    ),
                                  ],
                                ),
                              )
                        : Container(
                            width: 600,
                            padding: const EdgeInsets.all(16.0),
                            decoration: BoxDecoration(
                              color: Colors.white,
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: const Row(
                              mainAxisAlignment: MainAxisAlignment.spaceAround,
                              children: [
                                // Name
                                Column(
                                  children:  [
                                    Text(
                                      'Name:',
                                      style: TextStyle(
                                          fontWeight: FontWeight.bold),
                                    ),
                                    Text('security.yara'),
                                  ],
                                ),
                                // Size
                                Column(
                                  children:  [
                                    Text(
                                      'Size:',
                                      style: TextStyle(
                                          fontWeight: FontWeight.bold),
                                    ),
                                    Text('2.00 KB'),
                                  ],
                                ),
                                // Type
                                Column(
                                  children:  [
                                    Text(
                                      'Type:',
                                      style: TextStyle(
                                          fontWeight: FontWeight.bold),
                                    ),
                                    Text('text/plain'),
                                  ],
                                ),
                                // Last Modified
                                Column(
                                  children:  [
                                    Text(
                                      'Last Modified:',
                                      style: TextStyle(
                                          fontWeight: FontWeight.bold),
                                    ),
                                    Text('N/A'),
                                  ],
                                ),
                              ],
                            ),
                          ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
