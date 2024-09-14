import 'dart:developer';
import 'dart:io';

import 'package:crypta/apis/analyze_file.dart';
import 'package:crypta/providers/analysis_provider.dart';
import 'package:crypta/providers/files_provider.dart';
import 'package:crypta/screens/dashboard_page.dart';
import 'package:crypta/utils/hexcolor.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:gap/gap.dart';
import 'package:lottie/lottie.dart';
import 'package:path/path.dart' as path;
import 'package:url_launcher/url_launcher.dart';

class UploadRulesPage extends ConsumerStatefulWidget {
  const UploadRulesPage({super.key});

  @override
  ConsumerState<UploadRulesPage> createState() {
    return _UploadRulesPageState();
  }
}

class _UploadRulesPageState extends ConsumerState<UploadRulesPage> {
  File? selectedFile;
  PlatformFile? file;
  Map<String, dynamic> fileInfo = {};

  Future<void> pickFile() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles();

    if (result != null) {
      setState(() {
        file = result.files.first;
        selectedFile = File(file!.path!);
        getFileInfo(selectedFile!);
        val = 0;
      });
    }
  }

  Future<void> getFileInfo(File file) async {
    final fileStat = await selectedFile!.stat();
    final fileSizeInMB = (fileStat.size / (1024));
    final fileType = fileStat.type;
    final fileLastModified = await file.lastModified();
    String formattedDate =
        '${fileLastModified.day}/${fileLastModified.month}/${fileLastModified.year}';
    setState(() {
      fileInfo = {
        'name': path.basename(selectedFile!.path),
        'size': fileSizeInMB,
        'type': fileType,
        'lastModified': formattedDate,
      };
    });
  }

  var val = 0;

  void _goToGithub() async {
    const url = 'https://github.com/areebahmeddd/Crypta';
    try {
      await launchUrl(Uri.parse(url));
    } catch (e) {
      log(e.toString());
    }
  }

  void _goToWebsite() async {
    const url = '';
    try {
      await launchUrl(Uri.parse(url));
    } catch (e) {
      log(e.toString());
    }
  }

  void _goToYoutube() async {
    const url = 'https://www.youtube.com/@areebahmeddd';
    try {
      await launchUrl(Uri.parse(url));
    } catch (e) {
      log(e.toString());
    }
  }

  @override
  void initState() {
    super.initState();
    final files = ref.read(filesProvider);
    for (int i = 0; i < files.length; i++) {
      log(files[i].path);
    }
  }

  var isAnalysing = false;

  @override
  Widget build(BuildContext context) {
    Future<void> uploadFiles() async {
      final files = ref.read(filesProvider);
      final yaraFile = File('assets/security.yara');

      setState(() {
        isAnalysing = true;
      });
      final response = await analyzeFile(files, yaraFile);
      log(response.toString());

      if (response['status'] == 'success') {
        ref.read(analysisProvider.notifier).saveAnalysis(response['data']);
        Navigator.push(
          context,
          MaterialPageRoute(
            builder: (context) => const DashboardPage(),
          ),
        );
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Failed to upload file'),
          ),
        );
      }
    }

    return Scaffold(
      body: Stack(
        children: [
          isAnalysing
              ? Container(
                  child: Center(
                    child:
                        Lottie.asset('assets/lottie/loading.json', height: 400),
                  ),
                )
              : Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Center(
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
                                        mainAxisAlignment:
                                            MainAxisAlignment.start,
                                        crossAxisAlignment:
                                            CrossAxisAlignment.start,
                                        children: [
                                          Row(
                                            children: [
                                              GestureDetector(
                                                onTap: () {
                                                  setState(() {
                                                    selectedFile = null;
                                                    val == 0
                                                        ? val = 1
                                                        : val = 0;
                                                    
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
                                                              shape: BoxShape
                                                                  .circle,
                                                              color:
                                                                  Colors.green,
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
                                                    fontWeight:
                                                        FontWeight.bold),
                                              ),
                                            ],
                                          ),
                                          const SizedBox(width: 8),
                                          const Text(
                                            'security.yara',
                                            style: TextStyle(
                                                fontSize: 14,
                                                color: Color.fromARGB(
                                                    255, 94, 93, 93),
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
                                        backgroundColor: const Color.fromARGB(
                                            255, 203, 203, 203),
                                        padding: const EdgeInsets.symmetric(
                                            horizontal: 100, vertical: 25),
                                        shape: RoundedRectangleBorder(
                                          borderRadius:
                                              BorderRadius.circular(8),
                                        ),
                                      ),
                                      child: const Text(
                                        'Back',
                                        style: TextStyle(color: Colors.black),
                                      ),
                                    ),
                                    const SizedBox(width: 20),
                                    ElevatedButton(
                                      onPressed:
                                          val == 0 && selectedFile == null
                                              ? () {}
                                              : uploadFiles,
                                      style: ElevatedButton.styleFrom(
                                        backgroundColor:
                                            val == 0 && selectedFile == null
                                                ? Colors.grey
                                                : myColorFromHex('#457d58'),
                                        padding: const EdgeInsets.symmetric(
                                            horizontal: 100, vertical: 25),
                                        shape: RoundedRectangleBorder(
                                          borderRadius:
                                              BorderRadius.circular(8),
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
                                                    fontWeight:
                                                        FontWeight.bold),
                                              ),
                                              Text(fileInfo['name']!),
                                            ],
                                          ),
                                          // Size
                                          Column(
                                            children: [
                                              const Text(
                                                'Size:',
                                                style: TextStyle(
                                                    fontWeight:
                                                        FontWeight.bold),
                                              ),
                                              Text(
                                                  '${fileInfo['size'].toStringAsFixed(2)} KB'),
                                            ],
                                          ),
                                          // Type
                                          Column(
                                            children: [
                                              const Text(
                                                'Type:',
                                                style: TextStyle(
                                                    fontWeight:
                                                        FontWeight.bold),
                                              ),
                                              Text(
                                                  fileInfo['type']!.toString()),
                                            ],
                                          ),
                                          // Last Modified
                                          Column(
                                            children: [
                                              const Text(
                                                'Last Modified:',
                                                style: TextStyle(
                                                    fontWeight:
                                                        FontWeight.bold),
                                              ),
                                              Text(fileInfo['lastModified']!),
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
                                    mainAxisAlignment:
                                        MainAxisAlignment.spaceAround,
                                    children: [
                                      // Name
                                      Column(
                                        children: [
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
                                        children: [
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
                                        children: [
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
                                        children: [
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
                ),
          Positioned(
            top: -10,
            right: -15,
            child: GestureDetector(
              onTap: _goToGithub,
              child: Container(
                padding: const EdgeInsets.all(16),
                child: const Image(
                  image: AssetImage(
                    'assets/images/github-logo.png',
                  ),
                  height: 25,
                ),
              ),
            ),
          ),
          Positioned(
            top: -10,
            right: 30,
            child: GestureDetector(
              onTap: _goToWebsite,
              child: Container(
                padding: const EdgeInsets.all(16),
                child: const Image(
                  image: AssetImage(
                    'assets/images/domain.png',
                  ),
                  height: 25,
                ),
              ),
            ),
          ),
          Positioned(
            top: -11,
            right: 80,
            child: GestureDetector(
              onTap: _goToYoutube,
              child: Container(
                padding: const EdgeInsets.all(16),
                child: const Image(
                  image: AssetImage(
                    'assets/images/youtube.png',
                  ),
                  height: 30,
                ),
              ),
            ),
          ),
          Positioned(
            bottom: 5,
            right: 10,
            child: ElevatedButton(
              style: ElevatedButton.styleFrom(
                backgroundColor: myColorFromHex('#457d58'),
                shape: const CircleBorder(side: BorderSide.none),
              ),
              onPressed: () {},
              child: Container(
                padding: const EdgeInsets.all(12),
                child: const Image(
                  image: AssetImage(
                    'assets/images/chatbot.png',
                  ),
                  height: 40,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
