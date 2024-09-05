import 'dart:developer';
import 'dart:io';

import 'package:crypta/screens/upload_rules_page.dart';
import 'package:crypta/utils/hexcolor.dart';
import 'package:file_picker/file_picker.dart';
import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:gap/gap.dart';
import 'package:url_launcher/url_launcher.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  HomePageState createState() => HomePageState();
}

class HomePageState extends State<HomePage> {
  PlatformFile? _selectedFile;
  List<Map<String, String>> uploadedFilesMetadata = [];

  List<File> selectedFiles = [];

  double _progress = 0.0;

  Future<void> pickFile() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles();

    if (result != null) {
      setState(() {
        _selectedFile = result.files.first;
      });
    }
  }

  Future<void> pickFolder() async {
    String? folderPath = await getDirectoryPath();

    if (folderPath != null) {
      final directory = Directory(folderPath);
      List<FileSystemEntity> files = directory.listSync();

      setState(() {
        selectedFiles.clear();
        uploadedFilesMetadata.clear();
        _progress = 0.0;
      });

      for (int i = 0; i < files.length; i++) {
        var fileEntity = files[i];

        if (fileEntity is File) {
          log('Adding file: ${fileEntity.path}');

          double progress = (i + 1) / files.length;
          setState(() {
            selectedFiles.add(fileEntity);
            _progress = progress;
          });

          await getFileMetadatas(fileEntity);

          await Future.delayed(const Duration(milliseconds: 500));
        }
      }
    }
  }

  Future<void> getFileMetadatas(File file) async {
    final fileStat = await file.stat();
    final fileSizeInMB = (fileStat.size / (1024 * 1024)).toStringAsFixed(2);
    final fileType = fileStat.type;
    final fileExtension = file.path.split('.').last;
    setState(() {
      uploadedFilesMetadata.add({
        'name': file.path.split('/').last,
        'size': '$fileSizeInMB MB',
        'type': fileType.toString(),
        'extension': fileExtension,
      });
    });
  }

  void _goToGithub() async {
    const url = 'https://github.com/areebahmeddd/Crypta';
    try {
      await launchUrl(Uri.parse(url));
    } catch (e) {
      log(e.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      // appBar: AppBar(

      //   // title: const Center(
      //   //   child: Row(
      //   //     mainAxisAlignment: MainAxisAlignment.center,
      //   //     crossAxisAlignment: CrossAxisAlignment.center,
      //   //     mainAxisSize: MainAxisSize.min,
      //   //     children: [
      //   //       Gap(100),
      //   //       Text('About'),
      //   //       Gap(8),
      //   //       Text('Team'),
      //   //       Gap(8),
      //   //       Text('Contact'),
      //   //     ],
      //   //   ),
      //   // ),
      //   actions: [
      //     Row(children: [
      //       // IconButton(
      //       //   icon: const Icon(Icons.download),
      //       //   onPressed: () {},
      //       // ),
      //       // const Gap(4),
      //       // const Text('Download'),
      //       const Gap(16),
      //       GestureDetector(
      //         onTap: () {},
      //         child: Container(
      //           padding: const EdgeInsets.all(16),
      //           child: const Image(
      //             image: AssetImage(
      //               'assets/github-logo.png',
      //             ),
      //             height: 100,
      //           ),
      //         ),
      //       )
      //     ]),
      //   ],
      //   titleTextStyle: const TextStyle(
      //       fontSize: 18, color: Colors.black, fontWeight: FontWeight.bold),
      //   centerTitle: true,
      //   elevation: 4,
      //   backgroundColor: Colors.white,
      // ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Stack(
          children: [
            Center(
              child: Row(
                children: [
                  Expanded(
                    flex: 4,
                    child: ScrollConfiguration(
                      behavior: ScrollConfiguration.of(context)
                          .copyWith(scrollbars: false),
                      child: SingleChildScrollView(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.center,
                          children: [
                            Container(
                              width: 550,
                              height: 150,
                              padding: const EdgeInsets.all(16),
                              decoration: BoxDecoration(
                                color: Colors.white,
                                border: Border.all(color: Colors.grey),
                                borderRadius: const BorderRadius.all(
                                  Radius.circular(10),
                                ),
                              ),
                              child: Column(
                                mainAxisAlignment: MainAxisAlignment.start,
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  const Padding(
                                    padding: EdgeInsets.only(left: 16.0),
                                    child: Text(
                                      'Connect Drive',
                                      style: TextStyle(
                                        color: Colors.black,
                                        fontWeight: FontWeight.bold,
                                        fontSize: 30,
                                      ),
                                    ),
                                  ),
                                  const Gap(16),
                                  Center(
                                    child: ElevatedButton(
                                      onPressed: () {},
                                      style: ElevatedButton.styleFrom(
                                        backgroundColor:
                                            myColorFromHex('#457d58'),
                                        padding: const EdgeInsets.symmetric(
                                            horizontal: 200, vertical: 25),
                                        shape: RoundedRectangleBorder(
                                          borderRadius:
                                              BorderRadius.circular(8),
                                        ),
                                      ),
                                      child: const Text(
                                        'Detect Drive',
                                        style: TextStyle(color: Colors.white),
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                            ),
                            const SizedBox(height: 20),
                            GestureDetector(
                              onTap: pickFolder,
                              child: Container(
                                width: 550,
                                height: 400,
                                padding: const EdgeInsets.all(16),
                                decoration: BoxDecoration(
                                  color: Colors.white,
                                  border: Border.all(color: Colors.grey),
                                  borderRadius: BorderRadius.circular(8),
                                ),
                                child: const Column(
                                  children: [
                                    Align(
                                      alignment: Alignment.centerLeft,
                                      child: Padding(
                                        padding: EdgeInsets.only(left: 16.0),
                                        child: Text(
                                          'Upload File',
                                          style: TextStyle(
                                            color: Colors.black,
                                            fontWeight: FontWeight.bold,
                                            fontSize: 28,
                                          ),
                                        ),
                                      ),
                                    ),
                                    Gap(60),
                                    Icon(Icons.cloud_upload,
                                        size: 50, color: Colors.grey),
                                    SizedBox(height: 10),
                                    Text(
                                      'Drag and drop a folder here or',
                                      style: TextStyle(color: Colors.grey),
                                    ),
                                    SizedBox(height: 10),
                                    Text(
                                      'Choose folder',
                                      style: TextStyle(
                                          color: Colors.blue,
                                          fontWeight: FontWeight.bold),
                                    ),
                                  ],
                                ),
                              ),
                            ),
                            if (selectedFiles.isNotEmpty) ...[
                              const SizedBox(height: 20),
                              Row(
                                crossAxisAlignment: CrossAxisAlignment.center,
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  SizedBox(
                                    width: 400,
                                    height: 10,
                                    child: LinearProgressIndicator(
                                      value: _progress,
                                      backgroundColor: Colors.grey,
                                      color: Colors.green,
                                    ),
                                  ),
                                  const Gap(20),
                                  Text(
                                    '${(_progress * 100).toStringAsFixed(2)}%',
                                    style: const TextStyle(
                                      color: Colors.black,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 20),
                              Row(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  ElevatedButton(
                                    onPressed: () {
                                      setState(() {
                                        selectedFiles = [];
                                        uploadedFilesMetadata = [];
                                      });
                                    },
                                    style: ElevatedButton.styleFrom(
                                      backgroundColor: const Color.fromARGB(
                                          255, 203, 203, 203),
                                      padding: const EdgeInsets.symmetric(
                                          horizontal: 100, vertical: 25),
                                      shape: RoundedRectangleBorder(
                                        borderRadius: BorderRadius.circular(8),
                                      ),
                                    ),
                                    child: const Text(
                                      'Cancel',
                                      style: TextStyle(color: Colors.white),
                                    ),
                                  ),
                                  const SizedBox(width: 20),
                                  ElevatedButton(
                                    onPressed: () {
                                      Navigator.push(
                                        context,
                                        MaterialPageRoute(
                                          builder: (context) => const UploadRulesPage(),
                                        ),
                                      );
                                    },
                                    style: ElevatedButton.styleFrom(
                                      backgroundColor: Colors.blue,
                                      padding: const EdgeInsets.symmetric(
                                          horizontal: 100, vertical: 25),
                                      shape: RoundedRectangleBorder(
                                        borderRadius: BorderRadius.circular(8),
                                      ),
                                    ),
                                    child: const Text(
                                      'Next',
                                      style: TextStyle(color: Colors.white),
                                    ),
                                  ),
                                ],
                              ),
                            ],
                          ],
                        ),
                      ),
                    ),
                  ),
                  selectedFiles.isEmpty
                      ? const SizedBox()
                      : Expanded(
                          flex: 2,
                          child: Padding(
                            padding:
                                const EdgeInsets.all(8.0).copyWith(right: 60),
                            child: ListView.builder(
                              itemCount: uploadedFilesMetadata.length,
                              itemBuilder: (context, index) {
                                return Card(
                                  elevation: 4,
                                  color: Colors.white,
                                  margin:
                                      const EdgeInsets.symmetric(vertical: 8),
                                  child: ListTile(
                                    title: Text(uploadedFilesMetadata[index]
                                            ['name'] ??
                                        ''),
                                    subtitle: Text(
                                      'Size: ${uploadedFilesMetadata[index]['size']}\n'
                                      'Type: ${uploadedFilesMetadata[index]['type']}\n'
                                      'Extension: ${uploadedFilesMetadata[index]['extension']}',
                                    ),
                                  ),
                                );
                              },
                            ),
                          ),
                        )
                ],
              ),
            ),
            Positioned(
              top: -15,
              right: -15,
              child: GestureDetector(
                onTap: _goToGithub,
                child: Container(
                  padding: const EdgeInsets.all(16),
                  child: const Image(
                    image: AssetImage(
                      'assets/github-logo.png',
                    ),
                    height: 25,
                  ),
                ),
              ),
            )
          ],
        ),
      ),
    );
  }

  Widget _buildFileInfo(PlatformFile file) {
    final fileSizeInMB = (file.size / (1024 * 1024)).toStringAsFixed(2);
    final fileType = file.extension;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('File Name: ${file.name}'),
        Text('File Size: $fileSizeInMB MB'),
        Text('File Type: image/$fileType'),
        Text('File Extension: .$fileType'),
      ],
    );
  }
}
