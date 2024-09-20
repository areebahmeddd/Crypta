import 'dart:developer';
import 'dart:io';

import 'package:crypta/providers/files_metadata_provider.dart';
import 'package:crypta/providers/files_provider.dart';
import 'package:crypta/screens/upload_rules_page.dart';
import 'package:crypta/utils/hexcolor.dart';
import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:gap/gap.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:path/path.dart' as path;

class HomePage extends ConsumerStatefulWidget {
  const HomePage({super.key});
  @override
  HomePageState createState() => HomePageState();
}

class HomePageState extends ConsumerState<HomePage> {
  // PlatformFile? _selectedFile;
  List<Map<String, String>> uploadedFilesMetadata = [];

  double _progress = 0.0;

  // Future<void> pickFile() async {
  //   FilePickerResult? result = await FilePicker.platform.pickFiles();

  //   if (result != null) {
  //     setState(() {
  //       _selectedFile = result.files.first;
  //     });
  //   }
  // }

  @override
  void initState() {
    _progress = 0.0;
    uploadedFilesMetadata = [];
    super.initState();
  }

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
    const url = 'https://youtube.com/watch?v=-SN-jaTEgIE';
    try {
      await launchUrl(Uri.parse(url));
    } catch (e) {
      log(e.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    Future<void> getFileMetadatas(File file) async {
      final fileStat = await file.stat();
      final fileSizeInMB = (fileStat.size / (1024 * 1024)).toStringAsFixed(2);
      final fileType = fileStat.type;
      final fileExtension = file.path.split('.').last;
      final fileLastModified = await file.lastModified();
      String formattedDate =
          '${fileLastModified.day}/${fileLastModified.month}/${fileLastModified.year}';
      setState(() {
        ref.read(filesMetadataProvider.notifier).addFileMetadata({
          'name': path.basename(file.path),
          'size': '$fileSizeInMB MB',
          'type': fileType.toString(),
          'extension': fileExtension,
          'path': file.path,
          'last modified': formattedDate,
        });
        uploadedFilesMetadata.add({
          'name': path.basename(file.path),
          'size': '$fileSizeInMB MB',
          'type': fileType.toString(),
          'extension': fileExtension,
          'path': file.path,
          'last modified': formattedDate,
        });
      });
    }

    Future<void> pickFolder() async {
      String? folderPath = await getDirectoryPath();

      if (folderPath != null) {
        final directory = Directory(folderPath);
        List<FileSystemEntity> files = directory.listSync();

        setState(() {
          ref.watch(filesProvider.notifier).clearFiles();
          uploadedFilesMetadata.clear();
          _progress = 0.0;
        });

        for (int i = 0; i < files.length; i++) {
          var fileEntity = files[i];

          if (fileEntity is File) {
            log('Adding file: ${fileEntity.path}');

            double progress = (i + 1) / files.length;
            setState(() {
              ref.read(filesProvider.notifier).addFile(fileEntity);
              _progress = progress;
            });

            await getFileMetadatas(fileEntity);

            await Future.delayed(const Duration(milliseconds: 100));
          }
        }
      }
    }

    return Scaffold(
      body: Padding(
        padding: const EdgeInsets.all(16.0).copyWith(top: 0, right: 0),
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
                                        'Detect',
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
                                    Image(
                                      image: AssetImage(
                                          'assets/images/upload.png'),
                                      height: 100,
                                    ),
                                    SizedBox(height: 10),
                                    Text(
                                      'Drag & Drop Your Folder',
                                      style: TextStyle(color: Colors.grey),
                                    ),
                                    SizedBox(height: 10),
                                    Text(
                                      'Choose Folder',
                                      style: TextStyle(
                                          color: Colors.blue,
                                          fontWeight: FontWeight.bold),
                                    ),
                                  ],
                                ),
                              ),
                            ),
                            if (ref.watch(filesProvider).isNotEmpty) ...[
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
                                      color: myColorFromHex('#457d58'),
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
                                        ref
                                            .watch(filesProvider.notifier)
                                            .clearFiles();
                                        uploadedFilesMetadata = [];

                                        ref
                                            .watch(
                                                filesMetadataProvider.notifier)
                                            .clearFilesMetadata();
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
                                      style: TextStyle(color: Colors.black),
                                    ),
                                  ),
                                  const SizedBox(width: 20),
                                  ElevatedButton(
                                    onPressed: () {
                                      _progress != 1.0
                                          ? null
                                          : Navigator.push(
                                              context,
                                              MaterialPageRoute(
                                                builder: (context) =>
                                                    const UploadRulesPage(),
                                              ),
                                            );
                                    },
                                    style: ElevatedButton.styleFrom(
                                      backgroundColor: _progress != 1.0
                                          ? Colors.grey
                                          : myColorFromHex('#457d58'),
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
                  ref.watch(filesProvider).isEmpty
                      ? const SizedBox()
                      : Expanded(
                          flex: 3,
                          child: Padding(
                            padding: const EdgeInsets.all(8.0)
                                .copyWith(right: 100, top: 30),
                            child: ListView.builder(
                              itemCount: uploadedFilesMetadata.length,
                              itemBuilder: (context, index) {
                                return Card(
                                  elevation: 4,
                                  color: Colors.white,
                                  margin:
                                      const EdgeInsets.symmetric(vertical: 8),
                                  child: Padding(
                                    padding: const EdgeInsets.all(
                                        10.0), // Add some padding for a clean look
                                    child: ListTile(
                                      title: RichText(
                                        text: TextSpan(
                                          text: uploadedFilesMetadata[index]
                                              ['name']!, // File name
                                          style: const TextStyle(
                                            fontWeight: FontWeight
                                                .bold, // Bold file name
                                            fontSize: 16, // Increase font size
                                            color: Colors
                                                .black, // Use black for title
                                          ),
                                        ),
                                      ),
                                      subtitle: RichText(
                                        text: TextSpan(
                                          children: [
                                            const TextSpan(
                                              text: 'Size: ',
                                              style: TextStyle(
                                                fontWeight: FontWeight
                                                    .bold, // Bold for label
                                                fontSize: 14,
                                                color: Colors
                                                    .black87, // Darker color for labels
                                              ),
                                            ),
                                            TextSpan(
                                              text:
                                                  '${uploadedFilesMetadata[index]['size']!} \n',
                                              style: const TextStyle(
                                                fontWeight: FontWeight
                                                    .normal, // Normal font weight for value
                                                fontSize: 14,
                                                color: Colors
                                                    .grey, // Grey color for file details
                                              ),
                                            ),
                                            const TextSpan(
                                              text: 'Type: ',
                                              style: TextStyle(
                                                fontWeight: FontWeight.bold,
                                                fontSize: 14,
                                                color: Colors.black87,
                                              ),
                                            ),
                                            TextSpan(
                                              text:
                                                  '${uploadedFilesMetadata[index]['type']!} \n',
                                              style: const TextStyle(
                                                fontWeight: FontWeight.normal,
                                                fontSize: 14,
                                                color: Colors.grey,
                                              ),
                                            ),
                                            const TextSpan(
                                              text: 'Extension: ',
                                              style: TextStyle(
                                                fontWeight: FontWeight.bold,
                                                fontSize: 14,
                                                color: Colors.black87,
                                              ),
                                            ),
                                            TextSpan(
                                              text:
                                                  '${uploadedFilesMetadata[index]['extension']!} \n',
                                              style: const TextStyle(
                                                fontWeight: FontWeight.normal,
                                                fontSize: 14,
                                                color: Colors.grey,
                                              ),
                                            ),
                                            const TextSpan(
                                              text: 'Last Modified: ',
                                              style: TextStyle(
                                                fontWeight: FontWeight.bold,
                                                fontSize: 14,
                                                color: Colors.black87,
                                              ),
                                            ),
                                            TextSpan(
                                              text: uploadedFilesMetadata[index]
                                                  ['last modified']!,
                                              style: const TextStyle(
                                                fontWeight: FontWeight.normal,
                                                fontSize: 14,
                                                color: Colors.grey,
                                              ),
                                            ),
                                          ],
                                        ),
                                      ),
                                      trailing: IconButton(
                                        icon: const Icon(Icons.delete,
                                            color: Colors
                                                .red), // Red delete icon for emphasis
                                        onPressed: () {
                                          ref
                                              .read(filesProvider.notifier)
                                              .removeFile(
                                                  uploadedFilesMetadata[index]
                                                      ['path']!);
                                          ref
                                              .read(filesMetadataProvider
                                                  .notifier)
                                              .removeFileMetadata(
                                                  uploadedFilesMetadata[index]
                                                      ['path']!);
                                          setState(() {
                                            uploadedFilesMetadata
                                                .removeAt(index);
                                          });
                                        },
                                      ),
                                    ),
                                  ),
                                );
                              },
                            ),
                          ),
                        ),
                ],
              ),
            ),
            // Positioned(
            //   top: -10,
            //   right: -1,
            //   child: GestureDetector(
            //     onTap: _goToGithub,
            //     child: Container(
            //       padding: const EdgeInsets.all(16),
            //       child: const Row(
            //         children: [
            //           Text(
            //             'Github',
            //             style: const TextStyle(
            //               color: Colors.black,
            //               fontWeight: FontWeight.bold,
            //             ),
            //           ),
            //           const Image(
            //             image: AssetImage(
            //               'assets/images/github-logo.png',
            //             ),
            //             height: 25,
            //           ),
            //         ],
            //       ),
            //     ),
            //   ),
            // ),
            Positioned(
              top: -10,
              right: 1,
              child: Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  GestureDetector(
                    onTap: _goToYoutube,
                    child: Container(
                      padding: const EdgeInsets.all(16),
                      child: const Row(
                        children: [
                          const Text(
                            'Website',
                            style: TextStyle(
                              color: Colors.black,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          Gap(6),
                          const Image(
                            image: AssetImage(
                              'assets/images/domain.png',
                            ),
                            height: 20,
                          ),
                        ],
                      ),
                    ),
                  ),
                  GestureDetector(
                    onTap: _goToYoutube,
                    child: Container(
                      padding: const EdgeInsets.all(16),
                      child: const Row(
                        children: [
                          const Text(
                            'Youtube',
                            style: TextStyle(
                              color: Colors.black,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          Gap(6),
                          const Image(
                            image: AssetImage(
                              'assets/images/youtube.png',
                            ),
                            height: 20,
                          ),
                        ],
                      ),
                    ),
                  ),
                  GestureDetector(
                    onTap: _goToYoutube,
                    child: Container(
                      padding: const EdgeInsets.all(16),
                      child: const Row(
                        children: [
                          const Text(
                            'Github',
                            style: TextStyle(
                              color: Colors.black,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          Gap(6),
                          const Image(
                            image: AssetImage(
                              'assets/images/github-logo.png',
                            ),
                            height: 20,
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
            // Positioned(
            //   top: -10,
            //   right: 40,
            //   child: GestureDetector(
            //     onTap: _goToYoutube,
            //     child: Container(
            //       padding: const EdgeInsets.all(16),
            //       child: const Row(
            //         children: [
            //           const Text(
            //             'Youtube',
            //             style: TextStyle(
            //               color: Colors.black,
            //               fontWeight: FontWeight.bold,
            //             ),
            //           ),
            //           const Image(
            //             image: AssetImage(
            //               'assets/images/youtube.png',
            //             ),
            //             height: 30,
            //           ),
            //         ],
            //       ),
            //     ),
            //   ),
            // ),
            // Positioned(
            //   top: -9,
            //   right: 90,
            //   child: GestureDetector(
            //     onTap: _goToWebsite,
            //     child: Container(
            //       padding: const EdgeInsets.all(16),
            //       child: const Row(
            //         children: [
            //           const Text(
            //             'Website',
            //             style: TextStyle(
            //               color: Colors.black,
            //               fontWeight: FontWeight.bold,
            //             ),
            //           ),
            //           const Image(
            //             image: AssetImage(
            //               'assets/images/domain.png',
            //             ),
            //             height: 25,
            //           ),
            //         ],
            //       ),
            //     ),
            //   ),
            // ),
            Positioned(
              bottom: 5,
              right: 5,
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
      ),
    );
  }

  // Widget _buildFileInfo(PlatformFile file) {
  //   final fileSizeInMB = (file.size / (1024 * 1024)).toStringAsFixed(2);
  //   final fileType = file.extension;
  //   return Column(
  //     crossAxisAlignment: CrossAxisAlignment.start,
  //     children: [
  //       Text('File Name: ${file.name}'),
  //       Text('File Size: $fileSizeInMB MB'),
  //       Text('File Type: image/$fileType'),
  //       Text('File Extension: .$fileType'),
  //     ],
  //   );
  // }
}
