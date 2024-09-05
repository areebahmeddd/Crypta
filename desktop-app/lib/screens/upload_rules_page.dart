import 'package:crypta/utils/hexcolor.dart';
import 'package:flutter/material.dart';

class UploadRulesPage extends StatefulWidget {
  const UploadRulesPage({super.key});

  @override
  State<StatefulWidget> createState() {
    return _UploadRulesPageState();
  }
}

class _UploadRulesPageState extends State<UploadRulesPage> {
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
                      height: 450,
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
                          const SizedBox(height: 20),

                          // Drag and drop box
                          Container(
                            width: 400,
                            height: 150,
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
                                  onPressed: () {
                                    // Trigger file picker
                                  },
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

                          const SizedBox(height: 20),

                          // OR divider
                          const Text('--OR--'),

                          const SizedBox(height: 20),

                          // Default Rules
                          Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              Radio(
                                value: 1,
                                groupValue:
                                    1, // Assuming you are managing the state
                                onChanged: (value) {},
                              ),
                              const Icon(Icons.insert_drive_file),
                              const SizedBox(width: 8),
                              const Text(
                                'Default Rules',
                                style: TextStyle(fontSize: 16),
                              ),
                              const SizedBox(width: 8),
                              const Text(
                                'security.yara',
                                style: TextStyle(
                                  fontSize: 16,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ],
                          ),

                          const SizedBox(height: 30),

                          // Back and Analyze Buttons
                          Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              ElevatedButton(
                                onPressed: () {
                                  // Back action
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
                                },
                                style: ElevatedButton.styleFrom(
                                  backgroundColor:
                                      myColorFromHex('#457d58'),
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
                    Container(
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
                            children: const [
                              Text(
                                'Name:',
                                style: TextStyle(fontWeight: FontWeight.bold),
                              ),
                              Text('security.yara'),
                            ],
                          ),
                          // Size
                          Column(
                            children: const [
                              Text(
                                'Size:',
                                style: TextStyle(fontWeight: FontWeight.bold),
                              ),
                              Text('2.00 KB'),
                            ],
                          ),
                          // Type
                          Column(
                            children: const [
                              Text(
                                'Type:',
                                style: TextStyle(fontWeight: FontWeight.bold),
                              ),
                              Text('text/plain'),
                            ],
                          ),
                          // Last Modified
                          Column(
                            children: const [
                              Text(
                                'Last Modified:',
                                style: TextStyle(fontWeight: FontWeight.bold),
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
