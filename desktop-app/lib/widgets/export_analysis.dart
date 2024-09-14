import 'dart:convert';
import 'dart:developer';
import 'dart:io';

import 'package:crypta/model/exportable_file_types.dart';
import 'package:crypta/providers/analysis_provider.dart';
import 'package:crypta/utils/hexcolor.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:gap/gap.dart';
import 'package:open_filex/open_filex.dart';
import 'package:path_provider/path_provider.dart';

class ExportAnalysis extends ConsumerStatefulWidget {
  const ExportAnalysis({super.key});
  @override
  ConsumerState<ExportAnalysis> createState() {
    return _ExportAnalysisState();
  }
}

class _ExportAnalysisState extends ConsumerState<ExportAnalysis> {
  String exportFileType = exportableFileTypes[0];
  @override
  Widget build(BuildContext context) {
    var jsonData = ref.read(analysisProvider); 

    Future<void> createJsonFile() async {
      try {
        // Convert the JSON data into a string format
        String jsonString = jsonEncode(jsonData);

        // Get the application's document directory
        Directory appDir = await getApplicationDocumentsDirectory();

        // Construct the full file path with the .json extension
        String filePath = '${appDir.path}/analysis.json';

        // Create a new file in the application directory
        File file = File(filePath);

        // Write the JSON string to the file
        await file.writeAsString(jsonString);

        OpenFilex.open(filePath);

        log('JSON file created at: $filePath');
      } catch (e) {
        log('Error creating JSON file: $e');
      }
    }

    return Row(
      children: [
        ElevatedButton(
          onPressed: createJsonFile,
          style: ElevatedButton.styleFrom(
              backgroundColor: myColorFromHex('#457d58'),
              padding: const EdgeInsets.symmetric(horizontal: 20),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
              )),
          child: const Padding(
            padding: EdgeInsets.symmetric(horizontal: 100, vertical: 8),
            child: Text(
              'Export Analysis',
              style: TextStyle(color: Colors.white),
            ),
          ),
        ),
        const Gap(20),
        DropdownButton<String>(
          value: exportFileType, // Current selected value
          items: exportableFileTypes
              .map((String fileType) => DropdownMenuItem<String>(
                    value: fileType,
                    child: Text(fileType),
                  ))
              .toList(),
          onChanged: (String? newValue) {
            setState(() {
              exportFileType = newValue ?? exportFileType; // Set new value
            });
          },
        ),
      ],
    );
  }
}
