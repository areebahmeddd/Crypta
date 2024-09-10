import 'package:crypta/model/exportable_file_types.dart';
import 'package:crypta/utils/hexcolor.dart';
import 'package:flutter/material.dart';

class ExportAnalysis extends StatefulWidget {
  const ExportAnalysis({super.key});
  @override
  State<StatefulWidget> createState() {
    return _ExportAnalysisState();
  }
}

class _ExportAnalysisState extends State<ExportAnalysis> {
  String exportFileType = exportableFileTypes[0];
  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        ElevatedButton(
          onPressed: () {},
          style: ElevatedButton.styleFrom(
              backgroundColor: myColorFromHex('#457d58'),
              padding: const EdgeInsets.symmetric(horizontal: 20),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
              )),
          child: const Padding(
            padding: EdgeInsets.symmetric(horizontal: 132, vertical: 8),
            child: Text(
              'Export Analysis',
              style: TextStyle(color: Colors.white),
            ),
          ),
        ),
        const Spacer(),
        SizedBox(
          width: 200,
          child: Center(
            child: DropdownButton<String>(
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
          ),
        ),
      ],
    );
  }
}
