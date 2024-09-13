import 'package:crypta/model/iOC.dart';
import 'package:crypta/model/vulnerability_data.dart';
import 'package:crypta/utils/get_color_based_on_type.dart';
import 'package:crypta/utils/hexcolor.dart';
import 'package:data_table_2/data_table_2.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

class FileTable2 extends ConsumerStatefulWidget {
  const FileTable2({super.key});

  @override
  FileTable2State createState() => FileTable2State();
}

class FileTable2State extends ConsumerState<FileTable2> {
  Map<int, bool> selectedRows = {};

  void showDetailedFileDialog(
      BuildContext context, Map<String, String> fileData) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(10),
          ),
          contentPadding: const EdgeInsets.all(16.0),
          content: SizedBox(
            width: 1000,
            child: SingleChildScrollView(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    "Threat Analysis",
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 16),
                  // Table with 4 columns
                  Table(
                    columnWidths: const {
                      0: FlexColumnWidth(1),
                      1: FlexColumnWidth(2),
                      2: FlexColumnWidth(2),
                    },
                    border: TableBorder.all(color: Colors.grey, width: 1),
                    children: [
                      _buildTableRow("Level", "Type", "Triggered Action",
                          isHeader: true),
                      _buildTableRow(
                          fileData['level'] ?? "High",
                          fileData['type'] ?? "Authentication",
                          fileData['ioc'] ?? "SSH - Attempt"),
                      for (int i = 0; i < iOC.length; i++)
                        _buildTableRow(
                          iOC[i]['level']!,
                          iOC[i]['type']!,
                          iOC[i]['ioc']!,
                        ),
                      // Additional rows can be added here.
                    ],
                  ),
                  const SizedBox(height: 16),
                  const Text(
                    "Recommended Fixes",
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),
                  ),
                  const SizedBox(height: 8),
                  Text(
                      "• Found ${fileData['threatCount'] ?? '10'} high-level threats for authentication."),
                  const Text("• Found multiple break-in attempts."),
                  const SizedBox(height: 16),
                  // Action Buttons
                  Row(
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: [
                      // ElevatedButton(
                      //   onPressed: () {
                      //     // Handle Download Report action
                      //   },
                      //   style: ElevatedButton.styleFrom(
                      //     padding: const EdgeInsets.symmetric(horizontal: 20),
                      //     backgroundColor: Colors.blueGrey,
                      //   ),
                      //   child: const Text("Download Report"),
                      // ),
                      // ElevatedButton(
                      //   onPressed: () {
                      //     // Handle Export Analytics action
                      //   },
                      //   style: ElevatedButton.styleFrom(
                      //     padding: const EdgeInsets.symmetric(horizontal: 20),
                      //     backgroundColor: Colors.green,
                      //   ),
                      //   child: const Text("Export Analytics"),
                      // ),
                      ElevatedButton(
                        onPressed: () {
                          Navigator.of(context).pop();
                        },
                        style: ElevatedButton.styleFrom(
                          padding: const EdgeInsets.symmetric(horizontal: 20),
                          backgroundColor: Colors.redAccent,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(10),
                          ),
                        ),
                        child: const Text(
                          "Close",
                          style: TextStyle(color: Colors.black),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

// Helper function to build a table row
  TableRow _buildTableRow(String level, String type, String ioc,
      {bool isHeader = false}) {
    return TableRow(
      decoration: isHeader
          ? const BoxDecoration(color: Colors.grey)
          : const BoxDecoration(),
      children: [
        isHeader
            ? Padding(
                padding: const EdgeInsets.all(8.0),
                child: Text(
                  level,
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                  ),
                ),
              )
            : Padding(
                padding: const EdgeInsets.all(8.0),
                child: Container(
                  height: 30,
                  width: 10,
                  padding: const EdgeInsets.all(4),
                  decoration: BoxDecoration(
                    borderRadius: const BorderRadius.all(Radius.circular(5)),
                    color: getColorBasedOnType(level),
                  ),
                  child: Center(
                    child: Text(
                      level,
                      style: const TextStyle(
                          fontWeight: FontWeight.normal, color: Colors.black),
                    ),
                  ),
                ),
              ),
        Padding(
          padding: const EdgeInsets.all(8.0),
          child: Text(
            type,
            style: TextStyle(
              fontWeight: isHeader ? FontWeight.bold : FontWeight.normal,
            ),
          ),
        ),
        Padding(
          padding: const EdgeInsets.all(8.0),
          child: Text(
            ioc,
            style: TextStyle(
              fontWeight: isHeader ? FontWeight.bold : FontWeight.normal,
            ),
          ),
        ),
        // Padding(
        //   padding: const EdgeInsets.all(8.0),
        //   child: Text(
        //     details,
        //     style: TextStyle(
        //       fontWeight: isHeader ? FontWeight.bold : FontWeight.normal,
        //     ),
        //   ),
        // ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(10),
        boxShadow: const [
          BoxShadow(
            color: Colors.black12,
            blurRadius: 10,
            spreadRadius: 2,
          ),
        ],
        color: Colors.white,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Top controls (e.g., Show column, Dispatch selected, pagination)
          const Padding(
            padding: EdgeInsets.only(bottom: 8.0),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.start,
              children: [
                Text(
                  "Vulnerability Summary",
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                // Dropdown and button
                // Row(
                //   children: [
                //     DropdownButton<String>(
                //       value: 'All Column',
                //       items: [
                //         'All Column',
                //         'File',
                //         'Vulnerability Type',
                //         'Indicators'
                //       ].map((String value) {
                //         return DropdownMenuItem<String>(
                //           value: value,
                //           child: Text(value),
                //         );
                //       }).toList(),
                //       onChanged: (String? newValue) {
                //         // Handle dropdown change
                //       },
                //     ),
                //     const SizedBox(width: 10),
                //     // ElevatedButton(
                //     //   onPressed: () {
                //     //     // Handle dispatch action
                //     //   },
                //     //   style: ElevatedButton.styleFrom(
                //     //     backgroundColor: myColorFromHex('#457d58'),
                //     //     padding: const EdgeInsets.symmetric(horizontal: 20),
                //     //     shape: RoundedRectangleBorder(
                //     //       borderRadius: BorderRadius.circular(8),
                //     //     ),
                //     //   ),
                //     //   child: const Text("DISPATCH SELECTED",
                //     //       style: TextStyle(color: Colors.white)),
                //     // ),
                //   ],
                // ),
              ],
            ),
          ),
          // Data table
          SizedBox(
            height: 300,
            child: DataTable2(
              columnSpacing: 20,
              horizontalMargin: 16,
              columns: const [
                DataColumn(
                  label: Text(
                    'File',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                DataColumn(
                  label: Text(
                    'Vulnerability Type',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                DataColumn(
                  label: Center(
                    child: Text(
                      'Indicators of Compromise',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                ),
              ],
              rows: vulnerabilityData
                  .asMap()
                  .entries
                  .map(
                    (entry) => DataRow(
                      // onSelectChanged: (isSelected) {
                      //   setState(() {
                      //     selectedRows[entry.key] = isSelected ?? false;
                      //   });
                      // },
                      cells: [
                        DataCell(
                          Text(entry.value['file']!),
                        ),
                        DataCell(Text(entry.value['type']!)),
                        DataCell(
                          Center(
                            child: ElevatedButton(
                              style: ElevatedButton.styleFrom(
                                backgroundColor: myColorFromHex('#457d58'),
                                shape: RoundedRectangleBorder(
                                  borderRadius: BorderRadius.circular(8),
                                ),
                              ),
                              onPressed: () =>
                                  showDetailedFileDialog(context, entry.value),
                              child: const Text(
                                'View',
                                style: TextStyle(color: Colors.white),
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  )
                  .toList(),
            ),
          ),
          const SizedBox(height: 16),
          const Text(
            "Alert",
            style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),
          ),
          const SizedBox(height: 8),
          const Text("• Found 10 high-level threats for authentication."),
          const Text("• Found multiple break-in attempts."),
          const SizedBox(height: 16),
          // Pagination Controls
          // Padding(
          //   padding: const EdgeInsets.only(top: 10.0),
          //   child: Row(
          //     mainAxisAlignment: MainAxisAlignment.end,
          //     children: [
          //       TextButton(
          //         onPressed: () {
          //           // Handle previous page action
          //         },
          //         child: const Text("< Previous"),
          //       ),
          //       const SizedBox(width: 10),
          //       const Text(
          //         "Page 1 of 5", // Example page info
          //         style: const TextStyle(fontWeight: FontWeight.bold),
          //       ),
          //       const SizedBox(width: 10),
          //       TextButton(
          //         onPressed: () {
          //           // Handle next page action
          //         },
          //         child: const Text("Next >"),
          //       ),
          //     ],
          //   ),
          // ),
        ],
      ),
    );
  }
}
