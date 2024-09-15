import 'dart:developer';

import 'package:crypta/model/file_data.dart';
import 'package:crypta/providers/analysis_provider.dart';
import 'package:crypta/providers/files_metadata_provider.dart';
import 'package:crypta/providers/files_provider.dart';
import 'package:crypta/utils/get_color_based_on_value.dart';
import 'package:data_table_2/data_table_2.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

class FileTable extends ConsumerStatefulWidget {
  const FileTable({super.key});

  @override
  FileTableState createState() => FileTableState();
}

class FileTableState extends ConsumerState<FileTable> {
  // For row selection, use a map to keep track of selected rows
  Map<int, bool> selectedRows = {};

  bool ascending = true;
  int sortColumnIndex = 0;

  @override
  Widget build(BuildContext context) {
    List<Map<String, String>> sortedFileData = [
      ...ref.read(filesMetadataProvider)
    ];

    Map<String, dynamic> analysis = ref.read(analysisProvider);

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
                  "File Summary",
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
              ],
            ),
          ),
          // Data table
          ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 250),
            child: DataTable2(
              columnSpacing: 20,
              horizontalMargin: 12,
              sortColumnIndex: sortColumnIndex,
              sortAscending: ascending,
              minWidth: 200,
              columns: [
                const DataColumn(
                  label: Text(
                    'File',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                const DataColumn(
                  label: const Text(
                    'Type',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  // onSort: (columnIndex, ascending) {
                  //   setState(() {
                  //     this.ascending = ascending;
                  //     sortColumnIndex = columnIndex;
                  //     sortedFileData.sort((a, b) {
                  //       return ascending
                  //           ? a['type']!.compareTo(b['type']!)
                  //           : b['type']!.compareTo(a['type']!);
                  //     });
                  //   });
                  // },
                ),
                DataColumn(
                  label: const Padding(
                    padding: EdgeInsets.all(8.0),
                    child: Text(
                      'Size',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                  onSort: (columnIndex, ascending) {
                    setState(() {
                      this.ascending = ascending;
                      sortColumnIndex = columnIndex;
                      sortedFileData.sort((a, b) {
                        double sizeA = double.tryParse(a['size']!
                                .replaceAll(' MB', '')
                                .replaceAll(' KB', '')) ??
                            0;
                        double sizeB = double.tryParse(b['size']!
                                .replaceAll(' MB', '')
                                .replaceAll(' KB', '')) ??
                            0;
                        return ascending
                            ? sizeA.compareTo(sizeB)
                            : sizeB.compareTo(sizeA);
                      });
                    });
                  },
                ),
                const DataColumn(
                  label:  Center(
                    child: Text(
                      'Vulnerability Count',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                  // onSort: (columnIndex, ascending) {
                  //   setState(() {
                  //     this.ascending = ascending;
                  //     sortColumnIndex = columnIndex;
                  //     analysis['results'].sort((a, b) {
                  //       return ascending
                  //           ? int.tryParse(a['vulnerabilities']!)!
                  //               .compareTo(int.tryParse(b['vulnerabilities']!)!)
                  //           : int.tryParse(b['vulnerabilities']!)!.compareTo(
                  //               int.tryParse(a['vulnerabilities']!)!);
                  //     });
                  //   });
                  // },
                ),
              ],
              rows: analysis['results'].asMap().entries.map<DataRow>((result) {
                log(result.value['file']);
                log(result.value['risk_type']);
                log(result.value['vulnerability_type']);
                log(result.value['vulnerability_count'].toString());
                Map<String, String> matchingFile = sortedFileData.firstWhere(
                  (file) => file['name'] == result.value['file'],
                  orElse: () => {}, // Return null if no match is found
                );
            
                String size = '';
                String type = '';
            
                if (matchingFile.isNotEmpty) {
                  // Access size and type
                  size = matchingFile['size']!;
                  type = matchingFile['type']!;
            
                  log('File size: $size');
                  log('File type: $type');
                } else {
                  log('No file found with the name ${result.value['file']}');
                }
                return DataRow(
                  cells: [
                    DataCell(Text(result.value['file']!)),
                    DataCell(Text(type)),
                    DataCell(Text(size)),
                    DataCell(
                      Center(
                        child: Container(
                          width: 100,
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              color: getColorBasedOnValue(
                                  result.value['vulnerability_count'])),
                          child: Text(
                            result.value['vulnerability_count']!.toString(),
                            textAlign: TextAlign.center,
                            style: const TextStyle(fontWeight: FontWeight.bold),
                          ),
                        ),
                      ),
                    ),
                  ],
                );
              }).toList(),
            ),
          ),
          Text('No. of Files: ${sortedFileData.length}'),
          // Pagination Controls
          Padding(
            padding: const EdgeInsets.only(top: 4.0),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                TextButton(
                  onPressed: () {
                    // Handle previous page action
                  },
                  child: const Text("< Previous"),
                ),
                const SizedBox(width: 10),
                const Text(
                  "Page 1 of 5", // Example page info
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
                const SizedBox(width: 10),
                TextButton(
                  onPressed: () {
                    // Handle next page action
                  },
                  child: const Text("Next >"),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
