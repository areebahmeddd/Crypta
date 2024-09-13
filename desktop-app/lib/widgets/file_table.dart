import 'package:crypta/model/file_data.dart';
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

  List<Map<String, String>> sortedFileData = [...fileData];

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
                  "File Summary",
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                // Dropdown and button
                // Row(
                //   children: [
                //     DropdownButton<String>(
                //       value: 'All Column',
                //       items: ['All Column', 'File', 'Type', 'Size']
                //           .map((String value) {
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
                //     //   child: const Text("DISPATCH SELECTED", style: TextStyle(color: Colors.white)),
                //     // ),
                //   ],
                // ),
              ],
            ),
          ),
          // Data table
          Expanded(
            child: DataTable2(
              columnSpacing: 20,
              horizontalMargin: 12,
              sortColumnIndex: sortColumnIndex,
              sortAscending: ascending,
              columns: [
                const DataColumn(
                  label: Text(
                    'File',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                DataColumn(
                  label: const Text(
                    'Type',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  onSort: (columnIndex, ascending) {
                    setState(() {
                      this.ascending = ascending;
                      sortColumnIndex = columnIndex;
                      sortedFileData.sort((a, b) {
                        return ascending
                            ? a['type']!.compareTo(b['type']!)
                            : b['type']!.compareTo(a['type']!);
                      });
                    });
                  },
                ),
                DataColumn(
                  label: const Padding(
                    padding:  EdgeInsets.all(8.0),
                    child:  Text(
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
                        int sizeA = int.tryParse(a['size']!
                                .replaceAll(' MB', '')
                                .replaceAll(' KB', '')) ??
                            0;
                        int sizeB = int.tryParse(b['size']!
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
                 DataColumn(
                  label: const Center(
                    child: Text(
                      'Vulnerability Count',
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
                        return ascending
                            ? int.tryParse(a['vulnerabilities']!)!
                                .compareTo(int.tryParse(b['vulnerabilities']!)!)
                            : int.tryParse(b['vulnerabilities']!)!
                                .compareTo(int.tryParse(a['vulnerabilities']!)!);
                      });

                    });
                  },
                ),
              ],
              rows: sortedFileData
                  .asMap()
                  .entries
                  .map(
                    (entry) => DataRow(
                      cells: [
                        DataCell(Text(entry.value['file']!)),
                        DataCell(Text(entry.value['type']!)),
                        DataCell(Text(entry.value['size']!)),
                        DataCell(Center(
                          child: Container(
                            width: 100,
                            padding: const EdgeInsets.all(8),
                            decoration: BoxDecoration(
                                shape: BoxShape.circle,
                                color: getColorBasedOnValue(int.tryParse(
                                    entry.value['vulnerabilities']!)!)),
                            child: Text(
                              entry.value['vulnerabilities']!,
                              textAlign: TextAlign.center,
                              style:
                                  const TextStyle(fontWeight: FontWeight.bold),
                            ),
                          ),
                        )),
                      ],
                    ),
                  )
                  .toList(),
            ),
          ),
          // Pagination Controls
          Padding(
            padding: const EdgeInsets.only(top: 10.0),
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
