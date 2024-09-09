import 'package:crypta/model/file_data.dart';
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
  // For row selection, use a map to keep track of selected rows
  Map<int, bool> selectedRows = {};

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
          Padding(
            padding: const EdgeInsets.only(bottom: 8.0),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Text(
                  "Vulnerability Summary",
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                // Dropdown and button
                Row(
                  children: [
                    DropdownButton<String>(
                      value: 'All Column',
                      items: ['All Column', 'File', 'Vulnerability Type', 'Indicators']
                          .map((String value) {
                        return DropdownMenuItem<String>(
                          value: value,
                          child: Text(value),
                        );
                      }).toList(),
                      onChanged: (String? newValue) {
                        // Handle dropdown change
                      },
                    ),
                    const SizedBox(width: 10),
                    ElevatedButton(
                      onPressed: () {
                        // Handle dispatch action
                      },
                      style: ElevatedButton.styleFrom(
                        backgroundColor: myColorFromHex('#457d58'),
                        padding: const EdgeInsets.symmetric(horizontal: 20),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(8),
                        ),
                      ),
                      child: const Text("DISPATCH SELECTED", style: TextStyle(color: Colors.white)),
                    ),
                  ],
                ),
              ],
            ),
          ),
          // Data table
          Expanded(
            child: DataTable2(
              columnSpacing: 20,
              horizontalMargin: 12,
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
                  label: Text(
                    'Indicators of Compromise',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ],
              rows: fileData
                  .asMap()
                  .entries
                  .map(
                    (entry) => DataRow(
                      onSelectChanged: (isSelected) {
                        setState(() {
                          selectedRows[entry.key] = isSelected ?? false;
                        });
                      },
                      cells: [
                        DataCell(Text(entry.value['file']!)),
                        DataCell(Text(entry.value['type']!)),
                        DataCell(Text(entry.value['size']!)),
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
                  style: const TextStyle(fontWeight: FontWeight.bold),
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
