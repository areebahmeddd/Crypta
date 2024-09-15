import 'package:crypta/providers/analysis_provider.dart';
import 'package:crypta/utils/hexcolor.dart';
import 'package:crypta/widgets/iOC.dart';
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
  late List<bool> isExpanded;

  @override
  Widget build(BuildContext context) {
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
                  "Vulnerability Summary",
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
              ],
            ),
          ),
          // Data table
          SizedBox(
            height: 250,
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
              rows: analysis['results']
                  .asMap()
                  .entries
                  .map<DataRow>(
                    (result) => DataRow(
                      cells: [
                        DataCell(
                          Text(result.value['file']!),
                        ),
                        DataCell(Text(result.value['vulnerability_type']!)),
                        DataCell(
                          Center(
                            child: ElevatedButton(
                              style: ElevatedButton.styleFrom(
                                backgroundColor: myColorFromHex('#457d58'),
                                shape: RoundedRectangleBorder(
                                  borderRadius: BorderRadius.circular(8),
                                ),
                              ),
                              onPressed: () => showDialog(
                                context: context,
                                builder: (context) => Ioc(
                                  analysis: analysis,
                                  result: result.value,
                                ),
                              ),
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

          Text('No. of files: ${analysis['results'].length}', style: const TextStyle(color: Colors.grey),),
        ],
      ),
    );
  }
}
