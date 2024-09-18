import 'dart:developer';

import 'package:crypta/utils/get_color_based_on_type.dart';
import 'package:flutter/material.dart';
import 'package:gap/gap.dart';

class Ioc extends StatefulWidget {
  final Map<String, dynamic> result;
  final Map<String, dynamic> analysis;
  const Ioc({super.key, required this.analysis, required this.result});

  @override
  State<Ioc> createState() => _IocState();
}

class _IocState extends State<Ioc> {
  List recommendations = [];
  List<bool> expandedStates = [];
  @override
  void initState() {
    super.initState();
    recommendations = widget.analysis['gemini']['recommended_fixes'];
    expandedStates = List.generate(recommendations.length, (_) => false);
  }

  @override
  Widget build(BuildContext context) {
    TableRow buildTableRow(String level, String type, String ioc,
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
        ],
      );
    }

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
              Text(
                "Threat Analysis - ${widget.result['file']} ",
                style: const TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 16),
              // Table with 4 columns
              SizedBox(
                height: 375,
                child: SingleChildScrollView(
                  scrollDirection: Axis.vertical,
                  child: Table(
                    columnWidths: const {
                      0: FlexColumnWidth(1),
                      1: FlexColumnWidth(2),
                      2: FlexColumnWidth(2),
                    },
                    border: TableBorder.all(color: Colors.grey, width: 1),
                    children: [
                      buildTableRow("Level", "Type", "Triggered Action",
                          isHeader: true),
                      for (var rule in widget.result['yara'].entries!)
                        buildTableRow(
                          "Low",
                          "Authentication",
                          rule.key,
                        ),
                      // Additional rows can be added here.
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              const Text(
                "Recommended Fixes",
                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),
              ),
              const SizedBox(height: 12),
              SizedBox(
                height: 200,
                width: double.infinity,
                child: SingleChildScrollView(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisAlignment: MainAxisAlignment.start,
                    children: [
                      for (int i = 0; i < recommendations.length; i++)
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              mainAxisAlignment: MainAxisAlignment.start,
                              children: [
                                Text(
                                  '${i + 1}. Issue:',
                                  style: const TextStyle(
                                    fontWeight: FontWeight.bold,
                                    fontSize: 14,
                                  ),
                                ),
                                const Gap(4),
                                Text(recommendations[i]['issue'], style: const TextStyle(fontSize: 14),),
                              ],
                            ),
                            
                            const SizedBox(height: 8),
                            const Text(
                              'Action:',
                              style: TextStyle(
                                fontWeight: FontWeight.bold,
                                fontSize: 14,
                              ),
                            ),
                            for (int j = 0;
                                j < recommendations[i]['fix'].length;
                                j++)
                              if (expandedStates[i] ||
                                  j < 2) // Show 2 items initially
                                Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Padding(
                                      padding: const EdgeInsets.only(left: 16),
                                      child: Text(
                                          '• ${recommendations[i]['fix'][j]}'),
                                    ),
                                    const SizedBox(height: 4),
                                  ],
                                ),
                            if (recommendations[i]['fix'].length > 2)
                              TextButton(
                                onPressed: () {
                                  log('initial state: ${expandedStates[i]}');
                                  setState(() {
                                    log('${i + 1}');
                                    log(expandedStates[i].toString());
                                    expandedStates[i] = !expandedStates[i];
                                  });
                                  log('final state: ${expandedStates[i]}');
                                },
                                child: Text(
                                  expandedStates[i] ? 'Show Less' : 'Show More',
                                  style: const TextStyle(
                                    color: Colors.blue,
                                    fontWeight: FontWeight.bold,
                                    fontSize: 14,
                                  ),
                                ),
                              ),
                            const SizedBox(height: 16),
                          ],
                        ),
                    ],
                  ),
                ),
              ),

              // Action Buttons
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
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
  }
}
