import 'dart:io';

import 'package:crypta/widgets/alerts.dart';
import 'package:crypta/widgets/barchart.dart';
import 'package:crypta/widgets/download_report.dart';
import 'package:crypta/widgets/export_analysis.dart';
import 'package:crypta/widgets/file_table.dart';
import 'package:crypta/widgets/file_tables_2.dart';
import 'package:crypta/widgets/filesize_distribution.dart';
import 'package:crypta/widgets/linechart.dart';
import 'package:crypta/widgets/piechart.dart';
import 'package:crypta/widgets/search_bar.dart';
import 'package:crypta/widgets/vulnerability_distribution.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:gap/gap.dart';

class AnalysisPage extends StatefulWidget {
  const AnalysisPage({super.key});
  @override
  State<AnalysisPage> createState() => _AnalysisPageState();
}

class _AnalysisPageState extends State<AnalysisPage> {
  @override
  Widget build(BuildContext context) {
    return const SingleChildScrollView(
      child: Padding(
        padding: const EdgeInsets.all(8.0),
        child: Column(
          children: [
            const CustomSearchBar(),
            const Gap(20),
            const FileTable(),
            // ConstrainedBox(
            //   constraints: const BoxConstraints(
            //       minHeight: 100, maxHeight: 300 // Adjust as per your requirement
            //       ),
            //   child: const FileTable(),
            // ),
            const Gap(20),
            // ConstrainedBox(
            //   constraints: const BoxConstraints(
            //       minHeight: 100, maxHeight: 366 // Adjust as per your requirement
            //       ),
            //   child: const FileTable2(),
            // ),
            const FileTable2(),
            const Gap(20),
            const Alerts(),
            const Gap(20),
            const Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // Gap(80),
                DownloadReport(),
                // Spacer(),
                Gap(20),
                ExportAnalysis(),
                // Gap(80)
              ],
            ),
            const Gap(60),
            const SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: Column(
                children: [
                  Row(
                    children: [
                      SizedBox(
                        width: 500,
                        height: 500,
                        child: LineChartSample(),
                      ),
                      Gap(45),
                      SizedBox(
                        width: 500,
                        height: 500,
                        child: FileSizeDistribution(),
                      ),
                      Gap(50)
                    ],
                  ),
                  Gap(50),
                  Row(
                    children: [
                      SizedBox(
                        width: 500,
                        height: 500,
                        child: VulnerabilityCountDistribution(),
                      ),
                      Gap(45),
                      SizedBox(
                        width: 500,
                        height: 500,
                        child: Piechart(),
                      ),
                      Gap(50)
                    ],
                  ),
                ],
              ),
            )
          ],
        ),
      ),
    );
  }
}
