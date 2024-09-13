import 'package:crypta/widgets/barchart.dart';
import 'package:crypta/widgets/download_report.dart';
import 'package:crypta/widgets/export_analysis.dart';
import 'package:crypta/widgets/file_table.dart';
import 'package:crypta/widgets/file_tables_2.dart';
import 'package:crypta/widgets/linechart.dart';
import 'package:crypta/widgets/search_bar.dart';
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
      child: Column(
        children: [
          CustomSearchBar(),
          Gap(20),
          SizedBox(
            height: 500,
            width: double.infinity,
            child: FileTable(),
          ),
          Gap(20),
          SizedBox(
            height: 480,
            width: double.infinity,
            child: FileTable2(),
          ),
          Gap(20),
          Row(
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
          Gap(60),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
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
                  child: BarChartSample(),
                ),
                Gap(50)
              ],
            ),
          )
        ],
      ),
    );
  }
}
