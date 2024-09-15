import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:gap/gap.dart';

class FileSizeDistribution extends StatefulWidget {
  const FileSizeDistribution({super.key});

  @override
  _FileSizeDistributionState createState() => _FileSizeDistributionState();
}

class _FileSizeDistributionState extends State<FileSizeDistribution> {
  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        const Center(
          child: Text('File Size Distribution', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 24),),
        ),
        Gap(30),
        Expanded(
          child: BarChart(
            BarChartData(
              alignment: BarChartAlignment.spaceAround,
              maxY: 50, // Define the maximum value for the Y-axis
              barTouchData: BarTouchData(enabled: true),
              titlesData: FlTitlesData(
                show: true,
                bottomTitles: AxisTitles(
                  axisNameWidget: const Text(
                    'File Name', // X-axis label
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                  axisNameSize: 30, // Spacing for the axis label
                  sideTitles: SideTitles(
                    showTitles: true,
                    getTitlesWidget: (double value, TitleMeta meta) {
                      const style = TextStyle(
                        color: Colors.black,
                        fontSize: 12,
                      );
                      switch (value.toInt()) {
                        case 0:
                          return Text('file1.txt', style: style);
                        case 1:
                          return Text('file2.jpg', style: style);
                        case 2:
                          return Text('file3.docx', style: style);
                        case 3:
                          return Text('file4.png', style: style);
                        case 4:
                          return Text('file5.pdf', style: style);
                        case 5:
                          return Text('file6.txt', style: style);
                        // case 6:
                        //   return Text('file7.docx', style: style);
                        default:
                          return Container();
                      }
                    },
                  ),
                ),
                leftTitles: AxisTitles(
                  axisNameWidget: const Text(
                    'Size (MB)', // Y-axis label
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                  axisNameSize: 30, // Spacing for the axis label
                  sideTitles: SideTitles(
                    showTitles: true,
                    getTitlesWidget: (double value, TitleMeta meta) {
                      return Text('${value.toInt()} MB', style: const TextStyle(fontSize: 12,),);
                    },
                  ),
                ),
              ),
              borderData: FlBorderData(show: false),
              barGroups: _createFileSizeBarGroups(),
            ),
          ),
        ),
      ],
    );
  }

  // Method to generate file size bar groups
  List<BarChartGroupData> _createFileSizeBarGroups() {
    return [
      BarChartGroupData(x: 0, barRods: [
        BarChartRodData(toY: 10, color: Colors.purple, width: 20), // file1.txt
      ]),
      BarChartGroupData(x: 1, barRods: [
        BarChartRodData(toY: 20, color: Colors.purple, width: 20), // file2.jpg
      ]),
      BarChartGroupData(x: 2, barRods: [
        BarChartRodData(toY: 45, color: Colors.purple, width: 20), // file3.docx
      ]),
      BarChartGroupData(x: 3, barRods: [
        BarChartRodData(toY: 30, color: Colors.purple, width: 20), // file4.png
      ]),
      BarChartGroupData(x: 4, barRods: [
        BarChartRodData(toY: 25, color: Colors.purple, width: 20), // file5.pdf
      ]),
      BarChartGroupData(x: 5, barRods: [
        BarChartRodData(toY: 15, color: Colors.purple, width: 20), // file6.txt
      ]),
      // BarChartGroupData(x: 6, barRods: [
      //   BarChartRodData(toY: 35, color: Colors.purple, width: 20), // file7.docx
      // ]),
    ];
  }
}
