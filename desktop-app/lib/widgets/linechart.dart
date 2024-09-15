import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:gap/gap.dart';

class LineChartSample extends StatelessWidget {
  const LineChartSample({super.key});

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        const Center(
          child: Text('File Type Distribution', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 24),),
        ),
        Gap(30),
        Expanded(// Adjust the height as needed
          child: LineChart(
            LineChartData(
              titlesData: FlTitlesData(
                bottomTitles: AxisTitles(
                  axisNameWidget: const Text(
                    'File Types', // X-axis label
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                  axisNameSize: 30, // Spacing for the axis label
                  sideTitles: SideTitles(
                    showTitles: true,
                    getTitlesWidget: (double value, TitleMeta meta) {
                      const labels = [
                        'Text',
                        'Image',
                        'Document'
                      ]; // Custom labels
                      String text = '';
                      if (value.toInt() >= 0 && value.toInt() < labels.length) {
                        text = labels[value.toInt()];
                      }
                      return SideTitleWidget(
                        axisSide: meta.axisSide,
                        child: Text(text, style: const TextStyle(fontSize: 12)),
                      );
                    },
                  ),
                ),
                leftTitles: AxisTitles(
                  axisNameWidget: const Text(
                    'Number of Files', // Y-axis label
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                  axisNameSize: 30, // Spacing for the axis label
                  sideTitles: SideTitles(
                    showTitles: true,
                    getTitlesWidget: (double value, TitleMeta meta) {
                      return Text(
                        '${value.toInt()}',
                        style: const TextStyle(fontSize: 12),
                      );
                    },
                  ),
                ),
              ),
              gridData: const FlGridData(show: true),
              borderData: FlBorderData(
                show: true,
                border: Border.all(color: Colors.black, width: 1),
              ),
              lineBarsData: [
                LineChartBarData(
                  spots: [
                    FlSpot(0, 1),
                    FlSpot(1, 2),
                    FlSpot(2, 3),
                  ],
                  isCurved: true,
                  barWidth: 3,
                  color: Colors.blue,
                  dotData:
                      FlDotData(show: true), // Show dots at each data point
                  belowBarData: BarAreaData(
                    show: true,
                    color: Colors.blue
                        .withOpacity(0.3), // Fill the area below the line
                  ),
                ),
              ],
              lineTouchData: LineTouchData(
                touchTooltipData: LineTouchTooltipData(
                  getTooltipItems: (touchedSpots) {
                    return touchedSpots.map((LineBarSpot touchedSpot) {
                      final label = ['Text', 'Image', 'Document'];
                      return LineTooltipItem(
                        '${label[touchedSpot.x.toInt()]}: ${touchedSpot.y}',
                        const TextStyle(color: Colors.white),
                      );
                    }).toList();
                  },
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}
