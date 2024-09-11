import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';

class LineChartSample extends StatelessWidget {
  const LineChartSample({super.key});
  @override
  Widget build(BuildContext context) {
    return LineChart(
      LineChartData(
        gridData: FlGridData(show: true),
        titlesData: FlTitlesData(show: true),
        borderData: FlBorderData(
          show: true,
          border: Border.all(color: Colors.black, width: 1),
        ),
        lineBarsData: [
          LineChartBarData(
            spots: [
              FlSpot(0, 1),
              FlSpot(1, 2),
              FlSpot(2, 1.5),
              FlSpot(3, 3),
              FlSpot(4, 2.5),
              FlSpot(5, 4),
            ],
            isCurved: true,
            barWidth: 2,
            color: Colors.blue,
          ),
        ],
      ),
    );
  }
}
