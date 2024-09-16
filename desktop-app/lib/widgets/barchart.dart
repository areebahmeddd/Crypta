import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';

class BarChartSample extends StatefulWidget {
  const BarChartSample({super.key});
  @override
  _BarChartSampleState createState() => _BarChartSampleState();
}

class _BarChartSampleState extends State<BarChartSample> {
  @override
  Widget build(BuildContext context) {
    return BarChart(
      BarChartData(
        alignment: BarChartAlignment.spaceAround,
        maxY: 100, // Define the maximum value for the Y-axis
        barTouchData:
            BarTouchData(enabled: true), // Disable touch interactions
        titlesData: FlTitlesData(
          show: true,
          bottomTitles: AxisTitles(
            sideTitles: SideTitles(
              showTitles: true,
              getTitlesWidget: (double value, TitleMeta meta) {
                const style = TextStyle(
                  color: Colors.black,
                  fontWeight: FontWeight.bold,
                  fontSize: 14,
                );
                switch (value.toInt()) {
                  case 0:
                    return Text('2020', style: style);
                  case 1:
                    return Text('2021', style: style);
                  case 2:
                    return Text('2022', style: style);
                  case 3:
                    return Text('2023', style: style);
                  default:
                    return Container();
                }
              },
            ),
          ),
          leftTitles: AxisTitles(
            sideTitles: SideTitles(
              showTitles: true,
              getTitlesWidget: (double value, TitleMeta meta) {
                return Text(value.toInt().toString());
              },
            ),
          ),
        ),
        borderData:
            FlBorderData(show: false), // Hide the borders around the chart
        barGroups: _createBarGroups(), // Call the method that creates the bars
      ),
    );
  }

  // Method to generate bar groups
  List<BarChartGroupData> _createBarGroups() {
    return [
      BarChartGroupData(x: 0, barRods: [
        BarChartRodData(
          toY: 5, // Value for 2020
          color: Colors.blue,
          width: 20,
        ),
      ]),
      BarChartGroupData(x: 1, barRods: [
        BarChartRodData(
          toY: 25, // Value for 2021
          color: Colors.blue,
          width: 20,
        ),
      ]),
      BarChartGroupData(x: 2, barRods: [
        BarChartRodData(
          toY: 100, // Value for 2022
          color: Colors.blue,
          width: 20,
        ),
      ]),
      BarChartGroupData(x: 3, barRods: [
        BarChartRodData(
          toY: 75, // Value for 2023
          color: Colors.blue,
          width: 20,
        ),
      ]),
    ];
  }
}
