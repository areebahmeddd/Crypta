import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:gap/gap.dart';

class Piechart extends StatefulWidget {
  const Piechart({super.key});

  @override
  State<StatefulWidget> createState() {
    return _PiechartState();
  }
}

class _PiechartState extends State<Piechart> {
  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        const Center(
          child: Text('Vulnerability Type Distribution', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 24),),
        ),
        Gap(30),
        Expanded(
          child: PieChart(
            PieChartData(
              centerSpaceRadius: 0,
              sections: [
                PieChartSectionData(
                  color: Colors.red,
                  value: 25,
                  title: 'SQL Injection',
                  radius: 200,
                ),
                PieChartSectionData(
                  color: Colors.blue,
                  value: 20,
                  title: 'Cross-Site Scripting',
                  radius: 200,
                ),
                PieChartSectionData(
                  color: Colors.green,
                  value: 30,
                  title: 'Broken Authentication',
                  radius: 200,
                ),
                PieChartSectionData(
                  color: Colors.yellow,
                  value: 25,
                  title: 'Sensitive Data Exposure',
                  radius: 200,
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}
