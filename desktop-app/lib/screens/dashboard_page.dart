import "package:crypta/screens/home_page.dart";
import "package:crypta/utils/hexcolor.dart";
import "package:crypta/widgets/barchart.dart";
import "package:crypta/widgets/download_report.dart";
import "package:crypta/widgets/export_analysis.dart";
import "package:crypta/widgets/file_table.dart";
import "package:crypta/widgets/file_tables_2.dart";
import "package:crypta/widgets/linechart.dart";
import "package:crypta/widgets/search_bar.dart";
import "package:flutter/material.dart";
import "package:flutter_riverpod/flutter_riverpod.dart";
import "package:gap/gap.dart";

class DashboardPage extends ConsumerStatefulWidget {
  const DashboardPage({super.key});
  @override
  DashboardPageState createState() => DashboardPageState();
}

class DashboardPageState extends ConsumerState<DashboardPage> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(
        children: [
          // Sidebar
          Container(
            width: 200, // Fixed width for the sidebar
            color: myColorFromHex('#457d58'),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.start,
              children: [
                const DrawerHeader(
                  child: Text(
                    'Dashboard',
                    style: TextStyle(color: Colors.white, fontSize: 24),
                  ),
                ),
                ListTile(
                  leading: const Icon(Icons.home, color: Colors.white),
                  title:
                      const Text('Home', style: TextStyle(color: Colors.white)),
                  onTap: () {
                    Navigator.push(
                        context,
                        MaterialPageRoute(
                            builder: (context) => const HomePage()));
                  },
                ),
                ListTile(
                  leading: const Icon(Icons.chat, color: Colors.white),
                  title:
                      const Text('Chat', style: TextStyle(color: Colors.white)),
                  onTap: () {
                    // Navigator.push(
                    //     context,
                    //     MaterialPageRoute(
                    //         builder: (context) => const HomePage()));
                  },
                ),
                ListTile(
                  leading: const Icon(Icons.settings, color: Colors.white),
                  title: const Text('Settings',
                      style: TextStyle(color: Colors.white)),
                  onTap: () {
                    // Handle navigation or actions here
                  },
                ),
                // Add more items as needed
              ],
            ),
          ),

          // Main Content
          Expanded(
            child: Container(
              color: Colors.white,
              child: const Padding(
                padding: EdgeInsets.all(16.0),
                child: SingleChildScrollView(
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
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
