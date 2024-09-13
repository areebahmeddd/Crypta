import "package:crypta/screens/analysis_page.dart";
import "package:crypta/screens/chat_page.dart";
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
  bool isAnalysisPage = true;
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
                  leading: const Icon(Icons.analytics, color: Colors.white),
                  title:
                      const Text('Analysis', style: TextStyle(color: Colors.white)),
                  onTap: () {
                    setState(() {
                      isAnalysisPage = true; 
                    });
                  },
                ),
                ListTile(
                  leading: const Icon(Icons.chat, color: Colors.white),
                  title:
                      const Text('Chat', style: TextStyle(color: Colors.white)),
                  onTap: () {
                    setState(() {
                      isAnalysisPage = false; 
                    });
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
              child:  Padding(
                padding: const EdgeInsets.all(16.0),
                child: isAnalysisPage ? const AnalysisPage() : const ChatPage(),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
