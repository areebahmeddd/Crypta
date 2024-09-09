import "package:crypta/utils/hexcolor.dart";
import "package:crypta/widgets/file_table.dart";
import "package:crypta/widgets/file_tables_2.dart";
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
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            // Sidebar
            Container(
              width: 250, // Fixed width for the sidebar
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
                    title: const Text('Home',
                        style: TextStyle(color: Colors.white)),
                    onTap: () {
                      // Handle navigation or actions here
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
                            child: FileTable()),
                        Gap(20),
                        SizedBox(
                            height: 500,
                            width: double.infinity,
                            child: FileTable2()),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
