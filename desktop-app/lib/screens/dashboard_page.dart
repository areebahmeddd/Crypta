import "dart:developer";

import "package:crypta/providers/analysis_provider.dart";
import "package:crypta/providers/files_provider.dart";
import "package:crypta/screens/analysis_page.dart";
import "package:crypta/screens/chat_page.dart";
import "package:crypta/screens/home_page.dart";
import "package:crypta/utils/hexcolor.dart";
import "package:flutter/material.dart";
import "package:flutter_riverpod/flutter_riverpod.dart";
import "package:url_launcher/url_launcher.dart";

class DashboardPage extends ConsumerStatefulWidget {
  const DashboardPage({super.key});
  @override
  DashboardPageState createState() => DashboardPageState();
}

class DashboardPageState extends ConsumerState<DashboardPage> {
  bool isAnalysisPage = true;

  void _goToGithub() async {
    const url = 'https://github.com/areebahmeddd/Crypta';
    try {
      await launchUrl(Uri.parse(url));
    } catch (e) {
      log(e.toString());
    }
  }

  void _goToWebsite() async {
    const url = '';
    try {
      await launchUrl(Uri.parse(url));
    } catch (e) {
      log(e.toString());
    }
  }

  void _goToYoutube() async {
    const url = 'https://youtube.com/watch?v=-SN-jaTEgIE';
    try {
      await launchUrl(Uri.parse(url));
    } catch (e) {
      log(e.toString());
    }
  }

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
                const SizedBox(
                  height: 90,
                  child: Center(
                    child: DrawerHeader(
                      child: Text(
                        'Dashboard',
                        style: TextStyle(color: Colors.white, fontSize: 24),
                      ),
                    ),
                  ),
                ),
                ListTile(
                  leading: const Icon(Icons.home, color: Colors.white),
                  title:
                      const Text('Home', style: TextStyle(color: Colors.white)),
                  onTap: () {
                    ref.read(filesProvider.notifier).clearFiles();
                    ref.read(analysisProvider.notifier).clearAnalysis();
                    Navigator.push(
                        context,
                        MaterialPageRoute(
                            builder: (context) => const HomePage()));
                  },
                ),
                ListTile(
                  leading: Icon(Icons.analytics,
                      color: isAnalysisPage ? Colors.black : Colors.white),
                  title: Text('Analysis',
                      style: TextStyle(
                          color: isAnalysisPage ? Colors.black : Colors.white)),
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
                  leading:
                      const Icon(Icons.groups_2_outlined, color: Colors.white),
                  title:
                      const Text('Team', style: TextStyle(color: Colors.white)),
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
                const Spacer(),
                ListTile(
                  leading: const Image(
                    image: AssetImage(
                      'assets/images/domain.png',
                    ),
                    height: 22,
                  ),
                  title: const Text('Website',
                      style: TextStyle(color: Colors.white)),
                  onTap: _goToWebsite,
                ),
                ListTile(
                  leading: const Image(
                    image: AssetImage(
                      'assets/images/github-logo.png',
                    ),
                    height: 22,
                  ),
                  title: const Text('Github',
                      style: TextStyle(color: Colors.white)),
                  onTap: _goToGithub,
                ),
                ListTile(
                  leading: const Image(
                    image: AssetImage(
                      'assets/images/youtube.png',
                    ),
                    height: 22,
                  ),
                  title: const Text('Youtube',
                      style: TextStyle(color: Colors.white)),
                  onTap: _goToYoutube,
                ),
              ],
            ),
          ),

          // Main Content
          Expanded(
            child: Container(
              color: Colors.white,
              child: Padding(
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
