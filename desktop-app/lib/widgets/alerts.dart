import 'package:crypta/providers/analysis_provider.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

class Alerts extends ConsumerStatefulWidget {
  const Alerts({super.key});

  @override
  ConsumerState<Alerts> createState() {
    return _AlertsState();
  }
}

class _AlertsState extends ConsumerState<Alerts> {
  // Track the expanded state of each alert type
  final Map<String, bool> _expandedStates = {};

  @override
  Widget build(BuildContext context) {
    final Map<String, dynamic> analysis = ref.read(analysisProvider);

    Map<String, List<String>> groupAlertsByType(List<dynamic> alerts) {
      final Map<String, List<String>> groupedAlerts = {};

      for (var alert in alerts) {
        final type = alert['type'] as String;
        final detail = alert['detail'] as String;

        if (groupedAlerts.containsKey(type)) {
          groupedAlerts[type]!.add(detail);
        } else {
          groupedAlerts[type] = [detail];
        }
      }

      return groupedAlerts;
    }

    Widget buildAlertsSections(Map<String, List<String>> groupedAlerts) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: groupedAlerts.entries.map((entry) {
          final type = entry.key;
          final details = entry.value;
          
          // Initialize the expanded state for the type if not already present
          if (!_expandedStates.containsKey(type)) {
            _expandedStates[type] = false;
          }

          // Show the first 1 or 2 details as a snippet
          final visibleDetails = _expandedStates[type]! ? details : details.take(2).toList();
          final hasMore = details.length > 2;

          return Padding(
            padding: const EdgeInsets.all(8.0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  type,
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 16,
                  ),
                ),
                const SizedBox(height: 8),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    for (var detail in visibleDetails)
                      Padding(
                        padding: const EdgeInsets.only(bottom: 8.0),
                        child: Text(
                          '• $detail',
                          style: const TextStyle(fontSize: 14),
                        ),
                      ),
                    if (hasMore && !_expandedStates[type]!)
                      Padding(
                        padding: const EdgeInsets.only(bottom: 8.0),
                        child: Text(
                          '...and ${details.length - 2} more',
                          style: const TextStyle(
                            fontStyle: FontStyle.italic,
                            color: Colors.grey,
                            fontSize: 14,
                          ),
                        ),
                      ),
                  ],
                ),
                if (hasMore)
                  TextButton(
                    onPressed: () {
                      setState(() {
                        _expandedStates[type] = !_expandedStates[type]!;
                      });
                    },
                    child: Text(
                      _expandedStates[type]! ? 'Show Less' : 'Show More',
                      style: const TextStyle(
                        color: Colors.blue,
                        fontWeight: FontWeight.bold,
                        fontSize: 14,
                      ),
                    ),
                  ),
              ],
            ),
          );
        }).toList(),
      );
    }

    final List<dynamic> alerts = analysis['gemini']['alerts'] ?? [];
    final Map<String, List<String>> groupedAlerts = groupAlertsByType(alerts);

    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(10),
        boxShadow: const [
          BoxShadow(
            color: Colors.black12,
            blurRadius: 10,
            spreadRadius: 2,
          ),
        ],
        color: Colors.white,
      ),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              "Alert",
              style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),
            ),
            const SizedBox(height: 8),
            buildAlertsSections(groupedAlerts),
            const SizedBox(height: 16),
          ],
        ),
      ),
    );
  }
}
