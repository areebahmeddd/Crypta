import 'package:crypta/apis/download_report_api.dart';
import 'package:crypta/model/downloadable_file_types.dart';
import 'package:crypta/providers/analysis_provider.dart';
import 'package:crypta/utils/hexcolor.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:gap/gap.dart';
import 'package:open_filex/open_filex.dart';

class DownloadReport extends ConsumerStatefulWidget {
  const DownloadReport({super.key});
  @override
  ConsumerState<DownloadReport> createState() {
    return _DownloadReportState();
  }
}

class _DownloadReportState extends ConsumerState<DownloadReport> {
  String exportFileType = downloadableFileTypes[0];
  var isDownloading = false;
  @override
  Widget build(BuildContext context) {
    List<dynamic> results = ref.read(analysisProvider)['results'];

    Future<void> onDownloadReport() async {
      setState(() {
        isDownloading = true;
      });
      var result = await downloadReport(results);
      setState(() {
        isDownloading = false;
      });
      if (result != null) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Report downloaded successfully!'),
          ),
        );
        await Future.delayed(const Duration(seconds: 1));
        OpenFilex.open(result);
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Failed to download report!'),
          ),
        );
      }
    }

    return Row(
      children: [
        ElevatedButton(
          onPressed: onDownloadReport,
          style: ElevatedButton.styleFrom(
              backgroundColor: myColorFromHex('#457d58'),
              padding: const EdgeInsets.symmetric(horizontal: 20),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
              )),
          child:  Padding(
            padding: const EdgeInsets.symmetric(horizontal: 100, vertical: 8),
            child: isDownloading ? const SizedBox(
              height: 18,
              width: 18,
              child:  CircularProgressIndicator(
                color: Colors.white,
              ),
            ): const Text(
              'Download Report',
              style: TextStyle(color: Colors.white),
            ),
          ),
        ),
        const Gap(20),
        DropdownButton<String>(
          value: exportFileType, // Current selected value
          items: downloadableFileTypes
              .map((String fileType) => DropdownMenuItem<String>(
                    value: fileType,
                    child: Text(fileType),
                  ))
              .toList(),
          onChanged: (String? newValue) {
            setState(() {
              exportFileType = newValue ?? exportFileType; // Set new value
            });
          },
        ),
      ],
    );
  }
}
