import 'dart:convert';
import 'dart:developer';
import 'dart:io';
import 'package:path_provider/path_provider.dart';
import 'package:http/http.dart' as http;

Future<String?> downloadReport(List<dynamic> results) async {
  try {
    String url = 'http://127.0.0.1:8000/api/download';
    var body = <String, dynamic>{'data': results, 'type': 'PDF'};

    // Sending POST request to the server
    final response = await http.post(Uri.parse(url), body: jsonEncode(body));

    if (response.statusCode == 200) {
      // Since the response is a PDF file, not JSON, save the PDF directly
      Directory appDir = await getApplicationDocumentsDirectory();
      String fileName =
          'report.pdf'; // You can get this from the headers or set a default name
      String localPath = '${appDir.path}/$fileName';

      // Write the file to the local storage
      File file = File(localPath);
      await file.writeAsBytes(response.bodyBytes);

      log('PDF file downloaded and saved to: $localPath');

      return localPath;
    } else {
      log('Failed to download report: ${response.body}');

      return null;
    }
  } catch (e) {
    log('Failed to download report: $e');
    return null;
  }
}
