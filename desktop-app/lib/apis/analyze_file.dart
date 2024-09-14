import 'dart:convert';
import 'dart:developer';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:path/path.dart';

Future<Map<String, dynamic>> analyzeFile(
    List<File> files, File yaraFile) async {
  const String url = 'http://127.0.0.1:8000/api/analyze';

  const header = <String, String>{
    'content-type': 'multipart/form-data',
  };

  log('making request');
  var request = http.MultipartRequest('POST', Uri.parse(url));

  for (var file in files) {
    request.files.add(
      await http.MultipartFile.fromPath('uploadedFiles', file.path,
          filename: basename(file.path)),
    );
  }

  log(request.files.toString());

  request.files.add(
    await http.MultipartFile.fromPath('yaraFile', yaraFile.path,
        filename: basename(yaraFile.path)),
  );

  log(request.files.toString());



  request.headers.addAll(header);

  log('sending request');

  var response = await request.send();
  log(response.statusCode.toString());


  if (response.statusCode == 200) {
    final responseData = await response.stream.bytesToString();
    log(responseData);
    final Map<String, dynamic> result = json.decode(responseData);
    return {
      'status': 'success',
      'message': 'File uploaded successfully',
      'data': result,
    };
  } else {
    return {
      'status': 'error',
      'message': response.reasonPhrase,
    };
  }
}
