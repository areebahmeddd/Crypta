import 'package:crypta/providers/files_provider.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

class FileDetails extends ConsumerStatefulWidget {
  final List<Map<String, String>> uploadedFilesMetadata;
  final int index;
  const FileDetails(
      {super.key, required this.index, required this.uploadedFilesMetadata});

  @override
  ConsumerState<ConsumerStatefulWidget> createState() {
    return FileDetailsState();
  }
}

class FileDetailsState extends ConsumerState<FileDetails> {
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(10),
      child: ListTile(
        title: Text(widget.uploadedFilesMetadata[widget.index]['name']!),
        subtitle: Text(
          'Size: ${widget.uploadedFilesMetadata[widget.index]['size']}\n'
          'Type: ${widget.uploadedFilesMetadata[widget.index]['type']}\n'
          'Extension: ${widget.uploadedFilesMetadata[widget.index]['extension']}',
        ),
        trailing: IconButton(
          icon: const Icon(Icons.delete),
          onPressed: () {
            setState(() {
              ref.read(filesProvider.notifier).removeFile(
                  widget.uploadedFilesMetadata[widget.index]['path']!);
              widget.uploadedFilesMetadata.removeAt(widget.index);
            });
          },
        ),
      ),
    );
  }
}
