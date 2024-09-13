import 'package:crypta/utils/hexcolor.dart';
import 'package:flutter/material.dart';

Color getColorBasedOnType(String type) {
  switch (type) {
    case 'High':
      return myColorFromHex("#DF5656");
    case 'Medium':
      return myColorFromHex("#F8A72C");
    case 'Low to Medium':
      return myColorFromHex("#FFD65A");
    case 'Low':
      return myColorFromHex("#E0E0E0");
    default:
      return Colors.grey;
  }
}
