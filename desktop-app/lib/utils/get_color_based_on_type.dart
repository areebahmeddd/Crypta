import 'package:crypta/utils/hexcolor.dart';
import 'package:flutter/material.dart';

Color getColorBasedOnType(String type) {
  switch (type) {
    case 'High':
      return myColorFromHex("#F28B82");
    case 'Medium':
      return myColorFromHex("#F7BC71");
    case 'Low to Medium':
      return myColorFromHex("#FFF4B3");
    case 'Low':
      return myColorFromHex("#E0E0E0");
    default:
      return Colors.grey;
  }
}
