import 'package:crypta/utils/hexcolor.dart';
import 'package:flutter/material.dart';

Color getColorBasedOnType(String type) {
  switch (type) {
    case 'High':
      return myColorFromHex("#8B0000");
    case 'Medium':
      return myColorFromHex("#FF8C00");
    case 'Low to Medium':
      return myColorFromHex("#D2B04C");
    case 'Low':
      return myColorFromHex("#708090");
    default:
      return Colors.grey;
  }
}
