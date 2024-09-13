import 'package:crypta/utils/hexcolor.dart';
import 'package:flutter/material.dart';

Color getColorBasedOnValue(int value) {
  if (value == 0) {
    return myColorFromHex("#90EE90"); // Green for 0
  } else if (value >= 1 && value <= 10) {
    return myColorFromHex("#708090"); // Gray for 1-10
  } else if (value >= 11 && value <= 50) {
    return myColorFromHex("#D2B04C"); // Yellow for 11-50
  } else if (value >= 51 && value <= 100) {
    return myColorFromHex("#FF8C00"); // Orange for 51-100
  } else {
    return myColorFromHex("#8B0000"); // Red for 101+
  }
}