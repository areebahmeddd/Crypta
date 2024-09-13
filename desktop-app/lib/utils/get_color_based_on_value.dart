import 'package:crypta/utils/hexcolor.dart';
import 'package:flutter/material.dart';

Color getColorBasedOnValue(int value) {
  if (value == 0) {
    return myColorFromHex("#C3E88D"); // Green for 0
  } else if (value >= 1 && value <= 20) {
    return myColorFromHex("#FFF4B3"); // Gray for 1-10
  } else if (value >= 21 && value <= 40) {
    return myColorFromHex("#F7BC71"); // Yellow for 11-50
  } else if (value >= 41) {
    return myColorFromHex("#F28B82"); // Orange for 51-100
  } else {
    return myColorFromHex("#8B0000"); // Red for 101+
  }
}