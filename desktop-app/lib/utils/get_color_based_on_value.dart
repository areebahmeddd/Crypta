import 'package:crypta/utils/hexcolor.dart';
import 'package:flutter/material.dart';

Color getColorBasedOnValue(int value) {
  if (value == 0) {
    return myColorFromHex("#8AC449"); // Green for 0
  } else if (value >= 1 && value <= 20) {
    return myColorFromHex("#FFD65A"); // Gray for 1-10
  } else if (value >= 21 && value <= 40) {
    return myColorFromHex("#F8A72C"); // Yellow for 11-50
  } else if (value >= 41) {
    return myColorFromHex("#DF5656"); // Orange for 51-100
  } else {
    return myColorFromHex("#8B0000"); // Red for 101+
  }
}