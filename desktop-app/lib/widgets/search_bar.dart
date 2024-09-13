import 'dart:developer';

import 'package:crypta/utils/hexcolor.dart';
import 'package:flutter/material.dart';

class CustomSearchBar extends StatefulWidget {
  const CustomSearchBar({super.key});
  @override
  CustomSearchBarState createState() => CustomSearchBarState();
}

class CustomSearchBarState extends State<CustomSearchBar> {
  String? selectedCategory = 'All';
  String? selectedStatus = 'All';
  final TextEditingController searchController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(10),
        boxShadow: const [
          BoxShadow(
            color: Colors.black12,
            blurRadius: 10,
            spreadRadius: 2,
          ),
        ],
      ),
      child: Row(
        children: [
          // Search Field
          Expanded(
            flex: 3,
            child: TextField(
              controller: searchController,
              decoration: InputDecoration(
                prefixIcon: const Icon(Icons.search),
                hintText: 'Search for category, file, vulnerability, etc.',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10),
                  borderSide: BorderSide.none,
                ),
                suffixIcon: GestureDetector(
                    onTap: () {}, child: const Icon(Icons.filter_alt_outlined)),
                filled: true,
                fillColor: Colors.grey[200],
              ),
            ),
          ),
          const SizedBox(width: 10),

          // // Category Dropdown
          // Expanded(
          //   flex: 1,
          //   child: DropdownButtonFormField<String>(
          //     value: selectedCategory,
          //     items: ['All', 'Category 1', 'Category 2']
          //         .map<DropdownMenuItem<String>>((String value) {
          //       return DropdownMenuItem<String>(
          //         value: value,
          //         child: Text(value),
          //       );
          //     }).toList(),
          //     decoration: InputDecoration(
          //       contentPadding: const EdgeInsets.symmetric(horizontal: 10),
          //       filled: true,
          //       fillColor: Colors.grey[200],
          //       border: OutlineInputBorder(
          //         borderRadius: BorderRadius.circular(10),
          //         borderSide: BorderSide.none,
          //       ),
          //     ),
          //     onChanged: (String? newValue) {
          //       setState(() {
          //         selectedCategory = newValue!;
          //       });
          //     },
          //   ),
          // ),
          // const SizedBox(width: 10),

          // // Status Dropdown
          // Expanded(
          //   flex: 1,
          //   child: DropdownButtonFormField<String>(
          //     value: selectedStatus,
          //     items: ['All', 'Active', 'Inactive']
          //         .map<DropdownMenuItem<String>>((String value) {
          //       return DropdownMenuItem<String>(
          //         value: value,
          //         child: Text(value),
          //       );
          //     }).toList(),
          //     decoration: InputDecoration(
          //       contentPadding: EdgeInsets.symmetric(horizontal: 10),
          //       filled: true,
          //       fillColor: Colors.grey[200],
          //       border: OutlineInputBorder(
          //         borderRadius: BorderRadius.circular(10),
          //         borderSide: BorderSide.none,
          //       ),
          //     ),
          //     onChanged: (String? newValue) {
          //       setState(() {
          //         selectedStatus = newValue!;
          //       });
          //     },
          //   ),
          // ),

          // Search Button
          ElevatedButton(
            onPressed: () {
              // Handle search functionality
              log("Search: ${searchController.text}, "
                  "Category: $selectedCategory, "
                  "Status: $selectedStatus");
            },
            style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(horizontal: 30, vertical: 20),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(10),
              ),
              backgroundColor: myColorFromHex('#457d58'),
            ),
            child: const Text(
              'SEARCH',
              style: TextStyle(color: Colors.white),
            ),
          ),
        ],
      ),
    );
  }
}
