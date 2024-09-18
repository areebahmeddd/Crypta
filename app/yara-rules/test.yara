rule Detect_Plaintext_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects plain text files by analyzing common file characteristics"

    strings:
        $newline = "\n"
        $carriage_return = "\r"

    condition:
        $newline in (0..10240) or $carriage_return in (0..10240)
}

rule Detect_XML_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects XML files based on typical XML tags"

    strings:
        $xml_header = "<?xml"
        $xml_tag = "<root>"

    condition:
        $xml_header at 0 or $xml_tag in (0..filesize)
}

rule Detect_HTML_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects HTML files based on common HTML tags"

    strings:
        $html_doctype = "<!DOCTYPE html>"
        $html_tag = "<html>"

    condition:
        $html_doctype at 0 or $html_tag in (0..filesize)
}

rule Detect_JSON_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects JSON files based on their structure"

    strings:
        $json_brace = "{"
        $json_bracket = "["

    condition:
        $json_brace at 0 or $json_bracket at 0
}

rule Detect_CSS_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects CSS files based on common CSS syntax"

    strings:
        $css_selector = ".class"
        $css_brace = "{"

    condition:
        $css_selector in (0..filesize) or $css_brace in (0..filesize)
}

rule Detect_JS_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects JavaScript files based on common JS patterns"

    strings:
        $js_function = "function"
        $js_var = "var "

    condition:
        $js_function in (0..filesize) or $js_var in (0..filesize)
}

rule Detect_YAML_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects YAML files based on common YAML patterns"

    strings:
        $yaml_key_value = ": "
        $yaml_dash = "- "

    condition:
        $yaml_key_value in (0..filesize) or $yaml_dash in (0..filesize)
}

rule Detect_TOML_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects TOML files based on common TOML syntax"

    strings:
        $toml_key_value = "= "
        $toml_section = "["

    condition:
        $toml_key_value in (0..filesize) or $toml_section at 0
}

rule Detect_INI_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects INI configuration files based on their structure"

    strings:
        $ini_section = "["
        $ini_key_value = "= "

    condition:
        $ini_section at 0 or $ini_key_value in (0..filesize)
}

rule Detect_Log_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects log files based on common log patterns"

    strings:
        $log_timestamp = /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/
        $log_level = /INFO|WARN|ERROR|DEBUG/

    condition:
        $log_timestamp in (0..filesize) or $log_level in (0..filesize)
}

rule Detect_SQL_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects SQL files based on common SQL commands"

    strings:
        $sql_select = "SELECT"
        $sql_insert = "INSERT INTO"
        $sql_create = "CREATE TABLE"

    condition:
        $sql_select in (0..filesize) or $sql_insert in (0..filesize) or $sql_create in (0..filesize)
}

rule Detect_Bash_Scripts {
    meta:
        author = "Shivansh Karan"
        description = "Detects Bash scripts based on common Bash syntax"

    strings:
        $bash_shebang = "#!/bin/bash"
        $bash_var = "$"

    condition:
        $bash_shebang at 0 or $bash_var in (0..filesize)
}

rule Detect_Python_Scripts {
    meta:
        author = "Shivansh Karan"
        description = "Detects Python scripts based on common Python syntax"

    strings:
        $python_shebang = "#!/usr/bin/python"
        $python_def = "def "
        $python_import = "import "

    condition:
        $python_shebang at 0 or $python_def in (0..filesize) or $python_import in (0..filesize)
}

rule Detect_Ruby_Scripts {
    meta:
        author = "Shivansh Karan"
        description = "Detects Ruby scripts based on common Ruby syntax"

    strings:
        $ruby_shebang = "#!/usr/bin/ruby"
        $ruby_def = "def "
        $ruby_require = "require "

    condition:
        $ruby_shebang at 0 or $ruby_def in (0..filesize) or $ruby_require in (0..filesize)
}

rule Detect_PHP_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects PHP files based on common PHP syntax"

    strings:
        $php_open = "<?php"
        $php_function = "function "

    condition:
        $php_open at 0 or $php_function in (0..filesize)
}

rule Detect_Java_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects Java source files based on common Java syntax"

    strings:
        $java_class = "class "
        $java_package = "package "

    condition:
        $java_class in (0..filesize) or $java_package in (0..filesize)
}

rule Detect_JSONL_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects JSONL (JSON Lines) files based on their structure"

    strings:
        $jsonl_brace = "{\n"
        $jsonl_bracket = "[\n"

    condition:
        $jsonl_brace at 0 or $jsonl_bracket at 0
}

rule Detect_CSV_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects CSV files based on typical CSV structure"

    strings:
        $csv_comma = ","
        $csv_newline = "\n"

    condition:
        $csv_comma in (0..filesize) or $csv_newline in (0..filesize)
}

rule Detect_TSV_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects TSV files based on typical TSV structure"

    strings:
        $tsv_tab = "\t"
        $tsv_newline = "\n"

    condition:
        $tsv_tab in (0..filesize) or $tsv_newline in (0..filesize)
}

rule Detect_Properties_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects Java properties files based on common patterns"

    strings:
        $properties_key_value = "= "
        $properties_comment = "# "

    condition:
        $properties_key_value in (0..filesize) or $properties_comment at 0
}

rule Detect_RTF_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects RTF (Rich Text Format) files based on their file signatures"

    strings:
        $rtf_header = "{\\rtf1"

    condition:
        $rtf_header at 0
}

rule Detect_Docx_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects DOCX files based on ZIP structure and document.xml"

    strings:
        $docx_header = {50 4B 03 04}
        $docx_xml = "word/document.xml"

    condition:
        $docx_header at 0 and $docx_xml in (0..filesize)
}

rule Detect_PDF_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects PDF files based on common PDF file signatures"

    strings:
        $pdf_header = "%PDF-"

    condition:
        $pdf_header at 0
}

rule Detect_LaTeX_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects LaTeX files based on common LaTeX syntax"

    strings:
        $latex_header = "\\documentclass"
        $latex_command = "\\begin{"

    condition:
        $latex_header at 0 or $latex_command in (0..filesize)
}

rule Detect_Docs_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects DOC files based on file signatures"

    strings:
        $doc_header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $doc_header at 0
}

rule Detect_Markdown_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects Markdown files based on common Markdown syntax"

    strings:
        $md_heading = "# "
        $md_bold = "**"

    condition:
        $md_heading in (0..filesize) or $md_bold in (0..filesize)
}

rule Detect_Excel_Files {
    meta:
        author = "Shivansh Karan"
        description = "Detects Excel files based on ZIP structure and relevant XML files"

    strings:
        $excel_header = {50 4B 03 04}
        $excel_xml = "xl/workbook.xml"

    condition:
        $excel_header at 0 and $excel_xml in (0..filesize)
}
