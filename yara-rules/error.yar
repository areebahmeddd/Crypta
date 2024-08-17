rule GeneralLogError {
    meta:
        author = "Avantika Kesarwani"
        description = "Detect general errors in the log file that might indicate issues or potential security incidents"

    strings:
        $warning = "Warning"
        $error = "Error"
        $fail = "Failed"

    condition:
        $error or $fail or $warning
}

rule SoftwareQualityMetrics {
    meta:
        author = "Avantika Kesarwani"
        description = "Detection of unexpected SQM activity, which might indicate network issues or interference by malware"

    strings:
        $sqm_fail = "Failed to start upload"
        $sqm_warning = "Warning: Failed to upload all unsent reports"

    condition:
        $sqm_fail or $sqm_warning
}

rule NTTransactionCreation {
    meta:
        author = "Avantika Kesarwani"
        description = "Detect the creation of NT transactions, which could be related to system modifications"

    strings:
        $transaction_create = "Creating NT transaction"

    condition:
        $transaction_create
}
