rule Sample{
    meta:
        description = "sample rule"
        author = "Avantika"
    
    strings:
        $s1 = "hello" nocase ascii
        $s2 = "bye"
    
    condition:
        $s1 and $s2
}

rule Sqm{
    meta:
        description = "detection of unexpected sqm activity, might indicate network issues or interference by malware"
        author = "Avantika"
    
    strings:
        $sqm_fail = "Failed to start upload"
        $sqm_warning = "Warning: Failed to upload all unsent reports"
    
    condition:
        $sqm_fail or $sqm_warning
}

rule GerneralLogError{
    meta:
        description = "Detect general errors in the log file that might indicate issues or potential security incidents."
        author = "Avantika"
    
    strings:
        $warning = "Warning"
        $error = "Error"
        $fail = "Failed"
    
    condition:
        $error or $fail or $warning
}

rule NTTransactionCreation{
    meta:
        description = "Detect the creation of NT transactions, which could be related to system modifications."
        author = "Avantika"
    
    strings:
        $transaction_create = "Creating NT transaction"
        $transaction_result = "Created NT transaction"
    
    condition:
        $transaction_create or $transaction_result
}



