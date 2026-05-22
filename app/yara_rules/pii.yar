/*
AEGIS YARA Rules - PII Detection
Detects personally identifiable information patterns.
Complements regex-based detection with additional patterns.
Target latency: <10ms per scan
*/

rule pii_ssn_pattern
{
    meta:
        description = "Detects US Social Security Number patterns"
        category = "pii"
        severity = "critical"
        pii_type = "SSN"
        author = "AEGIS Team"
    
    strings:
        // Various SSN formats
        $ssn1 = /\b\d{3}-\d{2}-\d{4}\b/
        $ssn2 = /\b\d{3}\.\d{2}\.\d{4}\b/
        $ssn3 = /\b\d{3}\s\d{2}\s\d{4}\b/
        
        // SSN keywords near numbers
        $keyword1 = "social security" nocase
        $keyword2 = "SSN" nocase
        $keyword3 = "ss#" nocase
        $keyword4 = "ss number" nocase
    
    condition:
        (any of ($ssn*)) or (any of ($keyword*))
}

rule pii_credit_card
{
    meta:
        description = "Detects credit card number patterns"
        category = "pii"
        severity = "critical"
        pii_type = "CREDIT_CARD"
        author = "AEGIS Team"
    
    strings:
        // Credit card keywords
        $cc1 = "credit card number" nocase
        $cc2 = "card number" nocase
        $cc3 = "CVV" nocase
        $cc4 = "CVC" nocase
        $cc5 = "expiration date" nocase
        $cc6 = "exp date" nocase
        $cc7 = "valid thru" nocase
        
        // Card brand patterns
        $visa = /\b4[0-9]{12}(?:[0-9]{3})?\b/
        $mc = /\b5[1-5][0-9]{14}\b/
        $amex = /\b3[47][0-9]{13}\b/
        $discover = /\b6(?:011|5[0-9]{2})[0-9]{12}\b/
    
    condition:
        (any of ($cc*)) or (any of ($visa, $mc, $amex, $discover))
}

rule pii_bank_account
{
    meta:
        description = "Detects bank account information"
        category = "pii"
        severity = "critical"
        pii_type = "FINANCIAL"
        author = "AEGIS Team"
    
    strings:
        $bank1 = "bank account" nocase
        $bank2 = "account number" nocase
        $bank3 = "routing number" nocase
        $bank4 = "ABA number" nocase
        $bank5 = "IBAN" nocase
        $bank6 = "SWIFT code" nocase
        $bank7 = "BIC code" nocase
        $bank8 = "sort code" nocase
    
    condition:
        any of them
}

rule pii_health_info
{
    meta:
        description = "Detects protected health information (PHI)"
        category = "pii"
        severity = "critical"
        pii_type = "HEALTH"
        author = "AEGIS Team"
    
    strings:
        $health1 = "medical record" nocase
        $health2 = "patient ID" nocase
        $health3 = "diagnosis" nocase
        $health4 = "prescription" nocase
        $health5 = "health insurance" nocase
        $health6 = "Medicare" nocase
        $health7 = "Medicaid" nocase
        $health8 = "blood type" nocase
        $health9 = "medical history" nocase
        $health10 = "treatment plan" nocase
        $health11 = "lab results" nocase
        $health12 = "MRN" nocase // Medical Record Number
    
    condition:
        any of them
}

rule pii_government_id
{
    meta:
        description = "Detects government-issued ID information"
        category = "pii"
        severity = "critical"
        pii_type = "GOVERNMENT_ID"
        author = "AEGIS Team"
    
    strings:
        $gov1 = "driver license" nocase
        $gov2 = "driver's license" nocase
        $gov3 = "passport number" nocase
        $gov4 = "national ID" nocase
        $gov5 = "tax ID" nocase
        $gov6 = "TIN" nocase
        $gov7 = "EIN" nocase
        $gov8 = "ITIN" nocase
        $gov9 = "green card" nocase
        $gov10 = "visa number" nocase
        $gov11 = "immigration status" nocase
    
    condition:
        any of them
}

rule pii_contact_info
{
    meta:
        description = "Detects contact information patterns"
        category = "pii"
        severity = "high"
        pii_type = "CONTACT"
        author = "AEGIS Team"
    
    strings:
        $contact1 = "home address" nocase
        $contact2 = "mailing address" nocase
        $contact3 = "residential address" nocase
        $contact4 = "phone number" nocase
        $contact5 = "cell number" nocase
        $contact6 = "mobile number" nocase
        $contact7 = "personal email" nocase
        $contact8 = "emergency contact" nocase
    
    condition:
        any of them
}

rule pii_biometric
{
    meta:
        description = "Detects biometric information references"
        category = "pii"
        severity = "critical"
        pii_type = "BIOMETRIC"
        author = "AEGIS Team"
    
    strings:
        $bio1 = "fingerprint" nocase
        $bio2 = "retina scan" nocase
        $bio3 = "iris scan" nocase
        $bio4 = "facial recognition" nocase
        $bio5 = "voice print" nocase
        $bio6 = "DNA" nocase
        $bio7 = "biometric data" nocase
        $bio8 = "faceprint" nocase
    
    condition:
        any of them
}

rule pii_demographics
{
    meta:
        description = "Detects demographic PII"
        category = "pii"
        severity = "medium"
        pii_type = "DEMOGRAPHIC"
        author = "AEGIS Team"
    
    strings:
        $demo1 = "date of birth" nocase
        $demo2 = "DOB" nocase
        $demo3 = "place of birth" nocase
        $demo4 = "mother's maiden name" nocase
        $demo5 = "maiden name" nocase
        $demo6 = "ethnicity" nocase
        $demo7 = "race" nocase
        $demo8 = "religion" nocase
        $demo9 = "sexual orientation" nocase
        $demo10 = "political affiliation" nocase
    
    condition:
        any of them
}

rule pii_credentials
{
    meta:
        description = "Detects credential information"
        category = "pii"
        severity = "critical"
        pii_type = "CREDENTIALS"
        author = "AEGIS Team"
    
    strings:
        $cred1 = "password" nocase
        $cred2 = "passwd" nocase
        $cred3 = "secret key" nocase
        $cred4 = "API key" nocase
        $cred5 = "access token" nocase
        $cred6 = "auth token" nocase
        $cred7 = "private key" nocase
        $cred8 = "PIN number" nocase
        $cred9 = "security question" nocase
        $cred10 = "security answer" nocase
    
    condition:
        any of them
}

rule pii_extraction_attempt
{
    meta:
        description = "Detects attempts to extract PII"
        category = "pii"
        severity = "high"
        pii_type = "EXTRACTION_ATTEMPT"
        author = "AEGIS Team"
    
    strings:
        $extract1 = "tell me your password" nocase
        $extract2 = "what is your SSN" nocase
        $extract3 = "give me the credit card" nocase
        $extract4 = "provide your address" nocase
        $extract5 = "share your phone number" nocase
        $extract6 = "list all users" nocase
        $extract7 = "dump the database" nocase
        $extract8 = "export user data" nocase
        $extract9 = "show me the emails" nocase
        $extract10 = "reveal the passwords" nocase
    
    condition:
        any of them
}
