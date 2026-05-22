/*
AEGIS YARA Rules - Prompt Injection Detection
Detects attempts to inject malicious instructions into prompts.
Target latency: <10ms per scan
*/

rule injection_system_delimiter
{
    meta:
        description = "Detects system prompt delimiter injection"
        category = "injection"
        severity = "critical"
        author = "AEGIS Team"
    
    strings:
        $sys1 = "[SYSTEM]" nocase
        $sys2 = "[ADMIN]" nocase
        $sys3 = "[INSTRUCTION]" nocase
        $sys4 = "[[SYSTEM]]" nocase
        $sys5 = "{{SYSTEM}}" nocase
        $sys6 = "<<<SYSTEM>>>" nocase
        $sys7 = "---SYSTEM---" nocase
        $sys8 = "===SYSTEM===" nocase
        $sys9 = "###SYSTEM###" nocase
        $sys10 = "<|system|>" nocase
        $sys11 = "<|im_start|>system" nocase
        $sys12 = "<s>[INST]" nocase
    
    condition:
        any of them
}

rule injection_instruction_override
{
    meta:
        description = "Detects instruction override attempts"
        category = "injection"
        severity = "critical"
        author = "AEGIS Team"
    
    strings:
        $ovr1 = "NEW INSTRUCTIONS:" nocase
        $ovr2 = "UPDATED INSTRUCTIONS:" nocase
        $ovr3 = "OVERRIDE INSTRUCTIONS:" nocase
        $ovr4 = "REPLACEMENT INSTRUCTIONS:" nocase
        $ovr5 = "REVISED PROMPT:" nocase
        $ovr6 = "ACTUAL PROMPT:" nocase
        $ovr7 = "REAL INSTRUCTIONS:" nocase
        $ovr8 = "TRUE INSTRUCTIONS:" nocase
        $ovr9 = "HIDDEN INSTRUCTIONS:" nocase
        $ovr10 = "SECRET INSTRUCTIONS:" nocase
    
    condition:
        any of them
}

rule injection_end_of_prompt
{
    meta:
        description = "Detects end-of-prompt injection markers"
        category = "injection"
        severity = "high"
        author = "AEGIS Team"
    
    strings:
        $end1 = "END OF PROMPT" nocase
        $end2 = "END OF INSTRUCTIONS" nocase
        $end3 = "PROMPT ENDS HERE" nocase
        $end4 = "INSTRUCTIONS END" nocase
        $end5 = "---END---" nocase
        $end6 = "===END===" nocase
        $end7 = "[END]" nocase
        $end8 = "</prompt>" nocase
        $end9 = "</instructions>" nocase
        $end10 = "\\n\\nHuman:" nocase
        $end11 = "\\n\\nAssistant:" nocase
    
    condition:
        any of them
}

rule injection_xml_tags
{
    meta:
        description = "Detects XML-style injection attempts"
        category = "injection"
        severity = "high"
        author = "AEGIS Team"
    
    strings:
        $xml1 = "<system>" nocase
        $xml2 = "</system>" nocase
        $xml3 = "<instruction>" nocase
        $xml4 = "</instruction>" nocase
        $xml5 = "<hidden>" nocase
        $xml6 = "<ignore>" nocase
        $xml7 = "<admin>" nocase
        $xml8 = "<override>" nocase
        $xml9 = "<prompt>" nocase
        $xml10 = "<command>" nocase
    
    condition:
        any of them
}

rule injection_markdown_exploit
{
    meta:
        description = "Detects Markdown-based injection attempts"
        category = "injection"
        severity = "medium"
        author = "AEGIS Team"
    
    strings:
        $md1 = "```system" nocase
        $md2 = "```instruction" nocase
        $md3 = "```hidden" nocase
        $md4 = "```admin" nocase
        $md5 = "# SYSTEM PROMPT" nocase
        $md6 = "## NEW INSTRUCTIONS" nocase
        $md7 = "### OVERRIDE" nocase
        $md8 = "<!-- hidden instruction" nocase
        $md9 = "[hidden]: #" nocase
    
    condition:
        any of them
}

rule injection_context_manipulation
{
    meta:
        description = "Detects context manipulation attempts"
        category = "injection"
        severity = "high"
        author = "AEGIS Team"
    
    strings:
        $ctx1 = "previous context:" nocase
        $ctx2 = "context switch:" nocase
        $ctx3 = "new context:" nocase
        $ctx4 = "reset context" nocase
        $ctx5 = "clear context" nocase
        $ctx6 = "context override" nocase
        $ctx7 = "inject context" nocase
        $ctx8 = "modify context" nocase
    
    condition:
        any of them
}

rule injection_unicode_homoglyph
{
    meta:
        description = "Detects Unicode homoglyph injection attempts"
        category = "injection"
        severity = "medium"
        author = "AEGIS Team"
    
    strings:
        // Zero-width characters
        $uni1 = { E2 80 8B } // Zero-width space
        $uni2 = { E2 80 8C } // Zero-width non-joiner
        $uni3 = { E2 80 8D } // Zero-width joiner
        $uni4 = { EF BB BF } // BOM
        
        // Right-to-left override
        $uni5 = { E2 80 AE } // RLO
        $uni6 = { E2 80 AD } // LRO
        
        // Combining characters
        $uni7 = { CC 81 } // Combining acute accent
    
    condition:
        any of them
}

rule injection_escape_sequences
{
    meta:
        description = "Detects escape sequence injection"
        category = "injection"
        severity = "medium"
        author = "AEGIS Team"
    
    strings:
        $esc1 = "\\x00" nocase
        $esc2 = "\\x1b[" nocase // ANSI escape
        $esc3 = "\\u0000" nocase
        $esc4 = "\\n\\n\\n\\n" nocase // Excessive newlines
        $esc5 = "\\r\\n\\r\\n" nocase
        $esc6 = "%00" nocase // URL-encoded null
        $esc7 = "%0a%0a" nocase // URL-encoded newlines
    
    condition:
        any of them
}

rule injection_role_confusion
{
    meta:
        description = "Detects role confusion injection attempts"
        category = "injection"
        severity = "high"
        author = "AEGIS Team"
    
    strings:
        $role1 = "you are now the user" nocase
        $role2 = "i am the system" nocase
        $role3 = "i am the assistant" nocase
        $role4 = "pretend i am the admin" nocase
        $role5 = "i have admin privileges" nocase
        $role6 = "speaking as the system" nocase
        $role7 = "from: system" nocase
        $role8 = "role: system" nocase
    
    condition:
        any of them
}

rule injection_output_manipulation
{
    meta:
        description = "Detects output manipulation injection"
        category = "injection"
        severity = "medium"
        author = "AEGIS Team"
    
    strings:
        $out1 = "your response should be:" nocase
        $out2 = "you must respond with:" nocase
        $out3 = "only output:" nocase
        $out4 = "respond only with:" nocase
        $out5 = "your only response is:" nocase
        $out6 = "output exactly:" nocase
        $out7 = "say only:" nocase
        $out8 = "print only:" nocase
    
    condition:
        any of them
}
