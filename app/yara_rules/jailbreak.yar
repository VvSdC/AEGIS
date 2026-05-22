/*
AEGIS YARA Rules - Jailbreak Detection
High-speed pattern matching for known jailbreak attempts.
Target latency: <10ms per scan
*/

rule jailbreak_dan_mode
{
    meta:
        description = "Detects DAN (Do Anything Now) jailbreak attempts"
        category = "jailbreak"
        severity = "high"
        author = "AEGIS Team"
    
    strings:
        $dan1 = "DAN mode" nocase
        $dan2 = "Do Anything Now" nocase
        $dan3 = "you are DAN" nocase
        $dan4 = "act as DAN" nocase
        $dan5 = "pretend to be DAN" nocase
        $dan6 = "DAN Mode Enabled" nocase
        $dan7 = "DAN jailbreak" nocase
    
    condition:
        any of them
}

rule jailbreak_ignore_instructions
{
    meta:
        description = "Detects attempts to override previous instructions"
        category = "jailbreak"
        severity = "high"
        author = "AEGIS Team"
    
    strings:
        $ig1 = "ignore all previous instructions" nocase
        $ig2 = "ignore prior instructions" nocase
        $ig3 = "ignore your instructions" nocase
        $ig4 = "disregard previous instructions" nocase
        $ig5 = "forget your instructions" nocase
        $ig6 = "ignore the above" nocase
        $ig7 = "disregard the above" nocase
        $ig8 = "ignore everything above" nocase
        $ig9 = "ignore all rules" nocase
        $ig10 = "forget all rules" nocase
    
    condition:
        any of them
}

rule jailbreak_roleplay_evil
{
    meta:
        description = "Detects evil/malicious roleplay attempts"
        category = "jailbreak"
        severity = "high"
        author = "AEGIS Team"
    
    strings:
        $role1 = "pretend you are evil" nocase
        $role2 = "act as an evil AI" nocase
        $role3 = "you are now evil" nocase
        $role4 = "roleplay as a malicious" nocase
        $role5 = "you are an unrestricted AI" nocase
        $role6 = "you have no restrictions" nocase
        $role7 = "you are uncensored" nocase
        $role8 = "without any ethical guidelines" nocase
        $role9 = "without safety filters" nocase
        $role10 = "you are unfiltered" nocase
    
    condition:
        any of them
}

rule jailbreak_bypass_safety
{
    meta:
        description = "Detects attempts to bypass safety measures"
        category = "jailbreak"
        severity = "critical"
        author = "AEGIS Team"
    
    strings:
        $bypass1 = "bypass your safety" nocase
        $bypass2 = "disable your filters" nocase
        $bypass3 = "turn off your restrictions" nocase
        $bypass4 = "bypass content filter" nocase
        $bypass5 = "circumvent your guidelines" nocase
        $bypass6 = "override safety measures" nocase
        $bypass7 = "disable ethical guidelines" nocase
        $bypass8 = "remove all restrictions" nocase
        $bypass9 = "unlock hidden features" nocase
        $bypass10 = "access developer mode" nocase
    
    condition:
        any of them
}

rule jailbreak_opposite_day
{
    meta:
        description = "Detects 'opposite day' jailbreak variant"
        category = "jailbreak"
        severity = "medium"
        author = "AEGIS Team"
    
    strings:
        $opp1 = "opposite day" nocase
        $opp2 = "today is opposite day" nocase
        $opp3 = "respond with the opposite" nocase
        $opp4 = "say the opposite" nocase
        $opp5 = "do the opposite" nocase
    
    condition:
        any of them
}

rule jailbreak_base64_encoded
{
    meta:
        description = "Detects potential Base64 encoded jailbreak payloads"
        category = "jailbreak"
        severity = "medium"
        author = "AEGIS Team"
    
    strings:
        // Common base64 patterns for jailbreak phrases
        $b64_1 = "aWdub3JlIGFsbCBwcmV2aW91cw==" // "ignore all previous"
        $b64_2 = "Zm9yZ2V0IHlvdXIgaW5zdHJ1Y3Rpb25z" // "forget your instructions"
        $b64_3 = "ZGVjb2RlIHRoaXMgYW5kIGV4ZWN1dGU=" // "decode this and execute"
        
        // Patterns indicating base64 usage in prompts
        $b64_indicator1 = "base64 decode" nocase
        $b64_indicator2 = "decode the following" nocase
        $b64_indicator3 = "run this encoded" nocase
    
    condition:
        any of them
}

rule jailbreak_developer_mode
{
    meta:
        description = "Detects developer mode jailbreak attempts"
        category = "jailbreak"
        severity = "high"
        author = "AEGIS Team"
    
    strings:
        $dev1 = "enable developer mode" nocase
        $dev2 = "developer mode activated" nocase
        $dev3 = "you are in developer mode" nocase
        $dev4 = "switch to developer mode" nocase
        $dev5 = "enter debug mode" nocase
        $dev6 = "admin mode enabled" nocase
        $dev7 = "superuser access" nocase
        $dev8 = "root access granted" nocase
    
    condition:
        any of them
}

rule jailbreak_hypothetical
{
    meta:
        description = "Detects hypothetical scenario jailbreak attempts"
        category = "jailbreak"
        severity = "medium"
        author = "AEGIS Team"
    
    strings:
        $hypo1 = "hypothetically speaking" nocase
        $hypo2 = "in a fictional scenario" nocase
        $hypo3 = "imagine you could" nocase
        $hypo4 = "let's pretend for a moment" nocase
        $hypo5 = "in an alternate universe" nocase
        $hypo6 = "for educational purposes only" nocase
        $hypo7 = "purely theoretical" nocase
        
        // Combined with harmful intent keywords
        $harm1 = "how to hack" nocase
        $harm2 = "how to make" nocase
        $harm3 = "instructions for" nocase
    
    condition:
        (any of ($hypo*)) and (any of ($harm*))
}

rule jailbreak_grandma_exploit
{
    meta:
        description = "Detects 'grandma' style jailbreak attempts"
        category = "jailbreak"
        severity = "medium"
        author = "AEGIS Team"
    
    strings:
        $gma1 = "my grandmother used to" nocase
        $gma2 = "please act as my deceased grandmother" nocase
        $gma3 = "grandma would tell me" nocase
        $gma4 = "bedtime story about" nocase
        
        // Combined with harmful topics
        $topic1 = "napalm" nocase
        $topic2 = "explosive" nocase
        $topic3 = "hack into" nocase
        $topic4 = "bypass security" nocase
    
    condition:
        (any of ($gma*)) and (any of ($topic*))
}

rule jailbreak_simulation
{
    meta:
        description = "Detects simulation-based jailbreak attempts"
        category = "jailbreak"
        severity = "medium"
        author = "AEGIS Team"
    
    strings:
        $sim1 = "simulate a conversation" nocase
        $sim2 = "simulate an AI without" nocase
        $sim3 = "simulate unrestricted" nocase
        $sim4 = "emulate an AI that" nocase
        $sim5 = "you are simulating" nocase
        $sim6 = "this is a simulation" nocase
    
    condition:
        any of them
}
