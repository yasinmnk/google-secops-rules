rule automated_exfiltration {
    meta:
      author = "Yasin manka"
      description = "Detects automated data exfiltration tools or scripts"
      mitre_technique = "T1020"
      severity = "high"
      yara_version = "YL2.0"
      rule_version = "1.0"
  
    events:
      (
        $e1.metadata.event_type = "PROCESS_LAUNCH" and
        re.regex($e1.principal.process.command_line, `(?i)(scp|rsync|curl|ftp|wget|powershell.*-enc|tar\s+-cf|zip\s+-r|7z\s+a)`)
      )
  
    condition:
      $e1
  }



  rule ransomware_behavior_detection {
    meta:
      author = "Yasin Manka"
      description = "Detects behaviors associated with ransomware attacks"
      reference1 = "https://attack.mitre.org/techniques/T1486/"
      yara_version = "YL2.0"
      rule_version = "1.0"
  
    events:
      (
        $e1.metadata.event_type = "PROCESS_LAUNCH" and
        re.regex($e1.principal.process.command_line, `(?i)(vssadmin\s+delete\s+shadows|bcdedit\s+/set\s+recoveryenabled\s+no|wbadmin\s+delete|wmic\s+shadowcopy\s+delete)`)
      )
      or
      (
        $e1.metadata.event_type = "FILE_CREATION" and
        re.regex($e1.target.file.full_path, `(?i)(readme|how_to_decrypt|decrypt_instructions)[\._\- ]?.*\.txt$`)
      )
      or
      (
        $e1.metadata.event_type = "FILE_MODIFICATION" and
        re.regex($e1.target.file.full_path, `(?i).*\.(locky|crypted|crab|megacrypt|aes256|enc|encrypted)$`)
      )
  
    condition:
      $e1
  }
  

  