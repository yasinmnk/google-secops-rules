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
  

  #Intune Rules
  rule intune_device_wipe_spike {

    meta:
      author = "Yasin Manka"
      description = "Detects when a user initiates multiple device wipes via Microsoft Intune within one hour."
      rule_id = "mr_intune_device_wipe_spike"
      rule_name = "Microsoft Intune - Multiple Device Wipes"
      mitre_attack_tactic = "Impact"
      mitre_attack_technique = "Data Destruction"
      mitre_attack_url = "https://attack.mitre.org/techniques/T1485/"
      mitre_attack_version = "v14.1"
      type = "Alert"
      data_source = "Microsoft Intune Audit Logs"
      platform = "Microsoft Intune"
      severity = "High"
      priority = "High"
  
    events:
      $e.metadata.log_type = "INTUNE_AUDIT"
      $e.metadata.product_event_type = "DeviceWipe"
      $e.principal.user.userid = $user_id
  
    match:
      $user_id over 1h
  
    outcome:
      $event_count = count_distinct($e.metadata.id)
      $user_ids = array_distinct($e.principal.user.userid)
      $source_ips = array_distinct($e.principal.ip)
      $risk_score = max(80)
  
    condition:
      $e
  }
  
  
  rule intune_app_uninstall_spike {
  
    meta:
      author = "Yasin Manka"
      description = "Detects when a user uninstalls multiple apps via Microsoft Intune within one hour."
      rule_id = "mr_intune_app_uninstall_spike"
      rule_name = "Microsoft Intune - Multiple App Uninstalls"
      mitre_attack_tactic = "Persistence"
      mitre_attack_technique = "Indicator Removal on Host"
      mitre_attack_url = "https://attack.mitre.org/techniques/T1070/"
      mitre_attack_version = "v14.1"
      type = "Alert"
      data_source = "Microsoft Intune Audit Logs"
      platform = "Microsoft Intune"
      severity = "Medium"
      priority = "Medium"
  
    events:
      $e.metadata.log_type = "INTUNE_AUDIT"
      $e.metadata.product_event_type = "AppUninstall"
      $e.principal.user.userid = $user_id
  
    match:
      $user_id over 1h
  
    outcome:
      $event_count = count_distinct($e.metadata.id)
      $user_ids = array_distinct($e.principal.user.userid)
      $source_ips = array_distinct($e.principal.ip)
      $risk_score = max(60)
  
    condition:
      $e
  }
  
  
  rule intune_profile_delete_spike {
  
    meta:
      author = "Yasin Manka"
      description = "Detects when a user deletes multiple configuration profiles via Intune."
      rule_id = "mr_intune_profile_delete_spike"
      rule_name = "Microsoft Intune - Configuration Profile Deletions"
      mitre_attack_tactic = "Defense Evasion"
      mitre_attack_technique = "Modify Cloud Compute Infrastructure"
      mitre_attack_url = "https://attack.mitre.org/techniques/T1578/"
      mitre_attack_version = "v14.1"
      type = "Alert"
      data_source = "Microsoft Intune Audit Logs"
      platform = "Microsoft Intune"
      severity = "High"
      priority = "High"
  
    events:
      $e.metadata.log_type = "INTUNE_AUDIT"
      $e.metadata.product_event_type = "ConfigurationProfileDelete"
      $e.principal.user.userid = $user_id
  
    match:
      $user_id over 1h
  
    outcome:
      $event_count = count_distinct($e.metadata.id)
      $user_ids = array_distinct($e.principal.user.userid)
      $source_ips = array_distinct($e.principal.ip)
      $risk_score = max(80)
  
    condition:
      $e
  }
  
  
  rule intune_device_enrollment_spike {
  
    meta:
      author = "Yasin Manka"
      description = "Detects mass device enrollments within a short timeframe which may indicate abuse or automation."
      rule_id = "mr_intune_device_enrollment_spike"
      rule_name = "Microsoft Intune - Mass Device Enrollments"
      mitre_attack_tactic = "Initial Access"
      mitre_attack_technique = "Supply Chain Compromise"
      mitre_attack_url = "https://attack.mitre.org/techniques/T1195/"
      mitre_attack_version = "v14.1"
      type = "Alert"
      data_source = "Microsoft Intune Audit Logs"
      platform = "Microsoft Intune"
      severity = "Medium"
      priority = "Medium"
  
    events:
      $e.metadata.log_type = "INTUNE_AUDIT"
      $e.metadata.product_event_type = "DeviceEnrollment"
      $e.principal.user.userid = $user_id
  
    match:
      $user_id over 1h
  
    outcome:
      $event_count = count_distinct($e.metadata.id)
      $user_ids = array_distinct($e.principal.user.userid)
      $source_ips = array_distinct($e.principal.ip)
      $risk_score = max(60)
  
    condition:
      $e
  }
  
  
  rule intune_remote_wipe_triggered {
  
    meta:
      author = "Yasin Manka"
      description = "Detects device wipes initiated from unusual geographic IP addresses."
      rule_id = "mr_intune_remote_wipe_triggered"
      rule_name = "Microsoft Intune - Remote Wipe from Unusual Location"
      mitre_attack_tactic = "Impact"
      mitre_attack_technique = "Data Destruction"
      mitre_attack_url = "https://attack.mitre.org/techniques/T1485/"
      mitre_attack_version = "v14.1"
      type = "Alert"
      data_source = "Microsoft Intune Audit Logs"
      platform = "Microsoft Intune"
      severity = "High"
      priority = "High"
  
    events:
      $e.metadata.log_type = "INTUNE_AUDIT"
      $e.metadata.product_event_type = "DeviceWipe"
      $e.principal.user.userid = $user_id
  
    match:
      $user_id over 1h
  
    outcome:
      $event_count = count_distinct($e.metadata.id)
      $user_ids = array_distinct($e.principal.user.userid)
      $source_ips = array_distinct($e.principal.ip)
      $risk_score = max(80)
  
    condition:
      $e
  }