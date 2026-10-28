

CATEGORY_TECHNIQUE_MAP = {
    "apt": [
        "T1078",  # Valid Accounts
        "T1021",  # Remote Services
        "T1547",  # Boot or Logon Autostart Execution
        "T1027",  # Obfuscated Files or Information
        "T1070",  # Indicator Removal
        "T1090",  # Proxy
        "T1105",  # Ingress Tool Transfer
        "T1055",  # Process Injection
        "T1003",  # OS Credential Dumping
        "T1018",  # Remote System Discovery
    ],
    "ransomware": [
        "T1486",  # Data Encrypted for Impact
        "T1490",  # Inhibit System Recovery
        "T1489",  # Service Stop
        "T1485",  # Data Destruction
        "T1078",  # Valid Accounts — dominant initial-access vector for ransomware crews
        "T1021",  # Remote Services — RDP hands-on-keyboard lateral movement (Conti, LockBit, Ryuk playbooks)
        "T1567",  # Exfiltration Over Web Service — double-extortion staging before encryption
    ],
    "banking_trojan": [
        "T1185",  # Browser Session Hijacking
        "T1056",  # Input Capture
        "T1557",  # Adversary-in-the-Middle
        "T1055",  # Process Injection
    ],
    "infostealer": [
        "T1555",  # Credentials from Password Stores
        "T1056",  # Input Capture
        "T1005",  # Data from Local System
        "T1552",  # Unsecured Credentials
    ],
    "botnet_c2": [
        "T1071",  # Application Layer Protocol
        "T1571",  # Non-Standard Port
        "T1090",  # Proxy
        "T1105",  # Ingress Tool Transfer
        "T1568",  # Dynamic Resolution
    ],
    "phishing": [
        "T1566",  # Phishing
        "T1204",  # User Execution
        "T1598",  # Phishing for Information
    ],
    "cryptominer": [
        "T1496",  # Resource Hijacking
        "T1053",  # Scheduled Task/Job
    ],
    "scanner": [
        "T1595",  # Active Scanning
        "T1046",  # Network Service Discovery
        "T1110",  # Brute Force
    ],
    "spam": [
        "T1566",  # Phishing (spam is the delivery vector for phishing)
        "T1583",  # Acquire Infrastructure
    ],
    "malware": [
        "T1055",  # Process Injection
        "T1027",  # Obfuscated Files or Information
        "T1105",  # Ingress Tool Transfer
        "T1204",  # User Execution
        "T1547",  # Boot or Logon Autostart Execution
        "T1070",  # Indicator Removal
    ],
}
