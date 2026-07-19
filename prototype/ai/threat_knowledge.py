"""
Threat Knowledge Base
─────────────────────
One entry per threat type.  Passed verbatim into the LLM prompt so that
even small offline models (Mistral, Phi-3, Llama-3 8B, etc.) have enough
grounding to give accurate, specific answers without hallucinating.

Each entry has:
  description  – what this threat IS
  attack_goal  – what an attacker gains from this
  indicators   – how to spot it
  prevention   – 2-4 actionable steps (shown to user)
  severity_note – plain-English severity context
"""

THREAT_KNOWLEDGE: dict[str, dict] = {

    # ─── Web / Network ──────────────────────────────────────────────────────
    "http_browsing": {
        "description": (
            "HTTP is an unencrypted web protocol. Any data sent over HTTP — "
            "including login forms, cookies, and search terms — travels as "
            "plain text that anyone on the same network (Wi-Fi router, ISP, "
            "a nearby attacker) can read using freely available tools."
        ),
        "attack_goal": (
            "Session hijacking (stealing your login cookie), credential theft, "
            "or traffic injection (inserting malicious ads or scripts into pages you visit)."
        ),
        "indicators": [
            "URL starts with http:// instead of https://",
            "No padlock icon in the browser address bar",
            "Browser may show 'Not Secure' warning",
        ],
        "prevention": [
            "Only use sites that show https:// and a padlock in the address bar.",
            "Install the browser extension 'HTTPS Everywhere' to force secure connections.",
            "Avoid logging in or entering personal data on HTTP pages.",
            "If a site only offers HTTP, consider not trusting it with any data.",
        ],
        "severity_note": (
            "Low severity on its own, but rises to HIGH if you logged in or "
            "entered any personal information on this page."
        ),
    },

    "public_network": {
        "description": (
            "A Public network profile in Windows means the OS does not trust "
            "the network.  On public Wi-Fi (cafés, airports, hotels), other "
            "devices on the same network may be able to reach your computer's "
            "open ports, intercept unencrypted traffic, or run man-in-the-middle "
            "attacks."
        ),
        "attack_goal": (
            "Network sniffing, ARP spoofing to intercept traffic, "
            "exploitation of any open Windows shares or services."
        ),
        "indicators": [
            "Connected to a Wi-Fi network you do not own or manage",
            "Windows shows 'Public network' in network settings",
            "No VPN is running",
        ],
        "prevention": [
            "Enable your VPN before connecting to any public Wi-Fi.",
            "Ensure Windows Firewall is ON and set to 'Public' profile (it blocks inbound by default).",
            "Avoid accessing banking, email, or work systems without a VPN.",
            "Turn off file and printer sharing when on public networks.",
        ],
        "severity_note": (
            "Medium by default.  Becomes HIGH if you transmit sensitive data "
            "without a VPN."
        ),
    },

    # ─── Downloads ──────────────────────────────────────────────────────────
    "risky_download": {
        "description": (
            "Executable and script file types (.exe, .msi, .bat, .ps1, .vbs, "
            ".js, .jar, .scr, .hta, .wsf) can run arbitrary code on your "
            "computer the moment they are opened.  Malware is almost always "
            "delivered as one of these file types."
        ),
        "attack_goal": (
            "Install malware, ransomware, spyware, or a remote-access trojan "
            "(RAT) that gives attackers full control of the computer."
        ),
        "indicators": [
            "File has a double extension (e.g. invoice.pdf.exe)",
            "Downloaded from an unfamiliar or non-official website",
            "File was attached to an email or chat message",
            "Antivirus flagged the download",
        ],
        "prevention": [
            "Only download software from the official website of the developer.",
            "Right-click the file → 'Scan with Windows Defender' before opening.",
            "Check the file hash against the one published on the official site.",
            "Never open executable attachments from emails, even from known contacts.",
        ],
        "severity_note": (
            "HIGH from untrusted sources.  Even LOW-severity downloads from "
            "trusted publishers should still be scanned before running."
        ),
    },

    "torrent_download": {
        "description": (
            "Torrent files are used by peer-to-peer (P2P) file sharing.  "
            "Torrented software, games, and media are routinely repackaged by "
            "attackers to bundle malware alongside the desired content.  "
            "Piracy sites have no quality control and profit from malware installs."
        ),
        "attack_goal": (
            "Bundle ransomware, cryptocurrency miners (xmrig), or RATs "
            "inside pirated content.  Victims install the malware voluntarily "
            "while thinking they're getting free software."
        ),
        "indicators": [
            "File ends in .torrent",
            "Torrent client (uTorrent, qBittorrent) is running",
            "Content is commercial software, films, or games obtained for free",
        ],
        "prevention": [
            "Delete the .torrent file and do not open it.",
            "Use legitimate streaming or purchase channels for media and software.",
            "If you need open-source software, download it directly from the project's website.",
            "Run a full Windows Defender scan of your Downloads folder immediately.",
        ],
        "severity_note": (
            "HIGH.  Even if the specific torrent turns out to be clean, the "
            "behaviour significantly increases infection risk over time."
        ),
    },

    "unknown_source_download": {
        "description": (
            "A file was downloaded from a website that is not on the list of "
            "known-safe publishers.  Unfamiliar domains may be typosquatted "
            "(e.g. micros0ft.com), newly registered, or deliberately set up "
            "to distribute malware."
        ),
        "attack_goal": (
            "Trick users into downloading fake software updates, cracked tools, "
            "or documents that contain macros or exploits."
        ),
        "indicators": [
            "Domain is not the official vendor site",
            "Site registered recently (check via whois)",
            "Pop-up or ad directed you to this download",
        ],
        "prevention": [
            "Verify the download source by searching '[software name] official download'.",
            "Check the URL carefully for typos or unusual characters.",
            "Scan the file with Windows Defender before opening.",
            "Use VirusTotal (virustotal.com) to check the file hash online.",
        ],
        "severity_note": "Medium — escalates to HIGH if the file is executable.",
    },

    # ─── Processes ──────────────────────────────────────────────────────────
    "suspicious_process": {
        "description": (
            "A running process was matched against a list of tools commonly "
            "used for hacking, credential theft, remote access, or "
            "cryptocurrency mining.  Tools like Mimikatz, Metasploit, "
            "NetCat, and xmrig are almost never legitimately present on a "
            "standard user's computer."
        ),
        "attack_goal": (
            "Depending on the tool: dump password hashes (Mimikatz), "
            "establish a reverse shell (Netcat/Metasploit), mine crypto "
            "using your electricity (xmrig), or maintain persistent access (RATs)."
        ),
        "indicators": [
            "Process name matches a known hacking tool",
            "High CPU usage from an unknown process",
            "Process started automatically without user interaction",
            "Outbound network connection to an unusual IP",
        ],
        "prevention": [
            "End the process immediately in Task Manager.",
            "Run a full Windows Defender scan right now.",
            "Check Task Scheduler and startup programs for persistence entries.",
            "If you did not install this tool yourself, assume the system is compromised and change all passwords from a clean device.",
        ],
        "severity_note": (
            "HIGH to CRITICAL.  These tools have no legitimate place on a "
            "standard user workstation."
        ),
    },

    # ─── USB ────────────────────────────────────────────────────────────────
    "usb_connected": {
        "description": (
            "A USB device was connected to the computer.  USB drives can carry "
            "malware that auto-runs on connection (USB rubber ducky, BadUSB), "
            "or can be used to exfiltrate data silently.  "
            "Even charging cables from unknown sources can inject malicious code (Juice Jacking)."
        ),
        "attack_goal": (
            "Auto-run malware on connection, steal files silently, "
            "or act as a fake keyboard to type malicious commands."
        ),
        "indicators": [
            "Unknown or borrowed USB drive",
            "USB found in a public place",
            "Pop-up appears immediately after plugging in",
            "Antivirus alert triggered on connection",
        ],
        "prevention": [
            "Never plug in a USB device you did not buy yourself from a trusted retailer.",
            "Disable USB AutoRun in Windows (it should be off by default in modern Windows).",
            "Scan the drive with Windows Defender before opening any files.",
            "Use a dedicated 'quarantine' computer with no valuable data to inspect unknown drives.",
        ],
        "severity_note": (
            "Medium for personal devices you own.  HIGH for unknown, "
            "found, or borrowed drives."
        ),
    },

    # ─── Windows Security ───────────────────────────────────────────────────
    "defender_disabled": {
        "description": (
            "Windows Defender real-time protection is the primary anti-malware "
            "layer on Windows.  When disabled, every file you open, every "
            "website you visit, and every USB you plug in is scanned by nothing "
            "— malware can execute freely without detection."
        ),
        "attack_goal": (
            "Malware often disables Defender as its first step so that "
            "subsequent payloads are not removed.  This is a classic indicator "
            "of an active infection or a compromised administrator account."
        ),
        "indicators": [
            "Windows Security shows 'Virus & threat protection is off'",
            "Defender notifications disappeared from the taskbar",
            "Registry key or GPO change detected",
        ],
        "prevention": [
            "Re-enable real-time protection immediately: Start → Windows Security → Virus & threat protection → turn on.",
            "Do not download or open anything until protection is restored.",
            "Check if any software 'required' you to disable it — that software is malicious.",
            "If you cannot re-enable it, run the Windows Defender Offline scan from a restart.",
        ],
        "severity_note": (
            "CRITICAL.  Your computer is fully unprotected right now."
        ),
    },

    "defender_definitions_stale": {
        "description": (
            "Defender's virus definition database is 3 or more days old.  "
            "Threat definitions are the list of known malware signatures.  "
            "Without updates, Defender cannot detect malware released since "
            "the last update — which can include active ransomware campaigns."
        ),
        "attack_goal": (
            "Attackers time mass malware campaigns around weekends or holidays "
            "when definitions are likely to lag.  Stale definitions mean new "
            "malware slips through undetected."
        ),
        "indicators": [
            "Windows Security shows 'Definitions last updated' > 3 days ago",
            "Computer has been offline or in sleep mode for extended periods",
        ],
        "prevention": [
            "Update definitions now: Windows Security → Virus & threat protection → Check for updates.",
            "Ensure Windows Update is enabled and not paused.",
            "Connect the computer to the internet daily to keep definitions current.",
        ],
        "severity_note": "Medium.  Update definitions immediately.",
    },

    # ─── Event Log / Audit ──────────────────────────────────────────────────
    "login_failed": {
        "description": (
            "A Windows login attempt was rejected.  A single failure is usually "
            "a mistyped password.  Multiple failures in a short period indicate "
            "a brute-force or credential-stuffing attack, either from the network "
            "or from someone physically at the keyboard."
        ),
        "attack_goal": (
            "Gain access to the Windows account to steal files, install software, "
            "or use the computer as a pivot point to attack other systems."
        ),
        "indicators": [
            "Multiple failed logins within minutes (event ID 4625)",
            "Login attempts for user accounts that do not exist",
            "Attempts arriving from the network (logon type 3)",
        ],
        "prevention": [
            "Use a strong, unique password for your Windows account (12+ characters, mixed types).",
            "Enable Windows account lockout policy (locks after 5 wrong attempts).",
            "If remote access is not needed, disable Remote Desktop (RDP) in system settings.",
            "Review event viewer for the source of the failed attempts.",
        ],
        "severity_note": (
            "Medium for a single event.  HIGH if 3 or more occur within "
            "a short window."
        ),
    },

    "security_log_cleared": {
        "description": (
            "The Windows Security event log was deleted.  This log records all "
            "login attempts, privilege escalations, and policy changes.  "
            "Attackers clear it to destroy evidence of their intrusion.  "
            "Legitimate administrators almost never need to clear it."
        ),
        "attack_goal": (
            "Erase forensic evidence of compromise: hide which accounts were "
            "accessed, which tools were run, and how long the attacker was present."
        ),
        "indicators": [
            "Event ID 1102 (Security log cleared) in the Security log",
            "Large gap in security event timestamps",
        ],
        "prevention": [
            "Treat this as a potential active compromise — do not dismiss it.",
            "Immediately check Task Manager and running services for unknown processes.",
            "Enable log forwarding to a remote server or SIEM so logs cannot be locally deleted.",
            "Review who has administrator rights on this machine.",
        ],
        "severity_note": (
            "HIGH.  This is one of the strongest indicators of an active attacker."
        ),
    },

    "audit_policy_changed": {
        "description": (
            "Windows Audit Policy controls which events get written to the "
            "security log.  Reducing audit coverage makes malicious activity "
            "invisible.  Event ID 4719 indicates the policy was changed, "
            "often a precursor to or part of an attack."
        ),
        "attack_goal": (
            "Disable logging of specific activities (e.g. process creation, "
            "privilege use) before performing them, to avoid detection."
        ),
        "indicators": [
            "Event ID 4719 in the Security log",
            "Audit categories set to 'No auditing' for sensitive actions",
        ],
        "prevention": [
            "Review and restore the audit policy: secpol.msc → Advanced Audit Policy Configuration.",
            "Only domain administrators should ever modify audit policy.",
            "Forward logs to a remote server so policy changes are recorded off-device.",
        ],
        "severity_note": "HIGH.  Indicates deliberate evasion of security monitoring.",
    },

    "scheduled_task_created": {
        "description": (
            "A new scheduled task was created.  Scheduled tasks run programs "
            "automatically at set times or events (login, network change, etc.).  "
            "Malware uses them as a persistence mechanism — the malware survives "
            "a reboot by re-launching itself through a scheduled task."
        ),
        "attack_goal": (
            "Persist on the system after reboot, re-install deleted malware, "
            "or phone home to attacker infrastructure at regular intervals."
        ),
        "indicators": [
            "Event ID 4698 (task created) in the Security log",
            "Task runs an executable from a temp folder or AppData",
            "Task was created by an unknown process",
        ],
        "prevention": [
            "Review all scheduled tasks: open Task Scheduler (taskschd.msc) and look for unfamiliar entries.",
            "Delete any task you did not create or that points to a suspicious file.",
            "Check the task's 'action' field — legitimate tasks rarely run from Temp or AppData.",
        ],
        "severity_note": "HIGH.  Review Task Scheduler immediately.",
    },

    "scheduled_task_updated": {
        "description": (
            "An existing scheduled task was modified.  Attackers may modify a "
            "legitimate task (e.g. Windows Update) to also run their malware, "
            "making it harder to detect because the task name looks innocent."
        ),
        "attack_goal": (
            "Hijack a trusted scheduled task to add a malicious payload while "
            "keeping the original task's legitimate name."
        ),
        "indicators": [
            "Event ID 4702 (task updated) in the Security log",
            "Legitimate-looking task name now has additional actions",
        ],
        "prevention": [
            "Open Task Scheduler and inspect the modified task's actions.",
            "Compare to known-good task definitions.",
            "Delete the task if it contains unexpected executables or scripts.",
        ],
        "severity_note": "HIGH.  A common persistence and evasion technique.",
    },

    "service_start_changed": {
        "description": (
            "A Windows service's startup type was changed.  Services run in "
            "the background and can be set to start automatically.  Attackers "
            "set security services (Defender, firewall) to 'Disabled' to "
            "prevent them from starting, or add malicious services set to "
            "'Automatic' so they survive reboots."
        ),
        "attack_goal": (
            "Disable security tools, or add malicious services that start "
            "automatically and are invisible to casual inspection."
        ),
        "indicators": [
            "Event ID 7040 in the System log",
            "Security-related services (WinDefend, MpsSvc) changed to Disabled",
        ],
        "prevention": [
            "Check services.msc for any security services (Defender, Windows Firewall) set to Disabled.",
            "Re-enable any disabled security services immediately.",
            "Look for unfamiliar services set to Automatic start.",
        ],
        "severity_note": "HIGH.  Often part of a deliberate attack chain.",
    },
}


def get_knowledge(threat_type: str) -> dict:
    """
    Return the knowledge-base entry for a threat type.
    Falls back to a generic entry if the type is not found.
    """
    entry = THREAT_KNOWLEDGE.get(threat_type)
    if entry:
        return entry

    # Generic fallback — better than nothing for the LLM
    return {
        "description": (
            f"A security event of type '{threat_type}' was detected.  "
            "This may indicate unusual or risky activity on the computer."
        ),
        "attack_goal": "Varies depending on the specific activity involved.",
        "indicators": ["Unusual system behaviour", "Unexpected network activity"],
        "prevention": [
            "Review the specific details of this event.",
            "Run a full Windows Defender scan.",
            "Check recently installed software and browser extensions.",
            "Change passwords if any accounts may be affected.",
        ],
        "severity_note": "Review the alert details for severity context.",
    }


def format_knowledge_for_prompt(threat_type: str) -> str:
    """
    Return a compact, LLM-friendly text block from the knowledge base.
    Designed to fit within the tight context windows of small local models.
    """
    kb = get_knowledge(threat_type)

    indicators = "\n".join(f"  • {i}" for i in kb["indicators"])
    prevention = "\n".join(f"  {n+1}. {p}" for n, p in enumerate(kb["prevention"]))

    return (
        f"WHAT THIS THREAT IS:\n{kb['description']}\n\n"
        f"ATTACKER'S GOAL:\n{kb['attack_goal']}\n\n"
        f"WARNING SIGNS:\n{indicators}\n\n"
        f"HOW TO PREVENT IT:\n{prevention}\n\n"
        f"SEVERITY CONTEXT:\n{kb['severity_note']}"
    )
