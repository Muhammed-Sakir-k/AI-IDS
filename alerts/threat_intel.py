THREAT_ENCYCLOPEDIA = {

    "Port Scan": {
        "title": "Port Scan / Reconnaissance",
        "icon": "fa-magnifying-glass",
        "color": "#f59e0b",
        "severity": "MEDIUM",
        "what_is_it": "A port scan is the first step in almost every cyber attack. The attacker sends packets to many different ports on your machine to discover which services are running — like trying every door and window of a building to find one that is unlocked.",
        "how_it_happens": [
            "Attacker uses tools like Nmap, Masscan, or Zmap",
            "Sends TCP SYN packets to hundreds of ports rapidly",
            "Open ports reply with SYN-ACK, closed ports reply RST",
            "Attacker builds a map of your services from the replies",
            "This map is then used to find exploitable vulnerabilities"
        ],
        "what_attacker_wants": "To identify open ports like SSH (22), RDP (3389), HTTP (80), or database ports (3306, 5432) that may have weak credentials or unpatched vulnerabilities.",
        "real_world_examples": [
            "Shodan — a search engine that continuously port scans the entire internet",
            "Most ransomware attacks begin with an RDP port scan looking for exposed remote desktops",
            "The 2017 WannaCry ransomware spread by scanning for open SMB port 445"
        ],
        "prevention": [
            "Close all ports that are not needed using Windows Firewall",
            "Use a VPN instead of exposing services directly to the internet",
            "Change default service ports (e.g. SSH from 22 to a random high port)",
            "Enable port scan detection in your firewall/IDS",
            "Use fail2ban to auto-block IPs that scan multiple ports"
        ],
        "mitre_attack": "T1046 — Network Service Discovery",
        "risk_if_ignored": "An attacker with a port map of your system will move to the exploitation phase — attempting to break into the discovered services."
    },

    "UDP Flood": {
        "title": "UDP Flood Attack",
        "icon": "fa-water",
        "color": "#f43f5e",
        "severity": "HIGH",
        "what_is_it": "A UDP Flood is a Denial of Service attack where the attacker sends massive amounts of UDP packets to random ports on your machine. Your system wastes resources checking for applications listening on those ports and replying with ICMP 'Destination Unreachable' messages until it becomes overwhelmed.",
        "how_it_happens": [
            "Attacker sends thousands of UDP packets per second to random ports",
            "Your machine checks each packet — is any application listening here?",
            "For each empty port, your machine sends back an ICMP error reply",
            "This consumes CPU, memory, and network bandwidth rapidly",
            "Legitimate traffic cannot get through — service is denied"
        ],
        "what_attacker_wants": "To make your machine or network unreachable — taking down websites, game servers, or communication systems.",
        "real_world_examples": [
            "GitHub was hit with a 1.35 Tbps UDP amplification attack in 2018",
            "UDP floods are commonly used against game servers (Minecraft, CS:GO)",
            "DNS amplification attacks use UDP to generate massive traffic volumes"
        ],
        "prevention": [
            "Rate-limit UDP traffic at the router/firewall level",
            "Block UDP on ports your system does not use",
            "Use a DDoS protection service like Cloudflare for public-facing servers",
            "Configure your ISP to block spoofed source IPs (BCP38)",
            "Increase ICMP rate limiting to reduce resource exhaustion"
        ],
        "mitre_attack": "T1499.002 — Service Exhaustion Flood",
        "risk_if_ignored": "Complete network unavailability. All legitimate users are blocked while the attack continues."
    },

    "Traffic Burst": {
        "title": "Abnormal Traffic Burst",
        "icon": "fa-chart-line",
        "color": "#a78bfa",
        "severity": "MEDIUM",
        "what_is_it": "A sudden spike in traffic volume from a single IP that exceeds normal behavioral thresholds. This is detected by the behavioral analysis engine comparing current packets/sec against the established baseline for that IP.",
        "how_it_happens": [
            "An IP suddenly sends far more packets than its normal rate",
            "Could be the beginning of a flood attack being ramped up",
            "Could be data exfiltration — sending large volumes of stolen data out",
            "Could be a botnet command triggering coordinated traffic",
            "The flow analyzer detects the deviation from baseline behavior"
        ],
        "what_attacker_wants": "Either to overwhelm your system with volume, or to quickly exfiltrate data before detection.",
        "real_world_examples": [
            "Data exfiltration before ransomware deployment — attackers copy everything first",
            "Botnet activation — thousands of infected machines suddenly activate",
            "Cryptomining traffic bursts when new mining jobs are assigned"
        ],
        "prevention": [
            "Set per-IP bandwidth limits on your router",
            "Monitor traffic baselines and alert on deviations (what this system does)",
            "Use network segmentation to limit blast radius",
            "Deploy egress filtering to prevent unauthorized outbound traffic"
        ],
        "mitre_attack": "T1030 — Data Transfer Size Limits",
        "risk_if_ignored": "May escalate into a full DoS attack or indicates data theft in progress."
    },

    "Suspicious Data Transfer": {
        "title": "Suspicious Data Transfer",
        "icon": "fa-database",
        "color": "#f43f5e",
        "severity": "HIGH",
        "what_is_it": "An unusually high volume of data (bytes/sec) being transferred from or to an IP. This pattern is characteristic of data exfiltration — where an attacker who has already gained access is copying sensitive files out of your network.",
        "how_it_happens": [
            "Attacker has already compromised a machine on the network",
            "They compress and encrypt stolen files to reduce size and avoid detection",
            "Then transfer large amounts of data to an external server they control",
            "The high bytes/sec rate triggers the behavioral threshold",
            "Often happens at night or during off-hours to avoid detection"
        ],
        "what_attacker_wants": "Your data — credentials, documents, database dumps, intellectual property — to sell, ransom, or exploit.",
        "real_world_examples": [
            "The 2013 Target breach — 40 million credit cards exfiltrated over weeks",
            "SolarWinds attack — attackers exfiltrated data for months undetected",
            "Most ransomware attacks now exfiltrate before encrypting — double extortion"
        ],
        "prevention": [
            "Deploy Data Loss Prevention (DLP) software",
            "Monitor and alert on large outbound transfers",
            "Restrict which machines can communicate with external IPs",
            "Use HTTPS inspection to detect encrypted exfiltration",
            "Segment your network so compromised machines cannot reach all data"
        ],
        "mitre_attack": "T1048 — Exfiltration Over Alternative Protocol",
        "risk_if_ignored": "Critical. If this is genuine exfiltration, your sensitive data is already leaving the network."
    },

    "Behavioral Anomaly": {
        "title": "Behavioral Anomaly Detected",
        "icon": "fa-brain",
        "color": "#38bdf8",
        "severity": "LOW",
        "what_is_it": "The AI/ML engine detected that this IP's traffic pattern deviates from normal behavior based on flow features — even though it did not match a specific attack signature. This is the power of behavioral detection over signature-based systems.",
        "how_it_happens": [
            "XGBoost model analyzes: flow duration, packet count, bytes/sec, packets/sec",
            "Compares against patterns learned from 2.8 million labeled traffic samples",
            "Traffic does not match BENIGN patterns in the training data",
            "Flagged even though no specific rule was triggered",
            "This catches zero-day attacks and novel attack variations"
        ],
        "what_attacker_wants": "Unknown — the anomaly could be reconnaissance, a new attack type, or misconfigured software. Requires investigation.",
        "real_world_examples": [
            "Zero-day exploits that signature systems miss entirely",
            "Slow-and-low attacks that stay below individual thresholds",
            "Encrypted C2 traffic that looks unusual but not specifically malicious"
        ],
        "prevention": [
            "Investigate the flagged IP immediately",
            "Check if the IP belongs to a known service or internal machine",
            "Review full packet logs for that IP in the network stream",
            "Block the IP temporarily while investigating",
            "Update your threat intelligence feeds with the finding"
        ],
        "mitre_attack": "T1071 — Application Layer Protocol",
        "risk_if_ignored": "Could be a false positive — or could be a sophisticated attack. Always investigate anomalies."
    },

    "AI: Bot": {
        "title": "Botnet Activity Detected",
        "icon": "fa-robot",
        "color": "#f43f5e",
        "severity": "HIGH",
        "what_is_it": "The XGBoost model classified this traffic as botnet behavior. Botnets are networks of compromised computers controlled by an attacker. A machine showing bot traffic patterns may be infected and receiving commands from a remote Command & Control (C2) server.",
        "how_it_happens": [
            "A machine gets infected via phishing email, malicious download, or exploit",
            "Malware installs silently and connects to a C2 server for instructions",
            "The infected machine (bot) may send spam, participate in DDoS attacks, or mine crypto",
            "Traffic pattern: periodic beaconing to external IPs at regular intervals",
            "The ML model recognized this beaconing pattern from the CICIDS2017 dataset"
        ],
        "what_attacker_wants": "To use your machine as part of a larger botnet — for DDoS attacks, spam campaigns, crypto mining, or as a proxy for other attacks.",
        "real_world_examples": [
            "Mirai botnet — infected IoT devices to launch the largest DDoS attack ever recorded",
            "Emotet — one of the world's most dangerous botnets, spread via email",
            "Necurs botnet — sent billions of spam emails per day"
        ],
        "prevention": [
            "Run a full antivirus scan on the source machine immediately",
            "Block outbound connections to unknown external IPs at the firewall",
            "Check running processes on the machine for unknown executables",
            "Isolate the machine from the network until cleaned",
            "Update all software — botnets often exploit known vulnerabilities"
        ],
        "mitre_attack": "T1071.001 — Web Protocols C2 Communication",
        "risk_if_ignored": "Critical. An active bot in your network means an attacker has persistent access and is actively using your resources."
    },

    "AI: DDoS": {
        "title": "DDoS Attack Detected",
        "icon": "fa-skull",
        "color": "#f43f5e",
        "severity": "CRITICAL",
        "what_is_it": "A Distributed Denial of Service attack. The ML model classified this flow as DDoS traffic based on the CICIDS2017 training data. DDoS attacks use multiple sources to flood your network with traffic until legitimate users cannot connect.",
        "how_it_happens": [
            "Attacker controls thousands of bots (infected machines worldwide)",
            "Sends command to all bots simultaneously: attack this target",
            "Bots flood the target with packets from many different IPs",
            "Target's bandwidth and processing capacity is exhausted",
            "Legitimate users get connection timeouts — service is down"
        ],
        "what_attacker_wants": "To take your service offline — for extortion, competition, hacktivism, or distraction while another attack happens.",
        "real_world_examples": [
            "Amazon AWS suffered a 2.3 Tbps DDoS in 2020 — largest ever recorded",
            "Dyn DNS attack 2016 — took down Twitter, Netflix, Reddit simultaneously",
            "Banks regularly targeted with DDoS to distract security teams during fraud"
        ],
        "prevention": [
            "Use a DDoS mitigation service (Cloudflare, AWS Shield, Akamai)",
            "Configure rate limiting at the network edge",
            "Use anycast network diffusion to spread traffic across multiple servers",
            "Set up black hole routing for attack traffic",
            "Contact your ISP — they can block attack traffic upstream"
        ],
        "mitre_attack": "T1498 — Network Denial of Service",
        "risk_if_ignored": "Complete service unavailability. Can last hours or days without mitigation."
    },

    "AI: PortScan": {
        "title": "AI-Detected Port Scan",
        "icon": "fa-magnifying-glass",
        "color": "#f59e0b",
        "severity": "MEDIUM",
        "what_is_it": "The XGBoost model independently confirmed a port scan based on flow features — corroborating the rule-based detection. Double detection by both behavioral rules AND machine learning means high confidence.",
        "how_it_happens": [
            "Same as Port Scan — attacker maps your open services",
            "Both rule engine AND ML model flagged the same traffic",
            "This dual detection means very high confidence — not a false positive",
            "Flow features: high packet count, low bytes/packet, many destination ports"
        ],
        "what_attacker_wants": "A complete map of your network services to identify attack vectors.",
        "real_world_examples": [
            "Every penetration test begins with port scanning",
            "Automated vulnerability scanners run port scans continuously on the internet"
        ],
        "prevention": [
            "Same as Port Scan prevention above",
            "The dual ML + rule detection here means treat this as confirmed, not suspected"
        ],
        "mitre_attack": "T1046 — Network Service Discovery",
        "risk_if_ignored": "Attacker has or is building a service map. Attack likely follows reconnaissance."
    }
}


def get_threat_intel(threat_type):
    # Try exact match first
    if threat_type in THREAT_ENCYCLOPEDIA:
        return THREAT_ENCYCLOPEDIA[threat_type]

    # Try partial match for AI: prefix types
    for key in THREAT_ENCYCLOPEDIA:
        if key.lower() in threat_type.lower() or threat_type.lower() in key.lower():
            return THREAT_ENCYCLOPEDIA[key]

    # Default fallback
    return {
        "title": threat_type,
        "icon": "fa-triangle-exclamation",
        "color": "#64748b",
        "severity": "UNKNOWN",
        "what_is_it": "An unclassified threat pattern was detected by the monitoring system.",
        "how_it_happens": ["Traffic pattern deviated from normal baseline"],
        "what_attacker_wants": "Unknown — investigation required.",
        "real_world_examples": ["Investigate further to classify this threat"],
        "prevention": ["Block the source IP and investigate packet logs"],
        "mitre_attack": "Unknown",
        "risk_if_ignored": "Unknown risk level — treat as suspicious until investigated."
    }