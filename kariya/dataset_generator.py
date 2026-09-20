import os
import json
import random
from typing import List, Dict, Any

# Seed for reproducibility
random.seed(2026)

# Real-world Nigerian Institutions & Contexts
ORGANIZATIONS = [
    "Federal Ministry of Finance, Abuja",
    "Office of the Accountant-General of the Federation (IPPIS)",
    "Kano State Ministry of Science, Technology & Innovation",
    "Lagos State Internal Revenue Service (LIRS)",
    "Ahmadu Bello University (ABU), Zaria",
    "Bayero University Kano (BUK)",
    "University of Lagos (UNILAG)",
    "Aminu Kano Teaching Hospital (AKTH)",
    "National Hospital, Abuja",
    "Kaduna State Universal Basic Education Board (SUBEB)",
    "Rivers State Judiciary Portal",
    "Corporate Affairs Commission (CAC)",
    "National Identity Management Commission (NIMC) State Office",
    "Nigeria Inter-Bank Settlement System (NIBSS) Partner Desk",
    "Joint Admissions and Matriculation Board (JAMB) CBT Centre"
]

NIGERIAN_NAMES = [
    ("Musa", "Abdullahi"), ("Chinedu", "Okafor"), ("Olumide", "Adeyemi"),
    ("Fatima", "Bello"), ("Emeka", "Eze"), ("Blessing", "Johnson"),
    ("Ibrahim", "Garba"), ("Amina", "Shehu"), ("Babajide", "Sowore"),
    ("Ngozi", "Okonjo"), ("Usman", "Danjuma"), ("Khadija", "Mohammed"),
    ("Folake", "Balogun"), ("Tariq", "Aliyu"), ("Zainab", "Abubakar")
]

INCIDENT_CATEGORIES = [
    "Ransomware & Extortion",
    "Phishing & Credential Theft",
    "Unauthorized Access / Account Takeover",
    "Business Email Compromise (BEC)",
    "Website Defacement",
    "Data Leak & PII Exposure",
    "Denial of Service (DoS)"
]

ROUTING_TARGETS = {
    "Ransomware & Extortion": "National CERT (ngCERT)",
    "Phishing & Credential Theft": "Internal SOC / IR Team",
    "Unauthorized Access / Account Takeover": "Payroll & IPPIS Security",
    "Business Email Compromise (BEC)": "EFCC Cybercrime Unit",
    "Website Defacement": "NITDA Cyber Directorate",
    "Data Leak & PII Exposure": "NITDA Cyber Directorate",
    "Denial of Service (DoS)": "Internal SOC / IR Team"
}

SEVERITIES = {
    "Ransomware & Extortion": "Critical",
    "Unauthorized Access / Account Takeover": "Critical",
    "Business Email Compromise (BEC)": "High",
    "Data Leak & PII Exposure": "High",
    "Website Defacement": "Medium",
    "Phishing & Credential Theft": "Medium",
    "Denial of Service (DoS)": "Medium"
}

def generate_nigerian_phone() -> str:
    prefixes = ["0803", "0802", "0814", "0703", "0909", "0818", "0805", "0706", "+234803", "+234812"]
    prefix = random.choice(prefixes)
    suffix = "".join([str(random.randint(0, 9)) for _ in range(7)])
    return f"{prefix}{suffix}"

def generate_bvn() -> str:
    return "22" + "".join([str(random.randint(0, 9)) for _ in range(9)])

def generate_nin() -> str:
    return "54" + "".join([str(random.randint(0, 9)) for _ in range(9)])

def generate_account_num() -> str:
    return "01" + "".join([str(random.randint(0, 9)) for _ in range(8)])

# Base Incident Cluster Templates (Simulating root incidents that generate multiple duplicate reports)
CLUSTER_TEMPLATES = [
    {
        "type": "Ransomware & Extortion",
        "severity": "Critical",
        "target": "National CERT (ngCERT)",
        "iocs": ["185.220.101.5", "lockbit3-support-portal.onion", "decrypt-data-files.top", "hash_9a8f23b14c5d6e"],
        "variants": [
            "Good day team, our main database server at {org} has been hit with ransomware. All patient records and billing files now have .locked extension. A README_RESTORE.txt says we must pay 15 BTC to lockbit3-support-portal.onion or all medical histories will be published. Call the CMD Dr. {name} on {phone} urgently.",
            "URGENT: Ransomware outbreak on our local subnet at {org}. The server hosting patient records stopped responding at 3:15am. We saw an outbound connection to 185.220.101.5 before the files encrypted into .locked format. Attacker ransom note points to decrypt-data-files.top. Contact our ICT lead {name} ({phone}).",
            "Abeg help us! All our computer files for {org} don turn to .locked format this morning! Screen dey show red warning say make we pay bitcoin to lockbit3-support-portal.onion. Even the backup hard drive wey connect to server don freeze. Reach Malam {name} on {phone} right now, work don scatter.",
            "Security Incident Notification: Unidentified ransomware strain infected domain controller and file servers in {org}. SHA256 signature hash_9a8f23b14c5d6e identified in memory dump. Ransom demand left by threat actor linking to decrypt-data-files.top. System isolated from LAN. Reported by {name} ({email}, {phone})."
        ]
    },
    {
        "type": "Unauthorized Access / Account Takeover",
        "severity": "Critical",
        "target": "Payroll & IPPIS Security",
        "iocs": ["197.210.64.12", "portal-ippis-auth.com", "admin-session-hijack.xyz"],
        "variants": [
            "Alert from Payroll department: Accountant {name} tried to log into the salary disbursement portal at {org} and was told password has been changed. Looking at the audit log, an unrecognized IP 197.210.64.12 logged in at 2:00 AM and added 45 new ghost beneficiary accounts with BVN {bvn} and bank account {account}. Urgent action needed.",
            "Someone has hijacked our payroll officer's credentials at {org}. Mrs. {name} (Phone: {phone}) reports she received an OTP she did not request, and suddenly her access was revoked. Fraudulent salary schedule generated for Account {account}, BVN {bvn}. Reverse transaction immediately.",
            "Wahala dey o. Our IPPIS portal password don change by itself! Somebody use strange browser from IP 197.210.64.12 log in inside night come change all the payment batch to new accounts. Call our cashier {name} on {phone} make dem freeze the disbursement sharp sharp before bank release alert.",
            "Incident Escalation: Suspicious credential swap and session takeover on financial portal. Source IP 197.210.64.12 redirected traffic via portal-ippis-auth.com. Suspect unauthorized modifications to beneficiary batch. Affected staff: {name}, NIN: {nin}, BVN: {bvn}. Forwarded by internal audit."
        ]
    },
    {
        "type": "Business Email Compromise (BEC)",
        "severity": "High",
        "target": "EFCC Cybercrime Unit",
        "iocs": ["permsec-office-gov-ng.com", "finance-transfer-auth.net", "102.89.34.88"],
        "variants": [
            "We detected a fraudulent email pretending to come from the Permanent Secretary directing our accounts director {name} to disburse ₦48,500,000 to an offshore contractor. The sender address is spoofed as permsec@permsec-office-gov-ng.com originating from 102.89.34.88. Contact the officer on {phone} immediately.",
            "Vendor Payment Fraud Alert: An unauthorized revised invoice was sent to our finance desk at {org}. The email instructed us to reroute pending payments to Account {account} under the name of {name} (BVN: {bvn}). The email header shows return-path permsec-office-gov-ng.com. Do not pay.",
            "Scam email alert! One fake mail just drop inside our DG inbox with domain finance-transfer-auth.net saying ministry must approve urgent payment of contract funds to Account {account} belonging to one {name} (Phone: {phone}). IP trace show 102.89.34.88. Dem almost scam us.",
            "Executive Impersonation detected: Spoofed executive correspondence targeting {org} procurement team. Domain permsec-office-gov-ng.com registered 48 hours ago in Iceland. Requesting immediate transfer to {account}, NIN {nin}. Reported by Finance Director {name}."
        ]
    },
    {
        "type": "Phishing & Credential Theft",
        "severity": "Medium",
        "target": "Internal SOC / IR Team",
        "iocs": ["staff-webmail-update.online", "fg-grant-disbursement.top", "196.207.177.30", "cve-2025-21412"],
        "variants": [
            "Multiple staff in {org} received a suspicious email titled 'Mandatory HR Portal Password Reset'. The link leads to staff-webmail-update.online hosted on 196.207.177.30. Officer {name} accidentally entered her login and phone {phone}. Please block this URL on the perimeter firewall.",
            "WhatsApp broadcast claiming Federal Government is disbursing ₦50,000 palliatives to all civil servants is circulating widely in {org}. The URL is fg-grant-disbursement.top and asks users for their NIN {nin}, BVN {bvn}, and phone {phone}. At least 15 staff have submitted their details.",
            "Fake login page detected! Someone clone our staff webmail login page at staff-webmail-update.online. Staff member {name} ({phone}) forwarded the phishing message. IP resolve to 196.207.177.30. Make our network admin block the link before everybody enter their password.",
            "Mass Phishing Campaign: Email blast targeting {org} employees with subject 'URGENT: Update Your Staff Portal'. Uses lure fg-grant-disbursement.top and attempts browser exploit CVE-2025-21412. Victim {name} (Phone: {phone}) reported account lockout after clicking."
        ]
    },
    {
        "type": "Website Defacement",
        "severity": "Medium",
        "target": "NITDA Cyber Directorate",
        "iocs": ["hacked-by-ghostsec.html", "185.190.140.22", "cpanel-exploit-payload.php"],
        "variants": [
            "Our official website at {org} has been defaced. The home page index.php was replaced with hacked-by-ghostsec.html displaying political messages and skull banners. Attacker IP seems to be 185.190.140.22. We need urgent restoration assistance. Contact IT Officer {name} ({phone}).",
            "Public Portal Defacement: The public portal of {org} is showing an unauthorized takeover page uploaded via cpanel-exploit-payload.php. Threat group signature left on page. Webmaster {name} (Phone: {phone}) has taken the web server offline temporarily.",
            "Our ministry website don corrupt! If you open the site now, e dey show 'HACKED BY ANONYMOUS' with loud music and red screen. The index page don change to hacked-by-ghostsec.html. Server IP 185.190.140.22. Please tell engineer {name} ({phone}) make dem restore backup.",
            "Web Security Alert: CMS vulnerability on {org} official domain allowed malicious file write of cpanel-exploit-payload.php from IP 185.190.140.22. Root directory altered. Notified by citizen complaint through {name} ({phone})."
        ]
    },
    {
        "type": "Data Leak & PII Exposure",
        "severity": "High",
        "target": "NITDA Cyber Directorate",
        "iocs": ["mega.nz/folder/nigerian-civil-servants", "pastebin.com/raw/d84920aa", "149.202.88.19"],
        "variants": [
            "Severe Data Breach: A spreadsheet containing names, NIN, BVN, and salary figures of 12,000 civil servants at {org} was posted on a public Telegram channel and mega.nz/folder/nigerian-civil-servants. Sample record includes {name}, NIN: {nin}, BVN: {bvn}, Phone: {phone}. Immediate regulatory notice required.",
            "Unauthorized Data Dump: Sensitive candidate records from {org} have been leaked on pastebin.com/raw/d84920aa. Data includes exam numbers, NIN {nin}, phone numbers like {phone}, and home addresses. Reported by compliance auditor {name}.",
            "Somebody don dump all our staff bank details and salary schedule for public internet! Link dey mega.nz/folder/nigerian-civil-servants. See my own BVN {bvn} and account {account} inside the file! Reach Mr. {name} on {phone} make dem contact NITDA immediately.",
            "Breach Incident: Unencrypted database backup from {org} discovered on dark web forum hosted on 149.202.88.19. Extracted records verified genuine, including citizen {name}, NIN {nin}, and Account {account}. Privacy compliance officer notified."
        ]
    },
    {
        "type": "Denial of Service (DoS)",
        "severity": "Medium",
        "target": "Internal SOC / IR Team",
        "iocs": ["udp-flood-cluster", "45.142.214.50", "syn-storm-botnet"],
        "variants": [
            "The portal at {org} is completely unresponsive due to a massive SYN flood originating from botnet cluster 45.142.214.50. Traffic spike reached 42 Gbps during the online application window. IT lead {name} ({phone}) is working to implement upstream rate limiting.",
            "DDoS Attack Ongoing: Students and applicants cannot access the registration portal at {org}. Network graphs show 100% bandwidth saturation from syn-storm-botnet across multiple ports. Reported by system admin {name} (Phone: {phone}).",
            "Network down! Our online portal no dey open at all since morning. Server just dey hang because of heavy traffic attack from IP 45.142.214.50. Candidates dey cry for registration centre. Contact engineer {name} on {phone} make dem switch to Cloudflare.",
            "Availability Incident: Sustained Layer 4 UDP flood directed against {org} primary gateway. Source botnet nodes identified around 45.142.214.50. Service degraded for 3 hours. Reported by {name} (Email: {email}, Phone: {phone})."
        ]
    }
]

def build_dataset(total_reports: int = 360) -> List[Dict[str, Any]]:
    """Build a comprehensive, realistic dataset of incident reports with answer keys and duplicate clusters."""
    dataset = []
    report_counter = 1
    cluster_counter = 1

    # We generate multiple clusters with 2-5 report variants each
    while len(dataset) < total_reports:
        cluster_id = f"CLUSTER-NG-2026-{cluster_counter:03d}"
        template = random.choice(CLUSTER_TEMPLATES)
        org = random.choice(ORGANIZATIONS)
        first_name, last_name = random.choice(NIGERIAN_NAMES)
        full_name = f"{first_name} {last_name}"
        phone = generate_nigerian_phone()
        bvn = generate_bvn()
        nin = generate_nin()
        account = generate_account_num()
        email = f"{first_name.lower()}.{last_name.lower()}@gov.ng"

        # Determine how many reports in this duplicate cluster (2 to 5)
        num_variants = random.randint(2, min(4, total_reports - len(dataset)))
        chosen_variants = random.sample(template["variants"], min(num_variants, len(template["variants"])))

        for variant_text in chosen_variants:
            raw_text = variant_text.format(
                org=org,
                name=full_name,
                phone=phone,
                bvn=bvn,
                nin=nin,
                account=account,
                email=email
            )

            # Collect true ground truth IOCs in this text
            found_iocs = [ioc for ioc in template["iocs"] if ioc.lower() in raw_text.lower()]
            
            # Collect true ground truth PII entities in this text
            found_pii = []
            if phone in raw_text: found_pii.append({"type": "PHONE", "value": phone})
            if bvn in raw_text: found_pii.append({"type": "BVN", "value": bvn})
            if nin in raw_text: found_pii.append({"type": "NIN", "value": nin})
            if account in raw_text: found_pii.append({"type": "ACCOUNT", "value": account})
            if full_name in raw_text: found_pii.append({"type": "NAME", "value": full_name})
            if email in raw_text: found_pii.append({"type": "EMAIL", "value": email})

            report_entry = {
                "report_id": f"INC-2026-{report_counter:04d}",
                "cluster_id": cluster_id,
                "organization": org,
                "raw_text": raw_text,
                "ground_truth": {
                    "incident_type": template["type"],
                    "severity": template["severity"],
                    "routing_target": template["target"],
                    "iocs": found_iocs,
                    "pii_entities": found_pii
                }
            }
            dataset.append(report_entry)
            report_counter += 1

        cluster_counter += 1

    return dataset

def main():
    dataset_file = os.path.join(os.path.dirname(__file__), "dataset.json")
    print(f"Generating 360 realistic Nigerian incident reports with ground truth...")
    reports = build_dataset(360)
    with open(dataset_file, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2, ensure_ascii=False)
    print(f"✓ Successfully generated {len(reports)} incident reports across {len(set(r['cluster_id'] for r in reports))} clusters.")
    print(f"✓ Saved to {dataset_file}")

if __name__ == "__main__":
    main()
