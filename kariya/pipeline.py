import os
import re
import json
from typing import Dict, Any, List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics.pairwise import cosine_similarity

class TriagePipeline:
    """KARIYA AI: Autonomous Cyber Incident Triage & Response Engine for Track D."""

    INCIDENT_TYPES = [
        "Ransomware & Extortion",
        "Phishing & Credential Theft",
        "Unauthorized Access / Account Takeover",
        "Business Email Compromise (BEC)",
        "Website Defacement",
        "Data Leak & PII Exposure",
        "Denial of Service (DoS)"
    ]

    SEVERITY_SLAS = {
        "Critical": {"level": "P1", "sla": "15 Minutes", "score": 95},
        "High": {"level": "P2", "sla": "1 Hour", "score": 75},
        "Medium": {"level": "P3", "sla": "4 Hours", "score": 50},
        "Low": {"level": "P4", "sla": "24 Hours", "score": 25}
    }

    def __init__(self, dataset_path: str = None):
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=3000)
        self.classifier = LogisticRegression(max_iter=1000)
        self.is_trained = False
        
        if dataset_path and os.path.exists(dataset_path):
            self.train_from_dataset(dataset_path)

    def train_from_dataset(self, dataset_path: str):
        """Train the classifier from the ground-truth dataset."""
        try:
            with open(dataset_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            texts = [r["raw_text"] for r in data]
            labels = [r["ground_truth"]["incident_type"] for r in data]
            
            X = self.vectorizer.fit_transform(texts)
            self.classifier.fit(X, labels)
            self.is_trained = True
        except Exception as e:
            print(f"Warning: Could not train ML model: {e}. Falling back to rule-based classification.")

    def classify_type(self, text: str) -> Tuple[str, float, str]:
        """Classify incident type with confidence score and decision rationale."""
        text_lower = text.lower()

        # 1. Decisive Heuristic Threat Signals (Device lock extortion, Ransomware demands)
        is_extortion = (
            ("lock" in text_lower and "unlock" in text_lower) or 
            any(k in text_lower for k in ["phone is locked", "device is locked", "computer is locked", "server is locked", "system is locked", "files are locked", ".locked"]) or
            any(k in text_lower for k in ["ransomware", "extortion", "ransom demand", "pay to unlock", "demanding ransom", "decryption key"]) or
            ("ransom" in text_lower and any(k in text_lower for k in ["pay", "demand", "dollar", "btc", "bitcoin", "naira", "wallet", "transfer"]))
        )
        if is_extortion:
            return "Ransomware & Extortion", 0.98, "Detected active device/system lock and financial extortion demand requiring payment to unlock."

        is_defacement = any(k in text_lower for k in ["defaced by", "hacked by", "defacement landing page", "website defaced", "index.php replaced"])
        if is_defacement:
            return "Website Defacement", 0.96, "Detected explicit public portal root defacement."

        is_dos = any(k in text_lower for k in ["syn flood", "ddos attack", "udp flood", "botnet flood", "denial of service"])
        if is_dos:
            return "Denial of Service (DoS)", 0.96, "Detected network flooding / denial of service traffic."

        # 2. Statistical ML Classification if trained
        if self.is_trained:
            X = self.vectorizer.transform([text])
            predicted_type = self.classifier.predict(X)[0]
            probs = self.classifier.predict_proba(X)[0]
            max_prob = float(max(probs))
            rationale = f"Classified as '{predicted_type}' (Confidence: {max_prob:.1%}) based on linguistic patterns and threat indicators."
            return predicted_type, round(max_prob, 2), rationale

        # 3. Rule-based fallback for offline resilience
        if any(k in text_lower for k in ["ransomware", ".locked", "btc", "bitcoin", "decrypt"]):
            return "Ransomware & Extortion", 0.95, "Detected explicit encryption indicators (.locked) and cryptocurrency ransom demands."
        elif any(k in text_lower for k in ["ippis", "payroll", "beneficiary", "ghost", "salary"]):
            return "Unauthorized Access / Account Takeover", 0.92, "Detected unauthorized payroll credential swap or disbursement batch tampering."
        elif any(k in text_lower for k in ["defaced", "hacked by", "skull", "index.php", "cpanel"]):
            return "Website Defacement", 0.90, "Detected public website root tampering or defacement landing page."
        elif any(k in text_lower for k in ["permsec", "invoice", "transfer", "disburse", "vendor"]):
            return "Business Email Compromise (BEC)", 0.88, "Detected executive impersonation or unauthorized vendor account rerouting."
        elif any(k in text_lower for k in ["leak", "dump", "pastebin", "telegram", "spreadsheet"]):
            return "Data Leak & PII Exposure", 0.89, "Detected public dissemination of sensitive citizen or employee records."
        elif any(k in text_lower for k in ["syn flood", "botnet", "unresponsive", "udp", "ddos"]):
            return "Denial of Service (DoS)", 0.91, "Detected network flooding or infrastructure service degradation."
        else:
            return "Phishing & Credential Theft", 0.85, "Detected suspicious authentication lure or mass credential collection campaign."

    def score_severity(self, text: str, incident_type: str, iocs: List[str]) -> Tuple[str, int, str]:
        """Score incident severity and calculate SLA response timer."""
        text_lower = text.lower()
        score = self.SEVERITY_SLAS.get("Medium", {}).get("score", 50)
        severity = "Medium"

        if incident_type in ["Ransomware & Extortion", "Unauthorized Access / Account Takeover"]:
            severity = "Critical"
            score = 95
        elif incident_type in ["Business Email Compromise (BEC)", "Data Leak & PII Exposure"]:
            severity = "High"
            score = 75
        elif any(k in text_lower for k in ["urgent", "freeze", "disbursement", "immediately", "hospital", "patient"]):
            severity = "High"
            score = 80

        # Adjust score by asset criticality
        if "ippis" in text_lower or "patient" in text_lower or "medical" in text_lower:
            severity = "Critical"
            score = 98

        sla_info = self.SEVERITY_SLAS.get(severity, {})
        rationale = f"Level {sla_info.get('level', 'P2')}: Immediate action required within {sla_info.get('sla', '1 Hour')} due to {severity.lower()} threat severity."
        return severity, score, rationale

    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract all technical indicators of compromise (IOCs) from messy text."""
        iocs = {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "cves": []
        }

        # IPv4 regex (handles standard and defanged)
        clean_text = text.replace("[.]", ".").replace("(.)", ".")
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        for ip in re.findall(ip_pattern, clean_text):
            if not ip.startswith("127.") and not ip.startswith("0."):
                iocs["ips"].append(ip)

        # URLs
        url_pattern = r"(?:https?://|hxxps?://)[\w\.\-]+(?::\d+)?(?:/[\w\.\-\?=&%#]*)?"
        for url in re.findall(url_pattern, text):
            clean_url = url.replace("hxxp", "http")
            iocs["urls"].append(clean_url)

        # Domains (especially suspicious TLDs, Nigerian domains, onion)
        domain_pattern = r"\b[a-zA-Z0-9\.\-]+\.(?:onion|top|xyz|online|net|com|org|gov\.ng|com\.ng|ng)\b"
        for domain in re.findall(domain_pattern, clean_text):
            if domain not in iocs["ips"] and domain not in ["index.php", "README.txt"]:
                iocs["domains"].append(domain)

        # Hashes (MD5, SHA1, SHA256, or mock hash signatures)
        hash_pattern = r"\b(?:hash_[a-fA-F0-9]{14,}|[a-fA-F0-9]{32}|[a-fA-F0-9]{64})\b"
        for h in re.findall(hash_pattern, text):
            iocs["hashes"].append(h)

        # CVEs
        cve_pattern = r"\bCVE-\d{4}-\d{4,7}\b"
        for cve in re.findall(cve_pattern, text, re.IGNORECASE):
            iocs["cves"].append(cve.upper())

        # Cryptocurrency wallets (e.g. Bitcoin BTC addresses)
        btc_pattern = r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
        if "wallets" not in iocs:
            iocs["wallets"] = []
        for btc in re.findall(btc_pattern, text):
            iocs["wallets"].append(btc)

        # Deduplicate
        for k in iocs:
            iocs[k] = list(set(iocs[k]))

        return iocs

    def redact_pii(self, text: str) -> Tuple[str, List[Dict[str, str]]]:
        """Identify and redact Nigerian PII (BVN, NIN, Phone, Accounts, Names, Emails) under NDPR & NDPA 2023."""
        redacted_entities = []
        cleaned = text

        # 1. Redact Email Addresses (both gov.ng subdomains, .ng, and personal mail providers)
        email_pattern = r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)*(?:gov\.ng|mil\.ng|edu\.ng|org\.ng|com\.ng|ng|gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|proton\.me|protonmail\.com)\b"
        for m in re.finditer(email_pattern, cleaned, re.IGNORECASE):
            email = m.group(0)
            redacted_entities.append({"type": "EMAIL", "value": email})
        cleaned = re.sub(email_pattern, "[REDACTED_EMAIL]", cleaned, flags=re.IGNORECASE)

        # 2. Redact Nigerian Phone Numbers (e.g. 0803..., 070..., +234..., with spaces/dashes)
        phone_pattern = r"(\+?234\s*\d{2,3}[\s-]?\d{3,4}[\s-]?\d{4}|\+?234\d{10}|0[789][01]\d{8})"
        for m in re.finditer(phone_pattern, cleaned):
            phone = m.group(0)
            redacted_entities.append({"type": "PHONE", "value": phone})
        cleaned = re.sub(phone_pattern, "[REDACTED_PHONE]", cleaned)

        # 3. Redact BVN (Bank Verification Number - 11 digits)
        bvn_prefix_pattern = r"(?i)\bBVN\s*[:#-]?\s*(\d{11})\b"
        for m in re.finditer(bvn_prefix_pattern, cleaned):
            bvn = m.group(1)
            redacted_entities.append({"type": "BVN", "value": bvn})
        cleaned = re.sub(bvn_prefix_pattern, "BVN: [REDACTED_BVN]", cleaned)

        bvn_standalone = r"\b22\d{9}\b"
        for m in re.finditer(bvn_standalone, cleaned):
            bvn = m.group(0)
            if not any(bvn == r["value"] for r in redacted_entities):
                redacted_entities.append({"type": "BVN", "value": bvn})
        cleaned = re.sub(bvn_standalone, "[REDACTED_BVN]", cleaned)

        # 4. Redact NIN (National Identity Number - 11 digits)
        nin_prefix_pattern = r"(?i)\b(?:NIN|National\s+Identity(?:\s+Number)?)\s*(?:numbers?|no|#)?\s*[:#-]?\s*(?:\(?e\.g\.?\s*)?(\d{11})\b"
        for m in re.finditer(nin_prefix_pattern, cleaned):
            nin = m.group(1)
            redacted_entities.append({"type": "NIN", "value": nin})
        cleaned = re.sub(nin_prefix_pattern, "NIN [REDACTED_NIN]", cleaned)

        nin_standalone = r"\b54\d{9}\b"
        for m in re.finditer(nin_standalone, cleaned):
            nin = m.group(0)
            if not any(nin == r["value"] for r in redacted_entities):
                redacted_entities.append({"type": "NIN", "value": nin})
        cleaned = re.sub(nin_standalone, "[REDACTED_NIN]", cleaned)

        # 5. Redact NUBAN Bank Account numbers (10 digits across all Nigerian banks & mobile money)
        bank_keywords = r"(?:Bank\s+Details?|Banking\s+Details?|Bank\s+Account|Account|Acct|NUBAN|Beneficiary|Send\s+money\s+to|Transfer\s+to|Pay\s+into)"
        nigerian_banks = r"(?:Zenith|Access|GTB|GTBank|UBA|First\s+Bank|Fidelity|Sterling|Wema|Union|Ecobank|Polaris|FCMB|Stanbic|Kuda|Opay|Palmpay|Palm\s*pay|Moniepoint)"

        # 5a. Keyword + 10-digit number + optional bank name (e.g. bank details 8149751190 opay)
        bank_combined = rf"(?i)\b{bank_keywords}(?:\s*(?:Number|No|#))?\s*[:#-]?\s*(\d{{10}})(?:\s+({nigerian_banks}(?:\s+Bank)?))?\b"
        for m in re.finditer(bank_combined, cleaned):
            acct = m.group(1)
            bname = m.group(2) or ""
            redacted_entities.append({"type": "ACCOUNT", "value": acct + (f" ({bname})" if bname else "")})
        cleaned = re.sub(bank_combined, "Bank Details: [REDACTED_ACCOUNT]", cleaned)

        # 5b. 10-digit number followed by bank name (e.g. 8149751190 opay, 2088192039 zenith)
        bank_suffix_pattern = rf"(?i)\b(\d{{10}})\s+({nigerian_banks}(?:\s+Bank)?)\b"
        for m in re.finditer(bank_suffix_pattern, cleaned):
            acct = m.group(1)
            bname = m.group(2) or ""
            if not any(acct in r["value"] for r in redacted_entities):
                redacted_entities.append({"type": "ACCOUNT", "value": acct + (f" ({bname})" if bname else "")})
        cleaned = re.sub(bank_suffix_pattern, "[REDACTED_ACCOUNT] (Bank)", cleaned)

        # 5c. Bank name followed by 10-digit number (e.g. Opay 8149751190, Access Bank 0123456789)
        bank_named_acct = rf"(?i)\b{nigerian_banks}(?:\s+Bank)?(?:\s+(?:Account|Acct))?\s*[:#-]?\s*(\d{{10}})\b"
        for m in re.finditer(bank_named_acct, cleaned):
            acct = m.group(1)
            if not any(acct in r["value"] for r in redacted_entities):
                redacted_entities.append({"type": "ACCOUNT", "value": acct})
        cleaned = re.sub(bank_named_acct, "Bank Account [REDACTED_ACCOUNT]", cleaned)

        # 5d. Standalone NUBAN formats (01xxxxxxxx)
        acct_standalone = r"\b01\d{8}\b"
        for m in re.finditer(acct_standalone, cleaned):
            acct = m.group(0)
            if not any(acct in r["value"] for r in redacted_entities):
                redacted_entities.append({"type": "ACCOUNT", "value": acct})
        cleaned = re.sub(acct_standalone, "[REDACTED_ACCOUNT]", cleaned)

        # 6. Redact Known Nigerian Official/Citizen Names
        KNOWN_NIGERIAN_NAMES = [
            "Musa Abdullahi", "Chinedu Okafor", "Olumide Adeyemi",
            "Fatima Bello", "Emeka Eze", "Blessing Johnson",
            "Ibrahim Garba", "Amina Shehu", "Babajide Sowore",
            "Ngozi Okonjo", "Usman Danjuma", "Khadija Mohammed",
            "Folake Balogun", "Tariq Aliyu", "Zainab Abubakar"
        ]
        for name in KNOWN_NIGERIAN_NAMES:
            if name.lower() in cleaned.lower():
                pattern = re.compile(re.escape(name), re.IGNORECASE)
                for m in pattern.finditer(cleaned):
                    redacted_entities.append({"type": "NAME", "value": m.group(0)})
                cleaned = pattern.sub("[REDACTED_OFFICER_NAME]", cleaned)

        # 7. Redact common Nigerian Honorific + Names (e.g. Dr. Musa, Malam Ibrahim, Alhaji Sani)
        name_honorific = r"\b(?:Dr\.|Mr\.|Mrs\.|Ms\.|Malam|Mallam|Alhaji|Alhaja|Engr\.|Prof\.|Professor|Barrister|Barr\.|CMD|Lead|Officer)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b"
        for m in re.finditer(name_honorific, cleaned):
            name_val = m.group(1)
            redacted_entities.append({"type": "NAME", "value": name_val})
        cleaned = re.sub(name_honorific, "[REDACTED_OFFICER_NAME]", cleaned)

        # 8. Redact Contextual Reporter / Lead names ("Reported by [Name]", "Contact [Name]")
        reporter_pattern = r"(?i)\b(?:reported\s+by|contact|reach\s+out\s+to|reach)\s+(?:our\s+)?(?:ICT\s+lead\s+|lead\s+|officer\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+))\b"
        for m in re.finditer(reporter_pattern, cleaned):
            name_val = m.group(1)
            if "[REDACTED" not in name_val:
                redacted_entities.append({"type": "NAME", "value": name_val})
        cleaned = re.sub(reporter_pattern, r"Reported by [REDACTED_OFFICER_NAME]", cleaned)

        return cleaned, redacted_entities

    def route_incident(self, incident_type: str, severity: str, text: str) -> Tuple[str, str]:
        """Determine destination agency and provide institutional justification."""
        text_lower = text.lower()

        if incident_type == "Ransomware & Extortion":
            return (
                "National CERT (ngCERT)",
                "National cybersecurity threat involving extortion and critical infrastructure encryption; mandated for ngCERT coordinate containment."
            )
        elif "ippis" in text_lower or incident_type == "Unauthorized Access / Account Takeover":
            return (
                "Payroll & IPPIS Security Desk",
                "Direct compromise or modification of public salary disbursement systems requiring immediate payment freeze."
            )
        elif incident_type == "Business Email Compromise (BEC)":
            return (
                "EFCC Cybercrime Unit",
                "Financial fraud attempt involving impersonation of public officials to divert government contractor funds."
            )
        elif incident_type in ["Website Defacement", "Data Leak & PII Exposure"]:
            return (
                "NITDA Cyber Directorate",
                "Public sector data privacy breach under NDPR regulatory enforcement and government web compliance."
            )
        else:
            return (
                "Internal SOC / IR Team",
                "Perimeter security event requiring local firewall rule updates and endpoint quarantine."
            )

    def process_report(self, raw_text: str, report_id: str = "LIVE-001") -> Dict[str, Any]:
        """Full end-to-end Track D triage pipeline on a raw incident report."""
        incident_type, confidence, type_rationale = self.classify_type(raw_text)
        iocs = self.extract_iocs(raw_text)
        all_ioc_flat = iocs["ips"] + iocs["domains"] + iocs["urls"] + iocs["hashes"] + iocs["cves"]
        
        severity, score, sev_rationale = self.score_severity(raw_text, incident_type, all_ioc_flat)
        cleaned_text, redacted_pii = self.redact_pii(raw_text)
        destination, routing_rationale = self.route_incident(incident_type, severity, raw_text)

        # Detect target public sector entity
        target_entity = "Federal Public Sector MDA"
        org_patterns = [
            (r"\b(?:CBN|Central Bank(?: of Nigeria)?)\b", "Central Bank of Nigeria (CBN)"),
            (r"\b(?:FIRS|Federal Inland Revenue(?: Service)?)\b", "Federal Inland Revenue Service (FIRS)"),
            (r"\b(?:IPPIS|Accountant-General|OAGF|Payroll)\b", "Office of the Accountant-General (IPPIS)"),
            (r"\b(?:NIMC|National Identity(?: Management)?)\b", "National Identity Management Commission (NIMC)"),
            (r"\b(?:NAFDAC)\b", "NAFDAC Nigeria"),
            (r"\b(?:Federal High Court|Judiciary|Supreme Court)\b", "Federal High Court / Judiciary"),
            (r"\b(?:Bayero University|BUK|University of Lagos|UNILAG|ABU Zaria)\b", "Federal Universities / Tertiary"),
            (r"\b(?:Ministry of \w+)\b", "Federal Ministry"),
            (r"\b(?:LIRS|Lagos State Internal Revenue)\b", "Lagos State Internal Revenue Service (LIRS)")
        ]
        for pat, name in org_patterns:
            if re.search(pat, raw_text, re.IGNORECASE):
                target_entity = name
                break

        sla_data = self.SEVERITY_SLAS.get(severity, {})

        return {
            "report_id": report_id,
            "incident_type": incident_type,
            "confidence": confidence,
            "severity": severity,
            "urgency_score": score,
            "sla": sla_data.get("sla", "1 Hour"),
            "sla_level": sla_data.get("level", "P2"),
            "target_entity": target_entity,
            "technical_details": iocs,
            "ioc_count": len(all_ioc_flat),
            "cleaned_text": cleaned_text,
            "redacted_pii": redacted_pii,
            "pii_count": len(redacted_pii),
            "destination": destination,
            "statutory_router": destination,
            "routing_rationale": routing_rationale,
            "type_rationale": type_rationale,
            "raw_text": raw_text
        }

    def cluster_reports(self, triaged_reports: List[Dict[str, Any]], similarity_threshold: float = 0.35) -> List[Dict[str, Any]]:
        """Deduplicate reports and group repeat reports of the same incident."""
        if not triaged_reports:
            return []

        # Extract features for clustering
        corpus = [r["cleaned_text"] for r in triaged_reports]
        tfidf_matrix = self.vectorizer.fit_transform(corpus)
        sim_matrix = cosine_similarity(tfidf_matrix)

        clusters = []
        visited = set()

        for i, report in enumerate(triaged_reports):
            if i in visited:
                continue

            cluster_members = [report]
            visited.add(i)

            report_iocs = set(
                report["technical_details"]["ips"] +
                report["technical_details"]["domains"] +
                report["technical_details"]["urls"] +
                report["technical_details"]["hashes"]
            )

            for j in range(i + 1, len(triaged_reports)):
                if j in visited:
                    continue

                other_report = triaged_reports[j]
                other_iocs = set(
                    other_report["technical_details"]["ips"] +
                    other_report["technical_details"]["domains"] +
                    other_report["technical_details"]["urls"] +
                    other_report["technical_details"]["hashes"]
                )

                # Match condition: High text similarity OR exact shared IOC
                has_ioc_overlap = bool(report_iocs and other_iocs and (report_iocs & other_iocs))
                text_similarity = sim_matrix[i][j]

                if has_ioc_overlap or text_similarity >= similarity_threshold:
                    if report["incident_type"] == other_report["incident_type"]:
                        cluster_members.append(other_report)
                        visited.add(j)

            # Master Incident synthesis
            primary = max(cluster_members, key=lambda x: x["urgency_score"])
            # Merge all IOCs across members into a structured dict
            merged_iocs: Dict[str, list] = {"ips": [], "domains": [], "urls": [], "hashes": [], "cves": []}
            for m in cluster_members:
                td = m.get("technical_details", {})
                for key in merged_iocs:
                    merged_iocs[key] += td.get(key, [])
            # Deduplicate per key
            for key in merged_iocs:
                merged_iocs[key] = list(dict.fromkeys(merged_iocs[key]))

            # Derive target_entity from organization (fallback from reports)
            target_entity = None
            for m in cluster_members:
                org = m.get("organization") or m.get("target_entity")
                if org:
                    target_entity = org
                    break

            sla_data_cluster = self.SEVERITY_SLAS.get(primary["severity"], {})
            clusters.append({
                "cluster_id": f"INC-CLUSTER-{len(clusters)+1:03d}",
                "incident_type": primary["incident_type"],
                "severity": primary["severity"],
                "severity_level": sla_data_cluster.get("level", primary.get("sla_level", "P1")),
                "urgency_score": primary["urgency_score"],
                "sla": primary["sla"],
                "destination": primary["destination"],
                "statutory_router": primary["destination"],
                "target_entity": target_entity or "Federal Public Sector",
                "primary_report_id": primary["report_id"],
                "report_count": len(cluster_members),
                "is_duplicate_incident": len(cluster_members) > 1,
                "cleaned_summary": primary["cleaned_text"][:220] + "...",
                "raw_text": primary["raw_text"],
                "sanitized_text": primary["cleaned_text"],
                "iocs": merged_iocs,
                "all_iocs": list(set([
                    ioc for sub in merged_iocs.values() for ioc in sub
                ])),
                "reports": cluster_members
            })

        # Sort clusters by urgency score descending (most critical at top)
        clusters.sort(key=lambda c: c["urgency_score"], reverse=True)
        return clusters
