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

        # ML Classification if trained
        if self.is_trained:
            X = self.vectorizer.transform([text])
            predicted_type = self.classifier.predict(X)[0]
            probs = self.classifier.predict_proba(X)[0]
            max_prob = float(max(probs))
            
            # Confidence boost if decisive keywords present
            rationale = f"Classified as '{predicted_type}' (Confidence: {max_prob:.1%}) based on linguistic patterns and threat indicators."
            return predicted_type, round(max_prob, 2), rationale

        # Rule-based fallback for offline resilience
        if any(k in text_lower for k in ["ransomware", ".locked", "btc", "bitcoin", "decrypt"]):
            return "Ransomware & Extortion", 0.95, "Detected explicit encryption indicators (.locked) and cryptocurrency ransom demands."
        elif any(k in text_lower for k in ["ippis", "payroll", "beneficiary", "ghost", "bvn", "salary"]):
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

        # Deduplicate
        for k in iocs:
            iocs[k] = list(set(iocs[k]))

        return iocs

    def redact_pii(self, text: str) -> Tuple[str, List[Dict[str, str]]]:
        """Identify and redact Nigerian PII (BVN, NIN, Phone, Accounts, Names, Emails)."""
        redacted_entities = []
        cleaned = text

        # 1. Redact Nigerian Phone Numbers (e.g. 0803..., +234...)
        phone_pattern = r"(\+?234\d{10}|0[789][01]\d{8})"
        for m in re.finditer(phone_pattern, cleaned):
            phone = m.group(0)
            redacted_entities.append({"type": "PHONE", "value": phone})
        cleaned = re.sub(phone_pattern, "[REDACTED_PHONE]", cleaned)

        # 2. Redact BVN (11 digits, typically starting with 22)
        bvn_pattern = r"\b22\d{9}\b"
        for m in re.finditer(bvn_pattern, cleaned):
            bvn = m.group(0)
            redacted_entities.append({"type": "BVN", "value": bvn})
        cleaned = re.sub(bvn_pattern, "[REDACTED_BVN]", cleaned)

        # 3. Redact NIN (11 digits, typically starting with 54)
        nin_pattern = r"\b54\d{9}\b"
        for m in re.finditer(nin_pattern, cleaned):
            nin = m.group(0)
            redacted_entities.append({"type": "NIN", "value": nin})
        cleaned = re.sub(nin_pattern, "[REDACTED_NIN]", cleaned)

        # 4. Redact NUBAN Bank Account numbers (10 digits starting with 01)
        acct_pattern = r"\b01\d{8}\b"
        for m in re.finditer(acct_pattern, cleaned):
            acct = m.group(0)
            redacted_entities.append({"type": "ACCOUNT", "value": acct})
        cleaned = re.sub(acct_pattern, "[REDACTED_ACCOUNT]", cleaned)

        # 5. Redact Email Addresses (except attacker IOC domains)
        email_pattern = r"\b[A-Za-z0-9._%+-]+@(?:gov\.ng|gmail\.com|yahoo\.com|outlook\.com)\b"
        for m in re.finditer(email_pattern, cleaned, re.IGNORECASE):
            email = m.group(0)
            redacted_entities.append({"type": "EMAIL", "value": email})
        cleaned = re.sub(email_pattern, "[REDACTED_EMAIL]", cleaned)

        # 6. Redact common Nigerian Honorific + Names (e.g., Dr. Musa Abdullahi, Malam Ibrahim)
        name_pattern = r"\b(?:Dr\.|Mr\.|Mrs\.|Malam|Alhaji|Engr\.)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b"
        for m in re.finditer(name_pattern, cleaned):
            full_hit = m.group(0)
            name_val = m.group(1)
            redacted_entities.append({"type": "NAME", "value": name_val})
        cleaned = re.sub(name_pattern, "[REDACTED_OFFICER_NAME]", cleaned)

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
