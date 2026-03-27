from flask import Flask, render_template, request, make_response
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os
import traceback
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Legacy V2 modules
from cvss import get_vulnerability_data
from recon import perform_recon
from detection import (
    detect_advanced_sqli, detect_advanced_xss, detect_idor,
    detect_directory_traversal, detect_cors_misconfig, detect_information_disclosure,
    detect_csrf, detect_business_logic, detect_rate_limiting,
    detect_open_redirect, detect_http_methods, detect_weak_cookies,
    detect_server_banner, detect_directory_listing, detect_mixed_content,
    detect_command_injection, detect_dom_xss
)

# Next-Generation AI & Research Modules
from core.ai_analyzer import run_ai_analysis
from core.zero_day import run_zero_day_analysis
from core.feedback_loop import SelfLearningFeedbackLoop
from core.risk_model import apply_risk_intelligence
from core.intelligence_layer import correlate_hybrid_findings
from hybrid.sast_analyzer import run_sast
from orchestrator import DistributedOrchestrator

app = Flask(__name__)

SCAN_CONFIG = {
    "quick": { "max_pages": 10, "deep_payloads": False, "threads": 5 },
    "deep": { "max_pages": 30, "deep_payloads": True, "threads": 10 },
    "research": { "max_pages": 50, "deep_payloads": True, "threads": 15 }
}

def generate_pdf_report(target, security_score, recon_data, results):
    if not os.path.exists("static"): os.makedirs("static")
    filepath = f"static/report_{int(time.time())}.pdf"
    
    c = canvas.Canvas(filepath, pagesize=letter)
    width, height = letter
    
    c.setFont("Helvetica-Bold", 24)
    c.drawString(50, height - 70, "Next-Gen AI Security Intelligence Report")
    
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 100, f"Target Instance: {target}")
    c.drawString(50, height - 120, f"Predictive Security Score: {security_score}/100")
    
    y = height - 160
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Vulnerabilities Identified")
    y -= 25
    
    c.setFont("Helvetica", 10)
    for r in results:
        if y < 100:
            c.showPage()
            y = height - 50
        c.setFont("Helvetica-Bold", 11)
        name_str = f"{r['type']} ({r.get('contextual_severity', r.get('severity', 'Medium'))})"
        c.drawString(50, y, name_str)
        y -= 15
        
        c.setFont("Helvetica", 10)
        c.drawString(60, y, f"CVSS base: {r.get('cvss', 'N/A')} | AI Likelihood: {r.get('ai_likelihood', 0.5)} | Priority: {r.get('priority_score', 0)}")
        y -= 25
        
    c.save()
    return filepath

def generate_chart(results):
    severity_count = {}
    for r in results:
        sev = r.get("contextual_severity", r.get("severity", "Medium"))
        severity_count[sev] = severity_count.get(sev, 0) + 1

    if not os.path.exists("static"): os.makedirs("static")
    if not severity_count:
        plt.figure()
        plt.pie([1], labels=["AI Verified Secure"], colors=["#28a745"])
        plt.title("Priority Distribution")
        plt.savefig("static/severity_chart.png", transparent=True)
        plt.close()
        return

    colors_map = { "Critical": "#8b0000", "High": "#dc3545", "Medium": "#fd7e14", "Low": "#28a745" }
    colors = [colors_map.get(sev, "#6c757d") for sev in severity_count.keys()]

    plt.figure()
    plt.pie(severity_count.values(), labels=severity_count.keys(), colors=colors, autopct="%1.1f%%", shadow=True, startangle=140)
    plt.title("Priority Distribution")
    plt.savefig("static/severity_chart.png", transparent=True)
    plt.close()

# The core scanning function passed to the Orchestrator
def master_scan_url(url, forms, config):
    findings = []
    csrf_flag = False
    deep = config["deep_payloads"]

    # DAST Active Scanning
    for f in detect_advanced_sqli(url, forms, deep=deep): findings.append((f, url))
    for f in detect_advanced_xss(url, forms): findings.append((f, url))
    for f in detect_idor(url, forms): findings.append((f, url))
    
    if deep:
        for f in detect_directory_traversal(url): findings.append((f, url))
        for f in detect_cors_misconfig(url): findings.append((f, url))
        for f in detect_information_disclosure(url): findings.append((f, url))
        for f in detect_command_injection(url, forms): findings.append((f, url))
        for f in detect_dom_xss(url): findings.append((f, url))

    for f in detect_business_logic(url, forms): findings.append((f, url))
    for f in detect_rate_limiting(url, forms): findings.append((f, url))
    
    if detect_csrf(url, forms): csrf_flag = True

    for f in detect_open_redirect(url): findings.append((f, url))
    for f in detect_http_methods(url): findings.append((f, url))
    for f in detect_weak_cookies(url): findings.append((f, url))
    for f in detect_server_banner(url): findings.append((f, url))
    for f in detect_directory_listing(url): findings.append((f, url))
    for f in detect_mixed_content(url): findings.append((f, url))

    # Autonomous Zero-Day / Anomaly Simulation
    zero_days = run_zero_day_analysis(url, forms)
    for z in zero_days:
        findings.append((z, url))

    return findings, csrf_flag

global_latest_report = None
feedback_db = SelfLearningFeedbackLoop()

@app.route("/", methods=["GET", "POST"])
def dashboard():
    global global_latest_report
    
    if request.method == "POST":
        try:
            start_time = time.time()
            targets_raw = request.form["target"].strip()
            scan_mode = request.form.get("scan_mode", "quick")
            sast_dir = request.form.get("sast_dir", "").strip()

            targets = [t.strip() for t in targets_raw.split(',') if t.strip()]
            for i in range(len(targets)):
                if not targets[i].startswith(("http://", "https://")):
                    targets[i] = "http://" + targets[i]
                    
            if not targets:
                raise Exception("No valid targets provided.")

            config = SCAN_CONFIG.get(scan_mode, SCAN_CONFIG["quick"])
            
            # The dashboard only displays recon for the PRIMARY target if multiple
            primary_target = targets[0]
            recon_data = perform_recon(primary_target)

            # 1. Orchestrated DAST & Zero-Day Crawling
            orchestrator = DistributedOrchestrator(targets, max_workers=config["threads"])
            orch_results = orchestrator.run_distributed_scan(master_scan_url, config)
            
            # Extract total findings
            raw_dast_findings = []
            total_pages_crawled = 0
            scan_errors = []
            for t_url, t_data in orch_results.items():
                if "error" in t_data:
                    scan_errors.append(f"{t_url}: {t_data['error']}")
                    continue
                total_pages_crawled += len(t_data.get("urls", []))
                
                # Unpack tuple format (finding_dict, target_url)
                for f_tuple in t_data.get("findings", []):
                    f_dict = f_tuple[0]
                    f_dict["url"] = f_tuple[1]
                    raw_dast_findings.append(f_dict)
                    
                for csrf_url in t_data.get("csrf", []):
                    raw_dast_findings.append({"type": "Missing CSRF Protection", "confidence": "High", "url": csrf_url, "evidence": "Form token missing"})

            # 2. Add Missing Headers to Findings
            for audit in recon_data.get("header_audit", []):
                if audit["status"] == "Fail":
                    raw_dast_findings.append({
                        "type": "Missing Security Header",
                        "header": audit["header"],
                        "confidence": "High",
                        "url": primary_target,
                        "evidence": "Detected in base response"
                    })

            # 3. SAST Execution
            sast_findings = []
            if sast_dir and os.path.exists(sast_dir):
                sast_findings = run_sast(sast_dir)

            # 4. Hybrid Intelligence Correlation
            unified_findings = correlate_hybrid_findings(sast_findings, raw_dast_findings)

            # 5. AI Autonomous Evaluator (PoC Generation & Likelihood scoring)
            ai_enriched = run_ai_analysis(unified_findings)
            
            # 6. Self-Learning Feedback Weighting
            learned_findings = feedback_db.apply_learning(ai_enriched)
            
            # 7. Map OWASP/CVSS Baseline Details
            for f in learned_findings:
                mapped = get_vulnerability_data(f["type"])
                f["cvss"] = mapped["score"]
                f["severity"] = mapped["severity"]
                f["cwe"] = mapped["cwe"]
                f["owasp"] = mapped["owasp"]
                f["desc"] = mapped["desc"]
                f["remediation"] = mapped["remediation"]
                
            # Deduplicate by type and URL roughly
            unique_mapping = {}
            for f in learned_findings:
                key = f"{f['type']}_{f.get('url', '')}"
                if key not in unique_mapping:
                    unique_mapping[key] = f
            final_list = list(unique_mapping.values())

            # 8. Contextual Risk Prioritization
            business_context = {
                "critical_data_assets": request.form.get("critical_data", "off") == "on",
                "public_facing": True,
                "compliance_scoping": []
            }
            if request.form.get("gdpr", "off") == "on": business_context["compliance_scoping"].append("GDPR")
            
            prioritized_results = apply_risk_intelligence(final_list, business_context)

            # 9. Metrics Generation
            avg_priority = sum(r.get("priority_score", 0) for r in prioritized_results) / max(1, len(prioritized_results))
            security_score = round(max(0, 100 - avg_priority * 10), 2)
            
            if avg_priority >= 9.0: overall_severity = "Critical"
            elif avg_priority >= 7.0: overall_severity = "High"
            elif avg_priority >= 4.0: overall_severity = "Medium"
            else: overall_severity = "Low"
            if not raw_dast_findings:
                if scan_errors:
                    security_score = 0
                    overall_severity = "Unreachable"
                    for err in scan_errors:
                        raw_dast_findings.append({
                            "type": "Target Connectivity Failure",
                            "severity": "High",
                            "confidence": "Critical",
                            "desc": "The scanning engine was unable to establish a stable connection with the target.",
                            "remediation": f"Verify DNS resolution and firewall egress rules for host: {err}",
                            "url": primary_target
                        })
                else:
                    security_score = 100.0
                    overall_severity = "Secure Baseline"

            generate_chart(prioritized_results)
            
            duration = round(time.time() - start_time, 2)
            scan_meta = {
                "target": primary_target,
                "mode": scan_mode.capitalize(),
                "duration": duration,
                "pages_crawled": total_pages_crawled,
                "multi_target": len(targets) > 1,
                "sast_active": len(sast_findings) > 0
            }
            
            # Calculate severity counts for charts
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for r in prioritized_results:
                sev = r.get('contextual_severity', r.get('severity', 'Medium'))
                if sev in severity_counts:
                    severity_counts[sev] += 1

            return render_template(
                "dashboard.html",
                results=prioritized_results,
                security_score=security_score,
                overall_cvss=round(avg_priority, 2),
                overall_severity=overall_severity,
                recon_data=recon_data,
                scan_meta=scan_meta,
                pdf_report_available=True,
                severity_counts=severity_counts
            )

        except Exception as e:
            traceback.print_exc()
            return render_template("dashboard.html", error=str(e))

    return render_template("dashboard.html", results=None, security_score=None, severity_counts={"Critical": 0, "High": 0, "Medium": 0, "Low": 0})

@app.route("/download_report")
def download_report():
    global global_latest_report
    if global_latest_report and os.path.exists(global_latest_report):
        with open(global_latest_report, "rb") as f:
            pdf_data = f.read()
        response = make_response(pdf_data)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=AI_Risk_Report.pdf'
        return response
    return "Report not generated yet", 404

if __name__ == "__main__":
    app.run(debug=False)