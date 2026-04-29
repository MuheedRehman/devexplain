from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import re
import os
from openai import OpenAI

app = FastAPI(title="DevExplain MVP")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TerraformInput(BaseModel):
    terraform_text: str


class Finding(BaseModel):
    severity: str
    title: str
    explanation: str
    suggestion: str


class ScanResponse(BaseModel):
    findings: List[Finding]
    summary: str
    risk_score: int
    risk_level: str

class AISummaryRequest(BaseModel):
    terraform_text: str
    findings: List[Finding]
    risk_score: int
    risk_level: str


class AISummaryResponse(BaseModel):
    ai_summary: str

class ValidationResult(BaseModel):
    is_valid: bool
    message: str

def validate_terraform_input(terraform_text: str):
    text = terraform_text.strip()

    if not text:
        return False, "No input provided."

    terraform_patterns = [
        r'\bresource\s+"[^"]+"\s+"[^"]+"\s*\{',
        r'\bprovider\s+"[^"]+"\s*\{',
        r'\bmodule\s+"[^"]+"\s*\{',
        r'\bvariable\s+"[^"]+"\s*\{',
        r'\boutput\s+"[^"]+"\s*\{',
        r'\bterraform\s*\{'
    ]

    is_terraform = any(re.search(p, text, re.IGNORECASE) for p in terraform_patterns)

    if not is_terraform:
        return False, "❌ This does not look like Terraform code."

    if text.count("{") != text.count("}"):
        return False, "❌ Possible syntax error: mismatched braces."

    return True, ""

def analyze_terraform(terraform_text: str) -> List[Finding]:
    findings: List[Finding] = []
    text = terraform_text.lower()

    # 1. Public storage access
    if 'resource "azurerm_storage_account"' in text:
        public_access_patterns = [
            r"allow_blob_public_access\s*=\s*true",
            r"public_network_access_enabled\s*=\s*true",
        ]
        for pattern in public_access_patterns:
            if re.search(pattern, text):
                findings.append(
                    Finding(
                        severity="high",
                        title="Public storage access may be enabled",
                        explanation="Your Azure Storage Account appears to allow public access. This can expose data to the internet if not intentionally configured.",
                        suggestion="Review public access settings and disable them unless explicitly needed. For example, set allow_blob_public_access = false."
                    )
                )
                break

    # 2. Missing tags
    azure_resource_mentions = re.findall(
        r'resource\s+"azurerm_[^"]+"\s+"[^"]+"\s*\{',
        terraform_text
    )
    has_tags_block = re.search(r"\btags\s*=\s*\{", terraform_text, re.IGNORECASE)
    if azure_resource_mentions and not has_tags_block:
        findings.append(
            Finding(
                severity="low",
                title="Tags are missing",
                explanation="Tags help with cost tracking, ownership, and operations. Your Terraform appears to define Azure resources without tags.",
                suggestion="Add a tags map to your resources, for example: environment, owner, and project."
            )
        )

    # 3. Large VM size detection
    large_vm_match = re.search(r'(vm_size|size)\s*=\s*"(standard_[^"]+)"', text)
    if large_vm_match:
        vm_size = large_vm_match.group(2)
        large_sizes = ["standard_d4", "standard_d8", "standard_e4", "standard_e8"]
        if any(vm_size.startswith(size) for size in large_sizes):
            findings.append(
                Finding(
                    severity="low",
                    title="VM size may be larger than needed",
                    explanation=f"The VM size '{vm_size}' may be more expensive than necessary for development or testing workloads.",
                    suggestion="Consider using a smaller VM size to reduce cost."
                )
            )

    # 4. Missing NSG
    has_network_interface = 'resource "azurerm_network_interface"' in text
    has_nsg = 'resource "azurerm_network_security_group"' in text
    if has_network_interface and not has_nsg:
        findings.append(
            Finding(
                severity="medium",
                title="No Network Security Group detected",
                explanation="Your configuration contains a network interface but no Network Security Group. This may mean traffic rules are not explicitly controlled.",
                suggestion="Consider defining an azurerm_network_security_group and associating it with the subnet or NIC."
            )
        )

    # 5. Open internet access
    if "0.0.0.0/0" in text:
        findings.append(
            Finding(
                severity="high",
                title="Open to the Internet (0.0.0.0/0)",
                explanation="Your configuration allows access from any IP address on the internet.",
                suggestion="Restrict access to specific IP ranges or use private networking."
            )
        )

    # 6. Possible hardcoded secret
    if re.search(r'password\s*=\s*".+"', text):
        findings.append(
            Finding(
                severity="high",
                title="Hardcoded password detected",
                explanation="Sensitive values like passwords should not be hardcoded in Terraform.",
                suggestion="Use environment variables or secret management tools like Azure Key Vault."
            )
        )

    # 7. Open SSH/RDP ports to the internet
    open_port_patterns = [
        r'destination_port_range\s*=\s*"22"',
        r'destination_port_range\s*=\s*"3389"',
        r'destination_port_ranges\s*=\s*\[[^\]]*"22"[^\]]*\]',
        r'destination_port_ranges\s*=\s*\[[^\]]*"3389"[^\]]*\]'
    ]
    if "0.0.0.0/0" in text:
        for pattern in open_port_patterns:
            if re.search(pattern, text):
                findings.append(
                    Finding(
                        severity="high",
                        title="SSH or RDP may be open to the internet",
                        explanation="Your configuration appears to allow port 22 (SSH) or 3389 (RDP) from any IP address. This is a common security risk.",
                        suggestion="Restrict management access to trusted IP ranges, use a VPN, or use Azure Bastion instead of exposing SSH/RDP publicly."
                    )
                )
                break

    # 8. Missing HTTPS-only setting on Azure Storage
    if 'resource "azurerm_storage_account"' in text:
        has_https_only_true = re.search(r'enable_https_traffic_only\s*=\s*true', text)
        has_https_only_false = re.search(r'enable_https_traffic_only\s*=\s*false', text)

        if has_https_only_false:
            findings.append(
                Finding(
                    severity="high",
                    title="HTTPS-only traffic is disabled on storage",
                    explanation="Your storage account appears to allow non-HTTPS traffic, which can expose data in transit.",
                    suggestion="Set enable_https_traffic_only = true to enforce encrypted connections."
                )
            )
        elif not has_https_only_true:
            findings.append(
                Finding(
                    severity="medium",
                    title="HTTPS-only setting is not explicitly defined",
                    explanation="Your storage account does not explicitly enforce HTTPS-only traffic in this configuration.",
                    suggestion="Add enable_https_traffic_only = true to ensure traffic encryption is enforced."
                )
            )

    # 9. Public IP resource detected
    if 'resource "azurerm_public_ip"' in text:
        findings.append(
            Finding(
                severity="medium",
                title="Public IP resource detected",
                explanation="Your Terraform defines a public IP resource. Public IPs can be necessary, but they increase internet exposure and should be reviewed carefully.",
                suggestion="Confirm whether the public IP is truly needed. If not, consider private networking or controlled ingress patterns."
            )
        )

    return findings


HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>DevExplain</title>
  <style>
    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: #f5f7fb;
      color: #111;
    }

    .container {
      max-width: 1000px;
      margin: auto;
      padding: 40px 20px;
    }

    .hero {
      text-align: center;
      margin-bottom: 40px;
    }

    .hero h1 {
      font-size: 40px;
      margin-bottom: 10px;
    }

    .hero p {
      color: #555;
      font-size: 18px;
    }

    .features {
      display: flex;
      justify-content: center;
      gap: 20px;
      margin-bottom: 30px;
      flex-wrap: wrap;
    }

    .feature {
      background: white;
      padding: 12px 18px;
      border-radius: 10px;
      box-shadow: 0 4px 10px rgba(0,0,0,0.05);
      font-size: 14px;
    }

    .card {
      background: white;
      padding: 25px;
      border-radius: 14px;
      box-shadow: 0 8px 20px rgba(0,0,0,0.08);
    }

    textarea {
      width: 100%;
      height: 220px;
      padding: 12px;
      border-radius: 10px;
      border: 1px solid #ddd;
      font-family: monospace;
      margin-top: 10px;
    }

    input[type="file"] {
      margin-top: 10px;
    }

    .buttons {
      margin-top: 15px;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }

    button {
      padding: 10px 16px;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-weight: bold;
    }

    .scan {
      background: #2563eb;
      color: white;
    }

    .secondary {
      background: #e5e7eb;
    }

    .summary {
      margin-top: 25px;
      font-size: 18px;
      font-weight: bold;
    }

    .risk-box {
      margin-top: 10px;
      padding: 12px;
      border-radius: 10px;
      font-weight: bold;
    }

    .risk-high {
      background: #fee2e2;
      color: #991b1b;
    }

    .risk-medium {
      background: #fef3c7;
      color: #92400e;
    }

    .risk-low {
      background: #dcfce7;
      color: #166534;
    }

    .finding {
      margin-top: 15px;
      padding: 15px;
      border-radius: 10px;
      background: #fafafa;
      border-left: 5px solid #ccc;
    }

    .footer {
      text-align: center;
      margin-top: 40px;
      font-size: 13px;
      color: #777;
    }
  </style>
</head>
<body>

<div class="container">

  <div class="hero">
    <h1>🔍 DevExplain</h1>
    <p>Understand Terraform risks, security issues, costs , and AI explanations in seconds</p>
  </div>

  <div class="features">
    <div class="feature">⚡ Instant Analysis</div>
    <div class="feature">🔐 Security Insights</div>
    <div class="feature">💰 Cost Awareness</div>
  </div>

  <div class="card">

    <input type="file" id="fileInput" accept=".tf" onchange="loadFile(event)">

    <textarea id="input" placeholder="Paste your Terraform code here..."></textarea>

    <div class="buttons">
      <button class="scan" onclick="scan()">Scan</button>
      <button class="secondary" onclick="sample()">Sample</button>
      <button class="secondary" onclick="clearAll()">Clear</button>
      <button class="secondary" onclick="generateAiSummary()">AI Explanation</button>
    </div>

    <div id="results"></div>
    <div id="aiSummary"></div>

  </div>

  <div class="footer">
    Built for DevOps engineers • Terraform • Azure • Security-first
  </div>

</div>

<script>

let latestScanResult = null;

function loadFile(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    document.getElementById("input").value = e.target.result;
  };
  reader.readAsText(file);
}

function sample() {
  document.getElementById("input").value = 'resource "azurerm_storage_account" "example" { allow_blob_public_access = true }';
}

function clearAll() {
  document.getElementById("input").value = "";
  document.getElementById("results").innerHTML = "";
  document.getElementById("aiSummary").innerHTML = "";
  latestScanResult = null;
}

async function generateAiSummary() {
  if (!latestScanResult) {
    document.getElementById("aiSummary").innerHTML =
      `<div class="finding">Run a scan first.</div>`;
    return;
  }

  const terraformText = document.getElementById("input").value;

  document.getElementById("aiSummary").innerHTML =
    `<div class="finding">🤖 Generating AI explanation...</div>`;

  try {
    const res = await fetch("/ai-summary", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        terraform_text: terraformText,
        findings: latestScanResult.findings || [],
        risk_score: latestScanResult.risk_score || 0,
        risk_level: latestScanResult.risk_level || "Low"
      })
    });

    const data = await res.json();

    console.log("AI response:", data);

    const aiText =
      data.ai_summary ||
      JSON.stringify(data, null, 2) ||
      "No AI summary returned.";

    document.getElementById("aiSummary").innerHTML = `
      <div class="finding">
        <b>🤖 AI Explanation</b><br><br>
        <div style="white-space: pre-line;">${aiText}</div>
      </div>
    `;
  } catch (err) {
    document.getElementById("aiSummary").innerHTML =
      `<div class="finding">❌ AI failed: ${err.message}</div>`;
  }
}

async function scan() {
  const text = document.getElementById("input").value;

  document.getElementById("results").innerHTML = "Analyzing...";

  const res = await fetch("/scan", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ terraform_text: text })
  });

  const data = await res.json();
  latestScanResult = data;
  console.log("Scan result:", latestScanResult);

  let riskClass = "risk-low";
  if (data.risk_level === "High") riskClass = "risk-high";
  if (data.risk_level === "Medium") riskClass = "risk-medium";

  let html = `
    <div class="summary">${data.summary}</div>
    <div class="risk-box ${riskClass}">
      Risk Score: ${data.risk_score} | ${data.risk_level}
    </div>
  `;

  data.findings.forEach(f => {
    html += `
      <div class="finding">
        <b>${f.title}</b><br>
        ${f.explanation}<br><br>
        <i>${f.suggestion}</i>
      </div>
    `;
  });

  document.getElementById("results").innerHTML = html;
}

</script>

</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(content=HOME_PAGE)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ai-summary", response_model=AISummaryResponse)
def ai_summary(request: AISummaryRequest):
    api_key = os.environ.get("OPENAI_API_KEY")

    if not api_key:
        return AISummaryResponse(
            ai_summary="AI is not configured yet. Please set OPENAI_API_KEY in Azure App Service settings."
        )

    client = OpenAI(api_key=api_key)

    findings_text = "\n".join(
        [
            f"- Severity: {f.severity}\n  Title: {f.title}\n  Explanation: {f.explanation}\n  Suggested fix: {f.suggestion}"
            for f in request.findings
        ]
    )

    prompt = f"""
You are a DevSecOps assistant.

Analyze this Terraform scan result and explain it in simple, practical language.

Risk score: {request.risk_score}/10
Risk level: {request.risk_level}

Findings:
{findings_text}

Terraform code:
{request.terraform_text[:4000]}

Return:
1. A short overall summary
2. The top 3 most important risks
3. The first fixes the developer should apply
4. A beginner-friendly explanation
"""

    try:
        response = client.responses.create(
            model="gpt-4.1-mini",
            input=prompt,
        )

        return AISummaryResponse(ai_summary=response.output_text)

    except Exception as e:
        return AISummaryResponse(
            ai_summary=f"AI summary failed: {str(e)}"
        )


@app.post("/scan", response_model=ScanResponse)
def scan(request: TerraformInput):
     
    is_valid, message = validate_terraform_input(request.terraform_text)

    if not is_valid:
        return ScanResponse(
            summary=message,
            findings=[],
            risk_score=0,
            risk_level="Invalid"
        )

    findings = analyze_terraform(request.terraform_text)

    if not findings:
        summary = "✅ No obvious issues found in this basic scan."
    else:
        summary = f"⚠️ Found {len(findings)} potential issue(s)."

    raw_score = 0
    for finding in findings:
        severity = finding.severity.lower()
        if severity == "high":
            raw_score += 3
        elif severity == "medium":
            raw_score += 2
        else:
            raw_score += 1

    risk_score = min(10, raw_score)

    if risk_score >= 7:
        risk_level = "High"
    elif risk_score >= 4:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return ScanResponse(
        summary=summary,
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level
    )