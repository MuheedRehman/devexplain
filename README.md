# DevExplain 🔍

DevExplain is a lightweight DevOps tool that analyzes Terraform code and explains security risks, cost issues, and misconfigurations in a simple way.

## Features

- Paste Terraform code or upload a `.tf` file
- Detect public exposure risks
- Identify hardcoded secrets
- Flag insecure network configurations
- Detect missing tags and HTTPS-only settings
- Generate a risk score
- Provide suggested fixes
- Optional AI explanation for scan results

## Tech Stack

- Python
- FastAPI
- OpenAI API
- Azure App Service
- Terraform

## Live Demo

https://devexplain-22148.azurewebsites.net/

## How it works

1. Paste or upload Terraform code
2. Click **Scan**
3. Review findings and risk score
4. Generate AI explanation if enabled

## Security Note

The OpenAI API key is not stored in the code. It is configured as an environment variable in Azure App Service:

```bash
OPENAI_API_KEY
