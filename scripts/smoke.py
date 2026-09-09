#!/usr/bin/env python3
"""Real compiled-provider protocol/schema + offline validate/plan smoke.

No appliance is contacted. The plan contains resources only; no refresh or
apply occurs. Dev overrides deliberately bypass Registry installation.
"""
from pathlib import Path
import json
import os
import subprocess

root = Path(__file__).resolve().parents[1]
work = root / ".local" / "smoke"
work.mkdir(parents=True, exist_ok=True)
cli = work / "terraform.rc"
# Absolute paths are HCL strings encoded safely by json.dumps.
cli.write_text('provider_installation {\n  dev_overrides {\n'
               '    "Scriptception/algosec" = ' + json.dumps(str(root / "bin")) + '\n'
               '  }\n  direct {}\n}\n')
(work / "main.tf").write_text('''terraform {
  required_version = ">= 1.11.0"
  required_providers {
    algosec = {
      source = "Scriptception/algosec"
    }
  }
}
provider "algosec" {
  url = "https://appliance.example.invalid"
  session_id = "syntheticSmokeSession"
  read_only = false
  experimental_tags = true
  experimental_url_ip_memberships = true
  experimental_device_groups = true
  experimental_trusted_rules = true
  experimental_appviz_roles = true
 appviz_whole_role_ownership = true
  appviz_saas_url = "https://saas.example.invalid"
  appviz_saas_token = "syntheticSmokeToken"
}
resource "algosec_url_category" "smoke" {
  name = "tf-smoke"
  urls = { "service.example.invalid" = ["192.0.2.1"] }
}
resource "algosec_device_group" "smoke" {
  display_name = "Synthetic smoke"
  members = ["Example Device"]
}
resource "algosec_trusted_rule" "smoke" {
  device_name = "SyntheticDevice"
  rule_id = "synthetic-rule"
}
resource "algosec_appviz_role" "smoke" {
 name = "Synthetic reviewers"
}
resource "algosec_tag" "smoke" { name = "Synthetic tag" }
resource "algosec_url_ip_membership" "smoke" {
 category = "Separate existing category"
 url = "www.example.com"
 ip = "192.0.2.3"
}
''')
env = {k: v for k, v in os.environ.items() if not k.startswith("ALGOSEC_")}
env.update(TF_CLI_CONFIG_FILE=str(cli), TF_IN_AUTOMATION="1", CHECKPOINT_DISABLE="1")
terraform = os.environ.get("TERRAFORM", "terraform")

def run(*args, capture=False):
    return subprocess.run([terraform, *args], cwd=work, env=env, check=True,
                          text=True, stdout=subprocess.PIPE if capture else None)

result = run("providers", "schema", "-json", capture=True)
schema = json.loads(result.stdout)
p = schema["provider_schemas"]["registry.terraform.io/scriptception/algosec"]
assert len(p["resource_schemas"]) == 6
assert len(p["data_source_schemas"]) == 12
(work / "schema.json").write_text(result.stdout)
run("validate", "-no-color")
run("plan", "-refresh=false", "-input=false", "-no-color", "-out=smoke.tfplan")
plan = json.loads(run("show", "-json", "smoke.tfplan", capture=True).stdout)
assert all(r["change"]["actions"] == ["create"] for r in plan["resource_changes"])
assert len(plan["resource_changes"]) == 6
print("Compiled provider: schema 6 resources / 12 data sources; validate passed; plan has 6 creates.")
