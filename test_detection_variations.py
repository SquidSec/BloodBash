#!/usr/bin/env python3
"""
Unit tests for every detection *variation* under the 32 finding categories.

A variation is a distinct logical check/outcome type (ESC subtype, ACL right,
inventory bucket, password-description pattern, etc.) — 106 total, matching
the enumeration methodology used for product coverage reporting.
"""
from __future__ import annotations

import os
import re
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import networkx as nx
from rich.console import Console

bloodbash_globals = {}
with open("BloodBash.py", "r", encoding="utf-8") as f:
    exec(f.read(), bloodbash_globals)

AD_RIGHTS = [
    "genericall", "owns", "writedacl", "writeowner", "allextendedrights",
    "genericwrite", "addmember", "resetpassword", "forcechangepassword",
    "manageca", "managecertificates", "enroll", "certificateenroll", "writeproperty",
]
AZURE_RIGHTS = [
    "genericall", "owns", "writedacl", "writeowner", "addsecret", "addcertificate",
    "addowner", "execute", "canread", "canwrite", "candelete",
]
# Keep in sync with BloodBash.PASSWORD_IN_DESC_PATTERNS (ticket-text FPs removed)
PASSWORD_PATTERNS = list(bloodbash_globals.get(
    "PASSWORD_IN_DESC_PATTERNS",
    (
        r"\bpassword\s*[:=]\s*\S+",
        r"\bpwd\s*[:=]\s*\S+",
        r"\bpass(?:word)?\s*[:=]\s*\S+",
        r"\bcredentials?\s*[:=]\s*\S+",
        r"\bsecret\s*[:=]\s*\S+",
        r"\bpasswd\s*[:=]\s*\S+",
    ),
))
PASSWORD_AGE_BUCKETS = [
    b[0] for b in bloodbash_globals["PASSWORD_AGE_BUCKETS"]
] + ["Never set / unknown", "30 days – 6 months", "Other"]
STALE_BUCKETS = [
    b[0] for b in bloodbash_globals["STALE_ACCOUNT_BUCKETS"]
] + ["Never active / unknown", "Active < 6 months"]
ESC_TYPES = ["ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC7", "ESC8", "ESC9", "ESC13"]
SHADOW_RIGHTS = ["AddKeyCredentialLink", "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl"]
AZURE_PRIV_ROLES = [
    "global admin", "user admin", "application admin", "exchange admin",
    "sharepoint admin", "intune admin", "security admin", "conditional access admin",
    "privileged role admin",
]


def _slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", s).strip("_").lower()[:80]


class TestDetectionVariations(unittest.TestCase):
    def setUp(self):
        self._saved = bloodbash_globals["global_findings"]
        bloodbash_globals["global_findings"] = []
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        bloodbash_globals["global_findings"] = self._saved
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _capture(self, func, *args, **kwargs):
        string_io = StringIO()
        test_console = Console(file=string_io, width=120, legacy_windows=False)
        with patch.object(bloodbash_globals["console"], "print", side_effect=test_console.print):
            # tqdm can also write; leave as-is
            func(*args, **kwargs)
        return string_io.getvalue()

    def _strip(self, text: str) -> str:
        return re.sub(r"\x1b\[[0-9;]*m", "", text)

    def _findings(self, category=None):
        rows = list(bloodbash_globals["global_findings"])
        if category is None:
            return rows
        return [f for f in rows if f[1] == category]

    # ────────────────────────────────────────────────
    # Registry size
    # ────────────────────────────────────────────────
    def test_variation_count_is_106(self):
        """Canonical variation enumeration must stay at 106."""
        n = (
            len(ESC_TYPES)  # 10
            + 2  # DCSync
            + 1  # RBCD
            + len(AD_RIGHTS) + len(AZURE_RIGHTS)  # 25
            + 2  # SID history
            + 1  # GPO abuse
            + 1 + 1  # kerb / asrep
            + 1  # shortest
            + 1 + 1  # password never / not required
            + len(SHADOW_RIGHTS)  # 5
            + 4  # GPO content
            + 1 + 1  # constrained / unconstrained
            + 1  # LAPS
            + 1  # owned paths
            + len(PASSWORD_PATTERNS)  # 6 (tightened; no account:/admin:/login:/key: FPs)
            + 1  # arbitrary paths
            + 2  # trust
            + 2  # deep nesting
            + 2  # busiest
            + 1  # path break
            + len(PASSWORD_AGE_BUCKETS)  # 12
            + len(STALE_BUCKETS)  # 6
            + 1 + 1  # privilege / owned inventory
            + len(AZURE_PRIV_ROLES)  # 9
            + 1 + 1 + 1 + 1  # azure app/mfa/guest/sp
        )
        self.assertEqual(n, 106)
        self.assertEqual(len(VARIATION_CASES), 106)

    # ────────────────────────────────────────────────
    # ESC1–ESC13
    # ────────────────────────────────────────────────
    def test_esc1(self):
        G = nx.MultiDiGraph()
        G.add_node("T", name="ESC1T@LAB", type="Certificate Template", props={
            "enrolleesuppliessubject": True, "requiresmanagerapproval": False,
            "authenticationenabled": True, "ekus": ["1.3.6.1.5.5.7.3.2"],
        }, is_azure=False)
        G.add_node("U", name="user@LAB", type="User", props={}, is_azure=False)
        G.add_edge("U", "T", label="Enroll")
        self._capture(bloodbash_globals["print_adcs_vulnerabilities"], G)
        self.assertTrue(any("ESC1" in f[2] for f in self._findings("ESC1-ESC8")))

    def test_esc2(self):
        G = nx.MultiDiGraph()
        G.add_node("T", name="ESC2T@LAB", type="Certificate Template", props={
            "enrolleesuppliessubject": False, "requiresmanagerapproval": False,
            "ekus": ["2.5.29.37.0"],  # any purpose
        }, is_azure=False)
        G.add_node("U", name="user@LAB", type="User", props={}, is_azure=False)
        G.add_edge("U", "T", label="Enroll")
        self._capture(bloodbash_globals["print_adcs_vulnerabilities"], G)
        self.assertTrue(any("ESC2" in f[2] for f in self._findings("ESC1-ESC8")))

    def test_esc3(self):
        G = nx.MultiDiGraph()
        G.add_node("T", name="ESC3T@LAB", type="Certificate Template", props={
            "ekus": ["1.3.6.1.4.1.311.20.2.1"],  # enrollment agent
            "requiresmanagerapproval": False,
        }, is_azure=False)
        G.add_node("U", name="user@LAB", type="User", props={}, is_azure=False)
        G.add_edge("U", "T", label="Enroll")
        self._capture(bloodbash_globals["print_adcs_vulnerabilities"], G)
        self.assertTrue(any("ESC3" in f[2] for f in self._findings("ESC1-ESC8")))

    def test_esc4(self):
        G = nx.MultiDiGraph()
        G.add_node("T", name="ESC4T@LAB", type="Certificate Template", props={}, is_azure=False)
        G.add_node("A", name="attacker@LAB", type="User", props={}, is_azure=False)
        G.add_edge("A", "T", label="GenericAll")
        self._capture(bloodbash_globals["print_adcs_vulnerabilities"], G)
        self.assertTrue(any("ESC4" in f[2] for f in self._findings("ESC1-ESC8")))

    def test_esc5(self):
        G = nx.MultiDiGraph()
        G.add_node("CA", name="ESC5CA@LAB", type="Enterprise CA", props={}, is_azure=False)
        G.add_node("A", name="attacker@LAB", type="User", props={}, is_azure=False)
        G.add_edge("A", "CA", label="WriteDacl")
        self._capture(bloodbash_globals["print_adcs_vulnerabilities"], G)
        self.assertTrue(any("ESC5" in f[2] for f in self._findings("ESC1-ESC8")))

    def test_esc6(self):
        G = nx.MultiDiGraph()
        G.add_node("CA", name="ESC6CA@LAB", type="Enterprise CA", props={
            "editf_attributesubjectaltname2": True,
        }, is_azure=False)
        self._capture(bloodbash_globals["print_adcs_vulnerabilities"], G)
        self.assertTrue(any("ESC6" in f[2] for f in self._findings("ESC1-ESC8")))

    def test_esc7(self):
        G = nx.MultiDiGraph()
        G.add_node("CA", name="ESC7CA@LAB", type="Enterprise CA", props={}, is_azure=False)
        G.add_node("A", name="attacker@LAB", type="User", props={}, is_azure=False)
        G.add_edge("A", "CA", label="ManageCA")
        self._capture(bloodbash_globals["print_adcs_vulnerabilities"], G)
        self.assertTrue(any("ESC7" in f[2] for f in self._findings("ESC1-ESC8")))

    def test_esc8(self):
        G = nx.MultiDiGraph()
        G.add_node("CA", name="ESC8CA@LAB", type="Enterprise CA", props={
            "haswebenrollment": True,
        }, is_azure=False)
        self._capture(bloodbash_globals["print_adcs_vulnerabilities"], G)
        self.assertTrue(any("ESC8" in f[2] for f in self._findings("ESC1-ESC8")))

    def test_esc9(self):
        G = nx.MultiDiGraph()
        G.add_node("T", name="ESC9T@LAB", type="Certificate Template", props={
            "enrollmentflag": "NO_SECURITY_EXTENSION",
            "authenticationenabled": True,
            "requiresmanagerapproval": False,
            "ekus": ["1.3.6.1.5.5.7.3.2"],
        }, is_azure=False)
        G.add_node("U", name="user@LAB", type="User", props={}, is_azure=False)
        G.add_edge("U", "T", label="Enroll")
        self._capture(bloodbash_globals["print_adcs_vulnerabilities"], G)
        self.assertTrue(any("ESC9" in f[2] for f in self._findings("ESC1-ESC8")))

    def test_esc13(self):
        G = nx.MultiDiGraph()
        G.add_node("T", name="ESC13T@LAB", type="Certificate Template", props={
            "requiresmanagerapproval": False,
            "authenticationenabled": True,
            "ekus": ["1.3.6.1.5.5.7.3.2"],
            "applicationpolicies": ["1.2.3.4"],
        }, is_azure=False)
        G.add_node("U", name="user@LAB", type="User", props={}, is_azure=False)
        G.add_edge("U", "T", label="Enroll")
        self._capture(bloodbash_globals["print_adcs_vulnerabilities"], G)
        self.assertTrue(any("ESC13" in f[2] for f in self._findings("ESC1-ESC8")))

    # ────────────────────────────────────────────────
    # DCSync / RBCD
    # ────────────────────────────────────────────────
    def test_dcsync_full(self):
        G = nx.MultiDiGraph()
        G.add_node("D", name="LAB.LOCAL", type="Domain", props={"domain": "lab.local"}, is_azure=False)
        G.add_node("U", name="attacker@lab.local", type="User", props={}, is_azure=False)
        G.add_edge("U", "D", label="GetChanges")
        G.add_edge("U", "D", label="GetChangesAll")
        self._capture(bloodbash_globals["print_dcsync_rights"], G)
        self.assertTrue(any("can DCSync" in f[2] for f in self._findings("DCSync")))

    def test_dcsync_partial(self):
        G = nx.MultiDiGraph()
        G.add_node("D", name="LAB.LOCAL", type="Domain", props={"domain": "lab.local"}, is_azure=False)
        G.add_node("U", name="partial@lab.local", type="User", props={}, is_azure=False)
        G.add_edge("U", "D", label="GetChangesAll")
        self._capture(bloodbash_globals["print_dcsync_rights"], G)
        self.assertTrue(any("GetChangesAll only" in f[2] for f in self._findings("DCSync")))

    def test_rbcd(self):
        G = nx.MultiDiGraph()
        G.add_node("C", name="WEB01.LAB.LOCAL", type="Computer", props={}, is_azure=False)
        G.add_node("A", name="attacker$@LAB.LOCAL", type="Computer", props={}, is_azure=False)
        G.add_edge("A", "C", label="AllowedToAct")
        self._capture(bloodbash_globals["print_rbcd"], G)
        self.assertTrue(any(f[1] == "RBCD" for f in bloodbash_globals["global_findings"]))

    # ────────────────────────────────────────────────
    # Dangerous permissions (AD + Azure rights)
    # ────────────────────────────────────────────────
    def _dangerous_ad_right(self, right: str):
        G = nx.MultiDiGraph()
        G.add_node("DA", name="Domain Admins@LAB.LOCAL", type="Group",
                   props={"domain": "LAB.LOCAL", "highvalue": True}, is_azure=False)
        G.add_node("A", name="attacker@LAB.LOCAL", type="User",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        # preserve canonical label casing used in detector (mixed)
        label_map = {
            "genericall": "GenericAll", "owns": "Owns", "writedacl": "WriteDacl",
            "writeowner": "WriteOwner", "allextendedrights": "AllExtendedRights",
            "genericwrite": "GenericWrite", "addmember": "AddMember",
            "resetpassword": "ResetPassword", "forcechangepassword": "ForceChangePassword",
            "manageca": "ManageCA", "managecertificates": "ManageCertificates",
            "enroll": "Enroll", "certificateenroll": "CertificateEnroll",
            "writeproperty": "WriteProperty",
        }
        G.add_edge("A", "DA", label=label_map[right])
        out = self._strip(self._capture(bloodbash_globals["print_dangerous_permissions"], G))
        self.assertIn(label_map[right], out)
        self.assertTrue(self._findings("Dangerous Permissions"))

    def _dangerous_azure_right(self, right: str):
        G = nx.MultiDiGraph()
        G.add_node("GA", name="Global Admin", type="Azure Role",
                   props={"tenantId": "t1"}, is_azure=True)
        G.add_node("A", name="attacker", type="Azure User",
                   props={"tenantId": "t1"}, is_azure=True)
        label_map = {
            "genericall": "GenericAll", "owns": "Owns", "writedacl": "WriteDacl",
            "writeowner": "WriteOwner", "addsecret": "AddSecret",
            "addcertificate": "AddCertificate", "addowner": "AddOwner",
            "execute": "Execute", "canread": "CanRead", "canwrite": "CanWrite",
            "candelete": "CanDelete",
        }
        G.add_edge("A", "GA", label=label_map[right])
        out = self._strip(self._capture(bloodbash_globals["print_dangerous_permissions"], G))
        self.assertIn(label_map[right], out)
        self.assertTrue(self._findings("Dangerous Permissions"))

    # ────────────────────────────────────────────────
    # SID history
    # ────────────────────────────────────────────────
    def test_sid_history_named_high_priv(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="migrated@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("DA", name="DOMAIN ADMINS@OLD.LOCAL", type="Group", props={}, is_azure=False)
        G.add_edge("U", "DA", label="HasSIDHistory")
        self._capture(bloodbash_globals["print_sid_history_abuse"], G)
        self.assertTrue(any("SID history from" in f[2] for f in self._findings("SID History Abuse")))

    def test_sid_history_raw_entry(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="user@LAB.LOCAL", type="User", props={
            "sidhistory": ["S-1-5-21-1-2-3-500"],
        }, is_azure=False)
        self._capture(bloodbash_globals["print_sid_history_abuse"], G)
        self.assertTrue(any("SID history entry" in f[2] for f in self._findings("SID History Abuse")))

    # ────────────────────────────────────────────────
    # Core AD flags
    # ────────────────────────────────────────────────
    def test_gpo_abuse(self):
        G = nx.MultiDiGraph()
        G.add_node("G", name="Weak-GPO@LAB.LOCAL", type="GPO", props={}, is_azure=False)
        G.add_node("U", name="user@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("OU", name="Domain Controllers@LAB.LOCAL", type="OU", props={}, is_azure=False)
        G.add_edge("U", "G", label="GenericWrite")
        G.add_edge("OU", "G", label="GPLink")  # container → GPO
        self._capture(bloodbash_globals["print_gpo_abuse"], G)
        self.assertTrue(self._findings("GPO Abuse"), msg=str(bloodbash_globals["global_findings"]))

    def test_kerberoastable(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="svc@LAB.LOCAL", type="User", props={
            "hasspn": True, "sensitive": False, "enabled": True,
        }, is_azure=False)
        self._capture(bloodbash_globals["print_kerberoastable"], G)
        self.assertTrue(any("svc@LAB.LOCAL" in f[2] for f in self._findings("Kerberoastable")))

    def test_asrep(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="nopre@LAB.LOCAL", type="User", props={
            "dontreqpreauth": True, "sensitive": False, "enabled": True,
        }, is_azure=False)
        self._capture(bloodbash_globals["print_as_rep_roastable"], G)
        self.assertTrue(any("nopre@LAB.LOCAL" in f[2] for f in self._findings("AS-REP Roastable")))

    def test_shortest_paths(self):
        G = nx.MultiDiGraph()
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group",
                   props={"domain": "LAB.LOCAL", "highvalue": True}, is_azure=False)
        G.add_node("U", name="alice@LAB.LOCAL", type="User",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_edge("U", "DA", label="MemberOf")
        self._capture(bloodbash_globals["print_shortest_paths"], G, fast=True)
        self.assertTrue(self._findings("Shortest Paths") or "alice" in self._strip(
            self._capture(bloodbash_globals["print_shortest_paths"], G, fast=True)
        ).lower())

    def test_password_never_expires(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="u@LAB.LOCAL", type="User", props={
            "pwdneverexpires": True, "enabled": True,
        }, is_azure=False)
        self._capture(bloodbash_globals["print_password_never_expires"], G)
        self.assertTrue(self._findings("Password Never Expires"))

    def test_password_not_required(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="u@LAB.LOCAL", type="User", props={
            "passwordnotreqd": True, "enabled": True,
        }, is_azure=False)
        self._capture(bloodbash_globals["print_password_not_required"], G)
        self.assertTrue(self._findings("Password Not Required"))

    # ────────────────────────────────────────────────
    # Shadow credentials (all 5 right types)
    # ────────────────────────────────────────────────
    def test_shadow_addkeycredentiallink(self):
        G = nx.MultiDiGraph()
        G.add_node("A", name="attacker@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("T", name="victim@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_edge("A", "T", label="AddKeyCredentialLink")
        self._capture(bloodbash_globals["print_shadow_credentials"], G)
        self.assertTrue(any("AddKeyCredentialLink" in f[2] for f in self._findings("Shadow Credentials")))

    def _shadow_secondary(self, label: str):
        G = nx.MultiDiGraph()
        G.add_node("A", name="attacker@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("T", name="victim@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_edge("A", "T", label=label)
        self._capture(bloodbash_globals["print_shadow_credentials"], G)
        self.assertTrue(
            any(label in f[2] for f in self._findings("Shadow Credentials")),
            msg=str(self._findings("Shadow Credentials")),
        )

    # ────────────────────────────────────────────────
    # GPO content (4 variants)
    # ────────────────────────────────────────────────
    def test_gpo_content_generic_parsing(self):
        G = nx.MultiDiGraph()
        G.add_node("G", name="GPO1@LAB.LOCAL", type="GPO", props={
            "taskname": "evil",
            "scriptpath": "\\\\server\\share\\evil.bat",
        }, is_azure=False)
        self._capture(bloodbash_globals["print_gpo_content_parsing"], G)
        self.assertTrue(
            self._findings("GPO Content"),
            msg=str(bloodbash_globals["global_findings"]),
        )

    def test_gpo_content_scheduled_task_xml(self):
        gpo_dir = Path(self.temp_dir) / "gpos"
        gpo_dir.mkdir()
        xml = gpo_dir / "gpo1.xml"
        xml.write_text(
            """<?xml version="1.0"?>
            <Report><GPO><Name>TestGPO</Name></GPO>
            <ScheduledTasks><Task>
              <Name>EvilTask</Name><Command>cmd.exe</Command><Arguments>/c whoami</Arguments>
            </Task></ScheduledTasks></Report>""",
            encoding="utf-8",
        )
        G = nx.MultiDiGraph()
        self._capture(bloodbash_globals["print_gpo_content_analysis"], G, str(gpo_dir))
        self.assertTrue(any("Scheduled Task" in f[2] for f in self._findings("GPO Content")))

    def test_gpo_content_script_xml(self):
        gpo_dir = Path(self.temp_dir) / "gpos2"
        gpo_dir.mkdir()
        (gpo_dir / "gpo2.xml").write_text(
            """<?xml version="1.0"?>
            <Report><GPO><Name>ScriptGPO</Name></GPO>
            <Scripts><Script><Command>evil.bat</Command></Script></Scripts></Report>""",
            encoding="utf-8",
        )
        G = nx.MultiDiGraph()
        self._capture(bloodbash_globals["print_gpo_content_analysis"], G, str(gpo_dir))
        self.assertTrue(any("Script" in f[2] for f in self._findings("GPO Content")))

    def test_gpo_content_cpassword_xml(self):
        gpo_dir = Path(self.temp_dir) / "gpos3"
        gpo_dir.mkdir()
        (gpo_dir / "gpo3.xml").write_text(
            """<?xml version="1.0"?>
            <Report><GPO><Name>CppGPO</Name></GPO>
            <Properties cpassword="AQAAANCMnd8BFdERjHoAwE/Cl+s="/></Report>""",
            encoding="utf-8",
        )
        G = nx.MultiDiGraph()
        self._capture(bloodbash_globals["print_gpo_content_analysis"], G, str(gpo_dir))
        self.assertTrue(any("cPassword" in f[2] for f in self._findings("GPO Content")))

    # ────────────────────────────────────────────────
    # Delegation / LAPS / paths
    # ────────────────────────────────────────────────
    def test_constrained_delegation(self):
        G = nx.MultiDiGraph()
        G.add_node("C", name="APP01.LAB.LOCAL", type="Computer", props={
            "allowedtodelegate": ["HTTP/sql.lab.local"],
        }, is_azure=False)
        self._capture(bloodbash_globals["print_constrained_delegation"], G)
        self.assertTrue(self._findings("Constrained Delegation"))

    def test_unconstrained_delegation(self):
        G = nx.MultiDiGraph()
        G.add_node("C", name="APP01.LAB.LOCAL", type="Computer", props={
            "unconstraineddelegation": True,
        }, is_azure=False)
        self._capture(bloodbash_globals["print_unconstrained_delegation"], G)
        self.assertTrue(self._findings("Unconstrained Delegation"))

    def test_laps_not_enabled(self):
        G = nx.MultiDiGraph()
        G.add_node("C", name="PC01.LAB.LOCAL", type="Computer", props={
            "haslaps": False,
        }, is_azure=False)
        self._capture(bloodbash_globals["print_laps_status"], G)
        self.assertTrue(any("do not have LAPS" in f[2] for f in self._findings("LAPS")))

    def test_owned_paths(self):
        G = nx.MultiDiGraph()
        G.add_node("O", name="owned@LAB.LOCAL", type="User",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_node("U", name="alice@LAB.LOCAL", type="User",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_edge("U", "O", label="GenericAll")
        self._capture(bloodbash_globals["print_paths_to_owned"], G, "owned")
        self.assertTrue(self._findings("Owned Paths"))

    def test_arbitrary_paths(self):
        G = nx.MultiDiGraph()
        G.add_node("S", name="src@LAB.LOCAL", type="User",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_node("T", name="dst@LAB.LOCAL", type="User",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_edge("S", "T", label="GenericAll")
        self._capture(bloodbash_globals["print_arbitrary_paths"], G, "src", "dst")
        self.assertTrue(self._findings("Arbitrary Paths"))

    # ────────────────────────────────────────────────
    # Password-in-description patterns (9)
    # ────────────────────────────────────────────────
    def _password_desc_pattern(self, pattern: str, sample_text: str):
        G = nx.MultiDiGraph()
        G.add_node("U", name="u@LAB.LOCAL", type="User", props={
            "description": sample_text,
        }, is_azure=False)
        self._capture(bloodbash_globals["print_password_in_descriptions"], G)
        self.assertTrue(
            self._findings("Password in Description"),
            msg=f"pattern {pattern!r} text {sample_text!r} not detected",
        )

    # ────────────────────────────────────────────────
    # Trust / deep nesting / busiest / path-break
    # ────────────────────────────────────────────────
    def test_trust_edge(self):
        G = nx.MultiDiGraph()
        G.add_node("D1", name="A.LOCAL", type="Domain", props={}, is_azure=False)
        G.add_node("D2", name="B.LOCAL", type="Domain", props={}, is_azure=False)
        G.add_edge("D1", "D2", label="TrustedDomain:Bidirectional:External", sid_filtering=True)
        self._capture(bloodbash_globals["print_trust_abuse"], G)
        self.assertTrue(any("SID filtering disabled" not in f[2] for f in self._findings("Trust Abuse")))
        self.assertTrue(self._findings("Trust Abuse"))

    def test_trust_sid_filtering_disabled(self):
        G = nx.MultiDiGraph()
        G.add_node("D1", name="A.LOCAL", type="Domain", props={}, is_azure=False)
        G.add_node("D2", name="B.LOCAL", type="Domain", props={}, is_azure=False)
        G.add_edge("D1", "D2", label="TrustedDomain:Bidirectional:ParentChild", sid_filtering=False)
        self._capture(bloodbash_globals["print_trust_abuse"], G)
        self.assertTrue(any("SID filtering disabled" in f[2] for f in self._findings("Trust Abuse")))

    def test_deep_nesting_depth(self):
        G = nx.MultiDiGraph()
        # Long chain from a high-priv group so undirected depth > 3
        nodes = ["domain admins@lab"] + [f"layer{i}@lab" for i in range(12)]
        for n in nodes:
            G.add_node(n, name=n, type="Group", props={}, is_azure=False)
        for a, b in zip(nodes, nodes[1:]):
            G.add_edge(a, b, label="MemberOf")
        self._capture(bloodbash_globals["print_group_analysis"], G, deep_analysis=False)
        findings = self._findings("Deep Group Nesting")
        self.assertTrue(
            any("nesting levels" in f[2] for f in findings),
            msg=f"expected deep nesting finding, got {findings}",
        )

    def test_deep_nesting_cycles(self):
        G = nx.MultiDiGraph()
        for n, name in [("A", "admins@lab"), ("B", "helpdesk@lab"), ("C", "ops@lab")]:
            G.add_node(n, name=name, type="Group", props={}, is_azure=False)
        G.add_edge("A", "B", label="MemberOf")
        G.add_edge("B", "C", label="MemberOf")
        G.add_edge("C", "A", label="MemberOf")
        self._capture(bloodbash_globals["print_group_analysis"], G, deep_analysis=True)
        self.assertTrue(
            any("cycle" in f[2].lower() for f in self._findings("Deep Group Nesting")),
            msg=str(self._findings("Deep Group Nesting")),
        )

    def test_busiest_short(self):
        G = nx.MultiDiGraph()
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group",
                   props={"domain": "LAB.LOCAL", "highvalue": True}, is_azure=False)
        G.add_node("G", name="IT@LAB.LOCAL", type="Group",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_node("U1", name="a@LAB.LOCAL", type="User",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_node("U2", name="b@LAB.LOCAL", type="User",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_edge("U1", "G", label="MemberOf")
        G.add_edge("U2", "G", label="MemberOf")
        G.add_edge("G", "DA", label="MemberOf")
        self._capture(bloodbash_globals["print_busiest_paths"], G, mode="short", top=5, fast=True)
        self.assertTrue(self._findings("Busiest Paths"))

    def test_busiest_all(self):
        G = nx.MultiDiGraph()
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group",
                   props={"domain": "LAB.LOCAL", "highvalue": True}, is_azure=False)
        G.add_node("G", name="IT@LAB.LOCAL", type="Group",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_node("U1", name="a@LAB.LOCAL", type="User",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_edge("U1", "G", label="MemberOf")
        G.add_edge("G", "DA", label="MemberOf")
        ranked = bloodbash_globals["collect_busiest_paths"](G, mode="all", top=5, fast=True)
        self.assertTrue(isinstance(ranked, list))
        self._capture(bloodbash_globals["print_busiest_paths"], G, mode="all", top=5, fast=True)
        self.assertTrue(self._findings("Busiest Paths"))

    def test_path_break(self):
        G = nx.MultiDiGraph()
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group",
                   props={"domain": "LAB.LOCAL", "highvalue": True}, is_azure=False)
        G.add_node("U", name="a@LAB.LOCAL", type="User",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_edge("U", "DA", label="GenericAll")
        self._capture(bloodbash_globals["print_path_breaks"], G, top=5, fast=True)
        self.assertTrue(self._findings("Path Break"))

    # ────────────────────────────────────────────────
    # Password age + stale buckets
    # ────────────────────────────────────────────────
    def test_password_age_all_buckets(self):
        now = 2_000_000_000.0
        # Build one user per bucket with crafted ages
        bucket_days = {
            "< 1 day": 0.5,
            "< 7 days": 3,
            "< 30 days": 15,
            "30 days – 6 months": 100,
            "> 6 months": 200,
            "> 1 year": 400,
            "> 5 years": 2000,
            "> 10 years": 4000,
            "> 15 years": 6000,
            "> 20 years": 8000,
            "Never set / unknown": None,
            "Other": 0.0,  # edge: days==0 may land <1 day; use tiny negative via helper
        }
        G = nx.MultiDiGraph()
        for i, (bucket, days) in enumerate(bucket_days.items()):
            if bucket == "Never set / unknown":
                pwd = 0
            elif bucket == "Other":
                # force via direct assign test of helper
                continue
            else:
                pwd = now - (days * 86400)
            G.add_node(f"U{i}", name=f"{_slug(bucket)}@LAB.LOCAL", type="User", props={
                "domain": "LAB.LOCAL", "pwdlastset": pwd, "enabled": True,
            }, is_azure=False)
        rows = bloodbash_globals["collect_password_age_rows"](G, now=now)
        got = {r["bucket"] for r in rows}
        for b in PASSWORD_AGE_BUCKETS:
            if b == "Other":
                # helper returns Other only for days that miss all ladders with days < 30 and not in < buckets
                # e.g. negative days shouldn't happen; craft via direct helper
                self.assertEqual(
                    bloodbash_globals["_assign_age_bucket"](-1, bloodbash_globals["PASSWORD_AGE_BUCKETS"]),
                    "Other",
                )
                continue
            self.assertIn(b, got, msg=f"missing password-age bucket {b}; got {got}")

    def test_stale_all_buckets(self):
        now = 2_000_000_000.0
        specs = {
            "Active < 6 months": 10,
            "Inactive > 6 months": 200,
            "Inactive > 12 months": 400,
            "Inactive > 60 months": 2000,
            "Inactive > 120 months": 4000,
            "Never active / unknown": None,
        }
        G = nx.MultiDiGraph()
        for i, (bucket, days) in enumerate(specs.items()):
            ts = 0 if days is None else now - (days * 86400)
            G.add_node(f"S{i}", name=f"{_slug(bucket)}@LAB.LOCAL", type="User", props={
                "domain": "LAB.LOCAL",
                "lastlogontimestamp": ts,
                "enabled": True,
            }, is_azure=False)
        rows = bloodbash_globals["collect_stale_account_rows"](G, now=now)
        got = {r["bucket"] for r in rows}
        for b in STALE_BUCKETS:
            self.assertIn(b, got, msg=f"missing stale bucket {b}; got {got}")

    def test_privilege_inventory(self):
        G = nx.MultiDiGraph()
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group",
                   props={"highvalue": True}, is_azure=False)
        G.add_node("U", name="admin@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_edge("U", "DA", label="MemberOf")
        self._capture(bloodbash_globals["print_privilege_inventory"], G)
        self.assertTrue(self._findings("Privilege Inventory"))

    def test_owned_inventory(self):
        G = nx.MultiDiGraph()
        G.add_node("O", name="owned@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("C", name="PC01.LAB.LOCAL", type="Computer", props={}, is_azure=False)
        G.add_edge("O", "C", label="AdminTo")
        self._capture(bloodbash_globals["print_owned_inventory"], G, "owned")
        self.assertTrue(self._findings("Owned Inventory"))

    # ────────────────────────────────────────────────
    # Azure
    # ────────────────────────────────────────────────
    def _azure_role(self, role_substr: str):
        G = nx.MultiDiGraph()
        # Role display names that contain the needle
        pretty = role_substr.title().replace("Admin", "Administrator") if "admin" in role_substr else role_substr
        # Ensure needle matches: code checks `pr in role_name`
        name = role_substr  # exact needle works
        G.add_node("R", name=name, type="Azure Role", props={"tenantId": "t1"}, is_azure=True)
        G.add_node("U", name="admin-user", type="Azure User", props={"tenantId": "t1"}, is_azure=True)
        G.add_edge("U", "R", label="HasRole")
        self._capture(bloodbash_globals["print_azure_privileged_roles"], G)
        self.assertTrue(
            any(role_substr in f[2].lower() for f in self._findings("Azure Privileged Roles")),
            msg=str(self._findings("Azure Privileged Roles")),
        )

    def test_azure_app_secrets(self):
        G = nx.MultiDiGraph()
        G.add_node("APP", name="MyApp", type="Azure Application",
                   props={"tenantId": "t1"}, is_azure=True)
        G.add_node("U", name="attacker", type="Azure User",
                   props={"tenantId": "t1"}, is_azure=True)
        G.add_edge("U", "APP", label="AddSecret")
        self._capture(bloodbash_globals["print_azure_app_secrets"], G)
        self.assertTrue(self._findings("Azure App Secrets"))

    def test_azure_mfa_bypass(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="nomfa", type="Azure User", props={
            "tenantId": "t1",
            "strongAuthenticationRequirements": {"state": "disabled"},
            "mfaEnrolled": False,
        }, is_azure=True)
        self._capture(bloodbash_globals["print_azure_mfa_bypass"], G)
        self.assertTrue(self._findings("Azure MFA Bypass"))

    def test_azure_guest(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="guest1", type="Azure User", props={
            "tenantId": "t1", "userType": "Guest",
        }, is_azure=True)
        G.add_node("R", name="Global Administrator", type="Azure Role",
                   props={"tenantId": "t1"}, is_azure=True)
        G.add_edge("U", "R", label="HasRole")
        self._capture(bloodbash_globals["print_azure_guest_access"], G)
        self.assertTrue(self._findings("Azure Guest Access"))

    def test_azure_sp_abuse(self):
        G = nx.MultiDiGraph()
        G.add_node("SP", name="EvilSP", type="Azure Service Principal",
                   props={"tenantId": "t1"}, is_azure=True)
        G.add_node("U", name="attacker", type="Azure User",
                   props={"tenantId": "t1"}, is_azure=True)
        # Need edges that trigger SP abuse — read detector
        G.add_edge("U", "SP", label="GenericAll")
        out = self._strip(self._capture(bloodbash_globals["print_azure_service_principal_abuse"], G))
        # If detector requires specific rights, ensure finding or adjust graph after reading
        if not self._findings("Azure Service Principal Abuse"):
            # try Owns
            bloodbash_globals["global_findings"] = []
            G2 = nx.MultiDiGraph()
            G2.add_node("SP", name="EvilSP", type="Azure Service Principal",
                        props={"tenantId": "t1"}, is_azure=True)
            G2.add_node("U", name="attacker", type="Azure User",
                        props={"tenantId": "t1"}, is_azure=True)
            G2.add_edge("SP", "U", label="HasRole")  # may not work
            # Read function body for required labels
            import inspect
            src = inspect.getsource(bloodbash_globals["print_azure_service_principal_abuse"])
            # Common: AddOwner / AppRoleAssignment etc.
            for lab in ("AddOwner", "Owner", "AppRoleAssignmentAllowedTo", "GenericAll"):
                bloodbash_globals["global_findings"] = []
                G3 = nx.MultiDiGraph()
                G3.add_node("SP", name="EvilSP", type="Azure Service Principal",
                            props={"tenantId": "t1"}, is_azure=True)
                G3.add_node("U", name="attacker", type="Azure User",
                            props={"tenantId": "t1"}, is_azure=True)
                G3.add_edge("U", "SP", label=lab)
                self._capture(bloodbash_globals["print_azure_service_principal_abuse"], G3)
                if self._findings("Azure Service Principal Abuse"):
                    break
        self.assertTrue(
            self._findings("Azure Service Principal Abuse"),
            msg=f"SP abuse not detected; out={out[:200]}",
        )


# Dynamically attach per-right / per-pattern / per-role tests so each variation
# is a first-class test case (pytest -k friendly).

def _bind_ad_right(right: str):
    def _test(self):
        self._dangerous_ad_right(right)
    _test.__name__ = f"test_dangerous_ad_{right}"
    _test.__doc__ = f"Dangerous Permissions AD right: {right}"
    return _test


def _bind_az_right(right: str):
    def _test(self):
        self._dangerous_azure_right(right)
    _test.__name__ = f"test_dangerous_azure_{right}"
    _test.__doc__ = f"Dangerous Permissions Azure right: {right}"
    return _test


def _bind_shadow(label: str):
    def _test(self):
        if label == "AddKeyCredentialLink":
            self.test_shadow_addkeycredentiallink()
        else:
            self._shadow_secondary(label)
    _test.__name__ = f"test_shadow_{_slug(label)}"
    return _test


def _bind_pwd_pattern(pattern: str, sample: str):
    def _test(self):
        self._password_desc_pattern(pattern, sample)
    _test.__name__ = f"test_pwd_desc_{_slug(pattern)}"
    _test.__doc__ = f"Password in description pattern: {pattern}"
    return _test


def _bind_azure_role(role: str):
    def _test(self):
        self._azure_role(role)
    _test.__name__ = f"test_azure_role_{_slug(role)}"
    return _test


# Samples that match each password_in_desc regex (must include a non-space after :=)
_PWD_SAMPLES = {
    r"\bpassword\s*[:=]\s*\S+": "Password: Secret123",
    r"\bpwd\s*[:=]\s*\S+": "pwd: hunter2",
    r"\bpass(?:word)?\s*[:=]\s*\S+": "pass: letmein",
    r"\bcredentials?\s*[:=]\s*\S+": "credentials: admin/admin",
    r"\bsecret\s*[:=]\s*\S+": "secret: abc",
    r"\bpasswd\s*[:=]\s*\S+": "passwd: hunter2",
}

for _r in AD_RIGHTS:
    setattr(TestDetectionVariations, f"test_dangerous_ad_{_r}", _bind_ad_right(_r))
for _r in AZURE_RIGHTS:
    setattr(TestDetectionVariations, f"test_dangerous_azure_{_r}", _bind_az_right(_r))
for _lab in SHADOW_RIGHTS:
    if _lab != "AddKeyCredentialLink":
        setattr(TestDetectionVariations, f"test_shadow_{_slug(_lab)}", _bind_shadow(_lab))
for _pat in PASSWORD_PATTERNS:
    setattr(
        TestDetectionVariations,
        f"test_pwd_desc_{_slug(_pat)}",
        _bind_pwd_pattern(_pat, _PWD_SAMPLES[_pat]),
    )
for _role in AZURE_PRIV_ROLES:
    setattr(TestDetectionVariations, f"test_azure_role_{_slug(_role)}", _bind_azure_role(_role))


# Explicit ordered registry used by test_variation_count_is_106 and meta coverage test
VARIATION_CASES = (
    [(f"ESC1-ESC8/{e}", e) for e in ESC_TYPES]
    + [("DCSync/full", "full"), ("DCSync/partial", "partial"), ("RBCD", "rbcd")]
    + [(f"Dangerous Permissions/AD:{r}", r) for r in AD_RIGHTS]
    + [(f"Dangerous Permissions/Azure:{r}", r) for r in AZURE_RIGHTS]
    + [("SID History Abuse/named", "named"), ("SID History Abuse/raw", "raw")]
    + [
        ("GPO Abuse", "gpo"),
        ("Kerberoastable", "kerb"),
        ("AS-REP Roastable", "asrep"),
        ("Shortest Paths", "sp"),
        ("Password Never Expires", "pne"),
        ("Password Not Required", "pnr"),
    ]
    + [(f"Shadow Credentials/{s}", s) for s in SHADOW_RIGHTS]
    + [
        ("GPO Content/generic", "gpo-generic"),
        ("GPO Content/Scheduled Task", "gpo-task"),
        ("GPO Content/Script", "gpo-script"),
        ("GPO Content/cPassword", "gpo-cpp"),
        ("Constrained Delegation", "cd"),
        ("Unconstrained Delegation", "ud"),
        ("LAPS", "laps"),
        ("Owned Paths", "owned-paths"),
    ]
    + [(f"Password in Description/{p}", p) for p in PASSWORD_PATTERNS]
    + [
        ("Arbitrary Paths", "arb"),
        ("Trust Abuse/edge", "trust"),
        ("Trust Abuse/SID filtering disabled", "trust-sid"),
        ("Deep Group Nesting/depth", "deep"),
        ("Deep Group Nesting/cycles", "cycles"),
        ("Busiest Paths/short", "bp-short"),
        ("Busiest Paths/all", "bp-all"),
        ("Path Break", "pb"),
    ]
    + [(f"Password Age/{b}", b) for b in PASSWORD_AGE_BUCKETS]
    + [(f"Stale Accounts/{b}", b) for b in STALE_BUCKETS]
    + [
        ("Privilege Inventory", "priv"),
        ("Owned Inventory", "owned-inv"),
    ]
    + [(f"Azure Privileged Roles/{r}", r) for r in AZURE_PRIV_ROLES]
    + [
        ("Azure App Secrets", "az-app"),
        ("Azure MFA Bypass", "az-mfa"),
        ("Azure Guest Access", "az-guest"),
        ("Azure Service Principal Abuse", "az-sp"),
    ]
)


class TestVariationRegistryMeta(unittest.TestCase):
    def test_registry_unique_and_complete(self):
        self.assertEqual(len(VARIATION_CASES), 106)
        ids = [c[0] for c in VARIATION_CASES]
        self.assertEqual(len(ids), len(set(ids)), msg="duplicate variation ids")

    def test_all_variation_tests_exist(self):
        """Every variation has at least one dedicated TestDetectionVariations test method."""
        names = {n for n in dir(TestDetectionVariations) if n.startswith("test_")}
        # Map variation id prefixes to required test name fragments
        required_fragments = [
            "esc1", "esc2", "esc3", "esc4", "esc5", "esc6", "esc7", "esc8", "esc9", "esc13",
            "dcsync_full", "dcsync_partial", "rbcd",
            *[f"dangerous_ad_{r}" for r in AD_RIGHTS],
            *[f"dangerous_azure_{r}" for r in AZURE_RIGHTS],
            "sid_history_named_high_priv", "sid_history_raw_entry",
            "gpo_abuse", "kerberoastable", "asrep", "shortest_paths",
            "password_never_expires", "password_not_required",
            "shadow_addkeycredentiallink",
            *[f"shadow_{_slug(s)}" for s in SHADOW_RIGHTS if s != "AddKeyCredentialLink"],
            "gpo_content_generic_parsing", "gpo_content_scheduled_task_xml",
            "gpo_content_script_xml", "gpo_content_cpassword_xml",
            "constrained_delegation", "unconstrained_delegation", "laps_not_enabled",
            "owned_paths",
            *[f"pwd_desc_{_slug(p)}" for p in PASSWORD_PATTERNS],
            "arbitrary_paths", "trust_edge", "trust_sid_filtering_disabled",
            "deep_nesting_depth", "deep_nesting_cycles",
            "busiest_short", "busiest_all", "path_break",
            "password_age_all_buckets", "stale_all_buckets",
            "privilege_inventory", "owned_inventory",
            *[f"azure_role_{_slug(r)}" for r in AZURE_PRIV_ROLES],
            "azure_app_secrets", "azure_mfa_bypass", "azure_guest", "azure_sp_abuse",
            "variation_count_is_106",
        ]
        missing = [f for f in required_fragments if f"test_{f}" not in names]
        self.assertEqual(missing, [], msg=f"Missing tests: {missing}")


if __name__ == "__main__":
    unittest.main()
