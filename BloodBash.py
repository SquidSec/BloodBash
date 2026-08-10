#!/usr/bin/env python3

import json
import os
import sys
import argparse
import logging
import re
import networkx as nx
from collections import defaultdict, Counter
from datetime import date, datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from tqdm import tqdm
import time
import csv
import sqlite3
from html import escape
import yaml
import xml.etree.ElementTree as ET
from pathlib import Path
import traceback
import zipfile
import hashlib
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

__version__ = "1.4.2"
logger = logging.getLogger("bloodbash")
__org__ = "SquidSec"
__org_tagline__ = "Open source security tooling by SquidSec"
__org_url__ = "https://squidoffense.com/"
__project_url__ = "https://github.com/DotNetRussell/BloodBash"

console = Console()
# ────────────────────────────────────────────────
# Severity Scoring
# ────────────────────────────────────────────────
SEVERITY_SCORES = {
    "ESC1-ESC8": 10, "DCSync": 10, "RBCD": 9, "Dangerous Permissions": 9,
    "SID History Abuse": 8, "GPO Abuse": 7, "Kerberoastable": 5,
    "AS-REP Roastable": 5, "Shortest Paths": 6, "Password Never Expires": 4,
    "Password Not Required": 8, "Shadow Credentials": 8, "GPO Content": 7,
    "Constrained Delegation": 7, "Unconstrained Delegation": 8, "LAPS": 6,
    "LAPS Readers": 8, "Can Configure RBCD": 9,
    "Broad Principal ACL": 9,
    "Owned Paths": 9, "Password in Description": 6,
    "Arbitrary Paths": 6, "Trust Abuse": 7, "Deep Group Nesting": 6,
    "Busiest Paths": 7, "Path Break": 8, "Password Age": 5, "Stale Accounts": 4,
    "Privilege Inventory": 6, "Owned Inventory": 7, "Compromise Dossier": 8,
    "Privileged Kerberoastable": 9, "Privileged AS-REP Roastable": 9,
    "Collection Health": 3,
    "HasSession": 6,
    # Azure-specific
    "Azure Privileged Roles": 10, "Azure App Secrets": 9, "Azure MFA Bypass": 8,
    "Azure Guest Access": 7, "Azure Service Principal Abuse": 8,
}

# Enterprise-scale defaults (nodes/edges) for --all auto-fast and display caps
LARGE_GRAPH_NODES = 25_000
LARGE_GRAPH_EDGES = 500_000
# Hygiene categories: keep at most N individual findings + one summary row
FINDING_COLLAPSE_CAPS = {
    "Password Not Required": 25,
    "Password Never Expires": 25,
    "LAPS Readers": 25,
    "Shadow Credentials": 40,
    "Dangerous Permissions": 40,
    "Kerberoastable": 30,
    "AS-REP Roastable": 30,
}
# Domain well-known RIDs that hold expected DCSync (incl. foreign forest root EA)
EXPECTED_DCSYNC_RIDS = frozenset({
    "512",  # Domain Admins
    "516",  # Domain Controllers
    "518",  # Schema Admins
    "519",  # Enterprise Admins
    "526",  # Key Admins
    "527",  # Enterprise Key Admins
})

# Password-age and inactivity inventory ladders (days)
PASSWORD_AGE_BUCKETS = [
    ("< 1 day", 0, 1),
    ("< 7 days", 1, 7),
    ("< 30 days", 7, 30),
    ("> 6 months", 180, 365),
    ("> 1 year", 365, 365 * 5),
    ("> 5 years", 365 * 5, 365 * 10),
    ("> 10 years", 365 * 10, 365 * 15),
    ("> 15 years", 365 * 15, 365 * 20),
    ("> 20 years", 365 * 20, None),
]
STALE_ACCOUNT_BUCKETS = [
    ("Inactive > 6 months", 180, 365),
    ("Inactive > 12 months", 365, 365 * 5),
    ("Inactive > 60 months", 365 * 5, 365 * 10),
    ("Inactive > 120 months", 365 * 10, None),
]
PRIVILEGE_GROUP_KEYWORDS = (
    "domain admins", "enterprise admins", "schema admins", "administrators@",
    "account operators", "backup operators", "server operators", "print operators",
    "dnsadmins", "group policy creator owners", "protected users",
    "enterprise key admins", "key admins@", "cert publishers",
)
global_findings = []
def add_finding(category, details, score=None):
    if score is None:
        score = SEVERITY_SCORES.get(category, 5)
    global_findings.append((score, category, details))


def collapse_findings(
    findings: Optional[Sequence[Tuple[int, str, str]]] = None,
    caps: Optional[Dict[str, int]] = None,
) -> List[Tuple[int, str, str]]:
    """
    Collapse high-volume hygiene categories into scored summary rows.

    Keeps up to N detail rows per capped category (highest score first), then
    one summary finding for the remainder. Critical path categories stay intact
    unless listed in FINDING_COLLAPSE_CAPS.
    """
    src = list(findings if findings is not None else global_findings)
    cap_map = caps if caps is not None else FINDING_COLLAPSE_CAPS
    by_cat: Dict[str, List[Tuple[int, str, str]]] = defaultdict(list)
    other: List[Tuple[int, str, str]] = []
    for score, cat, det in src:
        if cat in cap_map:
            by_cat[cat].append((score, cat, det))
        else:
            other.append((score, cat, det))
    out: List[Tuple[int, str, str]] = list(other)
    for cat, rows in by_cat.items():
        rows_sorted = sorted(rows, key=lambda x: x[0], reverse=True)
        limit = cap_map[cat]
        keep = rows_sorted[:limit]
        rest = rows_sorted[limit:]
        out.extend(keep)
        if rest:
            top_score = rest[0][0]
            out.append(
                (
                    top_score,
                    cat,
                    f"{len(rest)} additional {cat} finding(s) collapsed "
                    f"(showing top {len(keep)}; use --export json for full list before collapse)",
                )
            )
    return sorted(out, key=lambda x: x[0], reverse=True)


def print_prioritized_findings(show_all=False):
    """
    Print findings summary table at end of run.

    Default: collapsed high-volume categories, top 20 by severity (skipped when empty).
    show_all / --all-findings: collapsed list of every remaining row after collapse,
    including an empty-state row when nothing was recorded.
    """
    raw_total = len(global_findings)
    sorted_findings = collapse_findings(global_findings)
    if show_all:
        console.rule("[bold magenta]All Findings by Severity[/bold magenta]")
        title = f"All Findings · {__org__} ({len(sorted_findings)})"
        rows = sorted_findings
    else:
        if not global_findings:
            return
        console.rule("[bold magenta]Prioritized Findings by Severity[/bold magenta]")
        title = f"Findings Summary · {__org__}"
        rows = sorted_findings[:20]
    table = Table(
        title=title,
        show_header=True,
        header_style="bold red",
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Severity Score", style="red", justify="right")
    table.add_column("Category", style="cyan")
    table.add_column("Details", style="yellow", overflow="fold")
    if not rows:
        table.add_row("—", "—", "(none)", "No findings recorded")
    else:
        for i, (score, cat, det) in enumerate(rows, 1):
            table.add_row(str(i), str(score), cat, det)
    console.print(table)
    if raw_total != len(sorted_findings):
        console.print(
            f"[dim]Collapsed high-volume categories: {raw_total} raw → "
            f"{len(sorted_findings)} displayed findings[/dim]"
        )
    if not show_all and len(sorted_findings) > 20:
        console.print(
            f"[dim]... and {len(sorted_findings) - 20} more "
            f"(pass --all-findings to list every finding)[/dim]"
        )
    elif show_all:
        console.print(f"[dim]Total findings (after collapse): {len(sorted_findings)} "
                      f"(raw {raw_total})[/dim]")
# ────────────────────────────────────────────────
# Intro Banner
# ────────────────────────────────────────────────
def print_intro_banner(mode_str):
    console.rule(
        f"[bold magenta]BloodBash v{__version__}[/bold magenta]  "
        f"[bold cyan]· {__org__} Open Source[/bold cyan]",
        style="magenta",
    )
    console.print(Panel(
        f"""
[bold cyan]{__org__}[/bold cyan]  ·  Open Source Security Tooling
[dim]{__org_url__}[/dim]
                                                                                             
[red]@@@@@@@   @@@        @@@@@@    @@@@@@   @@@@@@@      @@@@@@@    @@@@@@    @@@@@@   @@@  @@@[/red]  
[red]@@@@@@@@  @@@       @@@@@@@@  @@@@@@@@  @@@@@@@@     @@@@@@@@  @@@@@@@@  @@@@@@@   @@@  @@@[/red]    
[red]@@!  @@@  @@!       @@!  @@@  @@!  @@@  @@!  @@@     @@!  @@@  @@!  @@@  !@@       @@!  @@@[/red]    
[red]!@   @!@  !@!       !@!  @!@  !@!  @!@  !@!  @!@     !@   @!@  !@!  @!@  !@!       !@!  @!@[/red]    
[red]@!@!@!@   @!!       @!@  !@!  @!@  !@!  @!@  !@!     @!@!@!@   @!@!@!@!  !!@@!!    @!@!@!@![/red]    
[red]!!!@!!!!  !!!       !@!  !!!  !@!  !!!  !@!  !!!     !!!@!!!!  !!!@!!!!   !!@!!!   !!!@!!!![/red]    
[red]!!:  !!!  !!:       !!:  !!!  !!:  !!!  !!:  !!!     !!:  !!!  !!:  !!!       !:!  !!:  !!![/red]    
[red]:!:  !:!   :!:      :!:  !:!  :!:  !:!  :!:  !:!     :!:  !:!  :!:  !:!      !:!   :!:  !:![/red]    
[red] :: ::::   :: ::::  ::::: ::  ::::: ::   :::: ::      :: ::::  ::   :::  :::: ::   ::   :::[/red]    
[red]:: : ::   : :: : :   : :  :    : :  :   :: :  :      :: : ::    :   : :  :: : :     :   : :[/red]    
                                                                                             
[bold]BloodBash[/bold] — offline SharpHound / AzureHound analyzer from [bold cyan]{__org__}[/bold cyan]
Parses collector JSON → AD/Entra attack paths & misconfigurations (no Neo4j required)
Mode: [cyan]{mode_str}[/cyan]
Supports Active Directory (SharpHound/BloodHound-Python) and Azure AD (AzureHound) data.
[yellow]For authorized security testing / red teaming only.[/yellow]
Project: [dim]{__project_url__}[/dim]
Use --help for all options.
""",
        title=f"BloodBash by {__org__}",
        border_style="bright_blue",
        padding=(1, 2)
    ))
    console.print(f"[bold cyan]{__org_tagline__}[/bold cyan]\n")
    console.print("[bold]Color guide:[/bold]")
    console.print("  [red]Red[/red]          = Critical findings (ESCs, DCSync, Azure privileged roles)")
    console.print("  [yellow]Yellow[/yellow]       = Medium risk (weak GPOs, roastable accounts, Azure MFA bypass)")
    console.print("  [green]Green[/green]        = No issues / success / principals with rights")
    console.print("  [cyan]Cyan[/cyan]         = Object names, targets, templates, types, counts")
    console.print("  [magenta]Magenta[/magenta]      = Section headers & dividers only")
    console.print("  [dim]Dim[/dim]          = Minor notes or empty results\n")
# ────────────────────────────────────────────────
# Type Mapping (Extended for Azure)
# ────────────────────────────────────────────────
TYPE_FROM_META = {
    # SharpHound AD types (plural + singular meta.type variants)
    "users": "User", "user": "User",
    "computers": "Computer", "computer": "Computer",
    "groups": "Group", "group": "Group",
    "gpos": "GPO", "gpo": "GPO",
    "ous": "OU", "ou": "OU",
    "domains": "Domain", "domain": "Domain",
    "containers": "Container", "container": "Container",
    "certtemplates": "Certificate Template", "certtemplate": "Certificate Template",
    "enterprisecas": "Enterprise CA", "enterpriseca": "Enterprise CA",
    "rootcas": "Root CA", "rootca": "Root CA",
    "aiacas": "AIA CA", "aiaca": "AIA CA",
    "ntauthstores": "NTAuth Store", "ntauthstore": "NTAuth Store",
    # AzureHound types (added support)
    "azureusers": "Azure User", "azuregroups": "Azure Group", "azureapplications": "Azure Application",
    "azureserviceprincipals": "Azure Service Principal", "azuretenants": "Azure Tenant",
    "azureroles": "Azure Role", "azuredevices": "Azure Device", "azurekeyvaults": "Azure Key Vault",
}
# ────────────────────────────────────────────────
# Abuse Suggestions Helper (Extended for Azure)
# ────────────────────────────────────────────────
# When True (--all / --quick-wins), empty detector sections omit header + "No X found".
# Explicit single-check flags keep the green confirmation that the check ran.
_QUIET_EMPTY_SECTIONS = False


def set_quiet_empty_sections(enabled: bool = True) -> None:
    global _QUIET_EMPTY_SECTIONS
    _QUIET_EMPTY_SECTIONS = bool(enabled)


class DeferredSection:
    """Section header printed only when there is content (or when not quiet-empty)."""

    def __init__(self, title: str):
        self.title = title
        self._opened = False
        self.had_content = False

    def mark(self) -> None:
        """Open the section before the first real finding line."""
        if not self._opened:
            console.rule(f"[bold magenta]{self.title}[/bold magenta]")
            self._opened = True
        self.had_content = True

    def empty(self, msg: str) -> None:
        """No hits: suppress entirely under quiet mode; otherwise show green none."""
        if self.had_content:
            return
        if _QUIET_EMPTY_SECTIONS:
            return
        if not self._opened:
            console.rule(f"[bold magenta]{self.title}[/bold magenta]")
            self._opened = True
        console.print(f"[green]{msg}[/green]")


def print_abuse_panel(vuln_type: str):
    title = f"Abuse Suggestions: {vuln_type}"
    content = ""
    border = "red"
    if vuln_type == "ESC1-ESC8 (AD CS)":
        content = """
[bold red]Impact:[/bold red] Certificate-based privilege escalation (ESC1–ESC8) → impersonate users (often admins/DA), relay attacks, or obtain high-value certificates.
Common tools: Certipy, ntlmrelayx.py (Impacket)
"""
    elif vuln_type == "DCSync":
        content = """
[bold red]Impact:[/bold red] Dump NTDS hashes (krbtgt, admins, etc.) → Golden Ticket, pass-the-hash, domain compromise.
Tools: Mimikatz or Impacket secretsdump
"""
    elif vuln_type == "GPO Abuse":
        content = """
[bold yellow]Impact:[/bold yellow] Modify GPO → deploy malicious scheduled tasks/scripts → code execution / priv esc on affected machines.
Tools: SharpGPOAbuse, pyGPOAbuse, PowerView
"""
    elif vuln_type == "Dangerous Permissions":
        content = """
[bold red]Impact:[/bold red] Varies by right — ResetPassword → account takeover; GenericAll → full control; WriteDacl → own object.
"""
    elif vuln_type == "Kerberoastable":
        content = """
[bold yellow]Impact:[/bold yellow] Request TGS → offline crack weak service account password.
Tool: Impacket
"""
    elif vuln_type == "AS-REP Roastable":
        content = """
[bold yellow]Impact:[/bold yellow] Request AS-REP without preauth → offline crack user hash.
Tools: Rubeus or Impacket
"""
    elif vuln_type == "RBCD":
        content = """
[bold red]Impact:[/bold red] Resource-Based Constrained Delegation → S4U2Self/S4U2Proxy impersonation.
Tool: Impacket rbcd.py
"""
    elif vuln_type == "SID History Abuse":
        content = """
[bold yellow]Impact:[/bold yellow] If a user has SID history from a privileged group, they may retain rights.
"""
    elif vuln_type == "Unconstrained Delegation":
        content = """
[yellow]Impact:[/yellow] Computers with unconstrained delegation can impersonate any user who authenticates to them.
"""
    elif vuln_type == "Password in Description":
        content = """
[yellow]Impact:[/yellow] Users with passwords stored in plain text in their AD description field can be exploited for credential theft.
"""
    elif vuln_type == "Azure Privileged Roles":
        content = """
[bold red]Impact:[/bold red] Users with high-privilege Azure roles (e.g., Global Admin) can compromise the entire tenant.
Tools: Azure CLI, AzureAD PowerShell, or AzureHound for path finding.
"""
    elif vuln_type == "Azure App Secrets":
        content = """
[bold red]Impact:[/bold red] Applications with exposed secrets or certificates → service account takeover, tenant compromise.
Tools: Azure CLI, MSOL PowerShell.
"""
    elif vuln_type == "Azure MFA Bypass":
        content = """
[bold yellow]Impact:[/bold yellow] Users without MFA can be phished or password sprayed easily.
Tools: Azure AD tools for MFA enforcement.
"""
    elif vuln_type == "Azure Guest Access":
        content = """
[bold yellow]Impact:[/bold yellow] Guest users may have elevated access; potential for lateral movement.
"""
    elif vuln_type == "Azure Service Principal Abuse":
        content = """
[bold red]Impact:[/bold red] Service Principals with excessive permissions → resource manipulation or data exfiltration.
Tools: Azure CLI, Azure Graph API.
"""
    if content:
        console.print(Panel(content, title=title, border_style=border))
    else:
        console.print(f"[dim]No abuse example defined for {vuln_type}[/dim]")

def _get_prop_ci(item, keys):
    if not isinstance(item, dict):
        return None
    for key in keys:
        for k, v in item.items():
            if k.lower() == key.lower() and v is not None and v != '':
                return v
    return None

def _extract_node_props(node, is_azure=False):
    """Return the property bag for a SharpHound/AzureHound object.

    SharpHound uses ``Properties``; some exports use lowercase ``properties``.
    AzureHound typically nests attributes under ``data``.
    Never returns the raw node object (avoids shared mutable state with Aces/Members).
    """
    if not isinstance(node, dict):
        return {}
    if is_azure and isinstance(node.get("data"), dict):
        return node["data"]
    for k, v in node.items():
        if k.lower() == "properties" and isinstance(v, dict):
            return v
    # Already-flattened node (tests / partial records): copy scalar-ish props only
    structural = {
        "aces", "members", "memberof", "sessions", "privilegedsessions",
        "registrysessions", "localgroups", "links", "containedby", "childobjects",
        "trusts", "allowedtoact", "allowedtodelegate", "hassidhistory",
        "objectidentifier", "isdeleted", "isaclprotected", "primarygroupsid",
        "objecttype", "isazure", "kind", "data", "start", "end", "from", "to",
        "source", "target", "label", "relationship", "relationships",
    }
    return {
        k: v for k, v in node.items()
        if k.lower() not in structural and not isinstance(v, (list, dict))
    }

def _type_from_filename(filename: str) -> Optional[str]:
    """Infer object type from collector filenames like ``20240101_users.json``."""
    if not filename:
        return None
    stem = Path(filename).stem.lower()
    stem = re.sub(r"^\d+[_\-]?", "", stem)
    # Longer keys first so azureusers wins over users
    for key, typ in sorted(TYPE_FROM_META.items(), key=lambda kv: -len(kv[0])):
        if stem == key or stem.endswith("_" + key) or stem.endswith("-" + key):
            return typ
    return None

def _normalize_object_type(raw) -> Optional[str]:
    """Map a free-form type string to a canonical BloodBash type, or None if unusable."""
    if raw is None:
        return None
    s = str(raw).strip()
    if not s or s.lower() == "unknown":
        return None
    low = s.lower()
    if low in TYPE_FROM_META:
        return TYPE_FROM_META[low]
    # Common props.type values from collectors
    simple = {
        "user": "User",
        "computer": "Computer",
        "group": "Group",
        "gpo": "GPO",
        "ou": "OU",
        "domain": "Domain",
        "container": "Container",
    }
    if low in simple:
        return simple[low]
    return s

def _resolve_object_type(meta_type: str, item: dict, filename: str = "") -> str:
    """Resolve object type from meta.type, item fields, props, or filename."""
    mt = (meta_type or "").lower().strip()
    if mt in TYPE_FROM_META:
        return TYPE_FROM_META[mt]
    # Explicit type on the object (various casings / schemas)
    for key in ("ObjectType", "objectType", "objecttype", "Type", "type", "kind"):
        if key in item:
            norm = _normalize_object_type(item.get(key))
            if norm:
                return norm
    props = _extract_node_props(item, is_azure=bool(item.get("IsAzure")))
    if isinstance(props, dict):
        for key in ("type", "Type", "objectType", "ObjectType", "kind"):
            norm = _normalize_object_type(props.get(key))
            if norm:
                return norm
    from_file = _type_from_filename(filename)
    if from_file:
        return from_file
    return "Unknown"

# AzureHound entity kinds (exact) → BloodBash type labels
AZURE_ENTITY_KIND_MAP = {
    "aztenant": "Azure Tenant",
    "azuser": "Azure User",
    "azgroup": "Azure Group",
    "azapp": "Azure Application",
    "azapplication": "Azure Application",
    "azserviceprincipal": "Azure Service Principal",
    "azdevice": "Azure Device",
    "azrole": "Azure Role",
    "azkeyvault": "Azure Key Vault",
    "azsubscription": "Azure Subscription",
    "azresourcegroup": "Azure Resource Group",
    "azmanagementgroup": "Azure Management Group",
    "azvm": "Azure VM",
    "azvmscaleset": "Azure VM Scale Set",
    "azfunctionapp": "Azure Function App",
    "azwebapp": "Azure Web App",
    "azautomationaccount": "Azure Automation Account",
    "azlogicapp": "Azure Logic App",
    "azcontainerregistry": "Azure Container Registry",
    "azmanagedcluster": "Azure Managed Cluster",
}

# AzureHound relationship kinds → (edge label, source field, target field, list field)
# list field holds principal refs; source/target fields are scalar resource ids.
AZURE_REL_KIND_MAP = {
    "azgroupmember": ("MemberOf", "members", "groupId"),
    "azgroupowner": ("Owns", "owners", "groupId"),
    "azappowner": ("Owns", "owners", "appId"),
    "azserviceprincipalowner": ("Owns", "owners", "servicePrincipalId"),
    "azdeviceowner": ("Owns", "owners", "deviceId"),
    "azroleassignment": ("HasRole", "roleAssignments", "roleDefinitionId"),
    "azapproleassignment": ("HasAppRole", "appRoleAssignments", "resourceId"),
    "azvmowner": ("Owns", "owners", "vmId"),
    "azvmcontributor": ("Contributor", "contributors", "vmId"),
    "azvmuseraccessadmin": ("UserAccessAdmin", "userAccessAdmins", "vmId"),
    "azvmadminlogin": ("AdminLogin", "adminLogins", "vmId"),
    "azvmaverecontributor": ("AvereContributor", "avereContributors", "vmId"),
    "azresourcegroupowner": ("Owns", "owners", "resourceGroupId"),
    "azresourcegroupuseraccessadmin": ("UserAccessAdmin", "userAccessAdmins", "resourceGroupId"),
    "azsubscriptionowner": ("Owns", "owners", "subscriptionId"),
    "azsubscriptionuseraccessadmin": ("UserAccessAdmin", "userAccessAdmins", "subscriptionId"),
    "azkeyvaultaccesspolicy": ("KeyVaultAccess", "accessPolicies", "keyVaultId"),
}


def _azure_ref_id(ref) -> Optional[str]:
    """Extract an object id from an AzureHound nested principal/ref object."""
    if ref is None:
        return None
    if isinstance(ref, str):
        return ref
    if isinstance(ref, dict):
        for key in (
            "id", "objectId", "objectid", "ObjectId", "principalId",
            "principalObjectId", "appId", "deviceId", "userId", "groupId",
        ):
            if ref.get(key):
                return str(ref[key])
        owner = ref.get("owner") or ref.get("member") or ref.get("principal")
        if isinstance(owner, dict):
            return _azure_ref_id(owner)
        if isinstance(owner, str):
            return owner
    return None


def get_object_id(item):
    # Prefer SharpHound ObjectIdentifier before nested Azure data.id
    oid = _get_prop_ci(item, ('ObjectIdentifier', 'objectid', 'objectId', 'ObjectId'))
    if oid:
        return oid
    # Legacy SharpHound (pre-CE): Properties.objectsid / Guid / Name
    props = item.get("Properties") or item.get("properties")
    if isinstance(props, dict):
        oid = _get_prop_ci(
            props,
            ("objectsid", "objectSid", "objectid", "objectId", "ObjectIdentifier"),
        )
        if oid:
            return oid
    oid = _get_prop_ci(item, ("Guid", "guid", "GUID"))
    if oid:
        return oid
    data = item.get('data')
    if isinstance(data, dict):
        oid = _get_prop_ci(data, ('id', 'objectid', 'objectId', 'ObjectId', 'ObjectIdentifier'))
        if oid:
            return oid
    oid = _get_prop_ci(item, ('id',))
    if oid:
        return oid
    # Legacy name-only identity (stable, human-readable)
    name = item.get("Name") or item.get("name")
    if name and not _looks_like_sid(str(name)):
        return str(name)
    # Stable fallback for incomplete records (never use builtin hash() — it is
    # randomized per process via PYTHONHASHSEED and breaks SQLite identity).
    try:
        canonical = json.dumps(item, sort_keys=True, default=str, separators=(',', ':'))
    except (TypeError, ValueError):
        canonical = repr(item)
    digest = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    return f"synth-{digest[:32]}"

def _safe_extract_zip(zip_path, extract_to):
    """Extract zip members only if resolved paths stay under extract_to (Zip Slip safe)."""
    extract_to = Path(extract_to).resolve()
    extract_to.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for info in zip_ref.infolist():
            # Normalize separators so Windows-style ..\\ paths cannot slip on any OS
            name = (info.filename or "").replace("\\", "/")
            if not name or name.endswith('/'):
                continue
            # Reject absolute paths and Windows drive letters in member names
            if name.startswith('/') or (len(name) > 1 and name[1] == ':'):
                raise ValueError(f"Zip entry has absolute path: {name!r}")
            parts = [p for p in name.split('/') if p not in ('', '.')]
            if any(p == '..' for p in parts):
                raise ValueError(f"Zip entry escapes extract dir (Zip Slip): {name!r}")
            dest = (extract_to.joinpath(*parts)).resolve()
            try:
                dest.relative_to(extract_to)
            except ValueError:
                raise ValueError(f"Zip entry escapes extract dir (Zip Slip): {name!r}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zip_ref.open(info) as src, open(dest, 'wb') as out:
                out.write(src.read())

def load_json_dirs(paths, debug=False):
    """Load and merge SharpHound/AzureHound objects from multiple dirs/zips."""
    merged = {}
    pending_all = []
    for p in paths:
        if not p:
            continue
        part = load_json_dir(p, debug=debug)
        if not part:
            continue
        # Preserve azure pending edges attached as special key if present
        for oid, node in part.items():
            if oid == "__azure_pending_edges__":
                continue
            merged[oid] = node
        # load_json_dir currently returns only nodes dict; pending is internal
    return merged


def print_collection_health(G, nodes=None) -> dict:
    """Print collection completeness banner (reliability ceiling for this zip)."""
    console.rule("[bold magenta]Collection health[/bold magenta]")
    type_counts = Counter(
        str((d or {}).get("type") or "?").lower() for _, d in G.nodes(data=True)
    )
    n_users = type_counts.get("user", 0)
    n_computers = type_counts.get("computer", 0)
    n_groups = type_counts.get("group", 0)
    n_gpo = type_counts.get("gpo", 0)
    n_domain = type_counts.get("domain", 0)
    has_adcs = any(
        t in type_counts
        for t in (
            "certtemplate",
            "certificate template",
            "enterprise ca",
            "root ca",
            "ntauth store",
            "aia ca",
        )
    )
    # Session / local group coverage (edges)
    has_session = sum(1 for _, _, d in G.edges(data=True) if d.get("label") == "HasSession")
    local_admin = sum(
        1 for _, _, d in G.edges(data=True) if d.get("label") in ("LocalAdmin", "AdminTo")
    )
    can_rdp = sum(1 for _, _, d in G.edges(data=True) if d.get("label") == "CanRDP")
    trust_edges = sum(
        1
        for _, _, d in G.edges(data=True)
        if str(d.get("label") or "").lower().startswith("trusteddomain")
    )
    # Unresolved SID-like principal names on nodes
    unresolved = 0
    for _, d in G.nodes(data=True):
        name = d.get("name") or ""
        if _looks_like_sid(name):
            unresolved += 1
    ceiling = "high"
    notes = []
    if not has_adcs:
        notes.append("no ADCS objects")
        ceiling = "medium"
    if has_session == 0:
        notes.append("no HasSession edges")
        ceiling = "medium" if ceiling == "high" else ceiling
    if local_admin == 0 and can_rdp == 0:
        notes.append("no LocalAdmin/CanRDP edges")
        ceiling = "medium"
    if unresolved > 20:
        notes.append(f"{unresolved} SID-only principals")
        ceiling = "low" if unresolved > 100 else "medium"
    if n_computers < 5 and n_users < 20:
        notes.append("small collection")
    note_s = "; ".join(notes) if notes else "looks complete for AD object graph"
    console.print(
        f"  Objects: users={n_users} computers={n_computers} groups={n_groups} "
        f"gpos={n_gpo} domains={n_domain}"
    )
    console.print(
        f"  Edges: HasSession={has_session} LocalAdmin/AdminTo={local_admin} "
        f"CanRDP={can_rdp} trusts={trust_edges}"
    )
    console.print(
        f"  ADCS data: {'yes' if has_adcs else 'no'} · "
        f"SID-only nodes: {unresolved} · "
        f"[bold]Reliability ceiling: {ceiling}[/bold] ({note_s})"
    )
    health = {
        "users": n_users,
        "computers": n_computers,
        "groups": n_groups,
        "has_adcs": has_adcs,
        "has_session": has_session,
        "unresolved_sids": unresolved,
        "ceiling": ceiling,
    }
    if ceiling in ("low", "medium") and notes:
        add_finding(
            "Collection Health",
            f"Reliability ceiling {ceiling}: {note_s}",
            score=3,
        )
    return health


def load_json_dir(directory, debug=False):
    nodes = {}
    azure_pending_edges = []  # (src, dst, label) from AzureHound relationship kinds
    try:
        path_obj = Path(directory)
        if path_obj.suffix.lower() == '.zip':
            if debug:
                print(f"Extracting {path_obj.name}...")
            # Fresh temp dir avoids merging stale JSON from a previous extract of the same stem
            extract_to = Path(tempfile.mkdtemp(prefix="bloodbash-zip-"))
            _safe_extract_zip(path_obj, extract_to)
            directory = str(extract_to)
        files = [f for f in os.listdir(directory) if f.lower().endswith('.json')]
    except FileNotFoundError:
        console.print(f"[yellow]Warning: Directory '{directory}' not found. Skipping.[/yellow]")
        return nodes
    except ValueError as e:
        console.print(f"[red]Refused to extract zip (unsafe paths): {e}[/red]")
        return nodes
    with Progress() as progress:
        task = progress.add_task("[cyan]Loading JSON files...", total=len(files))
        for filename in files:
            path = os.path.join(directory, filename)
            if debug:
                console.print(f"[blue]DEBUG: Loading file: {filename}[/blue]")
            try:
                with open(path, 'r', encoding='utf-8-sig') as f:
                    raw = json.load(f)
                    if debug:
                        console.print(f"[blue]DEBUG: Top-level keys: {list(raw.keys()) if isinstance(raw, dict) else type(raw)}[/blue]")
                    meta = raw.get("meta") if isinstance(raw, dict) else None
                    meta_type = (meta or {}).get("type", "") if isinstance(meta, dict) else ""
                    meta_type = str(meta_type or "").lower()
                    # AzureHound bulk export: top-level list or {"data":[...]} of {kind,data}
                    # Important: empty list [] is valid SharpHound data — do not use
                    # `raw.get('data') or ...` (falsy empty list would fall through to raw dict
                    # and invent a synthetic node per empty certtemplates/enterprisecas file).
                    if isinstance(raw, list):
                        data = raw
                    elif isinstance(raw, dict):
                        if "data" in raw:
                            data = raw.get("data")
                        elif "Results" in raw:
                            data = raw.get("Results")
                        elif "objects" in raw:
                            data = raw.get("objects")
                        else:
                            # Legacy SharpHound (pre-CE): {"users":[...], "meta":{"type":"users"}}
                            legacy_keys = (
                                "users", "groups", "computers", "domains", "ous",
                                "gpos", "containers", "sessions", "gpomemberships",
                            )
                            data = None
                            if meta_type and isinstance(raw.get(meta_type), list):
                                data = raw.get(meta_type)
                            else:
                                for lk in legacy_keys:
                                    if isinstance(raw.get(lk), list):
                                        data = raw.get(lk)
                                        if not meta_type:
                                            meta_type = lk
                                        break
                            if data is None:
                                data = raw
                    else:
                        data = []
                    if debug:
                        console.print(f"[blue]DEBUG: data type: {type(data)}, len if list: {len(data) if isinstance(data, list) else 'not list'}[/blue]")
                    if not isinstance(data, list):
                        data = [data] if data and isinstance(data, dict) else []
                    # Legacy sessions.json is edge-only (UserName/ComputerName), not entities
                    if meta_type == "sessions" or (
                        "session" in filename.lower()
                        and data
                        and isinstance(data[0], dict)
                        and ("UserName" in data[0] or "ComputerName" in data[0])
                    ):
                        sess_pending = nodes.setdefault(
                            "__legacy_sessions__",
                            {"_pending_sessions": []},
                        )
                        if not isinstance(sess_pending, dict):
                            sess_pending = {"_pending_sessions": []}
                            nodes["__legacy_sessions__"] = sess_pending
                        pending_list = sess_pending.setdefault("_pending_sessions", [])
                        for item in data:
                            if not isinstance(item, dict):
                                continue
                            user = item.get("UserName") or item.get("userName")
                            computer = item.get("ComputerName") or item.get("computerName")
                            if user and computer:
                                pending_list.append((str(computer), str(user)))
                        if debug:
                            console.print(
                                f"[blue]DEBUG: {filename} → {len(pending_list)} legacy sessions[/blue]"
                            )
                        progress.advance(task)
                        continue
                    added = 0
                    for item in data:
                        if not isinstance(item, dict):
                            continue
                        kind_raw = item.get('kind') or item.get('Kind') or ''
                        kind_l = str(kind_raw).lower()
                        # Detect Azure (case-insensitive checks, expanded)
                        item_lower = {k.lower(): v for k, v in item.items()}
                        is_azure = (
                            meta_type.startswith("azure")
                            or bool(kind_l.startswith("az"))
                            or any(k in ['@odata.context', 'odata.context', 'cloudanchorobject'] for k in item_lower.keys())
                            or any(
                                v and isinstance(v, str) and ('microsoft.com' in v.lower() or 'azure' in v.lower())
                                for v in item_lower.values() if isinstance(v, str)
                            )
                        )
                        # AzureHound relationship kinds → pending edges (not entity nodes)
                        rel_spec = AZURE_REL_KIND_MAP.get(kind_l)
                        is_rel_kind = bool(rel_spec) or (
                            kind_l.startswith("az")
                            and any(
                                kind_l.endswith(sfx)
                                for sfx in (
                                    "owner", "owners", "member", "members",
                                    "roleassignment", "roleassignments",
                                    "accesspolicy", "accesspolicies",
                                    "useraccessadmin", "contributor",
                                    "adminlogin", "averecontributor",
                                )
                            )
                            and kind_l not in AZURE_ENTITY_KIND_MAP
                        )
                        if is_azure and is_rel_kind:
                            if rel_spec:
                                label, list_key, target_key = rel_spec
                            else:
                                # Generic: infer label from kind suffix
                                if kind_l.endswith("member") or kind_l.endswith("members"):
                                    label, list_key, target_key = "MemberOf", "members", "groupId"
                                elif "owner" in kind_l:
                                    label, list_key, target_key = "Owns", "owners", "id"
                                elif "roleassignment" in kind_l:
                                    label, list_key, target_key = "HasRole", "roleAssignments", "roleDefinitionId"
                                elif "useraccessadmin" in kind_l:
                                    label, list_key, target_key = "UserAccessAdmin", "userAccessAdmins", "id"
                                elif "contributor" in kind_l:
                                    label, list_key, target_key = "Contributor", "contributors", "id"
                                else:
                                    label, list_key, target_key = kind_raw or "Related", "principals", "id"
                            payload = item.get('data') if isinstance(item.get('data'), dict) else item
                            target = (
                                payload.get(target_key)
                                or payload.get('groupId')
                                or payload.get('appId')
                                or payload.get('servicePrincipalId')
                                or payload.get('deviceId')
                                or payload.get('roleDefinitionId')
                                or payload.get('resourceId')
                                or payload.get('vmId')
                                or payload.get('resourceGroupId')
                                or payload.get('subscriptionId')
                                or payload.get('keyVaultId')
                                or payload.get('id')
                            )
                            refs = payload.get(list_key)
                            if refs is None:
                                refs = []
                            if not isinstance(refs, list):
                                refs = [refs] if refs else []
                            for ref in refs:
                                src = _azure_ref_id(ref)
                                if not src:
                                    continue
                                if label == "MemberOf":
                                    if target:
                                        azure_pending_edges.append((src, str(target), label))
                                elif label == "HasRole":
                                    if isinstance(ref, dict) and ref.get('principalId'):
                                        src = str(ref.get('principalId'))
                                    role_id = str(target or (ref.get('roleDefinitionId') if isinstance(ref, dict) else '') or '')
                                    if src and role_id:
                                        azure_pending_edges.append((src, role_id, label))
                                else:
                                    if src and target:
                                        azure_pending_edges.append((src, str(target), label))
                            continue  # do not create a fake entity node for relationship kinds
                        if is_azure:
                            item['IsAzure'] = True
                            # Exact map first (AZUser / azuser); then bare AzureHound kinds (User, Group)
                            obj_type = AZURE_ENTITY_KIND_MAP.get(kind_l)
                            if not obj_type and kind_l.startswith("az"):
                                # az + entity name without substring traps on relationship kinds
                                if kind_l not in AZURE_REL_KIND_MAP:
                                    bare = kind_l[2:]
                                    obj_type = AZURE_ENTITY_KIND_MAP.get("az" + bare)
                                    if not obj_type:
                                        obj_type = f"Azure {kind_raw[2:]}" if len(str(kind_raw)) > 2 else "Unknown Azure"
                            if not obj_type:
                                bare_map = {
                                    "user": "Azure User",
                                    "group": "Azure Group",
                                    "role": "Azure Role",
                                    "application": "Azure Application",
                                    "app": "Azure Application",
                                    "serviceprincipal": "Azure Service Principal",
                                    "device": "Azure Device",
                                    "tenant": "Azure Tenant",
                                    "keyvault": "Azure Key Vault",
                                    "subscription": "Azure Subscription",
                                    "resourcegroup": "Azure Resource Group",
                                    "managementgroup": "Azure Management Group",
                                    "vm": "Azure VM",
                                }
                                obj_type = bare_map.get(kind_l.replace(" ", ""), "Unknown Azure")
                            if obj_type == "Unknown Azure":
                                typ = item.get('type') or item.get('Type')
                                if typ:
                                    obj_type = f"Azure {str(typ).title()}"
                        else:
                            obj_type = _resolve_object_type(meta_type, item, filename)
                        item['ObjectType'] = obj_type
                        # Prefer objectId on flat AzureHound fixture items
                        oid = (
                            item.get('objectId')
                            or item.get('ObjectId')
                            or item.get('objectid')
                            or get_object_id(item)
                        )
                        if oid in nodes and debug:
                            console.print(f"[yellow]DEBUG: OID collision, last write wins: {oid}[/yellow]")
                        nodes[oid] = item
                        added += 1
                        if debug and added <= 3:  # Print first 3 items for inspection
                            console.print(f"[blue]DEBUG: Sample item keys: {list(item.keys())}[/blue]")
                            console.print(f"[blue]DEBUG: Sample item type: {obj_type}[/blue]")
                            sample_data = item.get('data') if isinstance(item.get('data'), dict) else {}
                            console.print(f"[blue]DEBUG: Sample item sample data: {dict(list(sample_data.items())[:10])}[/blue]")
                    if debug:
                        console.print(f"[blue]DEBUG: {filename} → {added} objects added[/blue]")
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to parse {filename}: {e}[/yellow]")
                if debug:
                    console.print(f"[red]DEBUG: Full traceback for {filename}:[/red]\n{traceback.format_exc()}")
            progress.advance(task)
    # Stash Azure relationship edges for build_graph (attached as special key)
    if azure_pending_edges:
        nodes["__azure_pending_edges__"] = {
            "ObjectIdentifier": "__azure_pending_edges__",
            "ObjectType": "Meta",
            "IsAzure": True,
            "Properties": {},
            "_pending_edges": azure_pending_edges,
        }
    console.print(f"[green]✓ Loaded {len(nodes)} objects from {len(files)} files[/green]")
    return nodes


def _register_name_map(name_to_oid, name, oid):
    """Map full UPN/name and short SAM; never overwrite short key with a different oid."""
    if name is None or oid is None:
        return
    name_u = str(name).upper()
    name_to_oid[name_u] = oid
    short = name_u.split('@')[0].split('\\')[-1]
    if short and short not in name_to_oid:
        name_to_oid[short] = oid


def _coalesce_result_list(value) -> List[Any]:
    """
    Normalize SharpHound relationship / membership payloads to a flat list.

    Accepts:
      - None → []
      - list of refs → as-is
      - CE wrapper dict: {Results: [...], Collected, FailureReason}
      - single dict ref → [dict]
      - scalar → [scalar]
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        # SharpHound CE collection wrapper
        for key in ("Results", "results", "data", "Data", "Members", "members"):
            if key in value and isinstance(value[key], list):
                return value[key]
        # Single principal ref object
        if any(
            k in value
            for k in (
                "ObjectIdentifier",
                "objectid",
                "ObjectId",
                "MemberName",
                "Name",
                "name",
                "id",
            )
        ):
            return [value]
        return []
    return [value]


def _ref_object_id(ref) -> Optional[str]:
    """Extract principal/object id from a membership or relationship ref."""
    if ref is None:
        return None
    if isinstance(ref, dict):
        for key in (
            "ObjectIdentifier",
            "objectid",
            "ObjectId",
            "id",
            "MemberName",
            "memberName",
            "Name",
            "name",
            "PrincipalSID",
            "principalsid",
        ):
            val = ref.get(key)
            if val:
                return str(val)
        return None
    return str(ref)


def _ref_object_type(ref, default: str = "Unknown") -> str:
    if not isinstance(ref, dict):
        return default
    return (
        _normalize_object_type(
            ref.get("ObjectType")
            or ref.get("objectType")
            or ref.get("MemberType")
            or ref.get("memberType")
            or ref.get("Type")
            or ref.get("type")
        )
        or default
    )


def _ensure_graph_node(G, nodes, name_to_oid, oid, name=None, typ='Unknown', props=None, is_azure=False):
    if oid is None:
        return
    if oid not in G.nodes:
        G.add_node(
            oid,
            name=str(name if name is not None else oid),
            type=typ or 'Unknown',
            props=props if isinstance(props, dict) else {},
            is_azure=bool(is_azure),
        )
        if oid not in nodes:
            _register_name_map(name_to_oid, name if name is not None else oid, oid)
    elif name and (not G.nodes[oid].get('name') or G.nodes[oid].get('name') == oid):
        G.nodes[oid]['name'] = str(name)


def _edge_label_exists(G, u, v, label) -> bool:
    if not G.has_edge(u, v):
        return False
    want = (label or '').lower()
    for data in G.get_edge_data(u, v).values():
        if (data.get('label') or '').lower() == want:
            return True
    return False


def _add_unique_edge(G, u, v, label, **attrs):
    """Add edge only if no multi-edge with the same label already exists."""
    if u is None or v is None or not label:
        return False
    if _edge_label_exists(G, u, v, label):
        return False
    G.add_edge(u, v, label=label, **attrs)
    return True


def _sid_suffix(oid: str) -> str:
    """Normalize SID / domain-prefixed SID to a comparable tail (e.g. S-1-5-11)."""
    s = str(oid or "")
    # DOMAIN-S-1-5-11 or plain S-1-5-11
    idx = s.upper().find("S-1-")
    if idx >= 0:
        return s[idx:].upper()
    return s.upper()


def _node_domain_key(d: dict) -> str:
    props = d.get("props") or {}
    dom = (
        props.get("domain")
        or props.get("Domain")
        or props.get("domainsid")
        or ""
    )
    if not dom:
        name = d.get("name") or ""
        if "@" in name:
            dom = name.rsplit("@", 1)[-1]
        elif name.count(".") >= 1 and not name.upper().startswith("S-1-"):
            # computer FQDN-style DOMAIN.LOCAL
            parts = name.split(".", 1)
            if len(parts) == 2 and parts[1]:
                dom = parts[1]
    return str(dom).upper().strip()


def add_well_known_group_memberships(G) -> int:
    """Synthesize BloodHound-style well-known MemberOf edges missing from SharpHound JSON.

    SharpHound does not emit Domain Users → Authenticated Users → Everyone (etc.).
    BloodHound CE adds these at ingest so every Domain User inherits ACLs granted
    to AUTHENTICATED USERS / EVERYONE. Without them, compromise dossiers and path
    finding under-report (e.g. GenericWrite on GPOs held by Authenticated Users).
    """
    # domain_key -> role -> oid
    by_domain: Dict[str, Dict[str, str]] = defaultdict(dict)
    global_roles: Dict[str, List[str]] = defaultdict(list)

    for oid, d in G.nodes(data=True):
        if d.get("is_azure"):
            continue
        typ = str(d.get("type") or "").lower()
        if typ not in ("group", "unknown", ""):
            continue
        name = (d.get("name") or "").upper()
        sid = _sid_suffix(oid)
        dom = _node_domain_key(d) or "_GLOBAL_"
        role = None
        if sid.endswith("-513") or name.startswith("DOMAIN USERS@") or name == "DOMAIN USERS":
            role = "domain_users"
        elif sid.endswith("-515") or name.startswith("DOMAIN COMPUTERS@"):
            role = "domain_computers"
        elif sid.endswith("-516") or name.startswith("DOMAIN CONTROLLERS@"):
            role = "domain_controllers"
        elif sid == "S-1-5-11" or "AUTHENTICATED USERS" in name:
            role = "authenticated_users"
        elif sid == "S-1-1-0" or name.startswith("EVERYONE@"):
            role = "everyone"
        elif sid == "S-1-5-32-545" or (
            (name.startswith("USERS@") or name == "USERS") and "DOMAIN USERS" not in name
        ):
            role = "builtin_users"
        if not role:
            continue
        if role in ("authenticated_users", "everyone", "builtin_users"):
            global_roles[role].append(oid)
        by_domain[dom][role] = oid

    added = 0

    def _pick(role: str, dom: str, roles: dict) -> Optional[str]:
        if roles.get(role):
            return roles[role]
        cands = global_roles.get(role) or []
        if not cands:
            return None
        dom_compact = dom.replace(".", "")
        for cand in cands:
            cname = (G.nodes[cand].get("name") or "").upper()
            coid = str(cand).upper().replace(".", "")
            if dom != "_GLOBAL_" and (dom in cname or dom_compact in coid):
                return cand
        return cands[0] if len(cands) == 1 else None

    def _link(src, dst) -> None:
        nonlocal added
        if src and dst and src in G and dst in G:
            if _add_unique_edge(G, src, dst, "MemberOf"):
                added += 1

    for dom, roles in by_domain.items():
        if dom == "_GLOBAL_" and not any(
            r in roles for r in ("domain_users", "domain_computers", "domain_controllers")
        ):
            # Only link pure well-known globals when no domain-scoped groups keyed here
            au = roles.get("authenticated_users")
            ev = roles.get("everyone")
            _link(au, ev)
            continue
        du = roles.get("domain_users")
        dc = roles.get("domain_computers")
        dctrl = roles.get("domain_controllers")
        au = _pick("authenticated_users", dom, roles)
        ev = _pick("everyone", dom, roles)
        bu = _pick("builtin_users", dom, roles)

        # BloodHound CE well-known nesting
        _link(du, au)
        _link(dc, au)
        _link(dctrl, au)
        _link(au, ev)
        _link(du, bu)
        _link(au, bu)

    return added


def build_graph(nodes, db_path=None, debug=False):
    G = nx.MultiDiGraph()
    name_to_oid = {}
    relationship_edges = []
    placeholder_counter = 0
    if debug:
        console.print(f"[blue]DEBUG: Starting graph build with {len(nodes)} raw nodes[/blue]")
    azure_pending = []
    meta_pending = nodes.pop("__azure_pending_edges__", None)
    if isinstance(meta_pending, dict):
        azure_pending = list(meta_pending.get("_pending_edges") or [])

    legacy_sessions = []
    meta_sess = nodes.pop("__legacy_sessions__", None)
    if isinstance(meta_sess, dict):
        legacy_sessions = list(meta_sess.get("_pending_sessions") or [])

    with tqdm(total=len(nodes), desc="Building graph", unit="node") as pbar:
        for oid, node in nodes.items():
            if oid in ("__azure_pending_edges__", "__legacy_sessions__"):
                pbar.update(1)
                continue
            is_azure = node.get('IsAzure', False)
            # SharpHound: Properties / properties; Azure: data
            props = _extract_node_props(node, is_azure=is_azure)
            if not isinstance(props, dict):
                props = {}
            name = (
                props.get('name') or props.get('Name') or props.get('displayName')
                or node.get('name') or node.get('Name') or oid
            )
            # Prefer non-Unknown types: ObjectType may be "Unknown" when meta was
            # missing, which is truthy and previously blocked props.type fallback.
            obj_type = (
                _normalize_object_type(node.get('ObjectType'))
                or _normalize_object_type(node.get('Type'))
                or _normalize_object_type(props.get('type') or props.get('Type'))
                or 'Unknown'
            )
            if not oid.startswith('rel_'):
                G.add_node(oid, name=name, type=obj_type, props=props, is_azure=is_azure)
                _register_name_map(name_to_oid, name, oid)
            # Check for standalone relationships (various formats)
            if 'start' in node and 'end' in node and 'label' in node:
                relationship_edges.append((node['start'], node['end'], node['label']))
            elif 'from' in node and 'to' in node and 'relationship' in node:
                relationship_edges.append((node['from'], node['to'], node['relationship']))
            elif 'source' in node and 'target' in node and ('type' in node or 'label' in node):
                relationship_edges.append((node['source'], node['target'], node.get('type') or node.get('label')))
            # AD relationships (case-insensitive for Azure too)
            # AllowedToAct is inverted vs other list fields: SharpHound puts the
            # *resource* (computer) as the object and lists principals who may act
            # on it. BloodHound path direction is principal → AllowedToAct → resource.
            ad_rels = ['MemberOf', 'AdminTo', 'HasSession', 'AllowedToAct', 'HasSIDHistory']
            for key in ad_rels:
                rels = None
                for nk in node.keys():
                    if nk.lower() == key.lower():
                        rels = node[nk]
                        break
                if rels is None:
                    continue
                rels = _coalesce_result_list(rels)
                for rel in rels:
                    target = _ref_object_id(rel)
                    if not target:
                        continue
                    rel_type = _ref_object_type(rel, default='Unknown')
                    # Resolve name→SID when legacy/display names used
                    target_res = name_to_oid.get(str(target).upper()) or str(target)
                    _ensure_graph_node(
                        G, nodes, name_to_oid, target_res,
                        name=str(target), typ=rel_type,
                    )
                    if key.lower() == 'allowedtoact':
                        # principal (listed) → AllowedToAct → resource (this node)
                        _add_unique_edge(G, target_res, oid, key)
                    else:
                        _add_unique_edge(G, oid, target_res, key)
            # SharpHound CE stores group membership on groups as Members
            # (not MemberOf on users). Emit member → MemberOf → group edges.
            # Also accept CE wrapper {Results:[...]} and legacy MemberName refs.
            members = None
            for nk in node.keys():
                if nk.lower() == 'members':
                    members = node[nk]
                    break
            if members is not None:
                for rel in _coalesce_result_list(members):
                    member_id = _ref_object_id(rel)
                    member_type = _ref_object_type(rel, default='Unknown')
                    if member_id:
                        mid_s = str(member_id)
                        resolved = name_to_oid.get(mid_s.upper()) or mid_s
                        _ensure_graph_node(
                            G, nodes, name_to_oid, resolved,
                            name=mid_s, typ=member_type,
                        )
                        _add_unique_edge(G, resolved, oid, 'MemberOf')
            # PrimaryGroupSID is often not listed in group Members; still a MemberOf edge
            primary_group = None
            for nk in node.keys():
                if nk.lower() in ('primarygroupsid', 'primarygroup'):
                    primary_group = node[nk]
                    break
            if not primary_group and isinstance(props, dict):
                primary_group = (
                    props.get('primarygroupsid')
                    or props.get('PrimaryGroupSID')
                    or props.get('primaryGroupSID')
                )
            if primary_group:
                pg_s = str(primary_group)
                pg_id = name_to_oid.get(pg_s.upper()) or pg_s
                _ensure_graph_node(
                    G, nodes, name_to_oid, pg_id,
                    name=pg_s, typ='Group',
                )
                _add_unique_edge(G, oid, pg_id, 'MemberOf')
            # SharpHound CE nested session collections:
            # {Results: [{UserSID, ComputerSID}], Collected, FailureReason}
            # BloodHound edge: Computer -HasSession-> User (dedupe across collections)
            session_users = set()
            for session_key in ('Sessions', 'PrivilegedSessions', 'RegistrySessions'):
                block = None
                for nk in node.keys():
                    if nk.lower() == session_key.lower():
                        block = node[nk]
                        break
                if block is None:
                    continue
                results = []
                if isinstance(block, dict):
                    results = block.get('Results') or block.get('results') or []
                elif isinstance(block, list):
                    results = block
                for entry in results:
                    if not isinstance(entry, dict):
                        continue
                    user_sid = (
                        entry.get('UserSID')
                        or entry.get('ObjectIdentifier')
                        or entry.get('objectid')
                    )
                    if user_sid:
                        session_users.add(user_sid)
            for user_sid in session_users:
                _ensure_graph_node(
                    G, nodes, name_to_oid, user_sid,
                    name=str(user_sid), typ='User',
                )
                _add_unique_edge(G, oid, user_sid, 'HasSession')
            # SharpHound CE LocalGroups: list of local groups with Results members.
            # Map well-known RIDs to BloodHound-style edges (principal → right → computer).
            local_groups = None
            for nk in node.keys():
                if nk.lower() == 'localgroups':
                    local_groups = node[nk]
                    break
            if isinstance(local_groups, list):
                for lg in local_groups:
                    if not isinstance(lg, dict):
                        continue
                    group_sid = str(lg.get('ObjectIdentifier') or lg.get('objectid') or '')
                    group_name = str(lg.get('Name') or lg.get('name') or '').lower()
                    rid = group_sid.rsplit('-', 1)[-1] if group_sid else ''
                    label = None
                    if rid == '544' or 'administrator' in group_name:
                        label = 'LocalAdmin'
                    elif rid == '555' or 'remote desktop' in group_name:
                        label = 'CanRDP'
                    elif rid == '562' or 'distributed com' in group_name:
                        label = 'ExecuteDCOM'
                    if not label:
                        continue
                    members = lg.get('Results') or lg.get('results') or []
                    if not isinstance(members, list):
                        members = [members] if members else []
                    for member in members:
                        mid = None
                        mid_type = 'Unknown'
                        if isinstance(member, dict):
                            mid = (
                                member.get('ObjectIdentifier')
                                or member.get('objectid')
                                or member.get('ObjectId')
                                or member.get('id')
                                or member.get('Name')
                                or member.get('name')
                            )
                            mid_type = (
                                _normalize_object_type(
                                    member.get('ObjectType')
                                    or member.get('objectType')
                                    or member.get('Type')
                                )
                                or 'Unknown'
                            )
                        else:
                            mid = member
                        if mid:
                            mid_s = str(mid)
                            mid_res = name_to_oid.get(mid_s.upper()) or mid_s
                            _ensure_graph_node(
                                G, nodes, name_to_oid, mid_res,
                                name=mid_s, typ=mid_type,
                            )
                            _add_unique_edge(G, mid_res, oid, label)
            # Legacy SharpHound: LocalAdmins / RemoteDesktopUsers / DcomUsers as name lists
            for leg_key, leg_label in (
                ('LocalAdmins', 'LocalAdmin'),
                ('RemoteDesktopUsers', 'CanRDP'),
                ('DcomUsers', 'ExecuteDCOM'),
            ):
                leg = None
                for nk in node.keys():
                    if nk.lower() == leg_key.lower():
                        leg = node[nk]
                        break
                if not isinstance(leg, list):
                    continue
                for member in leg:
                    mid = None
                    mid_type = 'Unknown'
                    if isinstance(member, dict):
                        mid = (
                            member.get('ObjectIdentifier')
                            or member.get('Name')
                            or member.get('name')
                        )
                        mid_type = (
                            _normalize_object_type(
                                member.get('ObjectType')
                                or member.get('Type')
                                or member.get('type')
                            )
                            or 'Unknown'
                        )
                    else:
                        mid = member
                    if not mid:
                        continue
                    mid_s = str(mid)
                    mid_res = name_to_oid.get(mid_s.upper()) or mid_s
                    _ensure_graph_node(
                        G, nodes, name_to_oid, mid_res,
                        name=mid_s, typ=mid_type,
                    )
                    _add_unique_edge(G, mid_res, oid, leg_label)
            # ACLs (case-insensitive key; tolerate null / non-dict entries)
            aces = None
            for nk in node.keys():
                if nk.lower() == 'aces':
                    aces = node[nk]
                    break
            if aces is None:
                aces = []
            if not isinstance(aces, list):
                aces = [aces] if aces else []
            for ace in aces:
                if not isinstance(ace, dict):
                    continue
                principal = (
                    ace.get('PrincipalSID')
                    or ace.get('PrincipalObjectIdentifier')
                    or ace.get('principalsid')
                )
                principal_name = (
                    ace.get('PrincipalName')
                    or ace.get('principalName')
                    or ace.get('Principal')
                )
                right = ace.get('RightName') or ace.get('rightName') or ace.get('Right')
                # Legacy SharpHound: RightName=ExtendedRight + AceType=GetChanges/GetChangesAll
                ace_type = (
                    ace.get('AceType')
                    or ace.get('aceType')
                    or ace.get('RightGuid')
                    or ""
                )
                if right and str(right).lower() in (
                    'extendedright', 'extendedrights', 'allextendedrights'
                ) and ace_type:
                    at = str(ace_type).strip()
                    if at and at.lower() not in ('all', ''):
                        right = at  # GetChanges / GetChangesAll / etc.
                if not principal and principal_name:
                    pn = str(principal_name)
                    principal = name_to_oid.get(pn.upper()) or pn
                if principal and right:
                    ptype = (
                        _normalize_object_type(
                            ace.get('PrincipalType') or ace.get('principalType')
                        )
                        or 'Unknown'
                    )
                    pname = str(principal_name or principal)
                    # Prefer already-registered SID for this display name
                    if principal_name:
                        mapped = name_to_oid.get(str(principal_name).upper())
                        if mapped:
                            principal = mapped
                    _ensure_graph_node(
                        G, nodes, name_to_oid, principal,
                        name=pname, typ=ptype,
                    )
                    _add_unique_edge(G, principal, oid, right)
            # GPO Links on domains/OUs: container -GPLink→ GPO (BloodHound direction)
            links = None
            for nk in node.keys():
                if nk.lower() == 'links':
                    links = node[nk]
                    break
            if isinstance(links, list):
                for link in links:
                    if not isinstance(link, dict):
                        continue
                    gpo_guid = (
                        link.get('GUID')
                        or link.get('Guid')
                        or link.get('ObjectIdentifier')
                        or link.get('objectid')
                    )
                    if not gpo_guid:
                        continue
                    _ensure_graph_node(
                        G, nodes, name_to_oid, gpo_guid,
                        name=str(gpo_guid), typ='GPO',
                    )
                    enforced = link.get('IsEnforced')
                    if enforced is None:
                        enforced = link.get('isEnforced')
                    _add_unique_edge(
                        G, oid, gpo_guid, 'GPLink',
                        is_enforced=bool(enforced) if enforced is not None else None,
                    )
            # Containment: ContainedBy {ObjectIdentifier} → parent -Contains→ child
            contained_by = None
            for nk in node.keys():
                if nk.lower() == 'containedby':
                    contained_by = node[nk]
                    break
            if isinstance(contained_by, dict):
                parent_id = (
                    contained_by.get('ObjectIdentifier')
                    or contained_by.get('objectid')
                    or contained_by.get('ObjectId')
                )
                if parent_id:
                    parent_type = (
                        _normalize_object_type(
                            contained_by.get('ObjectType') or contained_by.get('objectType')
                        )
                        or 'Unknown'
                    )
                    _ensure_graph_node(
                        G, nodes, name_to_oid, parent_id,
                        name=str(parent_id), typ=parent_type,
                    )
                    _add_unique_edge(G, parent_id, oid, 'Contains')
            # Azure relationships (case-insensitive). Skip MemberOf — already handled in ad_rels.
            azure_rels = [
                'HasRole', 'Owns', 'CanRead', 'CanWrite', 'CanDelete', 'Execute',
                'AddMembers', 'ResetPassword', 'AddSecret', 'AddCertificate', 'AddOwner',
                'GetChanges', 'GetChangesAll', 'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner',
            ]
            for key in azure_rels:
                rels = None
                for nk in node.keys():
                    if nk.lower() == key.lower():
                        rels = node[nk]
                        break
                if rels is None:
                    continue
                if not isinstance(rels, list):
                    rels = [rels] if rels else []
                for rel in rels:
                    target = (rel.get('ObjectIdentifier') or rel.get('id')) if isinstance(rel, dict) else rel
                    if not target:
                        continue
                    _ensure_graph_node(
                        G, nodes, name_to_oid, target,
                        name=str(target), typ='Unknown', is_azure=True,
                    )
                    _add_unique_edge(G, oid, target, key)
            # Handle Azure 'Relationships' property if present
            if is_azure:
                rels_prop = None
                for nk in node.keys():
                    if nk.lower() == 'relationships':
                        rels_prop = node[nk]
                        break
                if rels_prop and isinstance(rels_prop, list):
                    for rel in rels_prop:
                        if isinstance(rel, dict):
                            rel_type = rel.get('RelationshipType') or rel.get('relationshipType') or rel.get('type')
                            target = rel.get('TargetObjectId') or rel.get('targetObjectId') or rel.get('target')
                            if rel_type and target:
                                _ensure_graph_node(
                                    G, nodes, name_to_oid, target,
                                    name=str(target), typ='Unknown', is_azure=True,
                                )
                                _add_unique_edge(G, oid, target, rel_type)
            # SharpHound domain Trusts[] → TrustedDomain edges for trust abuse detection
            if str(obj_type).lower() == 'domain' or (isinstance(props, dict) and props.get('domain') and 'Trusts' in node):
                trusts = None
                for nk in node.keys():
                    if nk.lower() == 'trusts':
                        trusts = node[nk]
                        break
                if isinstance(trusts, list):
                    for t in trusts:
                        if not isinstance(t, dict):
                            continue
                        t_sid = t.get('TargetDomainSid') or t.get('targetDomainSid')
                        t_name = (
                            t.get('TargetDomainName')
                            or t.get('targetDomainName')
                            or t.get('TargetName')  # legacy SharpHound
                            or t.get('targetName')
                            or t_sid
                        )
                        direction = t.get('TrustDirection') or t.get('trustDirection') or 'Unknown'
                        ttype = t.get('TrustType') or t.get('trustType') or ''
                        sid_filtering = t.get('SidFilteringEnabled')
                        if sid_filtering is None:
                            sid_filtering = t.get('sidFilteringEnabled')
                        target_oid = None
                        if t_sid and t_sid in G.nodes:
                            target_oid = t_sid
                        elif t_sid and t_sid in nodes:
                            target_oid = t_sid
                            if target_oid not in G.nodes:
                                G.add_node(
                                    target_oid,
                                    name=str(t_name),
                                    type='Domain',
                                    props={'name': t_name, 'domainsid': t_sid},
                                    is_azure=False,
                                )
                        else:
                            # Placeholder domain node by name/sid
                            target_oid = t_sid or f"trust-{t_name}"
                            if target_oid not in G.nodes:
                                G.add_node(
                                    target_oid,
                                    name=str(t_name),
                                    type='Domain',
                                    props={'name': t_name, 'domainsid': t_sid},
                                    is_azure=False,
                                )
                        label = f"TrustedDomain:{direction}"
                        if ttype:
                            label = f"{label}:{ttype}"
                        _add_unique_edge(G, oid, target_oid, label, sid_filtering=sid_filtering)
                        dir_l = str(direction).lower()
                        if dir_l in ('bidirectional', 'both', '2', 'inbound,outbound'):
                            _add_unique_edge(
                                G, target_oid, oid, label, sid_filtering=sid_filtering,
                            )
            # SID History property list → HasSIDHistory edges when not already present
            raw_sidhist = None
            if isinstance(props, dict):
                raw_sidhist = (
                    props.get('sidhistory')
                    or props.get('SidHistory')
                    or props.get('sidHistory')
                )
            if raw_sidhist:
                if not isinstance(raw_sidhist, list):
                    raw_sidhist = [raw_sidhist]
                for sh in raw_sidhist:
                    sid_val = sh.get('ObjectIdentifier') if isinstance(sh, dict) else sh
                    if not sid_val:
                        continue
                    _ensure_graph_node(
                        G, nodes, name_to_oid, sid_val,
                        name=str(sid_val), typ='Unknown',
                    )
                    _add_unique_edge(G, oid, sid_val, 'HasSIDHistory')
            pbar.update(1)
    if debug:
        console.print(f"[blue]DEBUG: Main graph build complete - {G.number_of_nodes()} nodes, {G.number_of_edges()} edges[/blue]")
    # AzureHound relationship-kind edges collected during load
    azure_edges_added = 0
    for src, dst, label in azure_pending:
        if not src or not dst or not label:
            continue
        _ensure_graph_node(G, nodes, name_to_oid, src, name=str(src), typ='Unknown', is_azure=True)
        _ensure_graph_node(G, nodes, name_to_oid, dst, name=str(dst), typ='Unknown', is_azure=True)
        if _add_unique_edge(G, src, dst, label):
            azure_edges_added += 1
    if azure_edges_added:
        console.print(f"[green]Added {azure_edges_added} AzureHound relationship edges[/green]")
    # Legacy sessions.json: Computer -HasSession→ User (by display name)
    sess_added = 0
    for computer_name, user_name in legacy_sessions:
        c_oid = name_to_oid.get(str(computer_name).upper()) or str(computer_name)
        u_oid = name_to_oid.get(str(user_name).upper()) or str(user_name)
        _ensure_graph_node(
            G, nodes, name_to_oid, c_oid, name=str(computer_name), typ="Computer"
        )
        _ensure_graph_node(
            G, nodes, name_to_oid, u_oid, name=str(user_name), typ="User"
        )
        if _add_unique_edge(G, c_oid, u_oid, "HasSession"):
            sess_added += 1
    if sess_added:
        console.print(f"[green]Added {sess_added} legacy session edges[/green]")
    console.print("[cyan]Processing standalone relationships...[/cyan]")
    added = 0
    placeholders_added = 0
    for start, end, label in relationship_edges:
        start = str(start) if start is not None else ""
        end = str(end) if end is not None else ""
        if not start or not end:
            continue
        start_u = start.upper()
        end_u = end.upper()
        start_norm = start_u.split('@')[0].split('\\')[-1]
        end_norm = end_u.split('@')[0].split('\\')[-1]
        start_oid = None
        if start in G.nodes:
            start_oid = start
        elif start_u in name_to_oid:
            start_oid = name_to_oid[start_u]
        elif start_norm in name_to_oid:
            start_oid = name_to_oid[start_norm]
        else:
            start_oid = f"placeholder_{placeholder_counter}"
            placeholder_counter += 1
            G.add_node(start_oid, name=start, type='Unknown', props={}, is_azure=False)
            _register_name_map(name_to_oid, start, start_oid)
            placeholders_added += 1
        end_oid = None
        if end in G.nodes:
            end_oid = end
        elif end_u in name_to_oid:
            end_oid = name_to_oid[end_u]
        elif end_norm in name_to_oid:
            end_oid = name_to_oid[end_norm]
        else:
            end_oid = f"placeholder_{placeholder_counter}"
            placeholder_counter += 1
            G.add_node(end_oid, name=end, type='Unknown', props={}, is_azure=False)
            _register_name_map(name_to_oid, end, end_oid)
            placeholders_added += 1
        if start_oid and end_oid:
            if _add_unique_edge(G, start_oid, end_oid, label):
                added += 1
    console.print(f"[green]Added {added} relationship edges ({placeholders_added} placeholder nodes created)[/green]")
    wk = add_well_known_group_memberships(G)
    if wk:
        console.print(f"[green]Added {wk} well-known group MemberOf edges (Auth Users / Everyone / …)[/green]")
    console.print(f"[green]✓ Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges[/green]")
    if debug:
        console.print(f"[blue]DEBUG: Final graph stats - Nodes: {G.number_of_nodes()} | Edges: {G.number_of_edges()}[/blue]")
    if db_path:
        save_graph_to_db(G, db_path)
    return G, name_to_oid

# Bump when build_graph edge/node semantics change so auto-cache invalidates.
GRAPH_CACHE_SCHEMA_VERSION = 1


def default_graph_cache_dir() -> Path:
    """User cache dir for automatic graph SQLite snapshots."""
    env = os.environ.get("BLOODBASH_CACHE_DIR") or os.environ.get("XDG_CACHE_HOME")
    if env:
        base = Path(env).expanduser()
        # BLOODBASH_CACHE_DIR is the bloodbash root; XDG_CACHE_HOME needs a subdir
        if os.environ.get("BLOODBASH_CACHE_DIR"):
            return base
        return base / "bloodbash"
    return Path.home() / ".cache" / "bloodbash"


def _normalize_source_paths(paths: Sequence[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        if not p:
            continue
        try:
            out.append(str(Path(p).expanduser().resolve()))
        except OSError:
            out.append(str(Path(p).expanduser()))
    return out


def collect_collection_file_records(paths: Sequence[str]) -> List[Tuple[str, int, int]]:
    """
    Stable (path, size, mtime_ns) records for fingerprinting.

    Matches ingest: zip as a whole; directories contribute top-level ``*.json`` only
    (same as load_json_dir). Missing paths are recorded so fingerprint changes.
    """
    records: List[Tuple[str, int, int]] = []
    for raw in _normalize_source_paths(paths):
        p = Path(raw)
        if p.is_file() and p.suffix.lower() == ".zip":
            try:
                st = p.stat()
                records.append((str(p), int(st.st_size), int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))))
            except OSError:
                records.append((str(p), -1, -1))
            continue
        if p.is_dir():
            try:
                names = sorted(
                    f for f in os.listdir(p) if f.lower().endswith(".json")
                )
            except OSError:
                records.append((str(p) + os.sep, -1, -1))
                continue
            if not names:
                records.append((str(p) + os.sep, 0, 0))
            for name in names:
                fp = p / name
                try:
                    st = fp.stat()
                    records.append(
                        (
                            str(fp),
                            int(st.st_size),
                            int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))),
                        )
                    )
                except OSError:
                    records.append((str(fp), -1, -1))
            continue
        records.append((str(p), -1, -1))
    records.sort(key=lambda r: r[0])
    return records


def compute_collection_fingerprint(
    paths: Sequence[str],
    *,
    schema_version: int = GRAPH_CACHE_SCHEMA_VERSION,
    app_version: Optional[str] = None,
) -> str:
    """
    SHA-256 fingerprint of collection inputs + graph schema version.

    Includes app version so releases that change ingest still invalidate caches
    even if schema constant was not bumped.
    """
    app_v = app_version if app_version is not None else __version__
    payload = {
        "schema": int(schema_version),
        "app": str(app_v),
        "files": [
            {"path": path, "size": size, "mtime_ns": mtime}
            for path, size, mtime in collect_collection_file_records(paths)
        ],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def auto_graph_cache_path(
    fingerprint: str,
    cache_dir: Optional[os.PathLike] = None,
) -> Path:
    """Deterministic SQLite path under the cache directory for a fingerprint."""
    base = Path(cache_dir) if cache_dir is not None else default_graph_cache_dir()
    short = (fingerprint or "unknown")[:16]
    return base / f"graph-{short}.db"


def _ensure_graph_cache_meta_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )


def write_graph_cache_meta(db_path: str, meta: Dict[str, Any]) -> None:
    """Upsert key/value metadata into a graph SQLite DB."""
    conn = sqlite3.connect(db_path)
    try:
        _ensure_graph_cache_meta_table(conn)
        for key, value in meta.items():
            if value is None:
                continue
            if isinstance(value, (dict, list)):
                stored = json.dumps(value, sort_keys=True, separators=(",", ":"))
            else:
                stored = str(value)
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                (str(key), stored),
            )
        conn.commit()
    finally:
        conn.close()


def read_graph_cache_meta(db_path: str) -> Dict[str, str]:
    """Return meta key→value strings; empty if table missing or unreadable."""
    if not db_path or not os.path.isfile(db_path):
        return {}
    try:
        conn = sqlite3.connect(db_path)
        try:
            _ensure_graph_cache_meta_table(conn)
            rows = conn.execute("SELECT key, value FROM meta").fetchall()
            return {str(k): ("" if v is None else str(v)) for k, v in rows}
        finally:
            conn.close()
    except sqlite3.Error:
        return {}


def graph_cache_is_valid(
    db_path: str,
    expected_fingerprint: Optional[str],
    *,
    require_fingerprint: bool = True,
) -> bool:
    """
    True when DB exists and matches expected fingerprint / schema.

    Legacy DBs (no meta table / no fingerprint) are invalid when
    require_fingerprint is True so stale explicit --db files are rebuilt
    against current inputs. When require_fingerprint is False (db-only reopen
    with no usable sources), any readable graph DB is accepted.
    """
    if not db_path or not os.path.isfile(db_path):
        return False
    try:
        conn = sqlite3.connect(db_path)
        try:
            n = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='nodes'"
            ).fetchone()
            if not n:
                return False
        finally:
            conn.close()
    except sqlite3.Error:
        return False
    meta = read_graph_cache_meta(db_path)
    if not require_fingerprint:
        return True
    if not expected_fingerprint:
        return False
    if meta.get("fingerprint") != expected_fingerprint:
        return False
    try:
        schema = int(meta.get("schema_version") or -1)
    except (TypeError, ValueError):
        schema = -1
    if schema != GRAPH_CACHE_SCHEMA_VERSION:
        return False
    return True


def save_graph_to_db(G, db_path, meta: Optional[Dict[str, Any]] = None):
    """
    Persist graph snapshot to SQLite.

    Optional ``meta`` is stored in a ``meta`` table (fingerprint, sources, …)
    so automatic caches can validate reuse.
    """
    parent = os.path.dirname(os.path.abspath(db_path)) or "."
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS nodes (oid TEXT PRIMARY KEY, name TEXT, type TEXT, props TEXT, is_azure INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS edges (start_oid TEXT, end_oid TEXT, label TEXT, attrs TEXT)''')
    _ensure_graph_cache_meta_table(conn)
    # Replace full snapshot: nodes upsert, edges must be cleared or they accumulate
    # on every re-save (no unique constraint on edges).
    # Migrate older DBs that only had (start, end, label)
    c.execute("PRAGMA table_info(edges)")
    edge_cols = {row[1] for row in c.fetchall()}
    if "attrs" not in edge_cols:
        c.execute("ALTER TABLE edges ADD COLUMN attrs TEXT")
    c.execute('DELETE FROM edges')
    c.execute('DELETE FROM nodes')
    for n, d in G.nodes(data=True):
        c.execute(
            "INSERT INTO nodes VALUES (?, ?, ?, ?, ?)",
            (
                n,
                d.get('name', n),
                d.get('type', 'Unknown'),
                json.dumps(d.get('props') if d.get('props') is not None else {}),
                int(d.get('is_azure', False)),
            ),
        )
    for u, v, d in G.edges(data=True):
        label = d.get('label', '')
        extra = {k: val for k, val in d.items() if k != 'label'}
        c.execute(
            "INSERT INTO edges VALUES (?, ?, ?, ?)",
            (u, v, label, json.dumps(extra) if extra else None),
        )
    conn.commit()
    conn.close()
    if meta:
        write_graph_cache_meta(db_path, meta)
    console.print(f"[green]Graph saved to DB: {db_path}[/green]")


def load_graph_from_db(db_path):
    G = nx.MultiDiGraph()
    name_to_oid = {}
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT oid, name, type, props, is_azure FROM nodes")
    for oid, name, typ, props, is_azure in c.fetchall():
        G.add_node(oid, name=name, type=typ, props=json.loads(props), is_azure=bool(is_azure))
        _register_name_map(name_to_oid, name, oid)
    c.execute("PRAGMA table_info(edges)")
    edge_cols = {row[1] for row in c.fetchall()}
    if "attrs" in edge_cols:
        c.execute("SELECT start_oid, end_oid, label, attrs FROM edges")
        rows = c.fetchall()
    else:
        c.execute("SELECT start_oid, end_oid, label FROM edges")
        rows = [(u, v, lab, None) for u, v, lab in c.fetchall()]
    for u, v, label, attrs_json in rows:
        attrs = {}
        if attrs_json:
            try:
                attrs = json.loads(attrs_json) or {}
            except (TypeError, ValueError, json.JSONDecodeError):
                attrs = {}
        if not isinstance(attrs, dict):
            attrs = {}
        G.add_edge(u, v, label=label, **{k: val for k, val in attrs.items() if k != "label"})
    conn.close()
    console.print(f"[green]Graph loaded from DB: {db_path}[/green]")
    return G, name_to_oid


def sources_have_collection_data(paths: Sequence[str]) -> bool:
    """True if any path is a zip or a directory with at least one top-level JSON."""
    for raw in paths:
        if not raw:
            continue
        p = Path(raw).expanduser()
        try:
            if p.is_file() and p.suffix.lower() == ".zip":
                return True
            if p.is_dir():
                for name in os.listdir(p):
                    if name.lower().endswith(".json"):
                        return True
        except OSError:
            continue
    return False


def load_or_build_graph(
    paths: Sequence[str],
    *,
    db_path: Optional[str] = None,
    cache_dir: Optional[str] = None,
    no_cache: bool = False,
    rebuild_cache: bool = False,
    debug: bool = False,
) -> Tuple[Any, Any, Dict[str, Any]]:
    """
    Load graph from SQLite cache when fingerprint matches, otherwise ingest + build.

    Returns ``(G, name_to_oid, info)`` where info includes cache_hit, cache_path,
    fingerprint, and source_paths.
    """
    path_list = [p for p in paths if p]
    if not path_list:
        path_list = ["."]
    has_data = sources_have_collection_data(path_list)
    fingerprint = compute_collection_fingerprint(path_list) if has_data else None

    # Explicit --db path, else auto path under cache dir (when caching enabled)
    if db_path:
        cache_path = str(Path(db_path).expanduser())
    elif no_cache:
        cache_path = None
    else:
        if fingerprint:
            cdir = Path(cache_dir).expanduser() if cache_dir else default_graph_cache_dir()
            cache_path = str(auto_graph_cache_path(fingerprint, cdir))
        else:
            cache_path = None

    info: Dict[str, Any] = {
        "cache_hit": False,
        "cache_path": cache_path,
        "fingerprint": fingerprint,
        "source_paths": list(path_list),
        "rebuilt": False,
    }

    env_no_cache = os.environ.get("BLOODBASH_NO_CACHE", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    use_cache = not no_cache and not env_no_cache

    # Attempt cache load
    if use_cache and cache_path and os.path.isfile(cache_path) and not rebuild_cache:
        require_fp = bool(fingerprint)
        if graph_cache_is_valid(cache_path, fingerprint, require_fingerprint=require_fp):
            G, name_to_oid = load_graph_from_db(cache_path)
            info["cache_hit"] = True
            if fingerprint:
                console.print(
                    f"[dim]Graph cache hit[/dim] (fingerprint {fingerprint[:12]}…) "
                    f"— skip re-ingest. [dim]--rebuild-cache[/dim] to force rebuild."
                )
            else:
                console.print(
                    "[dim]Graph cache hit[/dim] (db-only reopen; no collection JSON found). "
                    "Point at a SharpHound dir/zip to refresh."
                )
            return G, name_to_oid, info
        if os.path.isfile(cache_path) and fingerprint:
            meta = read_graph_cache_meta(cache_path)
            reason = "fingerprint mismatch or missing meta"
            if meta.get("fingerprint") and meta.get("fingerprint") != fingerprint:
                reason = "collection changed"
            elif meta.get("schema_version") and str(meta.get("schema_version")) != str(
                GRAPH_CACHE_SCHEMA_VERSION
            ):
                reason = "cache schema version mismatch"
            console.print(
                f"[yellow]Graph cache stale ({reason}); rebuilding from sources…[/yellow]"
            )

    if not has_data:
        # No JSON/zip to ingest
        if cache_path and os.path.isfile(cache_path) and use_cache and not rebuild_cache:
            # Last-resort: load explicit/auto db without fingerprint (legacy)
            if graph_cache_is_valid(cache_path, None, require_fingerprint=False):
                G, name_to_oid = load_graph_from_db(cache_path)
                info["cache_hit"] = True
                console.print(
                    "[yellow]Loaded graph from DB without validating collection "
                    "(no JSON/zip sources found).[/yellow]"
                )
                return G, name_to_oid, info
        console.print("[red]No objects loaded. Exiting.[/red]")
        sys.exit(1)

    if len(path_list) > 1:
        console.print(f"[dim]Merging {len(path_list)} collection path(s)…[/dim]")
        nodes = load_json_dirs(path_list, debug=debug)
    else:
        nodes = load_json_dir(path_list[0], debug=debug)
    if not nodes:
        console.print("[red]No objects loaded. Exiting.[/red]")
        sys.exit(1)

    # build_graph saves when db_path passed; we control meta write ourselves
    G, name_to_oid = build_graph(nodes, db_path=None, debug=debug)
    info["rebuilt"] = True

    if use_cache and cache_path and fingerprint:
        meta = {
            "fingerprint": fingerprint,
            "schema_version": str(GRAPH_CACHE_SCHEMA_VERSION),
            "app_version": __version__,
            "sources": path_list,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "nodes": str(G.number_of_nodes()),
            "edges": str(G.number_of_edges()),
        }
        try:
            save_graph_to_db(G, cache_path, meta=meta)
            console.print(
                f"[dim]Graph cached for reuse[/dim] → {cache_path} "
                f"(fingerprint {fingerprint[:12]}…)"
            )
        except OSError as e:
            console.print(f"[yellow]Could not write graph cache ({e}); continuing.[/yellow]")
    elif db_path and not use_cache:
        # Explicit --db with --no-cache still persists when user asked for a file
        try:
            meta = {
                "fingerprint": fingerprint or "",
                "schema_version": str(GRAPH_CACHE_SCHEMA_VERSION),
                "app_version": __version__,
                "sources": path_list,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            save_graph_to_db(G, db_path, meta=meta if fingerprint else None)
        except OSError as e:
            console.print(f"[yellow]Could not write --db ({e}); continuing.[/yellow]")

    return G, name_to_oid, info


# ────────────────────────────────────────────────
# VERBOSE SUMMARY (Extended for Azure)
# ────────────────────────────────────────────────
def list_domains(G) -> List[dict]:
    """List AD domains and Azure tenants present in the graph."""
    found: Dict[str, dict] = {}
    for n, d in G.nodes(data=True):
        props = d.get("props") or {}
        name = d.get("name") or ""
        typ = str(d.get("type") or "").lower()
        is_azure = bool(d.get("is_azure", False))
        if typ == "domain" or (not is_azure and typ == "domain"):
            key = name.upper() if name else str(n).upper()
            found[key] = {
                "name": name or str(n),
                "kind": "AD Domain",
                "id": props.get("domain") or props.get("objectid") or n,
            }
            continue
        if is_azure and ("tenant" in typ or props.get("tenantId") or props.get("tenantid")):
            tid = props.get("tenantId") or props.get("tenantid") or name or str(n)
            key = f"AZ:{tid}".upper()
            found[key] = {
                "name": str(tid),
                "kind": "Azure Tenant",
                "id": tid,
            }
            continue
        # Fallback: domain property on objects
        dom = props.get("domain") or props.get("Domain")
        if dom and not is_azure:
            key = str(dom).upper()
            if key not in found:
                found[key] = {
                    "name": str(dom),
                    "kind": "AD Domain",
                    "id": str(dom),
                }
        tid = props.get("tenantId") or props.get("tenantid")
        if tid and is_azure:
            key = f"AZ:{tid}".upper()
            if key not in found:
                found[key] = {
                    "name": str(tid),
                    "kind": "Azure Tenant",
                    "id": str(tid),
                }
    return sorted(found.values(), key=lambda x: (x["kind"], x["name"].upper()))


def print_list_domains(G):
    console.rule("[bold magenta]Domains / Tenants in collection[/bold magenta]")
    rows = list_domains(G)
    if not rows:
        console.print("[yellow]No domains or tenants found[/yellow]")
        return
    table = Table(title="Available domains")
    table.add_column("Kind", style="dim")
    table.add_column("Name", style="cyan")
    table.add_column("Id / filter value", style="green")
    for r in rows:
        table.add_row(r["kind"], r["name"], str(r["id"]))
    console.print(table)
    console.print(
        "[dim]Use --domain NAME to filter analysis (case-insensitive).[/dim]"
    )


def print_verbose_summary(G, domain_filter=None):
    console.rule("[bold magenta]VERBOSE SUMMARY[/bold magenta]")
    types_count = defaultdict(int)
    azure_count = 0
    ad_count = 0
    for _, d in G.nodes(data=True):
        if not _domain_matches(d, domain_filter):
            continue
        types_count[d['type']] += 1
        if d.get('is_azure', False):
            azure_count += 1
        else:
            ad_count += 1
    table = Table(title="Object Types", show_header=True, header_style="bold cyan")
    table.add_column("Type", style="green")
    table.add_column("Count", justify="right")
    for t, cnt in sorted(types_count.items(), key=lambda x: x[1], reverse=True):
        table.add_row(t, str(cnt))
    console.print(table)
    console.print(f"[cyan]AD Objects: {ad_count} | Azure Objects: {azure_count}[/cyan]")
    users = [d['name'] for _, d in G.nodes(data=True) if d['type'].lower() in ['user', 'azure user'] and _domain_matches(d, domain_filter)]
    if users:
        console.print(f"\n[bold cyan]Users (AD + Azure) ({len(users)}):[/bold cyan]")
        for name in sorted(users)[:30]:
            console.print(f"  • {name}")
    else:
        console.print("\n[yellow]No User objects found[/yellow]")
# ────────────────────────────────────────────────
# Helpers (Extended for Azure)
# ────────────────────────────────────────────────
UAC_FLAGS = {
    0x00000001: "SCRIPT",
    0x00000002: "ACCOUNTDISABLE",
    0x00000008: "HOMEDIR_REQUIRED",
    0x00000010: "LOCKOUT",
    0x00000020: "PASSWD_NOTREQD",
    0x00000040: "PASSWD_CANT_CHANGE",
    0x00000080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x00000100: "TEMP_DUPLICATE_ACCOUNT",
    0x00000200: "NORMAL_ACCOUNT",
    0x00000800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x00001000: "WORKSTATION_TRUST_ACCOUNT",
    0x00002000: "SERVER_TRUST_ACCOUNT",
    0x00010000: "DONT_EXPIRE_PASSWORD",
    0x00020000: "MNS_LOGON_ACCOUNT",
    0x00040000: "SMARTCARD_REQUIRED",
    0x00080000: "TRUSTED_FOR_DELEGATION",
    0x00100000: "NOT_DELEGATED",
    0x00200000: "USE_DES_KEY_ONLY",
    0x00400000: "DONT_REQ_PREAUTH",
    0x00800000: "PASSWORD_EXPIRED",
    0x01000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x04000000: "PARTIAL_SECRETS_ACCOUNT",
}

def decode_uac(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return str(value)
    flags = [name for bit, name in UAC_FLAGS.items() if value & bit]
    if flags:
        return f"{value} ({', '.join(flags)})"
    return str(value)


def format_lastlog_bucket(props, now: Optional[float] = None) -> Optional[str]:
    """Human last-logon age band for privilege-context tags (quickwin-style).

    Returns NEVER / < 1 year / > 1 year / > 2 years / > 3 years / > 5 years /
    > 10 years, or None when no timestamp property is present.
    """
    if not isinstance(props, dict):
        return None
    raw = _prop_raw_ci(
        props,
        [
            "lastlogontimestamp",
            "lastLogonTimestamp",
            "lastlogon",
            "lastLogon",
            "LastLogonTimestamp",
            "LastLogon",
        ],
    )
    if raw is None:
        return None
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return None
    if v in (0, -1):
        return "NEVER"
    ts = parse_ad_timestamp(v)
    if ts is None:
        return "NEVER"
    days = _days_since(ts, now=now)
    if days is None:
        return None
    years = days / 365.0
    if years > 10:
        return "> 10 years"
    if years > 5:
        return "> 5 years"
    if years > 3:
        return "> 3 years"
    if years > 2:
        return "> 2 years"
    if years > 1:
        return "> 1 year"
    return "< 1 year"


def format_privilege_context_tags(d: dict, now: Optional[float] = None) -> str:
    """Compact tags: [AdminCount] [OWNED] [LASTLOG: …] for credential findings."""
    props = (d or {}).get("props") or {}
    parts: List[str] = []
    if get_bool_prop_ci(props, ["admincount", "adminCount", "AdminCount"]):
        parts.append("[AdminCount]")
    if get_bool_prop_ci(props, ["owned", "Owned"]):
        parts.append("[OWNED]")
    bucket = format_lastlog_bucket(props, now=now)
    if bucket is not None:
        parts.append(f"[LASTLOG: {bucket}]")
    return (" " + " ".join(parts)) if parts else ""

def get_bool_prop_ci(props, keys, default=False):
    if not isinstance(props, dict):
        return default
    for key in keys:
        for p_key in props:
            if p_key.lower() == key.lower():
                val = props[p_key]
                if isinstance(val, str):
                    low = val.strip().lower()
                    if low in ('false', '0', 'no', 'off', 'disabled', ''):
                        return False
                    if low in ('true', '1', 'yes', 'on', 'enabled'):
                        return True
                return bool(val)
    return default


def _account_is_enabled(props, default=True) -> bool:
    """Resolve enabled state from explicit bool and/or UAC ACCOUNTDISABLE (0x2)."""
    if not isinstance(props, dict):
        return default
    raw_enabled = _prop_raw_ci(props, ['enabled', 'Enabled'])
    if raw_enabled is not None:
        return get_bool_prop_ci(props, ['enabled', 'Enabled'], default=default)
    uac_raw = _prop_raw_ci(props, ['useraccountcontrol', 'UserAccountControl'])
    try:
        if uac_raw is not None and int(uac_raw) & 0x2:
            return False
    except (TypeError, ValueError):
        pass
    return default


def _prop_raw_ci(props, keys, default=None):
    """Case-insensitive property lookup returning the raw value."""
    if not isinstance(props, dict):
        return default
    for key in keys:
        for p_key in props:
            if p_key.lower() == key.lower():
                return props[p_key]
    return default

def _principal_sam(name: str) -> str:
    """SAM / short account name from UPN, DOMAIN\\user, or plain name."""
    if not name:
        return ""
    nl = str(name).lower().strip()
    return nl.split("@")[0].split("\\")[-1].strip()


def _is_builtin_administrators_name(name: str) -> bool:
    """True only for Builtin Administrators — not 'System Administrators' etc."""
    if not name:
        return False
    nl = str(name).lower().strip()
    sam = _principal_sam(name)
    if sam == "administrators":
        return True
    if nl.startswith("administrators@"):
        return True
    if "builtin\\administrators" in nl or nl.endswith("\\administrators"):
        return True
    return False


def _is_default_high_priv_name(name):
    """Built-in / expected high-privilege principals (noise filters)."""
    if not name:
        return False
    nl = str(name).lower()
    sam = _principal_sam(name)
    if _is_builtin_administrators_name(name):
        return True
    # Phrase matches (safe as multi-word / anchored SAM)
    phrase_needles = (
        "domain admins",
        "enterprise admins",
        "schema admins",
        "nt authority",
        "enterprise domain controllers",
        "enterprise key admins",
        "account operators",
        "backup operators",
        "print operators",
        "server operators",
    )
    if any(n in nl for n in phrase_needles):
        return True
    # SAM / UPN-prefix matches (avoid 'administrators@' substring trap)
    if sam in (
        "domain admins",
        "enterprise admins",
        "schema admins",
        "domain controllers",
        "enterprise domain controllers",
        "enterprise key admins",
        "key admins",
        "krbtgt",
        "account operators",
        "backup operators",
        "print operators",
        "server operators",
    ):
        return True
    if nl.startswith("domain controllers@") or nl.startswith("key admins@"):
        return True
    if nl.startswith("krbtgt@"):
        return True
    return False

def _is_classic_high_value_name(name: str) -> bool:
    """True for DA/EA/Admins/krbtgt/DC-style names — not every *ADMIN* group."""
    if not name:
        return False
    if _is_builtin_administrators_name(name):
        return True
    nl = str(name).lower()
    needles = (
        "domain admins",
        "enterprise admins",
        "schema admins",
        "enterprise domain controllers",
        "domain controllers",
        "enterprise key admins",
        "key admins@",
        "dnsadmins",
        "account operators",
        "backup operators",
        "server operators",
        "print operators",
        "group policy creator owners",
        "krbtgt",
        "global admin",
        "privileged role admin",
        "enterprise ca",
        "root ca",
        "ntauth",
    )
    return any(n in nl for n in needles)


def get_high_value_targets(G, domain_filter=None, include_all_highvalue=False):
    """
    Collect high-value attack targets.

    Default: classic names (DA/EA/Admins/krbtgt/DCs/CA) + Azure privileged roles.
    SharpHound ``highvalue`` alone is **not** enough for arbitrary groups (enterprise
    floods of workstation *_ADMINISTRATORS-GG). Use include_all_highvalue=True or
    CLI ``--all-highvalue`` to honor every collector highvalue flag.
    """
    # Prefer full group/role phrases; avoid bare "dc" which matches CDC-FILESERVER etc.
    # Do not treat every Certificate Template as HV (was: 'ca' in typ).
    # Builtin Administrators only via _is_builtin_administrators_name — bare
    # "administrators" matches workstation *_ADMINISTRATORS-GG groups (enterprise flood).
    ad_keywords = [
        'domain admins', 'enterprise admins', 'schema admins',
        'krbtgt', 'domain controllers', 'dnsadmins', 'enterprise key admins',
        'enterprise ca', 'root ca', 'ntauth store', 'ntauth',
        'builtin\\administrators',
    ]
    azure_keywords = [
        'global admin', 'user admin', 'application admin', 'exchange admin', 'sharepoint admin',
        'azure ad join', 'intune admin', 'security admin', 'conditional access admin', 'privileged role admin'
    ]
    ca_types = {
        'enterprise ca', 'root ca', 'aia ca', 'ntauth store', 'nt auth store',
    }
    targets = []
    for n, d in G.nodes(data=True):
        if not _domain_matches(d, domain_filter):
            continue
        disp = d.get('name') or ''
        name = disp.lower()
        typ = str(d.get('type') or '').lower()
        is_azure = d.get('is_azure', False)
        props = d.get('props') or {}
        marked_hv = get_bool_prop_ci(props, ['highvalue', 'HighValue'])
        # Domain Controllers are always HV (dangerous ACL / RBCD targets). Name is
        # often DC01.domain — not "domain controllers" — and highvalue-flood filter
        # must not drop them when collector marks highvalue.
        if (
            not is_azure
            and typ == 'computer'
            and get_bool_prop_ci(
                props, ['isdc', 'IsDC', 'IsDomainController', 'isDomainController']
            )
        ):
            targets.append((n, d['name'], d['type']))
            continue
        # Explicit SharpHound highvalue: only classic names / domains / adminCount users
        # unless include_all_highvalue (enterprise: highvalue floods workstation admin groups)
        if marked_hv:
            if include_all_highvalue:
                targets.append((n, d['name'], d['type']))
                continue
            if typ == 'domain' or (is_azure and 'tenant' in typ):
                targets.append((n, d['name'], d['type']))
                continue
            if _is_classic_high_value_name(disp):
                targets.append((n, d['name'], d['type']))
                continue
            if typ == 'user' and get_bool_prop_ci(props, ['admincount', 'adminCount']):
                targets.append((n, d['name'], d['type']))
                continue
            # else: ignore non-classic highvalue marks (e.g. HOST_ADMINISTRATORS-GG)
        if not is_azure and _is_builtin_administrators_name(disp):
            targets.append((n, d['name'], d['type']))
            continue
        keywords = azure_keywords if is_azure else ad_keywords
        is_ca_type = (not is_azure) and (typ in ca_types or typ.endswith(' ca'))
        is_azure_role = is_azure and 'role' in typ
        if any(k in name for k in keywords) or is_ca_type or is_azure_role:
            targets.append((n, d['name'], d['type']))
    return sorted(targets, key=lambda x: x[1])
def format_path(G, path):
    if not path or len(path) < 1:
        return "[dim]Invalid path[/dim]"
    if len(path) == 1:
        return f"[bold cyan]{G.nodes[path[0]].get('name', path[0])}[/bold cyan] (self)"
    parts = []
    for i in range(len(path)-1):
        u, v = path[i], path[i+1]
        edges = G.get_edge_data(u, v)
        label = next(iter(edges.values()))['label'] if edges else '???'
        uname = G.nodes[u].get('name', u) if u in G.nodes else u
        parts.append(f"[bold cyan]{uname}[/bold cyan] --[[yellow]{label}[/yellow]]-->")
    last = path[-1]
    lname = G.nodes[last].get('name', last) if last in G.nodes else last
    parts.append(f"[bold red]{lname}[/bold red]")
    return " ".join(parts)
def get_indirect_paths(G, source, target, max_depth=5):
    paths = []
    if source not in G or target not in G:
        return []
    try:
        for path in nx.all_simple_paths(G, source, target, cutoff=max_depth):
            if len(path) > 2:
                paths.append(path)
        return paths[:5]
    except (nx.NetworkXNoPath, nx.NodeNotFound, nx.NetworkXError):
        return []
# ────────────────────────────────────────────────
# All analysis functions (unchanged except where noted)
# ────────────────────────────────────────────────
# Patterns that look like secrets in AD description (avoid ticket text FPs like "account: 138894")
PASSWORD_IN_DESC_PATTERNS = (
    r"\bpassword\s*[:=]\s*\S+",
    r"\bpwd\s*[:=]\s*\S+",
    r"\bpass(?:word)?\s*[:=]\s*\S+",
    r"\bcredentials?\s*[:=]\s*\S+",
    r"\bsecret\s*[:=]\s*\S+",
    r"\bpasswd\s*[:=]\s*\S+",
)


def print_password_in_descriptions(G, domain_filter=None):
    sec = DeferredSection("Passwords in User Descriptions (AD)")
    found = False
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):  # Skip Azure for AD-specific checks
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if str(d.get('type', '')).lower() == 'user':
            props = d.get('props') or {}
            description = props.get('description') or ''
            if description:
                for pattern in PASSWORD_IN_DESC_PATTERNS:
                    if re.search(pattern, description, re.IGNORECASE):
                        found = True
                        sec.mark()
                        console.print(
                            f"[yellow]Potential password in description[/yellow]: "
                            f"[green]{d['name']}[/green] - '{props.get('description')}'"
                        )
                        add_finding(
                            "Password in Description",
                            f"User {d['name']} has potential password in description",
                            score=6,
                        )
                        break
    if found:
        print_abuse_panel("Password in Description")
    else:
        sec.empty("No passwords detected in user descriptions")

def print_password_never_expires(G, domain_filter=None):
    sec = DeferredSection("Users with 'Password Never Expires' Set (AD)")
    found = False
    hits = 0
    max_display = 50
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if str(d.get('type', '')).lower() != 'user':
            continue
        props = d.get('props') or {}
        # SharpHound CE uses pwdneverexpires; also accept UAC DONT_EXPIRE_PASSWORD
        password_never_expires = get_bool_prop_ci(
            props, ['passwordneverexpires', 'PasswordNeverExpires', 'pwdneverexpires']
        )
        if not password_never_expires:
            uac_raw = _prop_raw_ci(props, ['useraccountcontrol', 'UserAccountControl'])
            try:
                password_never_expires = bool(int(uac_raw) & 0x10000)
            except (TypeError, ValueError):
                pass
        if password_never_expires and _account_is_enabled(props):
            name = d.get('name') or ''
            # krbtgt / well-known system accounts are expected noise
            sam = _principal_sam(name)
            if sam in ('krbtgt',) or name.upper().startswith('KRBTGT@'):
                continue
            if _is_default_high_priv_name(name) and 'admin' in sam:
                # keep DA users if flagged PNE — still report
                pass
            found = True
            hits += 1
            sec.mark()
            uac_raw = _prop_raw_ci(props, ['useraccountcontrol', 'UserAccountControl'])
            uac_str = f" | UAC: {decode_uac(uac_raw)}" if uac_raw is not None else ""
            if hits <= max_display:
                console.print(f"[yellow]Password Never Expires enabled[/yellow]: [green]{d['name']}[/green]{uac_str}")
            # Cap individual findings; summarize large domains
            if hits <= 15:
                add_finding("Password Never Expires", f"User {d['name']} has 'Password Never Expires' set")
    if hits > max_display:
        console.print(f"  [dim]... and {hits - max_display} more[/dim]")
    if hits > 15:
        add_finding(
            "Password Never Expires",
            f"{hits} enabled users have Password Never Expires (list truncated in findings)",
            score=4,
        )
    if found:
        console.print(Panel("[bold yellow]Impact:[/bold yellow] Passwords may never expire, leading to old/weak passwords persisting indefinitely.\n[bold]Mitigation:[/bold] Review and enforce password policies; consider resetting passwords for affected accounts.\n[bold]Tools:[/bold] Use PowerShell (Get-ADUser) or AD tools to audit.", title="Abuse Suggestions: Password Never Expires", border_style="yellow"))
    else:
        sec.empty("No users with 'Password Never Expires' found")

def print_password_not_required(G, domain_filter=None):
    sec = DeferredSection("Users with 'Password Not Required' Set (AD)")
    found = False
    hits = 0
    max_display = 50
    # Hygiene: few detail findings + one summary (collapse_findings also caps)
    max_detail_findings = 15
    samples = []
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if str(d.get('type', '')).lower() != 'user':
            continue
        props = d.get('props') or {}
        # SharpHound CE uses passwordnotreqd; also accept UAC PASSWD_NOTREQD
        password_not_required = get_bool_prop_ci(
            props, ['passwordnotrequired', 'PasswordNotRequired', 'passwordnotreqd']
        )
        if not password_not_required:
            uac_raw = _prop_raw_ci(props, ['useraccountcontrol', 'UserAccountControl'])
            try:
                password_not_required = bool(int(uac_raw) & 0x20)
            except (TypeError, ValueError):
                pass
        if password_not_required and _account_is_enabled(props):
            found = True
            hits += 1
            sec.mark()
            uac_raw = _prop_raw_ci(props, ['useraccountcontrol', 'UserAccountControl'])
            uac_str = f" | UAC: {decode_uac(uac_raw)}" if uac_raw is not None else ""
            if hits <= max_display:
                console.print(
                    f"[red]Password Not Required enabled[/red]: "
                    f"[green]{d['name']}[/green]{uac_str}"
                )
            if hits <= max_detail_findings:
                samples.append(d['name'])
                add_finding(
                    "Password Not Required",
                    f"User {d['name']} has 'Password Not Required' set",
                )
    if hits > max_display:
        console.print(f"  [dim]... and {hits - max_display} more[/dim]")
    if hits > max_detail_findings:
        add_finding(
            "Password Not Required",
            f"{hits} enabled users have Password Not Required "
            f"(showing {max_detail_findings} samples; use --export json for more)",
            score=8,
        )
    elif hits:
        console.print(f"[dim]Found {hits} enabled user(s) with Password Not Required[/dim]")
    if found:
        console.print(Panel("[bold red]Impact:[/bold red] No password required for login, enabling easy account takeover or unauthorized access.\n[bold]Abuse:[/bold] Log in without a password; escalate privileges if account has rights.\n[bold]Mitigation:[/bold] Enforce passwords; disable or monitor such accounts.\n[bold]Tools:[/bold] ADUC, PowerShell, or BloodHound for auditing.", title="Abuse Suggestions: Password Not Required", border_style="red"))
    else:
        sec.empty("No users with 'Password Not Required' found")

def _is_expected_key_credential_holder(name: str) -> bool:
    """
    Principals that legitimately hold AddKeyCredentialLink / key-admin rights
    in most domains (Windows Hello / Key Admins). Not interesting as shadow-cred
    attack paths by themselves.
    """
    if not name:
        return False
    if _is_default_high_priv_name(name):
        return True
    nl = str(name).lower()
    expected = (
        "key admins@",
        "enterprise key admins",
        "key admins ",
        "msol_",  # Azure AD Connect sync accounts often have broad rights
    )
    return any(x in nl for x in expected)


def print_shadow_credentials(G, domain_filter=None):
    sec = DeferredSection("Shadow Credentials Detection (AD)")
    # Primary: AddKeyCredentialLink (direct msDS-KeyCredentialLink write) — high signal.
    # Secondary: strong ACL control (GenericAll / WriteDacl / WriteOwner) on *users*
    # from non-default principals. GenericWrite on computers is common connector noise
    # and is not reported as a shadow-cred path (use can-configure RBCD / other modules).
    found_abuse = False
    found_existing = False
    primary_labels = {'addkeycredentiallink'}
    # Strong secondary on users only. GenericWrite on computers is connector noise.
    secondary_user_labels = {
        'genericall',
        'genericwrite',
        'writeowner',
        'writedacl',
    }
    # Collect (principal, label, is_primary) -> list of target display names
    primary_hits = []  # list of (uname, label, tname, ttype)
    secondary_agg = defaultdict(list)  # (uname, label) -> [tname, ...]

    targets = []
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if d.get('type', '').lower() not in ('user', 'computer'):
            continue
        targets.append(n)

    for tid in targets:
        tname = G.nodes[tid]['name']
        ttype = G.nodes[tid]['type']
        ttype_l = str(ttype).lower()
        for u, _, edata in G.in_edges(tid, data=True):
            label = edata.get('label') or ''
            ll = label.lower()
            uname = G.nodes[u]['name']
            # Skip built-in / key-admin / broad principals
            if _is_expected_key_credential_holder(uname):
                continue
            if _is_broad_principal_name(uname):
                continue
            if ll in primary_labels:
                primary_hits.append((uname, label, tname, ttype))
            elif ll in secondary_user_labels and ttype_l == 'user':
                secondary_agg[(uname, label)].append(tname)

    # Primary: aggregate by principal+right (enterprise: one SID may hit thousands)
    primary_agg: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for uname, label, tname, ttype in primary_hits:
        primary_agg[(uname, label)].append(tname)
    max_primary_detail = 40
    max_primary_findings = 50
    primary_items = sorted(primary_agg.items(), key=lambda kv: len(kv[1]), reverse=True)
    for i, ((uname, label), tnames) in enumerate(primary_items):
        found_abuse = True
        sec.mark()
        n_targets = len(tnames)
        examples = ", ".join(tnames[:3])
        extra = f" … +{n_targets - 3} more" if n_targets > 3 else ""
        if i < max_primary_detail:
            if n_targets == 1:
                console.print(
                    f"[red]Shadow Credentials abuse right[/red]: "
                    f"[green]{uname}[/green] --[{label}]--> "
                    f"[cyan]{tnames[0]}[/cyan]"
                )
            else:
                console.print(
                    f"[red]Shadow Credentials abuse right[/red]: "
                    f"[green]{uname}[/green] --[{label}]--> "
                    f"[cyan]{n_targets}[/cyan] principal(s) "
                    f"[dim]({examples}{extra})[/dim]"
                )
        if i < max_primary_findings:
            if n_targets == 1:
                add_finding(
                    "Shadow Credentials",
                    f"{uname} has {label} on {tnames[0]} (shadow credential path)",
                    score=8,
                )
            else:
                add_finding(
                    "Shadow Credentials",
                    f"{uname} has {label} on {n_targets} principal(s) "
                    f"(e.g. {examples}{extra}) — shadow credential path",
                    score=8,
                )
    if len(primary_items) > max_primary_findings:
        add_finding(
            "Shadow Credentials",
            f"{len(primary_items) - max_primary_findings} additional principals with "
            f"AddKeyCredentialLink-style rights (truncated)",
            score=8,
        )

    # Secondary: aggregate per principal+right; skip bulk noise
    max_secondary_detail = 30
    max_targets_for_finding = 25  # more than this is usually over-delegation inventory noise
    secondary_items = sorted(
        secondary_agg.items(),
        key=lambda kv: len(kv[1]),
        reverse=True,
    )
    for i, ((uname, label), tnames) in enumerate(secondary_items):
        n_targets = len(tnames)
        if n_targets > max_targets_for_finding:
            continue
        found_abuse = True
        sec.mark()
        examples = ", ".join(tnames[:3])
        extra = f" … +{n_targets - 3} more" if n_targets > 3 else ""
        if i < max_secondary_detail:
            console.print(
                f"[yellow]Shadow Credentials ACL path[/yellow]: "
                f"[green]{uname}[/green] --[{label}]--> "
                f"[cyan]{n_targets}[/cyan] user principal(s) "
                f"[dim]({examples}{extra})[/dim]"
            )
        add_finding(
            "Shadow Credentials",
            f"{uname} has {label} on {n_targets} user(s) "
            f"(e.g. {examples}{extra}) — possible shadow credential path",
            score=7,
        )
    skipped_bulk = sum(1 for _, tnames in secondary_items if len(tnames) > max_targets_for_finding)
    if skipped_bulk:
        sec.mark()
        console.print(
            f"[dim]… suppressed {skipped_bulk} bulk secondary ACL pair(s) "
            f"(>{max_targets_for_finding} user targets each — connector/over-delegation noise)[/dim]"
        )

    # Informational: objects that already have key credentials populated
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if d.get('type', '').lower() not in ('user', 'computer'):
            continue
        props = d.get('props') or {}
        key_credential_link = get_bool_prop_ci(
            props, ['keycredentiallink', 'msds-keycredentiallink', 'KeyCredentialLink']
        )
        # Non-empty list/string also counts
        if not key_credential_link:
            raw = props.get('keycredentiallink') or props.get('msds-keycredentiallink') or props.get('KeyCredentialLink')
            if isinstance(raw, (list, str)) and raw:
                key_credential_link = True
        if key_credential_link:
            found_existing = True
            sec.mark()
            console.print(
                f"[yellow]Existing KeyCredentialLink[/yellow] (informational): "
                f"[green]{d['name']}[/green] — may be Windows Hello / legitimate device creds"
            )
    if found_abuse:
        print_abuse_panel("Shadow Credentials")
    if not found_abuse and not found_existing:
        sec.empty(
            "No Shadow Credentials abuse rights or existing KeyCredentialLink found"
        )
    elif not found_abuse and found_existing:
        console.print(
            "[dim]No non-default AddKeyCredentialLink / ACL abuse rights found; "
            "existing KeyCredentialLink entries listed above are informational only[/dim]"
        )

def print_gpo_content_parsing(G, domain_filter=None):
    sec = DeferredSection("GPO Content Parsing for Exploitable Settings (AD)")
    found = False
    exploitable_keys = ['taskname', 'scriptpath', 'scheduledtask', 'TaskName', 'ScriptPath', 'ScheduledTask']
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if d.get('type', '').lower() != 'gpo':
            continue
        name = d.get('name') or d.get('ObjectIdentifier', 'Unnamed GPO')
        props = d.get('props') or {}
        lower_props = {k.lower(): v for k, v in props.items()}
        found_keys = [k for k in exploitable_keys if k.lower() in lower_props and lower_props[k.lower()]]
        if found_keys:
            sec.mark()
            found = True
            console.print(f"[yellow]Exploitable GPO content detected[/yellow]: [bold cyan]{name}[/bold cyan]")
            for key in exploitable_keys:
                if key.lower() in lower_props:
                    value = props.get(key) or lower_props.get(key.lower())
                    console.print(f"  → [cyan]{key}[/cyan]: {value}")
            detail = f"GPO '{name}' has exploitable content: {', '.join(found_keys)}"
            add_finding("GPO Content", detail)
    if found:
        print_abuse_panel("GPO Abuse")
    else:
        sec.empty("No exploitable GPO content found")
        
def print_gpo_content_analysis(G, gpo_content_dir: str, domain_filter=None):
    sec = DeferredSection("GPO Content Analysis – Scheduled Tasks / Scripts / cPassword (AD)")
    if not gpo_content_dir or not Path(gpo_content_dir).is_dir():
        if not _QUIET_EMPTY_SECTIONS:
            sec.mark()
            console.print("[yellow]--gpo-content-dir not provided or invalid. Skipping XML analysis.[/yellow]")
        return
    found_exploitable = False
    sec.mark()
    gpo_name_to_oid = {}
    for nid, ndata in G.nodes(data=True):
        if ndata.get('type', '').lower() == 'gpo':
            name = (ndata['name'].split('@')[0] or '').strip().upper()
            gpo_name_to_oid[name] = nid
    xml_files = list(Path(gpo_content_dir).rglob("*.xml"))
    console.print(f"[cyan]Found {len(xml_files)} GPO XML report(s) to analyze[/cyan]")
    for xml_path in tqdm(xml_files, desc="Parsing GPO XMLs"):
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            gpo_name_elem = root.find(".//GPO/Name") or root.find(".//Name")
            gpo_name = (gpo_name_elem.text or Path(xml_path).stem).strip().upper() if gpo_name_elem is not None else Path(xml_path).stem.upper()
            for task in root.findall(".//ScheduledTasks/Task"):
                name = task.findtext("Name") or "UnnamedTask"
                command = task.findtext("Command") or ""
                arguments = task.findtext("Arguments") or ""
                if command or arguments:
                    found_exploitable = True
                    console.print(f"[yellow]Exploitable Scheduled Task[/yellow] in [bold cyan]{gpo_name}[/bold cyan]: {name}")
                    console.print(f"   → Command: [green]{command} {arguments}[/green]")
                    add_finding("GPO Content", f"Scheduled Task '{name}' in {gpo_name}", score=8)
            for script in root.findall(".//Scripts/Script"):
                cmd = script.findtext("Command") or ""
                if cmd:
                    found_exploitable = True
                    console.print(f"[yellow]Exploitable Script[/yellow] in [bold cyan]{gpo_name}[/bold cyan]: {cmd}")
                    add_finding("GPO Content", f"Script '{cmd}' in {gpo_name}", score=8)
            for cpass in root.findall(".//Properties[@cpassword]"):
                found_exploitable = True
                console.print(f"[red]GPP cPassword found![/red] in [bold cyan]{gpo_name}[/bold cyan] → decrypt with gpp-decrypt")
                add_finding("GPO Content", f"GPP cPassword in {gpo_name}", score=10)
        except ET.ParseError as e:
            console.print(f"[yellow]Warning: Could not parse {xml_path}: {e}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Error processing {xml_path}: {e}[/yellow]")
    if found_exploitable:
        print_abuse_panel("GPO Abuse")
    else:
        sec.empty("No exploitable scheduled tasks, scripts, or cPasswords found in GPO XMLs")

def print_constrained_delegation(G, domain_filter=None):
    sec = DeferredSection("Constrained Delegation Detection (AD)")
    found = False
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        typ = str(d.get('type', '')).lower()
        if typ not in ('computer', 'user'):
            continue
        props = dict(d.get('props') or {})
        # Top-level SharpHound AllowedToDelegate may not be under Properties
        for key in (
            'AllowedToDelegate', 'allowedtodelegate', 'allowedtodelegateto',
            'msds-allowedtodelegateto', 'TrustedToAuthForDelegation', 'trustedtoauth',
        ):
            if key in d and key not in props:
                props[key] = d[key]
        trusted_to_auth = get_bool_prop_ci(
            props,
            [
                'trustedtoauthfordelegation',
                'TrustedToAuthForDelegation',
                'trustedtoauth',
            ],
        )
        if not trusted_to_auth:
            uac_raw = _prop_raw_ci(props, ['useraccountcontrol', 'UserAccountControl'])
            try:
                # TRUSTED_TO_AUTH_FOR_DELEGATION
                trusted_to_auth = bool(int(uac_raw) & 0x1000000)
            except (TypeError, ValueError):
                pass
        allowed_to_delegate_to = (
            props.get('msds-allowedtodelegateto')
            or props.get('allowedtodelegateto')
            or props.get('allowedtodelegate')
            or props.get('AllowedToDelegate')
            or []
        )
        if not isinstance(allowed_to_delegate_to, list):
            allowed_to_delegate_to = [allowed_to_delegate_to] if allowed_to_delegate_to else []
        if not trusted_to_auth and not allowed_to_delegate_to:
            continue
        found = True
        sec.mark()
        kind = "User" if typ == "user" else "Computer"
        console.print(
            f"[yellow]Constrained Delegation enabled[/yellow]: "
            f"[bold cyan]{d['name']}[/bold cyan] ({kind})"
        )
        if allowed_to_delegate_to:
            console.print(
                f"  → Allowed to delegate to: {', '.join(str(x) for x in allowed_to_delegate_to)}"
            )
        if trusted_to_auth:
            console.print("  → Protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION) enabled")
        add_finding(
            "Constrained Delegation",
            f"{kind} {d['name']} has Constrained Delegation",
        )
    if found:
        print_abuse_panel("Constrained Delegation")
    else:
        sec.empty("No Constrained Delegation found")

def _has_laps_enabled(props):
    """SharpHound CE uses haslaps; password attrs are rarely collected and vary in case."""
    if not isinstance(props, dict):
        return False
    if get_bool_prop_ci(props, ['haslaps', 'HasLAPS']):
        return True
    # Legacy / rare: non-empty LAPS password attribute (case-insensitive key match)
    password_keys = {
        'ms-mcs-admpwd',
        'msmcsadmpwd',
        'ms-mcs-admpwdexpirationtime',
        'msmcsadmpwdexpirationtime',
    }
    for p_key, p_val in props.items():
        if p_val is None or p_val is False or p_val == '':
            continue
        if p_key.lower() in password_keys or 'admpwd' in p_key.lower():
            return True
    return False

def print_laps_status(G, domain_filter=None):
    sec = DeferredSection("LAPS (Local Administrator Password Solution) Status (AD)")
    computers = [
        d for _, d in G.nodes(data=True)
        if d['type'].lower() == 'computer'
        and _domain_matches(d, domain_filter)
        and not d.get('is_azure', False)
    ]
    if not computers:
        sec.empty("No computers found")
        return
    enabled = []
    disabled = []
    for d in computers:
        props = d.get('props') or {}
        if _has_laps_enabled(props):
            enabled.append(d.get('name') or '')
        else:
            disabled.append(d.get('name') or '')
    total = len(computers)
    # Quiet mode: only show LAPS section when there is a coverage gap (or all enabled is worth a note)
    if _QUIET_EMPTY_SECTIONS and not disabled:
        return
    sec.mark()
    console.print(
        f"  LAPS enabled: [green]{len(enabled)}[/green] / {total}  ·  "
        f"not enabled: [yellow]{len(disabled)}[/yellow] / {total}"
    )
    max_samples = 10
    if enabled:
        for name in enabled[:max_samples]:
            console.print(f"  [green]LAPS enabled[/green]: [bold cyan]{name}[/bold cyan]")
        if len(enabled) > max_samples:
            console.print(f"  [dim]... and {len(enabled) - max_samples} more with LAPS[/dim]")
    if disabled:
        for name in disabled[:max_samples]:
            console.print(f"  [yellow]LAPS not enabled[/yellow]: [bold cyan]{name}[/bold cyan]")
        if len(disabled) > max_samples:
            console.print(f"  [dim]... and {len(disabled) - max_samples} more without LAPS[/dim]")
        add_finding(
            "LAPS",
            f"{len(disabled)}/{total} computers do not have LAPS enabled",
            score=6,
        )
    if enabled and not disabled:
        console.print(Panel(
            "[bold green]Impact:[/bold green] LAPS secures local admin passwords.\n"
            "[bold]Mitigation:[/bold] Ensure LAPS stays enabled on all computers.",
            title="LAPS Fully Enabled",
            border_style="green",
        ))
    elif disabled:
        console.print(Panel(
            "[bold yellow]Impact:[/bold yellow] Local admin passwords may be weak or shared → easy compromise.\n"
            "[bold]Mitigation:[/bold] Enable LAPS to randomize and secure passwords.",
            title="LAPS Coverage Gap",
            border_style="yellow",
        ))


READLAPS_LABELS = frozenset({
    "readlapspassword",
    "read laps password",
    "ms-mcs-admpwd",
})


def collect_laps_readers(G, domain_filter=None, exclude_default_priv: bool = True) -> List[dict]:
    """Principals with ReadLAPSPassword (or equivalent) on computers."""
    rows: List[dict] = []
    seen = set()
    for u, v, ed in G.edges(data=True):
        label = (ed.get("label") or "").lower()
        if label not in READLAPS_LABELS:
            continue
        ud = G.nodes.get(u) or {}
        vd = G.nodes.get(v) or {}
        if ud.get("is_azure") or vd.get("is_azure"):
            continue
        if not _domain_matches(ud, domain_filter) and not _domain_matches(vd, domain_filter):
            # keep if either side matches filter when set
            if domain_filter:
                continue
        # Prefer computer as target
        reader_d, computer_d = ud, vd
        if str(vd.get("type", "")).lower() != "computer" and str(ud.get("type", "")).lower() == "computer":
            reader_d, computer_d = vd, ud
        reader = reader_d.get("name") or str(u)
        computer = computer_d.get("name") or str(v)
        if exclude_default_priv and _is_default_high_priv_name(reader):
            continue
        key = (reader, computer, label)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "reader": reader,
                "computer": computer,
                "label": ed.get("label") or "ReadLAPSPassword",
                "reader_oid": u if reader_d is ud else v,
                "computer_oid": v if computer_d is vd else u,
            }
        )
    rows.sort(key=lambda r: (r["reader"], r["computer"]))
    return rows


def print_laps_readers(G, domain_filter=None):
    sec = DeferredSection("LAPS Password Readers (ReadLAPSPassword) (AD)")
    rows = collect_laps_readers(G, domain_filter)
    # Aggregate by reader — per-computer rows explode on enterprise graphs
    by_reader: Dict[str, List[str]] = defaultdict(list)
    labels_by_reader: Dict[str, set] = defaultdict(set)
    for r in rows:
        by_reader[r["reader"]].append(r["computer"])
        labels_by_reader[r["reader"]].add(r.get("label") or "ReadLAPSPassword")
    summary = sorted(by_reader.items(), key=lambda kv: len(kv[1]), reverse=True)
    max_display = 40
    max_findings = 50
    for i, (reader, computers) in enumerate(summary):
        n = len(computers)
        samples = ", ".join(computers[:3])
        extra = f" … +{n - 3} more" if n > 3 else ""
        rights = ", ".join(sorted(labels_by_reader[reader]))
        sec.mark()
        if i < max_display:
            console.print(
                f"  • [green]{reader}[/green] can read LAPS on "
                f"[red]{n}[/red] computer(s) [dim]({rights})[/dim] "
                f"e.g. [cyan]{samples}{extra}[/cyan]"
            )
        if i < max_findings:
            add_finding(
                "LAPS Readers",
                f"{reader} can ReadLAPSPassword on {n} computer(s) "
                f"(e.g. {samples}{extra})",
                score=8,
            )
    if len(summary) > max_display:
        console.print(f"  [dim]... and {len(summary) - max_display} more readers[/dim]")
    if len(summary) > max_findings:
        add_finding(
            "LAPS Readers",
            f"{len(summary) - max_findings} additional LAPS password readers (truncated)",
            score=8,
        )
    if rows:
        console.print(
            f"[dim]{len(rows)} computer grant(s) across {len(summary)} reader principal(s)[/dim]"
        )
        console.print(
            Panel(
                "[bold red]Impact:[/bold red] Read LAPS password → local admin on target host → lateral movement.\n"
                "[bold]Abuse:[/bold] Get-LapsADPassword / netexec / bloodyAD once ACL allows read.\n"
                "[bold]Mitigation:[/bold] Restrict ReadLAPSPassword to helpdesk/tiered admin groups; "
                "remove broad Authenticated Users / Domain Users grants.",
                title="Abuse Suggestions: LAPS Readers",
                border_style="red",
            )
        )
    else:
        sec.empty("No non-default LAPS password readers found")


def is_domain_controller(G, oid: str, max_depth: int = 10) -> bool:
    """Detect DC via props, UAC SERVER_TRUST_ACCOUNT, or Domain Controllers membership."""
    if oid not in G:
        return False
    d = G.nodes[oid]
    props = d.get("props") or {}
    if get_bool_prop_ci(props, ["isdc", "IsDC", "IsDomainController", "isDomainController"]):
        return True
    uac_raw = _prop_raw_ci(props, ["useraccountcontrol", "UserAccountControl"])
    try:
        if bool(int(uac_raw) & 0x2000):  # SERVER_TRUST_ACCOUNT
            return True
    except (TypeError, ValueError):
        pass
    # Nested MemberOf Domain Controllers / Enterprise Domain Controllers
    seen = set()
    stack = [(oid, 0)]
    while stack:
        cur, depth = stack.pop()
        if cur in seen or depth > max_depth:
            continue
        seen.add(cur)
        for _, dst, ed in G.out_edges(cur, data=True):
            label = (ed.get("label") or "").lower()
            if label not in ("memberof", "member_of", "member"):
                continue
            dname = ((G.nodes.get(dst) or {}).get("name") or "").lower()
            if "domain controllers" in dname or "enterprise domain controllers" in dname:
                return True
            if depth + 1 <= max_depth:
                stack.append((dst, depth + 1))
    return False


def print_unconstrained_delegation(G, domain_filter=None):
    sec = DeferredSection("Unconstrained Delegation Detection (AD)")
    dcs: List[dict] = []
    non_dcs: List[dict] = []
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if str(d.get('type', '')).lower() not in ('computer', 'user'):
            continue
        props = d.get('props') or {}
        # SharpHound CE uses unconstraineddelegation
        trusted_for_delegation = get_bool_prop_ci(
            props,
            ['trustedfordelegation', 'TrustedForDelegation', 'unconstraineddelegation'],
        )
        if not trusted_for_delegation:
            uac_raw = _prop_raw_ci(props, ['useraccountcontrol', 'UserAccountControl'])
            try:
                trusted_for_delegation = bool(int(uac_raw) & 0x80000)
            except (TypeError, ValueError):
                pass
        if not trusted_for_delegation:
            continue
        # Disabled users/computers are not live abuse candidates
        if not _account_is_enabled(props, default=True):
            continue
        os_name = _prop_raw_ci(props, ['operatingsystem', 'OperatingSystem']) or ""
        entry = {"oid": n, "name": d.get("name") or "", "os": os_name, "type": d.get("type")}
        if is_domain_controller(G, n):
            dcs.append(entry)
        else:
            non_dcs.append(entry)

    if non_dcs:
        sec.mark()
        if dcs:
            console.print("[bold]Domain Controllers (expected unconstrained)[/bold]")
            for e in dcs:
                os_s = f" [{e['os']}]" if e["os"] else ""
                console.print(
                    f"  [dim]•[/dim] [cyan]{e['name']}[/cyan]{os_s}"
                )
        console.print("[bold yellow]Non-DC unconstrained delegation (abuse candidates)[/bold yellow]")
        for e in non_dcs:
            os_s = f" [{e['os']}]" if e["os"] else ""
            typ = str(e.get("type") or "Computer")
            console.print(
                f"  [yellow]•[/yellow] [bold cyan]{e['name']}[/bold cyan] ({typ}){os_s}"
            )
            add_finding(
                "Unconstrained Delegation",
                f"{typ} {e['name']} allows unconstrained delegation (non-DC)",
                score=8,
            )
        print_abuse_panel("Unconstrained Delegation")
    elif dcs:
        # DC-only is expected noise under quiet --all
        if not _QUIET_EMPTY_SECTIONS:
            sec.mark()
            console.print("[bold]Domain Controllers (expected unconstrained)[/bold]")
            for e in dcs:
                os_s = f" [{e['os']}]" if e["os"] else ""
                console.print(
                    f"  [dim]•[/dim] [cyan]{e['name']}[/cyan]{os_s}"
                )
            console.print(
                f"[dim]Only DC unconstrained delegation found ({len(dcs)}); "
                f"no non-DC abuse candidates.[/dim]"
            )
    else:
        sec.empty("No unconstrained delegation found")

def print_sid_history_abuse(G, domain_filter=None):
    sec = DeferredSection("SID History Abuse (AD)")
    found = False
    high_priv_groups = {'domain admins', 'enterprise admins', 'administrators', 'schema admins'}
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if d['type'].lower() not in ('user', 'computer'):
            continue
        # Graph edges (HasSIDHistory)
        for u, v, edge_data in G.out_edges(n, data=True):
            if (edge_data.get('label') or '').lower() != 'hassidhistory':
                continue
            hist_name = G.nodes[v]['name']
            group_name = hist_name.lower()
            if any(hp in group_name for hp in high_priv_groups) or _is_default_high_priv_name(hist_name):
                found = True
                sec.mark()
                console.print(
                    f"[yellow]SID History potential[/yellow]: [green]{d['name']}[/green] "
                    f"has SID history from [cyan]{hist_name}[/cyan]"
                )
                add_finding("SID History Abuse", f"{d['name']} has SID history from {hist_name}")
            else:
                # Still surface non-empty history (informational)
                sec.mark()
                console.print(
                    f"[dim]SID History present[/dim]: [green]{d['name']}[/green] → [cyan]{hist_name}[/cyan]"
                )
        # Property-only list if edges were not built
        props = d.get('props') or {}
        raw = props.get('sidhistory') or props.get('SidHistory') or props.get('sidHistory')
        if raw and not any(
            (ed.get('label') or '').lower() == 'hassidhistory'
            for _, _, ed in G.out_edges(n, data=True)
        ):
            if not isinstance(raw, list):
                raw = [raw]
            for sh in raw:
                sid_val = sh.get('ObjectIdentifier') if isinstance(sh, dict) else sh
                if not sid_val:
                    continue
                found = True
                sec.mark()
                console.print(
                    f"[yellow]SID History present[/yellow]: [green]{d['name']}[/green] "
                    f"history SID [cyan]{sid_val}[/cyan]"
                )
                add_finding("SID History Abuse", f"{d['name']} has SID history entry {sid_val}", score=5)
    if found:
        print_abuse_panel("SID History Abuse")
    else:
        sec.empty("No obvious SID history abuse detected")

def print_adcs_vulnerabilities(G, domain_filter=None):
    """Detect AD CS misconfigs (SpecterOps ESC1–ESC14 where JSON signals allow).

    ESC1–ESC8 follow Certified Pre-Owned / BloodHound CE semantics.
    ESC9+ use template flags when present (NO_SECURITY_EXTENSION, etc.).
    ESC6/ESC8/ESC10–12 need CA registry or HTTP role data SharpHound may omit.
    """
    sec = DeferredSection("ADCS ESC Vulnerabilities (ESC1–ESC14) (AD)")
    found = False
    adcs_types = {
        'certificate template', 'enterprise ca', 'root ca', 'ntauth store', 'aia ca',
    }
    adcs_object_count = sum(
        1
        for _, d in G.nodes(data=True)
        if not d.get('is_azure', False)
        and _domain_matches(d, domain_filter)
        and (
            str(d.get('type') or '').lower() in adcs_types
            or str(d.get('type') or '').lower().endswith(' ca')
        )
    )
    # Open section when we will print anything (objects missing is itself a message)
    if adcs_object_count == 0 and _QUIET_EMPTY_SECTIONS:
        return
    sec.mark()
    if adcs_object_count == 0:
        console.print(
            "[yellow]No ADCS objects in this collection[/yellow] "
            "[dim](no certificate templates / enterprise CAs / NTauth). "
            "Re-collect with SharpHound ADCS / Certify modules — "
            "absence of data is not a clean bill of health.[/dim]"
        )
        return
    # Common EKUs
    EKU_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2'
    EKU_SMART_CARD = '1.3.6.1.4.1.311.20.2.2'
    EKU_ANY_PURPOSE = '2.5.29.37.0'
    EKU_CERT_REQUEST_AGENT = '1.3.6.1.4.1.311.20.2.1'  # Enrollment Agent
    DANGEROUS_TEMPLATE_RIGHTS = {
        'GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite', 'WriteProperty',
    }
    # CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000 in msPKI-Enrollment-Flag
    NO_SECURITY_EXT_BIT = 0x00080000

    def _enrollment_flag_text(props):
        raw = _prop_raw_ci(props, ['enrollmentflag', 'EnrollmentFlag', 'mspki-enrollment-flag'])
        if raw is None:
            return ''
        return str(raw)

    def _has_no_security_extension(props):
        if get_bool_prop_ci(
            props,
            ['nosecurityextension', 'NoSecurityExtension', 'no_security_extension'],
        ):
            return True
        text = _enrollment_flag_text(props).upper()
        if 'NO_SECURITY_EXTENSION' in text or 'NOSECURITYEXTENSION' in text.replace('_', ''):
            return True
        try:
            return bool(int(text) & NO_SECURITY_EXT_BIT)
        except (TypeError, ValueError):
            return False

    def _nondefault_holders(incoming, right_set):
        holders = []
        for u, _, edge in incoming:
            lab = edge.get('label')
            if lab not in right_set and (lab or '').lower() not in {r.lower() for r in right_set}:
                continue
            uname = G.nodes[u]['name']
            if not _is_default_high_priv_name(uname):
                holders.append((u, lab or edge.get('label')))
        return holders

    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        obj_type = d.get('type', 'Unknown').lower()
        if obj_type not in ['certificate template', 'enterprise ca', 'root ca', 'ntauth store']:
            continue
        name = d.get('name') or d.get('props', {}).get('name', n)
        props = dict(d.get('props') or {})
        # Lift common top-level SharpHound flags into props for detection
        for key in (
            'EnrolleeSuppliesSubject', 'enrolleesuppliessubject',
            'RequiresManagerApproval', 'requiresmanagerapproval',
            'EDITF_ATTRIBUTESUBJECTALTNAME2', 'editf_attributesubjectaltname2',
            'IsUserSpecifiesSanEnabled', 'isuserspecifiessanenabled',
            'IsUserSpecifiesSanEnabledCollected', 'isuserspecifiessanenabledcollected',
            'EnrollmentFlag', 'enrollmentflag',
            'HasWebEnrollment', 'haswebenrollment',
        ):
            if key in d and key not in props:
                props[key] = d[key]
        incoming = list(G.in_edges(n, data=True))
        rights = {edge_data.get('label') for _, _, edge_data in incoming if edge_data.get('label')}
        rights_ci = {r.lower() for r in rights if r}
        can_enroll = 'enroll' in rights_ci or 'autoenroll' in rights_ci
        enrollee_supplies = get_bool_prop_ci(
            props, ['enrolleesuppliessubject', 'EnrolleeSuppliesSubject']
        )
        requires_mgr_approval = get_bool_prop_ci(
            props, ['requiresmanagerapproval', 'RequiresManagerApproval'], default=False
        )
        # Pending all requests / manager approval via enrollment flags
        enroll_flag_text = _enrollment_flag_text(props).upper()
        if 'PEND_ALL_REQUESTS' in enroll_flag_text:
            requires_mgr_approval = True
        no_approval = not requires_mgr_approval
        # ESC6: CA allows user-specified SAN (value may be missing if only *Collected)
        editf_san2 = get_bool_prop_ci(
            props,
            [
                'editf_attributesubjectaltname2',
                'EDITF_ATTRIBUTESUBJECTALTNAME2',
                'isuserspecifiessanenabled',
                'IsUserSpecifiesSanEnabled',
                'userspecifiedsan',
                'UserSpecifiedSAN',
            ],
        )
        san_collected = get_bool_prop_ci(
            props,
            ['isuserspecifiessanenabledcollected', 'IsUserSpecifiesSanEnabledCollected'],
        )
        ekus = (
            props.get('ekus')
            or props.get('effectiveekus')
            or props.get('EffectiveEKUs')
            or props.get('mspki-certificate-application-policy')
            or []
        )
        if not isinstance(ekus, list):
            ekus = [ekus] if ekus else []
        eku_set = set(str(e) for e in ekus)
        auth_enabled = get_bool_prop_ci(props, ['authenticationenabled', 'AuthenticationEnabled'])
        has_client_auth = (
            auth_enabled
            or EKU_CLIENT_AUTH in eku_set
            or EKU_SMART_CARD in eku_set
            or EKU_ANY_PURPOSE in eku_set
        )
        # Empty EKU set is missing collection, not "Any Purpose"
        has_any_purpose = EKU_ANY_PURPOSE in eku_set
        has_cert_request_agent = EKU_CERT_REQUEST_AGENT in eku_set
        dangerous_on_object = {r for r in rights if r in DANGEROUS_TEMPLATE_RIGHTS}
        no_sec_ext = _has_no_security_extension(props)
        # Issuance / application policies (ESC13 signal)
        issuance = (
            props.get('applicationpolicies')
            or props.get('ApplicationPolicies')
            or props.get('issuancepolicies')
            or props.get('IssuancePolicies')
            or props.get('certificatepolicies')
            or props.get('CertificatePolicies')
            or []
        )
        if not isinstance(issuance, list):
            issuance = [issuance] if issuance else []

        def _print_enrollers():
            for u, _, edge in incoming:
                if edge.get('label', '').lower() in ('enroll', 'autoenroll'):
                    console.print(f"  → [green]{G.nodes[u]['name']}[/green] can Enroll")

        def _print_right_holders(right_set, nondefault_only=False):
            for u, _, edge in incoming:
                lab = edge.get('label')
                if lab not in right_set and (lab or '').lower() not in {r.lower() for r in right_set}:
                    continue
                uname = G.nodes[u]['name']
                if nondefault_only and _is_default_high_priv_name(uname):
                    continue
                console.print(f"  → [green]{uname}[/green] --[{lab}]-->")

        # ── ESC1: ESS + client auth path + enroll + no manager approval ──
        # Empty EKU with ESS still treated as auth-capable (common incomplete export).
        if obj_type == 'certificate template' and can_enroll and enrollee_supplies and no_approval:
            if has_client_auth or not eku_set:
                found = True
                console.print(
                    f"[red]ESC1[/red]: [bold cyan]{name}[/bold cyan] "
                    f"(Enroll + EnrolleeSuppliesSubject + no manager approval)"
                )
                _print_enrollers()
                add_finding("ESC1-ESC8", f"ESC1 on {name}")

        # ── ESC2: Any Purpose EKU + enroll + no approval (without ESS) ──
        if (
            obj_type == 'certificate template'
            and can_enroll
            and no_approval
            and not enrollee_supplies
            and has_any_purpose
            and not has_cert_request_agent  # avoid double-counting pure enrollment-agent templates
        ):
            found = True
            console.print(
                f"[red]ESC2[/red]: [bold cyan]{name}[/bold cyan] "
                f"(Enroll + Any Purpose EKU + no manager approval)"
            )
            _print_enrollers()
            add_finding("ESC1-ESC8", f"ESC2 on {name}")

        # ── ESC3: Enrollment Agent (CRA EKU) with enroll + no manager approval ──
        if (
            obj_type == 'certificate template'
            and has_cert_request_agent
            and can_enroll
            and no_approval
        ):
            found = True
            console.print(
                f"[red]ESC3[/red]: [bold cyan]{name}[/bold cyan] "
                f"(Certificate Request Agent / Enrollment Agent EKU + Enroll)"
            )
            _print_enrollers()
            add_finding("ESC1-ESC8", f"ESC3 on {name}")

        # ── ESC4: Dangerous ACLs on template from non-default principals ──
        if obj_type == 'certificate template' and dangerous_on_object:
            nd_holders = _nondefault_holders(incoming, dangerous_on_object)
            if nd_holders:
                found = True
                console.print(
                    f"[red]ESC4[/red]: [bold cyan]{name}[/bold cyan] "
                    f"(dangerous rights on certificate template — non-default principals)"
                )
                for u, lab in nd_holders[:10]:
                    console.print(f"  → [green]{G.nodes[u]['name']}[/green] --[{lab}]-->")
                add_finding("ESC1-ESC8", f"ESC4 on {name}")
            # else: only DA/EA hold the rights — skip to cut noise

        # ── ESC5: Dangerous ACLs on PKI objects from non-default principals ──
        if obj_type in ['enterprise ca', 'root ca', 'ntauth store']:
            esc5_rights = dangerous_on_object
            nd_holders = _nondefault_holders(incoming, esc5_rights) if esc5_rights else []
            if nd_holders:
                found = True
                console.print(
                    f"[red]ESC5[/red]: [bold cyan]{name}[/bold cyan] "
                    f"(dangerous rights on PKI object — non-default principals)"
                )
                for u, lab in nd_holders[:10]:
                    console.print(f"  → [green]{G.nodes[u]['name']}[/green] --[{lab}]-->")
                add_finding("ESC1-ESC8", f"ESC5 on {name}")

        # ── ESC6: CA allows requester-specified SAN ──
        if obj_type == 'enterprise ca':
            if editf_san2:
                found = True
                console.print(
                    f"[red]ESC6[/red]: [bold cyan]{name}[/bold cyan] "
                    f"(CA allows user-specified SAN / EDITF_ATTRIBUTESUBJECTALTNAME2)"
                )
                add_finding("ESC1-ESC8", f"ESC6 on {name}")
            elif san_collected and _prop_raw_ci(
                props, ['isuserspecifiessanenabled', 'IsUserSpecifiesSanEnabled']
            ) is None:
                # SharpHound marked collection attempted but value absent — note only
                console.print(
                    f"[dim]ESC6 data incomplete for {name}: "
                    f"IsUserSpecifiesSanEnabledCollected but value not present[/dim]"
                )

        # ── ESC7: ManageCA / ManageCertificates on CA (non-default) ──
        if obj_type in ['enterprise ca', 'root ca']:
            manage_rights = {r for r in rights if r in ('ManageCA', 'ManageCertificates')}
            nd_holders = _nondefault_holders(incoming, manage_rights) if manage_rights else []
            if nd_holders:
                found = True
                console.print(
                    f"[red]ESC7[/red]: [bold cyan]{name}[/bold cyan] "
                    f"(ManageCA/ManageCertificates on CA — non-default principals)"
                )
                for u, lab in nd_holders[:10]:
                    console.print(f"  → [green]{G.nodes[u]['name']}[/green] --[{lab}]-->")
                add_finding("ESC1-ESC8", f"ESC7 on {name}")
            elif manage_rights:
                # Still report if any ManageCA exists (including DA) — high impact, keep dim note
                # Prefer reporting when collected: default priv often expected; skip pure DA-only
                pass

        # ── ESC8: Web enrollment / HTTP AD CS ──
        if obj_type == 'enterprise ca':
            web_enroll = get_bool_prop_ci(
                props,
                [
                    'webenrollment',
                    'WebEnrollment',
                    'httpenrollment',
                    'HttpEnrollment',
                    'haswebenrollment',
                    'HasWebEnrollment',
                    'httpenabled',
                    'HttpEnabled',
                ],
            )
            # Some exports encode endpoints as strings
            if not web_enroll:
                for pk, pv in props.items():
                    if isinstance(pv, str) and 'certsrv' in pv.lower():
                        web_enroll = True
                        break
                    if pk.lower() in ('webenrollmentendpoints', 'httpenrollmentendpoints') and pv:
                        web_enroll = True
                        break
            if web_enroll:
                found = True
                console.print(
                    f"[red]ESC8[/red]: [bold cyan]{name}[/bold cyan] "
                    f"(web/HTTP enrollment enabled — NTLM relay risk)"
                )
                add_finding("ESC1-ESC8", f"ESC8 on {name}")

        # ── ESC9: No security extension on auth-capable template ──
        if (
            obj_type == 'certificate template'
            and no_sec_ext
            and has_client_auth
            and can_enroll
            and no_approval
        ):
            found = True
            console.print(
                f"[red]ESC9[/red]: [bold cyan]{name}[/bold cyan] "
                f"(NO_SECURITY_EXTENSION + client auth + enroll — weak cert mapping)"
            )
            _print_enrollers()
            add_finding("ESC1-ESC8", f"ESC9 on {name}", score=9)

        # ── ESC13: Issuance policy / application policy present on enrollable auth template ──
        # Full ESC13 needs OID→group link; we surface when policies + enroll + auth exist.
        if (
            obj_type == 'certificate template'
            and issuance
            and has_client_auth
            and can_enroll
            and no_approval
        ):
            found = True
            console.print(
                f"[yellow]ESC13 (candidate)[/yellow]: [bold cyan]{name}[/bold cyan] "
                f"(issuance/application policies present — verify OID group links)"
            )
            add_finding(
                "ESC1-ESC8",
                f"ESC13 candidate on {name} (policies: {', '.join(str(x) for x in issuance[:5])})",
                score=7,
            )

        # ── ESC14 hint: NO_SECURITY_EXTENSION + UPN/DNS SAN without strong mapping data ──
        if (
            obj_type == 'certificate template'
            and no_sec_ext
            and has_client_auth
            and can_enroll
        ):
            san_upn = get_bool_prop_ci(props, ['subjectaltrequireupn', 'SubjectAltRequireUPN'])
            san_dns = get_bool_prop_ci(props, ['subjectaltrequiredns', 'SubjectAltRequireDNS'])
            if san_upn or san_dns:
                # Distinct from ESC9 only when we already reported ESC9; still useful as note
                if not (no_approval and can_enroll and has_client_auth and no_sec_ext and False):
                    pass  # ESC9 covers primary case; skip duplicate ESC14 spam

    if found:
        print_abuse_panel("ESC1-ESC8 (AD CS)")
        console.print(
            "[dim]Note: ESC6/ESC8/ESC10–12 often need CA registry or HTTP role data "
            "not present in all SharpHound collections. ESC9 uses NO_SECURITY_EXTENSION.[/dim]"
        )
    else:
        if not _QUIET_EMPTY_SECTIONS:
            console.print("[green]No obvious ESC1–ESC14 misconfigurations detected[/green]")

def _is_broad_principal_name(name: str) -> bool:
    """Everyone / Authenticated Users / Domain Users — domain-wide ACL holders."""
    if not name:
        return False
    nl = str(name).lower()
    sam = _principal_sam(name)
    if sam in ("everyone", "authenticated users", "domain users", "users"):
        return True
    if "authenticated users" in nl or nl.startswith("everyone@"):
        return True
    if nl.startswith("domain users@"):
        return True
    return False


def print_gpo_abuse(G, domain_filter=None):
    sec = DeferredSection("GPO Abuse Risks (AD)")
    found = False
    high_value_keywords = [
        'domain controllers', 'domain admins', 'enterprise admins',
    ]
    dangerous = {'genericall', 'writedacl', 'writeowner', 'genericwrite'}
    hits: List[dict] = []
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if d['type'].lower() != 'gpo':
            continue
        name = d['name']
        incoming = list(G.in_edges(n, data=True))
        # Non-default writers only (DA/EA GenericWrite on GPOs is expected noise)
        writers = []
        for u, _, edge in incoming:
            label_lower = (edge.get('label') or '').lower()
            if label_lower not in dangerous:
                continue
            principal_name = resolve_principal_display_name(G, u)
            if _is_default_high_priv_name(principal_name):
                continue
            if is_expected_admin_principal(G, u):
                continue
            writers.append((principal_name, edge.get('label') or label_lower, u))
        if not writers:
            continue
        is_high_risk = False
        linked_ous = []
        # BloodHound GPLink is container (OU/domain) → GPO (in-edges on the GPO).
        for src, _, edge_data in incoming:
            if (edge_data.get('label') or '').lower() in ('gplink', 'linkedto'):
                ou_name = (G.nodes[src].get('name') or '').lower()
                linked_ous.append(G.nodes[src].get('name') or str(src))
                if any(kw in ou_name for kw in high_value_keywords):
                    is_high_risk = True
                if _is_builtin_administrators_name(G.nodes[src].get('name') or ''):
                    is_high_risk = True
        if any(_is_broad_principal_name(p) for p, _, _ in writers):
            is_high_risk = True
        if linked_ous:
            risk_tag = "High-risk" if is_high_risk else "Linked"
            scope_note = f" ({risk_tag}: Linked to {', '.join(linked_ous[:3])})"
        else:
            scope_note = " (No links detected - low risk)"
        writers.sort(key=lambda w: (0 if _is_broad_principal_name(w[0]) else 1, w[0]))
        hits.append({
            "name": name,
            "scope_note": scope_note,
            "high_risk": is_high_risk,
            "writers": writers,
        })
    # High-risk first; cap console + findings on enterprise collections
    hits.sort(key=lambda h: (0 if h["high_risk"] else 1, h["name"]))
    max_display = 40
    max_findings = 50
    for i, h in enumerate(hits):
        found = True
        sec.mark()
        risk_color = "[red]" if h["high_risk"] else "[yellow]"
        if i < max_display:
            console.print(
                f"{risk_color}Weak GPO{risk_color}: "
                f"[bold cyan]{h['name']}[/bold cyan]{h['scope_note']}"
            )
            for principal_name, label, _ in h["writers"][:8]:
                style = "red" if _is_broad_principal_name(principal_name) else "green"
                console.print(f"  → [{style}]{principal_name}[/{style}] --[{label}]-->")
            if len(h["writers"]) > 8:
                console.print(f"  [dim]… +{len(h['writers']) - 8} more writers[/dim]")
        if i < max_findings:
            add_finding(
                "GPO Abuse",
                f"Weak GPO: {h['name']}{h['scope_note']}",
                score=9 if h["high_risk"] else 7,
            )
    if len(hits) > max_display:
        console.print(f"  [dim]... and {len(hits) - max_display} more weak GPOs[/dim]")
    if len(hits) > max_findings:
        add_finding(
            "GPO Abuse",
            f"{len(hits) - max_findings} additional weak GPOs (truncated in findings)",
            score=7,
        )
    if hits:
        console.print(f"[dim]Found {len(hits)} GPO(s) with non-default write rights[/dim]")
    if found:
        print_abuse_panel("GPO Abuse")
    else:
        sec.empty("No dangerous GPO rights found from non-default principals")

# Multi-word / unambiguous DCSync holder phrases (substring-safe).
EXPECTED_DCSYNC_NAME_NEEDLES = (
    "domain admins",
    "enterprise admins",
    "schema admins",
    "enterprise domain controllers",
    "enterprise read-only domain controllers",
    "read-only domain controllers",
)


def _is_expected_dcsync_name(name: str) -> bool:
    """True if display name is a built-in DCSync holder (not 'System Administrators')."""
    if not name:
        return False
    nl = str(name).lower().strip()
    sam = _principal_sam(name)
    if _is_builtin_administrators_name(name):
        return True
    if any(k in nl for k in EXPECTED_DCSYNC_NAME_NEEDLES):
        return True
    if sam in (
        "domain admins",
        "enterprise admins",
        "schema admins",
        "domain controllers",
        "enterprise domain controllers",
        "enterprise read-only domain controllers",
        "read-only domain controllers",
        "administrators",
    ):
        return True
    if nl.startswith("domain controllers@"):
        return True
    return False


def _sid_trailing_rid(value: str) -> Optional[str]:
    """Extract trailing RID from a SID or FOREIGN (… RID-N) display label."""
    s = str(value or "").strip()
    if not s:
        return None
    m = re.search(r"RID-(\d+)\s*\)?\s*$", s, re.IGNORECASE)
    if m:
        return m.group(1)
    # Plain SID or DOMAIN-S-1-5-21-…-RID (legacy PrincipalSID style)
    sid = s
    idx = s.upper().find("-S-1-")
    if idx > 0:
        sid = s[idx + 1 :]  # drop domain prefix before S-1-…
    if sid.upper().startswith("S-1-") or s.upper().startswith("S-1-"):
        parts = (sid if sid.upper().startswith("S-1-") else s).split("-")
        for part in reversed(parts):
            if part.isdigit():
                return part
    return None


def _is_expected_dcsync_sid(oid: str, name: str = "") -> bool:
    """Well-known domain/builtin RIDs that hold expected DCSync (incl. foreign EA)."""
    for val in (oid, name):
        s = str(val or "")
        su = s.upper()
        if "S-1-5-32-544" in su or su.endswith("S-1-5-32-544"):
            return True
        rid = _sid_trailing_rid(s)
        if rid in EXPECTED_DCSYNC_RIDS:
            return True
    return False


def is_expected_dcsync_principal(G, oid: str, max_depth: int = 25) -> bool:
    """True if principal is a built-in DCSync holder or nested into one."""
    name = ""
    if oid in G:
        nd = G.nodes[oid]
        name = nd.get("name") or ""
        if _is_expected_dcsync_name(name):
            return True
    # Unresolved / foreign forest well-known RIDs (EA 519, DA 512, …)
    if _is_expected_dcsync_sid(str(oid), name):
        return True
    if oid not in G:
        return False
    # Nested MemberOf into an expected group
    seen = set()
    stack = [(oid, 0)]
    while stack:
        cur, depth = stack.pop()
        if cur in seen or depth > max_depth:
            continue
        seen.add(cur)
        for _, dst, ed in G.out_edges(cur, data=True):
            label = (ed.get("label") or "").lower()
            if label not in ("memberof", "member_of", "member"):
                continue
            dnd = G.nodes.get(dst) or {}
            dname = dnd.get("name") or ""
            if _is_expected_dcsync_name(dname) or _is_expected_dcsync_sid(str(dst), dname):
                return True
            if depth + 1 <= max_depth:
                stack.append((dst, depth + 1))
    return False


def print_dcsync_rights(G, domain_filter=None):
    console.rule("[bold magenta]DCSync / Replication Rights (AD)[/bold magenta]")
    # Classic DCSync requires GetChanges + GetChangesAll together.
    # GetChangesInFilteredSet alone is RODC-related, not full DCSync.
    # Unexpected (non-default / non-nested-DA) full DCSync is the critical finding.
    found = False
    unexpected = 0
    domain_oids = [
        n for n, d in G.nodes(data=True)
        if d.get('type', '').lower() == 'domain'
        and _domain_matches(d, domain_filter)
        and not d.get('is_azure', False)
    ]
    if not domain_oids:
        console.print("[yellow]No domain objects found[/yellow]")
        return
    get_changes_labels = {
        'getchanges',
        'replicating directory changes',
        'ds-replication-get-changes',
    }
    get_changes_all_labels = {
        'getchangesall',
        'replicating directory changes all',
        'ds-replication-get-changes-all',
    }
    filtered_set_labels = {
        'getchangesinfilteredset',
        'replicating directory changes in filtered set',
        'ds-replication-get-changes-in-filtered-set',
    }

    expected_full: List[Tuple[str, str]] = []  # (principal, domain)
    expected_partial = 0
    filtered_n = 0
    for domain_oid in domain_oids:
        domain_name = G.nodes[domain_oid]['name']
        # Collect rights per principal
        by_principal = defaultdict(set)
        for u, _, d in G.in_edges(domain_oid, data=True):
            label_lower = (d.get('label') or '').lower()
            by_principal[u].add(label_lower)
        for u, labels in by_principal.items():
            principal_name = resolve_principal_display_name(G, u)
            has_gc = bool(labels & get_changes_labels)
            has_gca = bool(labels & get_changes_all_labels)
            has_filtered = bool(labels & filtered_set_labels)
            # SharpHound often emits AllExtendedRights / GenericAll on the domain
            # instead of the pair of replication rights; both imply full DCSync.
            full_control = bool(labels & {
                'allextendedrights',
                'all extended rights',
                'genericall',
                'owns',
            })
            if full_control:
                has_gc = True
                has_gca = True
            if has_gc and has_gca:
                found = True
                if is_expected_dcsync_principal(G, u):
                    expected_full.append((principal_name, domain_name))
                else:
                    unexpected += 1
                    console.print(
                        f"[red]DCSync possible[/red]: [green]{principal_name}[/green] "
                        f"has GetChanges + GetChangesAll on [cyan]{domain_name}[/cyan] "
                        f"[Unexpected / non-default]"
                    )
                    add_finding(
                        "DCSync",
                        f"{principal_name} can DCSync on {domain_name} (unexpected)",
                    )
            elif has_gca and not has_gc:
                # Incomplete — note but do not call full DCSync.
                # Domain Controllers / other expected holders often show this layout; demote noise.
                if is_expected_dcsync_principal(G, u) or _is_expected_dcsync_name(principal_name):
                    expected_partial += 1
                else:
                    console.print(
                        f"[yellow]Partial replication rights[/yellow]: [green]{principal_name}[/green] "
                        f"has GetChangesAll without GetChanges on [cyan]{domain_name}[/cyan]"
                    )
                    add_finding(
                        "DCSync",
                        f"{principal_name} has GetChangesAll only on {domain_name}",
                        score=4,
                    )
                    found = True
            elif has_filtered and not (has_gc and has_gca):
                filtered_n += 1
    if expected_full:
        # Collapse built-in holders into one dim line (still searchable as "Expected DCSync")
        by_dom: Dict[str, List[str]] = defaultdict(list)
        for pname, dname in expected_full:
            by_dom[dname].append(pname)
        for dname, names in by_dom.items():
            uniq = sorted(set(names))
            if len(uniq) <= 6:
                shown = ", ".join(uniq)
            else:
                shown = ", ".join(uniq[:6]) + f" … +{len(uniq) - 6} more"
            console.print(
                f"[dim]Expected DCSync holders on {dname}[/dim]: [cyan]{shown}[/cyan] "
                f"[dim](built-in / nested high privilege)[/dim]"
            )
    if expected_partial:
        console.print(
            f"[dim]Partial replication (expected layout): {expected_partial} "
            f"principal(s) with GetChangesAll only[/dim]"
        )
    if filtered_n:
        console.print(
            f"[dim]Filtered-set replication: {filtered_n} principal(s) "
            f"(RODC-related, not full DCSync)[/dim]"
        )
    if unexpected:
        console.print(
            f"[bold red]Unexpected DCSync principals: {unexpected}[/bold red] "
            f"(excluding DA/EA/DC nested membership)"
        )
    if unexpected:
        print_abuse_panel("DCSync")
    elif not found and not expected_full and not expected_partial and not filtered_n:
        if not _QUIET_EMPTY_SECTIONS:
            console.print("[green]No DCSync rights detected[/green]")
    elif not unexpected and (expected_full or expected_partial or filtered_n):
        # expected-only: no abuse panel
        pass

def print_rbcd(G, domain_filter=None):
    sec = DeferredSection("Resource-Based Constrained Delegation (RBCD) (AD)")
    # RBCD is msDS-AllowedToActOnBehalfOfOtherIdentity / AllowedToAct edges
    # (principal → AllowedToAct → resource). msDS-AllowedToDelegateTo is KCD,
    # handled by print_constrained_delegation — do not treat it as RBCD.
    found = False
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if d.get('type', '').lower() != 'computer':
            continue
        principals = []
        # Graph edges (preferred after AllowedToAct direction fix)
        for u, _, edata in G.in_edges(n, data=True):
            if edata.get('label', '').lower() == 'allowedtoact':
                principals.append(G.nodes[u]['name'])
        # Property fallback for raw SharpHound fields if edges were not built
        if not principals:
            props = d.get('props') or {}
            raw = (
                props.get('allowedtoact')
                or props.get('AllowedToAct')
                or props.get('msds-allowedtoactonbehalfofotheridentity')
                or props.get('msDS-AllowedToActOnBehalfOfOtherIdentity')
            )
            if raw:
                if not isinstance(raw, list):
                    raw = [raw]
                for item in raw:
                    if isinstance(item, dict):
                        principals.append(
                            item.get('ObjectIdentifier')
                            or item.get('name')
                            or str(item)
                        )
                    else:
                        principals.append(str(item))
        principals = [p for p in principals if p]
        if principals:
            found = True
            sec.mark()
            console.print(
                f"[yellow]RBCD configured[/yellow]: [bold cyan]{d['name']}[/bold cyan] "
                f"allows delegation from:"
            )
            for pname in principals:
                console.print(f"  → [green]{pname}[/green]")
            add_finding("RBCD", f"RBCD on {d['name']}")
    if found:
        print_abuse_panel("RBCD")
    else:
        sec.empty("No RBCD configured computers found")


# Rights that let a principal set msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD).
# Omit bare WriteProperty: SharpHound emits many property writes; only
# WriteAccountRestrictions / AddAllowedToAct (and full control) reliably mean RBCD.
RBCD_CONFIGURE_RIGHTS = frozenset({
    "genericall",
    "genericwrite",
    "writeowner",
    "writedacl",
    "owns",
    "allextendedrights",
    "writeaccountrestrictions",
    "addallowedtoact",
})
# Prefer specific / strongest configure rights when multiple edges exist.
RBCD_RIGHT_RANK = {
    "addallowedtoact": 100,
    "writeaccountrestrictions": 90,
    "genericall": 80,
    "genericwrite": 70,
    "writedacl": 60,
    "writeowner": 50,
    "owns": 40,
    "allextendedrights": 30,
}


def _looks_like_sid(value: str) -> bool:
    s = str(value or "")
    return s.upper().startswith("S-1-") or "-S-1-" in s.upper()


def collect_known_domain_sids(G) -> Dict[str, str]:
    """Map domain SID (S-1-5-21-…) → domain DNS/NetBIOS name for foreign SID labels.

    Cached on G.graph to avoid O(nodes) rescans from resolve_principal_display_name
    during multi-million-edge ACL walks (can-configure RBCD, etc.).
    """
    if G is None:
        return {}
    cached = G.graph.get("_bb_domain_sids")
    if isinstance(cached, dict):
        return cached
    mapping: Dict[str, str] = {}
    for n, d in G.nodes(data=True):
        if str(d.get("type") or "").lower() != "domain":
            continue
        props = d.get("props") or {}
        dname = d.get("name") or props.get("name") or props.get("Name") or ""
        candidates = [
            props.get("domainsid"),
            props.get("domainSid"),
            props.get("objectid"),
            props.get("ObjectIdentifier"),
            n if _looks_like_sid(str(n)) else None,
        ]
        for sid in candidates:
            if sid and _looks_like_sid(str(sid)) and dname and not _looks_like_sid(str(dname)):
                mapping[str(sid)] = str(dname)
    G.graph["_bb_domain_sids"] = mapping
    return mapping


def format_sid_with_domain_context(sid: str, domain_sids: Dict[str, str]) -> str:
    """Label a raw SID using known domain SID prefixes (foreign / unresolved)."""
    s = str(sid or "")
    if not _looks_like_sid(s):
        return s
    # Longest domain SID prefix match
    best = None
    best_len = -1
    for dsid, dname in (domain_sids or {}).items():
        if s == dsid or s.startswith(dsid + "-"):
            if len(dsid) > best_len:
                best = (dsid, dname)
                best_len = len(dsid)
    if best:
        dsid, dname = best
        if s == dsid:
            return f"{dname} ({s})"
        rid = s[len(dsid) + 1 :]
        return f"FOREIGN ({dname} RID-{rid})"
    return f"UNRESOLVED ({s})"


def resolve_principal_display_name(G, oid) -> str:
    """Best display name for a principal node (prefer non-SID labels)."""
    if oid not in G:
        domain_sids = collect_known_domain_sids(G) if G is not None else {}
        return format_sid_with_domain_context(str(oid), domain_sids)
    d = G.nodes[oid] or {}
    name = d.get("name") or str(oid)
    if not _looks_like_sid(name):
        return name
    props = d.get("props") or {}
    for key in ("name", "Name", "displayname", "displayName", "samaccountname", "samAccountName"):
        cand = props.get(key)
        if cand and not _looks_like_sid(str(cand)):
            return str(cand)
    domain_sids = collect_known_domain_sids(G)
    return format_sid_with_domain_context(name, domain_sids)


def _is_admin_tier_principal_name(name: str) -> bool:
    """Admin-tier groups for ACL noise (excludes Domain Controllers / operators)."""
    if not name:
        return False
    if _is_builtin_administrators_name(name):
        return True
    nl = str(name).lower()
    sam = _principal_sam(name)
    if any(
        p in nl
        for p in (
            "domain admins",
            "enterprise admins",
            "schema admins",
            "enterprise key admins",
        )
    ):
        return True
    if sam in (
        "domain admins",
        "enterprise admins",
        "schema admins",
        "enterprise key admins",
        "key admins",
        "krbtgt",
    ):
        return True
    if nl.startswith("key admins@") or nl.startswith("krbtgt@"):
        return True
    return False


# Admin-tier domain RIDs (excludes Domain Controllers 516 for computer ACL noise filters)
EXPECTED_ADMIN_RIDS = frozenset({
    "512",  # Domain Admins
    "518",  # Schema Admins
    "519",  # Enterprise Admins
    "526",  # Key Admins
    "527",  # Enterprise Key Admins
})


def _is_expected_admin_sid(oid: str, name: str = "") -> bool:
    """Builtin Administrators + domain admin-tier RIDs (incl. foreign forest EA)."""
    for val in (oid, name):
        s = str(val or "")
        su = s.upper()
        if "S-1-5-32-544" in su or su.endswith("S-1-5-32-544"):
            return True
        rid = _sid_trailing_rid(s)
        if rid in EXPECTED_ADMIN_RIDS:
            return True
    return False


def is_expected_admin_principal(G, oid: str, max_depth: int = 25) -> bool:
    """True if principal is a built-in admin (or nested into one) for ACL noise filters.

    Unlike is_expected_dcsync_principal, this does **not** treat Domain Controllers /
    RODC / Account Operators as expected computer-ACL holders — only admin tier groups.
    """
    name = ""
    if oid in G:
        name = (G.nodes[oid].get("name") or "")
        if _is_admin_tier_principal_name(name):
            return True
    if _is_expected_admin_sid(str(oid), name):
        return True
    if oid not in G:
        return False
    seen = set()
    stack = [(oid, 0)]
    while stack:
        cur, depth = stack.pop()
        if cur in seen or depth > max_depth:
            continue
        seen.add(cur)
        for _, dst, ed in G.out_edges(cur, data=True):
            label = (ed.get("label") or "").lower()
            if label not in ("memberof", "member_of", "member"):
                continue
            dname = (G.nodes.get(dst) or {}).get("name") or ""
            if _is_admin_tier_principal_name(dname) or _is_expected_admin_sid(str(dst), dname):
                return True
            if depth + 1 <= max_depth:
                stack.append((dst, depth + 1))
    return False


def collect_can_configure_rbcd(G, domain_filter=None, exclude_default_priv: bool = True) -> List[dict]:
    """Non-default principals who can configure RBCD on a computer resource.

    Scans computer in-edges only (not the full edge set) and memoizes nested
    high-priv membership checks so large SharpHound graphs stay responsive.
    Keeps a single best right per (principal, target).
    """
    best: Dict[Tuple[Any, Any], dict] = {}
    expected_cache: Dict[Any, bool] = {}

    def _is_expected(oid) -> bool:
        cached = expected_cache.get(oid)
        if cached is not None:
            return cached
        result = is_expected_admin_principal(G, oid)
        expected_cache[oid] = result
        return result

    for v, vd in G.nodes(data=True):
        if vd.get("is_azure"):
            continue
        if str(vd.get("type") or "").lower() != "computer":
            continue
        if domain_filter and not _domain_matches(vd, domain_filter):
            continue
        target = vd.get("name") or str(v)
        for u, _, ed in G.in_edges(v, data=True):
            label = ed.get("label") or ""
            label_l = label.lower()
            if label_l not in RBCD_CONFIGURE_RIGHTS:
                continue
            ud = G.nodes.get(u) or {}
            if ud.get("is_azure"):
                continue
            principal = resolve_principal_display_name(G, u)
            if exclude_default_priv and (
                _is_default_high_priv_name(principal) or _is_expected(u)
            ):
                continue
            key = (u, v)
            rank = RBCD_RIGHT_RANK.get(label_l, 0)
            prev = best.get(key)
            if prev is None or rank > prev.get("_rank", -1):
                best[key] = {
                    "principal": principal,
                    "target": target,
                    "right": label,
                    "principal_oid": u,
                    "target_oid": v,
                    "_rank": rank,
                }
    rows = [{k: v for k, v in r.items() if k != "_rank"} for r in best.values()]
    rows.sort(key=lambda r: (r["principal"], r["target"], r["right"]))
    return rows


def summarize_can_configure_rbcd(rows: List[dict]) -> List[dict]:
    """Roll up can-configure-RBCD rows by principal (count + sample targets/rights)."""
    by_prin: Dict[str, dict] = {}
    for r in rows:
        p = r.get("principal") or ""
        bucket = by_prin.get(p)
        if bucket is None:
            bucket = {
                "principal": p,
                "principal_oid": r.get("principal_oid"),
                "count": 0,
                "targets": [],
                "rights": set(),
            }
            by_prin[p] = bucket
        bucket["count"] += 1
        bucket["rights"].add(r.get("right") or "")
        if len(bucket["targets"]) < 3:
            t = r.get("target") or ""
            if t and t not in bucket["targets"]:
                bucket["targets"].append(t)
    summary = []
    for bucket in by_prin.values():
        summary.append(
            {
                "principal": bucket["principal"],
                "principal_oid": bucket["principal_oid"],
                "count": bucket["count"],
                "targets": bucket["targets"],
                "rights": sorted(bucket["rights"]),
            }
        )
    summary.sort(key=lambda s: (-s["count"], s["principal"]))
    return summary


def _rbcd_configure_severity(G, summary_row: dict, rows: List[dict]) -> Tuple[int, str]:
    """Tier can-configure-RBCD: DC target critical; bulk domain-join lower severity."""
    count = int(summary_row.get("count") or 0)
    principal = (summary_row.get("principal") or "").lower()
    rights = {str(r).lower() for r in (summary_row.get("rights") or [])}
    # Any grant on a domain controller → critical
    hits_dc = False
    for r in rows:
        if r.get("principal") != summary_row.get("principal"):
            continue
        tid = r.get("target_oid")
        tname = (r.get("target") or "").lower()
        if tid and tid in G:
            props = (G.nodes[tid].get("props") or {})
            if get_bool_prop_ci(props, ["isdc", "IsDC"]) or "domain controllers" in (
                (props.get("distinguishedname") or props.get("distinguishedName") or "")
            ).lower():
                hits_dc = True
                break
        if "dc." in tname or tname.startswith("dc") or ".dc." in tname:
            # weak name heuristic only when props missing
            if "domaincontrol" in tname or tname.startswith("dc") or "-dc." in tname:
                hits_dc = True
                break
        if tid and tid in G:
            nd = G.nodes[tid]
            # MemberOf Domain Controllers group
            for _, dst, ed in G.out_edges(tid, data=True):
                if (ed.get("label") or "").lower() not in ("memberof", "member_of", "member"):
                    continue
                gname = ((G.nodes.get(dst) or {}).get("name") or "").lower()
                if "domain controllers@" in gname or gname.startswith("domain controllers"):
                    hits_dc = True
                    break
            if hits_dc:
                break
    if hits_dc:
        return 9, "includes domain controller"
    # Common domain-join / SCCM style bulk WAR
    joinish = any(
        x in principal
        for x in ("domainjoin", "domain-join", "sccm", "mdm", "intune", "join")
    )
    war_only = rights and rights <= {"writeaccountrestrictions", "owns", "allextendedrights"}
    if count >= 20 and (joinish or war_only):
        return 7, "bulk domain-join style ACL (verify scope)"
    if count >= 50:
        return 7, "very broad computer control"
    if "genericall" in rights or "genericwrite" in rights:
        return 9, "strong write on computer object(s)"
    return 8, "can configure RBCD"


def print_can_configure_rbcd(G, domain_filter=None):
    console.rule(
        "[bold magenta]Can Configure RBCD (write AllowedToAct on resource) (AD)[/bold magenta]"
    )
    rows = collect_can_configure_rbcd(G, domain_filter)
    summary = summarize_can_configure_rbcd(rows)
    max_display = 40
    max_findings = 50
    console.print(
        f"  [dim]{len(rows)} computer grant(s) across {len(summary)} principal(s)[/dim]"
    )
    for i, s in enumerate(summary):
        samples = ", ".join(s["targets"])
        if s["count"] > len(s["targets"]):
            samples += f", … (+{s['count'] - len(s['targets'])} more)"
        rights = ", ".join(s["rights"][:4])
        score, tier_note = _rbcd_configure_severity(G, s, rows)
        if i < max_display:
            console.print(
                f"  • [green]{s['principal']}[/green] "
                f"[red]×{s['count']}[/red] computers "
                f"[dim]({rights}; {tier_note})[/dim] e.g. [cyan]{samples}[/cyan]"
            )
        if i < max_findings:
            add_finding(
                "Can Configure RBCD",
                f"{s['principal']} can configure RBCD on {s['count']} computer(s) "
                f"via {rights} [{tier_note}]",
                score=score,
            )
    if len(summary) > max_display:
        console.print(f"  [dim]... and {len(summary) - max_display} more principals[/dim]")
    if len(summary) > max_findings:
        add_finding(
            "Can Configure RBCD",
            f"{len(summary) - max_findings} additional principals with can-configure-RBCD grants",
            score=8,
        )
    if rows:
        console.print(
            Panel(
                "[bold red]Impact:[/bold red] Write msDS-AllowedToActOnBehalfOfOtherIdentity → "
                "impersonate any user to the resource (RBCD).\n"
                "[bold]Abuse:[/bold] Add attacker computer as AllowedToAct, then S4U2Self/S4U2Proxy.\n"
                "[bold]Mitigation:[/bold] Remove broad GenericAll/WriteDacl/WriteAccountRestrictions "
                "on computers from non-admin principals.",
                title="Abuse Suggestions: Can Configure RBCD",
                border_style="red",
            )
        )
    else:
        if not _QUIET_EMPTY_SECTIONS:
            console.print("[green]No non-default principals can configure RBCD[/green]")


def print_shortest_paths(G, fast=False, max_paths=10, target_filter=None, domain_filter=None, indirect=False):
    console.rule("[bold magenta]Shortest Paths to High-Value Targets[/bold magenta]")
    users = [n for n, d in G.nodes(data=True) if d['type'].lower() in ['user', 'azure user'] and _domain_matches(d, domain_filter)]
    targets = get_high_value_targets(G, domain_filter)
    if target_filter:
        targets = [t for t in targets if target_filter.lower() in t[1].lower()]
    if not targets:
        console.print("[yellow]No high-value targets found (or none match filter)[/yellow]")
        return
    if not users:
        console.print("[yellow]No user objects found for path calculation[/yellow]")
        return
    # Prefer non-admin footholds as path sources (paths *from* Domain Admins group
    # objects are noise). Nested DA *members* must still appear as sources —
    # that is the attack path.
    def _is_noisy_source(oid: str) -> bool:
        name = (G.nodes[oid].get("name") or "")
        return _is_default_high_priv_name(name)

    interesting_users = [u for u in users if not _is_noisy_source(u)]
    if not interesting_users:
        interesting_users = users
    # Prioritize classic DA/EA/Administrators/krbtgt-style targets; in --fast only use these few
    priority_kw = (
        'domain admins', 'enterprise admins', 'schema admins', 'administrators', 'krbtgt',
        'global admin', 'privileged role admin',
    )
    prioritized = [t for t in targets if any(k in t[1].lower() for k in priority_kw)]
    if fast:
        targets_run = (prioritized or targets)[:3]
        max_paths = min(max_paths, 3)
        console.print(
            f"[yellow]Fast mode: limited pathfinding "
            f"({len(targets_run)} high-value targets, max {max_paths} paths each)[/yellow]"
        )
    else:
        # Prefer priority HV; fill remaining slots
        targets_run = list(prioritized)
        seen = {t[0] for t in targets_run}
        for t in targets:
            if t[0] not in seen:
                targets_run.append(t)
                seen.add(t[0])
            if len(targets_run) >= 8:
                break
    abuse_labels = {
        'genericall', 'genericwrite', 'writedacl', 'writeowner', 'owns',
        'forcechangepassword', 'addmember', 'allowedtoact',
        'adminto', 'localadmin', 'addkeycredentiallink', 'getchanges',
        'getchangesall', 'allextendedrights',
    }

    def _path_abuse_score(path) -> int:
        """Higher = more abuse edges (prefer interesting paths over pure MemberOf chains)."""
        score = 0
        for i in range(len(path) - 1):
            lab = (_edge_label(G, path[i], path[i + 1]) or "").lower()
            if lab in abuse_labels or lab.replace(" ", "") in abuse_labels:
                score += 3
            elif lab in ('memberof', 'member', 'contains'):
                score += 0
            elif lab in ('hassession',):
                score += 2
            else:
                score += 1
        return score

    for tid, tname, ttype in targets_run:
        console.print(f"\n[bold]Target:[/bold] [bold cyan]{tname}[/bold cyan] ({ttype})")
        count = 0
        # Prefer reverse shortest paths from target (cheaper than has_path × all users)
        try:
            lengths = nx.single_source_shortest_path_length(G.reverse(copy=False), tid, cutoff=12)
        except Exception:
            lengths = {}
        # Candidate sources: non-admin users that reach target
        candidates = []
        for source in interesting_users:
            if source == tid:
                continue
            if source in lengths:
                candidates.append((lengths[source], source))
        candidates.sort(key=lambda x: x[0])
        scored_paths = []
        for _, source in candidates[:200]:  # bound work
            try:
                path = nx.shortest_path(G, source, tid)
                scored_paths.append((-_path_abuse_score(path), len(path), path))
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
        scored_paths.sort()
        for _, __, path in scored_paths:
            path_length = len(path) - 1
            formatted_path = format_path(G, path)
            console.print(f"  [dim]→[/dim] (Length: {path_length}) {formatted_path}")
            count += 1
            if count >= max_paths:
                break
        if indirect and not fast:
            console.print(f"  [dim]Indirect paths (via groups):[/dim]")
            indirect_count = 0
            for source in users:
                paths = get_indirect_paths(G, source, tid)
                for path in paths:
                    formatted_path = format_path(G, path)
                    console.print(f"    [dim]→[/dim] {formatted_path}")
                    indirect_count += 1
                    if indirect_count >= max_paths:
                        break
                if indirect_count >= max_paths:
                    break
        if count == 0:
            console.print("    [dim]No paths found within limit[/dim]")
        else:
            add_finding("Shortest Paths", f"{count} path(s) to {tname}", score=6)

def print_dangerous_permissions(G, domain_filter=None, indirect=False, fast=False):
    sec = DeferredSection("Dangerous Permissions on High-Value Objects")
    dangerous_rights = {'genericall', 'owns', 'writedacl', 'writeowner', 'allextendedrights', 'genericwrite', 'addmember', 'resetpassword', 'forcechangepassword', 'manageca', 'managecertificates', 'enroll', 'certificateenroll', 'writeproperty'}
    azure_dangerous = {'genericall', 'owns', 'writedacl', 'writeowner', 'addsecret', 'addcertificate', 'addowner', 'execute', 'canread', 'canwrite', 'candelete'}
    targets = get_high_value_targets(G, domain_filter)
    found = False
    if not targets:
        sec.empty("No high-value targets found")
        return
    # Enterprise: prefer classic DA/EA/Administrators/krbtgt when HV set is huge
    max_targets = 40 if fast else 80
    limited_note = None
    if len(targets) > max_targets:
        priority = _priority_high_value_targets(G, domain_filter, limit=max_targets)
        if priority:
            limited_note = (
                f"Limiting dangerous-ACL scan to {len(priority)} priority high-value "
                f"targets (of {len(targets)} total; use without --fast for more)"
            )
            targets = priority
        else:
            targets = targets[:max_targets]
    max_display = 40
    max_findings = 50
    shown = 0
    findings_n = 0
    for tid, tname, ttype in targets:
        incoming = G.in_edges(tid, data=True)
        is_azure = G.nodes[tid].get('is_azure', False)
        rights_set = azure_dangerous if is_azure else dangerous_rights
        dangerous_edges = []
        for u, v, d in incoming:
            if u not in G.nodes or 'label' not in d:
                continue
            if d['label'].lower() not in rights_set:
                continue
            uname = G.nodes[u].get('name') or str(u)
            # Expected high-priv holders on HV objects are noise, not findings
            if _is_default_high_priv_name(uname):
                continue
            if not is_azure and is_expected_admin_principal(G, u):
                continue
            dangerous_edges.append((u, d['label']))
        if dangerous_edges:
            found = True
            sec.mark()
            if limited_note:
                console.print(f"[yellow]{limited_note}[/yellow]")
                limited_note = None
            if shown == 0:
                console.print(
                    "[dim]Showing non-default principals only "
                    "(Domain Admins / EA / Builtin Admins filtered)[/dim]"
                )
            if shown < max_display:
                console.print(f"\n[bold cyan]{tname} ({ttype}):[/bold cyan]")
                rights_by_type = defaultdict(list)
                for principal_oid, right in dangerous_edges:
                    rights_by_type[right].append(principal_oid)
                for right, principals in rights_by_type.items():
                    principal_names = [
                        resolve_principal_display_name(G, p) for p in principals[:5]
                    ]
                    count = len(principals)
                    extra = f" ... and {count - 5} more" if count > 5 else ""
                    console.print(
                        f"  • [yellow]{right}[/yellow]: "
                        f"[green]{', '.join(principal_names)}{extra}[/green]"
                    )
                console.print(
                    "    [dim](Note: Only direct non-default rights; "
                    "indirect via groups not included)[/dim]"
                )
                shown += 1
            if findings_n < max_findings:
                add_finding(
                    "Dangerous Permissions",
                    f"Non-default dangerous rights on {tname}",
                    score=9,
                )
                findings_n += 1
    if found and shown < findings_n:
        console.print(
            f"[dim]... displayed {shown} of {findings_n} dangerous-ACL targets[/dim]"
        )
    if findings_n >= max_findings:
        add_finding(
            "Dangerous Permissions",
            f"Additional high-value objects with non-default dangerous ACLs "
            f"(capped at {max_findings} findings)",
            score=9,
        )
    if indirect:
        console.print(f"\n[dim]Checking indirect dangerous permissions via groups...[/dim]")
        # Only walk edges into scanned targets (not full graph edge set)
        for tid, tname, ttype in targets[:max_targets]:
            for u, _, d in G.in_edges(tid, data=True):
                if 'label' not in d:
                    continue
                rights_set = (
                    azure_dangerous
                    if G.nodes[tid].get('is_azure', False)
                    else dangerous_rights
                )
                if d['label'].lower() not in rights_set:
                    continue
                group_name = G.nodes[u]['name']
                if _is_default_high_priv_name(group_name):
                    continue
                if G.nodes[u]['type'].lower() in ['group', 'azure group']:
                    members = [
                        m for m in G.predecessors(u)
                        if any(
                            edge_data.get('label') == 'MemberOf'
                            for edge_data in (G.get_edge_data(m, u) or {}).values()
                        )
                    ]
                    if members:
                        console.print(
                            f"  [yellow]Indirect via group {group_name}[/yellow]: "
                            f"{', '.join([G.nodes[m]['name'] for m in members[:3]])}"
                        )
    if found:
        print_abuse_panel("Dangerous Permissions")
    else:
        sec.empty("No non-default dangerous ACLs found on high-value objects")


# Non-HV ACL abuse: ForceChangePassword, GenericAll/Write on users/groups/computers
# that HV scan misses. Bulk computer GenericWrite (connector noise) is suppressed.
INTERESTING_ACL_RIGHTS = frozenset({
    "forcechangepassword",
    "resetpassword",
    "genericall",
    "genericwrite",
    "writedacl",
    "writeowner",
    "owns",
    "addmember",
    "addkeycredentiallink",
    "allextendedrights",
})
INTERESTING_ACL_TARGET_TYPES = frozenset({"user", "computer", "group"})
# Per principal+right: more computer targets than this = connector inventory noise
INTERESTING_ACL_MAX_COMPUTER_TARGETS = 25
INTERESTING_ACL_MAX_USER_TARGETS = 40
INTERESTING_ACL_MAX_GROUP_TARGETS = 40
INTERESTING_ACL_MAX_DISPLAY = 50
INTERESTING_ACL_MAX_FINDINGS = 60


def _interesting_acl_score(right_l: str, target_type_l: str) -> int:
    if right_l in ("forcechangepassword", "resetpassword", "addkeycredentiallink"):
        return 8
    if right_l in ("genericall", "writedacl", "writeowner", "owns", "allextendedrights"):
        return 8
    if right_l == "addmember":
        return 7
    if right_l == "genericwrite":
        return 7 if target_type_l in ("user", "computer", "group") else 6
    return 6


def collect_interesting_acl_abuse(G, domain_filter=None) -> List[dict]:
    """Non-default dangerous ACLs on user/computer/group targets (including non-HV).

    Complements print_dangerous_permissions (HV-only). Suppresses broad principals,
    expected admins, and bulk computer GenericWrite/GenericAll (connector noise).
    """
    hv_oids = {tid for tid, _, _ in get_high_value_targets(G, domain_filter)}
    # (principal_name, right, target_type_l) -> list of target names
    buckets: Dict[Tuple[str, str, str], List[str]] = defaultdict(list)
    right_display: Dict[Tuple[str, str, str], str] = {}

    for u, v, ed in G.edges(data=True):
        label = ed.get("label") or ""
        ll = label.lower()
        if ll not in INTERESTING_ACL_RIGHTS:
            continue
        ud = G.nodes.get(u) or {}
        vd = G.nodes.get(v) or {}
        if ud.get("is_azure") or vd.get("is_azure"):
            continue
        if domain_filter and not (
            _domain_matches(ud, domain_filter) or _domain_matches(vd, domain_filter)
        ):
            continue
        ttype = str(vd.get("type") or "").lower()
        if ttype not in INTERESTING_ACL_TARGET_TYPES:
            continue
        # HV targets already covered by print_dangerous_permissions
        if v in hv_oids:
            continue
        uname = ud.get("name") or str(u)
        if _is_default_high_priv_name(uname) or _is_broad_principal_name(uname):
            continue
        if is_expected_admin_principal(G, u):
            continue
        tname = vd.get("name") or str(v)
        key = (uname, ll, ttype)
        buckets[key].append(tname)
        right_display[key] = label

    rows: List[dict] = []
    for key, tnames in buckets.items():
        uname, ll, ttype = key
        uniq = sorted(set(tnames))
        n = len(uniq)
        if ttype == "computer" and n > INTERESTING_ACL_MAX_COMPUTER_TARGETS:
            continue
        if ttype == "user" and n > INTERESTING_ACL_MAX_USER_TARGETS:
            continue
        if ttype == "group" and n > INTERESTING_ACL_MAX_GROUP_TARGETS:
            continue
        rows.append(
            {
                "principal": uname,
                "right": right_display[key],
                "right_l": ll,
                "target_type": ttype,
                "targets": uniq,
                "count": n,
                "score": _interesting_acl_score(ll, ttype),
            }
        )
    # Highest score, then most targets, then name
    rows.sort(key=lambda r: (-r["score"], -r["count"], r["principal"], r["right_l"]))
    return rows


def print_interesting_acl_abuse(G, domain_filter=None):
    """Surface non-HV ACL abuse that HV-only dangerous-permissions scan misses."""
    rows = collect_interesting_acl_abuse(G, domain_filter)
    if not rows:
        sec = DeferredSection(
            "Interesting ACL Abuse (users / computers / groups, non-high-value)"
        )
        sec.empty(
            "No interesting non-high-value ACL abuse found "
            "(non-default ForceChangePassword / GenericAll / GenericWrite / …)"
        )
        return
    console.rule(
        "[bold magenta]Interesting ACL Abuse "
        "(users / computers / groups, non-high-value)[/bold magenta]"
    )
    console.print(
        "[dim]Non-default principals only; bulk computer GenericWrite suppressed; "
        "high-value targets listed in the section above[/dim]"
    )
    shown = 0
    findings_n = 0
    for r in rows:
        examples = ", ".join(r["targets"][:3])
        extra = f" … +{r['count'] - 3} more" if r["count"] > 3 else ""
        tlabel = r["target_type"]
        if shown < INTERESTING_ACL_MAX_DISPLAY:
            if r["count"] == 1:
                console.print(
                    f"  • [green]{r['principal']}[/green] --[{r['right']}]--> "
                    f"[cyan]{r['targets'][0]}[/cyan] ({tlabel})"
                )
            else:
                console.print(
                    f"  • [green]{r['principal']}[/green] --[{r['right']}]--> "
                    f"[cyan]{r['count']}[/cyan] {tlabel}(s) "
                    f"[dim]({examples}{extra})[/dim]"
                )
            shown += 1
        if findings_n < INTERESTING_ACL_MAX_FINDINGS:
            if r["count"] == 1:
                detail = (
                    f"{r['principal']} has {r['right']} on "
                    f"{r['targets'][0]} ({tlabel})"
                )
            else:
                detail = (
                    f"{r['principal']} has {r['right']} on {r['count']} {tlabel}(s) "
                    f"(e.g. {examples}{extra})"
                )
            add_finding("Dangerous Permissions", detail, score=r["score"])
            findings_n += 1
    if len(rows) > INTERESTING_ACL_MAX_DISPLAY:
        console.print(
            f"[dim]… displayed {INTERESTING_ACL_MAX_DISPLAY} of {len(rows)} ACL abuse rows[/dim]"
        )
    print_abuse_panel("Dangerous Permissions")


def graph_has_azure(G) -> bool:
    """True if the graph contains any AzureHound / Entra node."""
    for _, d in G.nodes(data=True):
        if d.get("is_azure"):
            return True
        typ = str(d.get("type") or "").lower()
        if typ.startswith("azure") or "tenant" in typ:
            return True
    return False


def collect_broad_principal_acls(G, domain_filter=None) -> List[dict]:
    """Dangerous ACLs held by Everyone / Authenticated Users / Domain Users."""
    dangerous = {
        "genericall", "genericwrite", "writedacl", "writeowner", "owns",
        "forcechangepassword", "resetpassword", "allextendedrights",
        "addmember", "addkeycredentiallink",
    }
    interesting_types = {
        "user", "computer", "gpo", "group", "domain", "ou",
        "certificate template", "enterprise ca",
    }
    rows: List[dict] = []
    for u, v, ed in G.edges(data=True):
        label = (ed.get("label") or "")
        label_l = label.lower()
        if label_l not in dangerous:
            continue
        ud = G.nodes.get(u) or {}
        vd = G.nodes.get(v) or {}
        if ud.get("is_azure") or vd.get("is_azure"):
            continue
        principal = ud.get("name") or str(u)
        if not _is_broad_principal_name(principal):
            continue
        if domain_filter and not (
            _domain_matches(ud, domain_filter) or _domain_matches(vd, domain_filter)
        ):
            continue
        vtype = str(vd.get("type") or "").lower()
        if vtype not in interesting_types:
            continue
        rows.append(
            {
                "principal": principal,
                "target": vd.get("name") or str(v),
                "target_type": vd.get("type") or "?",
                "right": label,
            }
        )
    rows.sort(key=lambda r: (r["principal"], r["target_type"], r["target"], r["right"]))
    return rows


def print_broad_principal_acls(G, domain_filter=None):
    sec = DeferredSection(
        "Broad Principal ACLs (Everyone / Auth Users / Domain Users) (AD)"
    )
    rows = collect_broad_principal_acls(G, domain_filter)
    max_display = 40
    max_findings = 50
    for i, r in enumerate(rows):
        sec.mark()
        if i < max_display:
            console.print(
                f"  • [red]{r['principal']}[/red] --[{r['right']}]--> "
                f"[cyan]{r['target']}[/cyan] ({r['target_type']})"
            )
        if i < max_findings:
            add_finding(
                "Broad Principal ACL",
                f"{r['principal']} has {r['right']} on {r['target']} ({r['target_type']})",
                score=9,
            )
    if len(rows) > max_display:
        console.print(f"  [dim]... and {len(rows) - max_display} more[/dim]")
    if rows:
        console.print(
            Panel(
                "[bold red]Impact:[/bold red] Domain-wide principals with write/reset rights → "
                "any authenticated user can abuse the target.\n"
                "[bold]Mitigation:[/bold] Remove Everyone/Authenticated Users/Domain Users from "
                "dangerous ACLs; prefer tiered admin groups.",
                title="Abuse Suggestions: Broad Principal ACLs",
                border_style="red",
            )
        )
    else:
        sec.empty("No dangerous ACLs held by Everyone/Auth Users/Domain Users")


def _user_has_spn(props) -> bool:
    """True if the user is Kerberoastable via hasspn flag or non-empty SPN list.

    Some collections set ``serviceprincipalnames`` without a reliable ``hasspn``
    bool (partial ObjectProps, older exporters, hand-merged JSON). Counting
    ``"hasspn": true`` in raw JSON can also miss accounts that only have the list.
    """
    if get_bool_prop_ci(props, ['hasspn', 'hasSPN', 'has_spn']):
        return True
    spns = _prop_raw_ci(
        props,
        ['serviceprincipalnames', 'servicePrincipalNames', 'serviceprincipalname', 'ServicePrincipalNames'],
    )
    if isinstance(spns, list):
        return any(bool(s) for s in spns)
    if isinstance(spns, str):
        return bool(spns.strip())
    return False


def print_kerberoastable(G, domain_filter=None):
    sec = DeferredSection("Kerberoastable Accounts (AD)")
    hits = []
    max_display = 50
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if str(d.get('type', '')).lower() != 'user':
            continue
        props = d.get('props') or {}
        hasspn = _user_has_spn(props)
        # Note: SharpHound "sensitive" = NOT_DELEGATED (cannot be delegated), NOT
        # "immune to Kerberoast". Still roastable offline — do not filter it out.
        enabled = _account_is_enabled(props, default=True)
        # krbtgt always has an SPN but is not a practical Kerberoast target here
        name = d.get('name') or ''
        if name.upper().startswith('KRBTGT@') or name.upper() == 'KRBTGT':
            continue
        if hasspn and enabled:
            hits.append((n, d))
    if not hits:
        sec.empty("None found")
        return
    sec.mark()
    console.print(f"[dim]Found {len(hits)} kerberoastable account(s)[/dim]")
    for i, (oid, d) in enumerate(hits):
        props = d.get('props') or {}
        uac_raw = _prop_raw_ci(props, ['useraccountcontrol', 'UserAccountControl'])
        uac_str = f" | UAC: {decode_uac(uac_raw)}" if uac_raw is not None else ""
        ctx = format_privilege_context_tags(d)
        is_priv, _ = is_member_of_privileged_group(G, oid)
        priv_tag = " [red][PRIV][/red]" if is_priv else ""
        if i < max_display:
            console.print(f"  • [cyan]{d['name']}[/cyan]{uac_str}{ctx}{priv_tag}")
        # One findings-table row per account (not a single aggregated count)
        add_finding("Kerberoastable", f"{d['name']} has SPN (Kerberoastable){ctx}", score=5)
    if len(hits) > max_display:
        console.print(
            f"  [dim]... and {len(hits) - max_display} more "
            f"(total {len(hits)}; use --export json for full list)[/dim]"
        )
    print_abuse_panel("Kerberoastable")

def print_as_rep_roastable(G, domain_filter=None):
    sec = DeferredSection("AS-REP Roastable Accounts (DONT_REQ_PREAUTH) (AD)")
    hits = []
    max_display = 50
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if str(d.get('type', '')).lower() != 'user':
            continue
        props = d.get('props') or {}
        dontreqpreauth = get_bool_prop_ci(
            props, ['dontreqpreauth', 'dontReqPreauth', 'dont_req_preauth']
        )
        if not dontreqpreauth:
            uac_raw = _prop_raw_ci(props, ['useraccountcontrol', 'UserAccountControl'])
            try:
                # DONT_REQ_PREAUTH
                dontreqpreauth = bool(int(uac_raw) & 0x400000)
            except (TypeError, ValueError):
                pass
        # "sensitive" (NOT_DELEGATED) does not block AS-REP roasting
        enabled = _account_is_enabled(props, default=True)
        if dontreqpreauth and enabled:
            hits.append((n, d))
    if not hits:
        sec.empty("None found")
        return
    sec.mark()
    console.print(f"[dim]Found {len(hits)} AS-REP roastable account(s)[/dim]")
    for i, (oid, d) in enumerate(hits):
        props = d.get('props') or {}
        uac_raw = _prop_raw_ci(props, ['useraccountcontrol', 'UserAccountControl'])
        uac_str = f" | UAC: {decode_uac(uac_raw)}" if uac_raw is not None else ""
        ctx = format_privilege_context_tags(d)
        is_priv, _ = is_member_of_privileged_group(G, oid)
        priv_tag = " [red][PRIV][/red]" if is_priv else ""
        if i < max_display:
            console.print(f"  • [cyan]{d['name']}[/cyan]{uac_str}{ctx}{priv_tag}")
        add_finding(
            "AS-REP Roastable",
            f"{d['name']} has DONT_REQ_PREAUTH (AS-REP roastable){ctx}",
            score=5,
        )
    if len(hits) > max_display:
        console.print(
            f"  [dim]... and {len(hits) - max_display} more "
            f"(total {len(hits)}; use --export json for full list)[/dim]"
        )
    print_abuse_panel("AS-REP Roastable")


PRIVILEGED_GROUP_MATCHERS = (
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators@",
    "builtin\\administrators",
    "account operators",
    "backup operators",
    "server operators",
    "print operators",
    "dnsadmins",
    "group policy creator owners",
    "enterprise key admins",
    "key admins@",
)


def _group_name_is_privileged(name: str) -> bool:
    if not name:
        return False
    if _is_builtin_administrators_name(name):
        return True
    nl = str(name).lower()
    if any(m in nl for m in PRIVILEGED_GROUP_MATCHERS):
        return True
    sam = _principal_sam(name)
    return sam in (
        "administrators",
        "domain admins",
        "enterprise admins",
        "schema admins",
        "dnsadmins",
        "account operators",
        "backup operators",
        "server operators",
        "print operators",
        "group policy creator owners",
        "enterprise key admins",
        "key admins",
    )


def is_member_of_privileged_group(G, oid: str, max_depth: int = 25) -> Tuple[bool, List[str]]:
    """True if principal is nested MemberOf a privileged group (DA/EA/Administrators/…).

    Returns (is_priv, list of privileged group names on the path).
    """
    if oid not in G:
        return False, []
    priv_groups: List[str] = []
    seen = set()
    stack = [(oid, 0)]
    while stack:
        cur, depth = stack.pop()
        if cur in seen or depth > max_depth:
            continue
        seen.add(cur)
        # Outbound MemberOf (user → group)
        for _, dst, ed in G.out_edges(cur, data=True):
            label = (ed.get("label") or "").lower()
            if label not in ("memberof", "member_of", "member"):
                continue
            nd = G.nodes.get(dst) or {}
            name = nd.get("name") or ""
            if _group_name_is_privileged(name):
                if name not in priv_groups:
                    priv_groups.append(name)
            if depth + 1 <= max_depth:
                stack.append((dst, depth + 1))
    return bool(priv_groups), priv_groups


def collect_privileged_roast_targets(G, domain_filter=None) -> List[dict]:
    """Users that are Kerberoastable and/or AS-REP roastable and nested into priv groups.

    Also treats AdminCount=1 + roastable as privileged when group walk finds nothing
    (partial collections / missing MemberOf edges).
    """
    rows: List[dict] = []
    for n, d in G.nodes(data=True):
        if d.get("is_azure", False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if str(d.get("type", "")).lower() != "user":
            continue
        props = d.get("props") or {}
        name = d.get("name") or ""
        if name.upper().startswith("KRBTGT@") or name.upper() == "KRBTGT":
            continue
        # Do not filter SharpHound "sensitive" (NOT_DELEGATED) — still roastable.
        enabled = _account_is_enabled(props, default=True)
        if not enabled:
            continue
        kerb = _user_has_spn(props)
        asrep = get_bool_prop_ci(
            props, ["dontreqpreauth", "dontReqPreauth", "dont_req_preauth"]
        )
        if not asrep:
            uac_raw = _prop_raw_ci(props, ["useraccountcontrol", "UserAccountControl"])
            try:
                asrep = bool(int(uac_raw) & 0x400000)
            except (TypeError, ValueError):
                pass
        if not kerb and not asrep:
            continue
        is_priv, groups = is_member_of_privileged_group(G, n)
        if not is_priv and get_bool_prop_ci(props, ["admincount", "adminCount"], default=False):
            is_priv = True
            groups = list(groups) + ["AdminCount=1"]
        if not is_priv:
            continue
        rows.append(
            {
                "oid": n,
                "name": name,
                "kerberoastable": kerb,
                "asrep": asrep,
                "groups": groups,
                "node": d,
            }
        )
    rows.sort(key=lambda r: (not r["kerberoastable"] or not r["asrep"], r["name"]))
    return rows


def print_privileged_roast_targets(G, domain_filter=None):
    sec = DeferredSection(
        "Privileged Kerberoast / AS-REP (nested into DA/EA/…) (AD)"
    )
    rows = collect_privileged_roast_targets(G, domain_filter)
    if not rows:
        sec.empty("No privileged Kerberoast / AS-REP targets found")
        return
    sec.mark()
    max_display = 30
    for i, r in enumerate(rows):
        kinds = []
        if r["kerberoastable"]:
            kinds.append("Kerberoast")
        if r["asrep"]:
            kinds.append("AS-REP")
        kind_str = "+".join(kinds)
        groups = ", ".join(r["groups"][:3])
        if len(r["groups"]) > 3:
            groups += f" (+{len(r['groups']) - 3})"
        ctx = format_privilege_context_tags(r["node"])
        if i < max_display:
            console.print(
                f"  • [red]{r['name']}[/red] [{kind_str}] via [cyan]{groups}[/cyan]{ctx}"
            )
        if r["kerberoastable"]:
            add_finding(
                "Privileged Kerberoastable",
                f"{r['name']} is Kerberoastable and member of {groups}{ctx}",
                score=9,
            )
        if r["asrep"]:
            add_finding(
                "Privileged AS-REP Roastable",
                f"{r['name']} is AS-REP roastable and member of {groups}{ctx}",
                score=9,
            )
    if len(rows) > max_display:
        console.print(f"  [dim]... and {len(rows) - max_display} more[/dim]")
    if rows:
        console.print(
            Panel(
                "[bold red]Impact:[/bold red] Roasting a privileged account can yield DA/EA credentials offline.\n"
                "[bold]Abuse:[/bold] Kerberoast SPN users / AS-REP roast DONT_REQ_PREAUTH, then crack.\n"
                "[bold]Mitigation:[/bold] Remove SPNs and preauth-disable from privileged accounts; "
                "use gMSAs; protect with Protected Users.",
                title="Abuse Suggestions: Privileged Roast",
                border_style="red",
            )
        )


def print_sessions_localadmin(G, domain_filter=None, fast=False):
    """Summarize LocalAdmin/RDP/DCOM breadth and HasSession inventory.

    Single O(E) edge pass — enterprise graphs have millions of edges; never
    re-scan the full edge set per principal (was quadratic and hung on large
    collections even under --fast / --quick-wins).
    """
    console.rule("[bold magenta]Session / LocalAdmin / RDP / DCOM Summary (AD)[/bold magenta]")
    computers = {
        n
        for n, d in G.nodes(data=True)
        if str(d.get("type") or "").lower() == "computer"
        and _domain_matches(d, domain_filter)
        and not d.get("is_azure", False)
    }
    if not computers:
        console.print("[yellow]No computers found[/yellow]")
        return
    table = Table(title="Top Local Admins / RDP / DCOM", show_header=True, header_style="bold magenta")
    table.add_column("Principal", style="cyan")
    table.add_column("Rights", justify="right")
    table.add_column("Count", justify="right")
    table.add_column("Examples", style="green")
    from collections import defaultdict, Counter
    # Local group edges only — GenericAll is an AD object ACL, not local admin.
    rights = frozenset({"LocalAdmin", "AdminTo", "CanRDP", "ExecuteDCOM"})
    counts = defaultdict(Counter)
    # right -> principal -> up to 3 example computer display names
    examples_map = defaultdict(lambda: defaultdict(list))
    max_examples = 3
    max_sess = 20 if fast else 40
    max_priv_check = 50 if fast else 200
    unique_sess = []
    seen_sess = set()

    for u, v, d in G.edges(data=True):
        label = d.get("label") or ""
        if label in rights and v in computers:
            counts[label][u] += 1
            ex = examples_map[label][u]
            if len(ex) < max_examples:
                ex.append(resolve_principal_display_name(G, v))
            continue
        if label != "HasSession":
            continue
        ud, vd = G.nodes.get(u) or {}, G.nodes.get(v) or {}
        if str(ud.get("type") or "").lower() == "computer":
            comp, user = u, v
        elif str(vd.get("type") or "").lower() == "computer":
            comp, user = v, u
        else:
            continue
        if domain_filter and not (
            _domain_matches(G.nodes.get(comp) or {}, domain_filter)
            or _domain_matches(G.nodes.get(user) or {}, domain_filter)
        ):
            continue
        key = (comp, user)
        if key in seen_sess:
            continue
        seen_sess.add(key)
        unique_sess.append((comp, user))

    for right, c in counts.items():
        for principal, count in c.most_common(5):
            table.add_row(
                resolve_principal_display_name(G, principal),
                right,
                str(count),
                ", ".join(examples_map[right][principal][:max_examples]),
            )
    console.print(table)

    sess_table = Table(
        title="HasSession (user sessions on computers)",
        show_header=True,
        header_style="bold yellow",
    )
    sess_table.add_column("Computer", style="cyan")
    sess_table.add_column("User", style="green")
    for i, (c, u) in enumerate(unique_sess):
        if i >= max_sess:
            break
        sess_table.add_row(
            resolve_principal_display_name(G, c),
            resolve_principal_display_name(G, u),
        )
    if unique_sess:
        console.print(sess_table)
        if len(unique_sess) > max_sess:
            console.print(f"  [dim]... and {len(unique_sess) - max_sess} more sessions[/dim]")
        # High-signal: one privileged session sample (cap BFS checks on large graphs)
        for c, u in unique_sess[:max_priv_check]:
            uname = resolve_principal_display_name(G, u)
            if is_member_of_privileged_group(G, u)[0] or _is_default_high_priv_name(uname):
                cname = resolve_principal_display_name(G, c)
                add_finding(
                    "HasSession",
                    f"Privileged session: {uname} on {cname}",
                    score=7,
                )
                break
    else:
        console.print("[dim]No HasSession edges in graph (sessions may not have been collected)[/dim]")
    console.print(
        f"[dim]Total computers: {len(computers)} · HasSession pairs: {len(unique_sess)}[/dim]"
    )

def print_paths_to_owned(G, owned_str, domain_filter=None):
    if not owned_str:
        return
    console.rule("[bold magenta]Shortest Paths to Owned Principals[/bold magenta]")
    owned_list = [o.strip() for o in owned_str.split(',') if o.strip()]
    owned_oids = []
    for o in owned_list:
        found = False
        for oid, d in G.nodes(data=True):
            if d['name'].upper().split('@')[0] == o.upper() and _domain_matches(d, domain_filter):
                owned_oids.append((oid, d['name'], d['type']))
                found = True
                break
        if not found:
            console.print(f"[yellow]Owned principal not found: {o}[/yellow]")
    if not owned_oids:
        return
    for tid, tname, ttype in owned_oids:
        console.print(f"\n[bold red]Owned target:[/bold red] [bold cyan]{tname}[/bold cyan] ({ttype})")
        count = 0
        for source_oid, sd in G.nodes(data=True):
            if sd['type'].lower() not in ['user', 'azure user']:
                continue
            if not nx.has_path(G, source_oid, tid):
                continue
            try:
                path = nx.shortest_path(G, source_oid, tid)
                formatted = format_path(G, path)
                console.print(f"  [dim]→ Length {len(path)-1}:[/dim] {formatted}")
                count += 1
                if count >= 10:
                    break
            except nx.NetworkXNoPath:
                continue
        add_finding("Owned Paths", f"Paths to owned {tname}", score=9)

def print_arbitrary_paths(G, path_from=None, path_to=None, domain_filter=None, max_paths=10):
    if not path_from or not path_to:
        return
    console.rule("[bold magenta]Arbitrary Shortest Paths (source → target)[/bold magenta]")
    sources = [s.strip() for s in path_from.split(',')]
    targets = [t.strip() for t in path_to.split(',')]
    for sname in sources:
        s_oid = None
        for oid, d in G.nodes(data=True):
            if d['name'].upper().split('@')[0] == sname.upper() and _domain_matches(d, domain_filter):
                s_oid = oid
                break
        if not s_oid:
            console.print(f"[yellow]Source not found: {sname}[/yellow]")
            continue
        for tname in targets:
            t_oid = None
            for oid, d in G.nodes(data=True):
                if d['name'].upper().split('@')[0] == tname.upper() and _domain_matches(d, domain_filter):
                    t_oid = oid
                    break
            if not t_oid:
                console.print(f"[yellow]Target not found: {tname}[/yellow]")
                continue
            try:
                path = nx.shortest_path(G, s_oid, t_oid)
                console.print(f"[cyan]{G.nodes[s_oid]['name']}[/cyan] → [bold cyan]{G.nodes[t_oid]['name']}[/bold cyan] (Length: {len(path)-1})")
                console.print(f"  {format_path(G, path)}")
                add_finding("Arbitrary Paths", f"{G.nodes[s_oid]['name']} → {G.nodes[t_oid]['name']}", score=6)
            except nx.NetworkXNoPath:
                console.print(f"[dim]No path from {sname} to {tname}[/dim]")

def _trust_edge_abuse_score(label: str, sid_filtering) -> tuple:
    """
    Score trust edges for abuse findings.

    Parent/child with SID filtering on (or unknown) is inventory only (score 0).
    Notable: SID filtering disabled, forest/external, foreign admin/group edges.
    Returns (score, reason) with score 0 = print only, no finding.
    """
    ll = (label or "").lower()
    if sid_filtering is False:
        return 8, "SID filtering disabled"
    if "foreignadmin" in ll or "foreigngroup" in ll:
        return 8, "foreign privileged principal"
    if "tenantmember" in ll or "cross-tenant" in ll:
        return 7, "cross-tenant relationship"
    # TrustedDomain:direction:TrustType
    parts = [p for p in (label or "").split(":") if p]
    ttype = parts[-1].lower() if len(parts) >= 3 else ""
    if ttype in ("forest", "external", "treeroot", "crosslink"):
        return 7, f"trust type {ttype}"
    if ttype in ("parentchild", "parent", "child", "tree"):
        return 0, ""  # expected hierarchy inventory
    if ll.startswith("trusteddomain") or "trusteddomain" in ll:
        # Unknown type — inventory only unless SID filtering off (handled above)
        return 0, ""
    if "foreign" in ll:
        return 6, "foreign relationship"
    return 0, ""


def print_trust_abuse(G, domain_filter=None):
    console.rule("[bold magenta]Domain Trust / Cross-Domain Abuse (AD) or Tenant Abuse (Azure)[/bold magenta]")
    found = False
    abuse_n = 0
    trust_labels = {
        'trustedby', 'trusts', 'trusteddomain', 'foreignadmin', 'foreigngroup',
        'memberof (cross-domain)',
    }
    azure_labels = {'tenantmember', 'cross-tenant'}
    seen = set()
    for u, v, d in G.edges(data=True):
        label = d.get('label') or ''
        label_lower = label.lower()
        is_azure = G.nodes[u].get('is_azure', False) or G.nodes[v].get('is_azure', False)
        labels = azure_labels if is_azure else trust_labels
        if not (any(t in label_lower for t in labels) or 'foreign' in label_lower or label_lower.startswith('trusteddomain')):
            continue
        u_name = G.nodes[u]['name']
        v_name = G.nodes[v]['name']
        if domain_filter and domain_filter.lower() not in (u_name.lower() + v_name.lower()):
            continue
        key = (u_name, v_name, label)
        if key in seen:
            continue
        seen.add(key)
        found = True
        sid_filt = d.get('sid_filtering')
        score, reason = _trust_edge_abuse_score(label, sid_filt)
        extra = ""
        if sid_filt is False:
            extra = " [yellow](SID filtering disabled)[/yellow]"
        elif reason:
            extra = f" [yellow]({reason})[/yellow]"
        if score > 0:
            abuse_n += 1
            detail = f"{u_name} {label} {v_name}"
            if reason:
                detail = f"{detail} ({reason})"
            add_finding("Trust Abuse", detail, score=score)
            console.print(
                f"[red]Trust abuse[/red]: [green]{u_name}[/green] --[{label}]--> "
                f"[cyan]{v_name}[/cyan]{extra}"
            )
        else:
            console.print(
                f"[dim]Trust (inventory)[/dim]: [green]{u_name}[/green] --[{label}]--> "
                f"[cyan]{v_name}[/cyan]{extra}"
            )
    if not found:
        console.print("[green]No obvious cross-domain or cross-tenant abuse detected[/green]")
    elif abuse_n == 0:
        console.print(
            f"[dim]{len(seen)} trust edge(s) inventory only "
            f"(parent/child with SID filtering on are not scored)[/dim]"
        )

def inspect_node(G, identifier, domain_filter=None):
    console.rule(f"[bold magenta]Detailed Inspection: {identifier}[/bold magenta]")
    found = False
    for oid, d in G.nodes(data=True):
        name_norm = d['name'].upper().split('@')[0]
        if (oid == identifier or name_norm == identifier.upper()) and _domain_matches(d, domain_filter):
            found = True
            console.print(f"[cyan]OID:[/cyan] {oid}")
            console.print(f"[cyan]Name:[/cyan] {d['name']}")
            console.print(f"[cyan]Type:[/cyan] {d['type']}")
            console.print(f"[cyan]Is Azure:[/cyan] {d.get('is_azure', False)}")
            console.print("[dim]Properties:[/dim]")
            for k, v in sorted(d.get('props', {}).items()):
                if k.lower() == 'useraccountcontrol':
                    console.print(f"  {k}: {decode_uac(v)}")
                else:
                    console.print(f"  {k}: {v}")
            console.print("[dim]Outgoing edges:[/dim]")
            for _, tgt, edata in G.out_edges(oid, data=True):
                console.print(f"  → [green]{G.nodes[tgt]['name']}[/green] [{edata.get('label')}]")
            console.print("[dim]Incoming edges:[/dim]")
            for src, _, edata in G.in_edges(oid, data=True):
                console.print(f"  ← [green]{G.nodes[src]['name']}[/green] [{edata.get('label')}]")
            break
    if not found:
        console.print(f"[yellow]Node '{identifier}' not found (or filtered)[/yellow]")

def print_group_analysis(G, domain_filter=None, deep_analysis=False):
    console.rule("[bold magenta]Group Nesting Depth & Cycle Analysis (AD + Azure)[/bold magenta]")
    groups = [n for n, d in G.nodes(data=True) if d['type'].lower() in ['group', 'azure group'] and _domain_matches(d, domain_filter)]
    if not groups:
        console.print("[green]No groups found[/green]")
        return
    high_priv_keywords = ['admin', 'domain admins', 'enterprise admins', 'schema admins', 'administrators', 'domain users', 'authenticated users', 'global admin', 'user admin']
    important_groups = [g for g in groups if any(k in G.nodes[g]['name'].lower() for k in high_priv_keywords)]
    groups_to_check = important_groups[:50] if important_groups else groups[:100]
    console.print(f"[cyan]Analyzing {len(groups_to_check)} important groups for nesting depth...[/cyan]")
    depths = {}
    with tqdm(groups_to_check, desc="Depth calculation", leave=False) as pbar:
        for g in pbar:
            try:
                lengths = nx.single_source_shortest_path_length(G.to_undirected(), g, cutoff=20)
                depths[g] = max(lengths.values()) if lengths else 0
            except:
                depths[g] = 0
    deep = sorted(depths.items(), key=lambda x: x[1], reverse=True)[:15]
    console.print("[yellow]Top 15 deepest nested groups (limited depth):[/yellow]")
    for g, depth in deep:
        if depth > 3:
            console.print(f"  [red]Deep nesting ({depth} levels):[/red] {G.nodes[g]['name']}")
            add_finding("Deep Group Nesting", f"{G.nodes[g]['name']} has {depth} nesting levels", score=6)
    if deep_analysis and len(G) < 2000:
        console.print("[cyan]Running full cycle detection...[/cyan]")
        try:
            cycles = list(nx.simple_cycles(G.to_undirected(), length_bound=6))
            if cycles:
                console.print(f"[red]Found {len(cycles)} group membership cycles![/red]")
                for c in cycles[:3]:
                    names = [G.nodes[n]['name'] for n in c]
                    console.print(f"  Cycle: {' → '.join(names)}")
                add_finding("Deep Group Nesting", f"{len(cycles)} group cycles detected", score=8)
            else:
                console.print("[green]No group membership cycles detected[/green]")
        except:
            console.print("[yellow]Cycle detection skipped (graph too complex)[/yellow]")
    else:
        console.print("[dim]Cycle detection skipped for performance (use --deep-analysis to enable)[/dim]")

def collect_domain_stats(G, domain_filter=None, now: Optional[float] = None) -> dict:
    """Quickwin-style domain hygiene stats with counts and percentages."""
    now = time.time() if now is None else now
    users = []
    computers = []
    for n, d in G.nodes(data=True):
        if d.get("is_azure", False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        t = str(d.get("type") or "").lower()
        if t == "user":
            users.append((n, d))
        elif t == "computer":
            computers.append((n, d))

    def _enabled(props):
        if _prop_raw_ci(props, ["enabled", "Enabled"]) is None:
            return True
        return get_bool_prop_ci(props, ["enabled", "Enabled"], default=True)

    all_users = len(users)
    enabled_users = sum(1 for _, d in users if _enabled(d.get("props") or {}))
    disabled_users = sum(1 for _, d in users if not _enabled(d.get("props") or {}))
    spn_users = sum(
        1
        for _, d in users
        if _enabled(d.get("props") or {}) and _user_has_spn(d.get("props") or {})
    )
    asrep_users = sum(
        1
        for _, d in users
        if _enabled(d.get("props") or {})
        and get_bool_prop_ci(
            d.get("props") or {},
            ["dontreqpreauth", "dontReqPreauth", "dont_req_preauth"],
        )
    )
    da_users = 0
    for n, d in users:
        if not _enabled(d.get("props") or {}):
            continue
        is_priv, _ = is_member_of_privileged_group(G, n)
        if is_priv:
            da_users += 1

    stale_6m = 0
    for _, d in users:
        props = d.get("props") or {}
        if not _enabled(props):
            continue
        raw = _prop_raw_ci(
            props,
            ["lastlogontimestamp", "lastLogonTimestamp", "lastlogon", "lastLogon"],
        )
        if raw is None:
            continue
        try:
            v = int(raw)
        except (TypeError, ValueError):
            continue
        if v in (0, -1):
            continue
        ts = parse_ad_timestamp(v)
        days = _days_since(ts, now=now)
        if days is not None and days >= 180:
            stale_6m += 1

    pwd_gt_1y = pwd_gt_2y = pwd_gt_5y = pwd_gt_10y = 0
    for _, d in users:
        props = d.get("props") or {}
        if not _enabled(props):
            continue
        raw = _prop_raw_ci(props, ["pwdlastset", "pwdLastSet", "PwdLastSet"])
        ts = parse_ad_timestamp(raw)
        days = _days_since(ts, now=now)
        if days is None:
            continue
        if days >= 365 * 10:
            pwd_gt_10y += 1
        if days >= 365 * 5:
            pwd_gt_5y += 1
        if days >= 365 * 2:
            pwd_gt_2y += 1
        if days >= 365:
            pwd_gt_1y += 1

    all_computers = len(computers)
    laps_computers = sum(
        1 for _, d in computers if _has_laps_enabled(d.get("props") or {})
    )

    def _pct(num, den):
        if not den:
            return 0.0
        return round(num * 100.0 / den, 2)

    return {
        "all_users": all_users,
        "enabled_users": enabled_users,
        "disabled_users": disabled_users,
        "enabled_pct": _pct(enabled_users, all_users),
        "disabled_pct": _pct(disabled_users, all_users),
        "da_users": da_users,
        "da_pct": _pct(da_users, enabled_users),
        "stale_6m": stale_6m,
        "stale_6m_pct": _pct(stale_6m, enabled_users),
        "pwd_gt_1y": pwd_gt_1y,
        "pwd_gt_1y_pct": _pct(pwd_gt_1y, enabled_users),
        "pwd_gt_2y": pwd_gt_2y,
        "pwd_gt_2y_pct": _pct(pwd_gt_2y, enabled_users),
        "pwd_gt_5y": pwd_gt_5y,
        "pwd_gt_5y_pct": _pct(pwd_gt_5y, enabled_users),
        "pwd_gt_10y": pwd_gt_10y,
        "pwd_gt_10y_pct": _pct(pwd_gt_10y, enabled_users),
        "spn_users": spn_users,
        "spn_pct": _pct(spn_users, enabled_users),
        "asrep_users": asrep_users,
        "asrep_pct": _pct(asrep_users, enabled_users),
        "all_computers": all_computers,
        "laps_computers": laps_computers,
        "laps_pct": _pct(laps_computers, all_computers),
    }


def print_stats_dashboard(G, domain_filter=None):
    console.rule("[bold magenta]AD & Azure Statistics Dashboard[/bold magenta]")
    filtered_nodes = [
        (n, d)
        for n, d in G.nodes(data=True)
        if not domain_filter
        or _domain_matches(d, domain_filter)
    ]
    total = len(filtered_nodes)
    by_type = defaultdict(int)
    azure_count = 0
    ad_count = 0
    for _, d in filtered_nodes:
        by_type[d['type']] += 1
        if d.get('is_azure', False):
            azure_count += 1
        else:
            ad_count += 1
    table = Table(title="Object Counts")
    table.add_column("Type", style="cyan")
    table.add_column("Count", justify="right")
    for t, c in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
        table.add_row(t, str(c))
    console.print(table)

    stats = collect_domain_stats(G, domain_filter)
    pct_table = Table(title="Domain Hygiene Stats")
    pct_table.add_column("Description", style="cyan")
    pct_table.add_column("Percentage", justify="right")
    pct_table.add_column("Total", justify="right")
    pct_rows = [
        ("All users", "N/A", stats["all_users"]),
        ("All users (enabled)", f"{stats['enabled_pct']}%", stats["enabled_users"]),
        ("All users (disabled)", f"{stats['disabled_pct']}%", stats["disabled_users"]),
        ("Users with privileged-group rights", f"{stats['da_pct']}%", stats["da_users"]),
        ("Not logged (enabled) ≥ 6 months", f"{stats['stale_6m_pct']}%", stats["stale_6m"]),
        ("Password not changed > 1 y (enabled)", f"{stats['pwd_gt_1y_pct']}%", stats["pwd_gt_1y"]),
        ("Password not changed > 2 y (enabled)", f"{stats['pwd_gt_2y_pct']}%", stats["pwd_gt_2y"]),
        ("Password not changed > 5 y (enabled)", f"{stats['pwd_gt_5y_pct']}%", stats["pwd_gt_5y"]),
        ("Password not changed > 10 y (enabled)", f"{stats['pwd_gt_10y_pct']}%", stats["pwd_gt_10y"]),
        ("Users with SPN", f"{stats['spn_pct']}%", stats["spn_users"]),
        ("Users with AS-REP roast", f"{stats['asrep_pct']}%", stats["asrep_users"]),
        ("All Computers", "N/A", stats["all_computers"]),
        ("LAPS Computers", f"{stats['laps_pct']}%", stats["laps_computers"]),
    ]
    for desc, pct, tot in pct_rows:
        pct_table.add_row(desc, str(pct), str(tot))
    console.print(pct_table)

    computers = sum(1 for _, d in filtered_nodes if d['type'].lower() == 'computer')
    local_admins = len({u for u, v, d in G.edges(data=True) if d.get('label') == 'LocalAdmin' and G.nodes[v]['type'].lower() == 'computer'})
    console.print(f"[cyan]Computers with at least one LocalAdmin right: {local_admins}/{computers} ({local_admins/computers*100 if computers else 0:.1f}%)[/cyan]")
    hv = len(get_high_value_targets(G, domain_filter))
    console.print(f"[cyan]High-value targets: {hv}[/cyan]")
    console.print(f"[cyan]Total nodes: {total} | AD: {ad_count} | Azure: {azure_count} | Edges: {G.number_of_edges()}[/cyan]")

# New Azure-specific functions
def print_azure_privileged_roles(G, domain_filter=None):
    console.rule("[bold magenta]Azure Privileged Roles Detection[/bold magenta]")
    found = False
    privileged_roles = ['global admin', 'user admin', 'application admin', 'exchange admin', 'sharepoint admin', 'intune admin', 'security admin', 'conditional access admin', 'privileged role admin']
    for n, d in G.nodes(data=True):
        if not d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if d['type'].lower() == 'azure role':
            role_name = d['name'].lower()
            if not any(pr in role_name for pr in privileged_roles):
                continue
            holders = [
                u for u, _, edata in G.in_edges(n, data=True)
                if (edata.get('label') or '').lower() in ('hasrole', 'member', 'memberof')
            ]
            if not holders:
                continue
            found = True
            console.print(f"[red]Privileged Azure role[/red]: [bold cyan]{d['name']}[/bold cyan]")
            for u in holders:
                console.print(f"  → [green]{G.nodes[u]['name']}[/green] has this role")
            add_finding(
                "Azure Privileged Roles",
                f"Privileged role assigned: {d['name']} ({len(holders)} holder(s))",
            )
    if found:
        print_abuse_panel("Azure Privileged Roles")
    else:
        console.print("[green]No privileged Azure role assignments detected[/green]")
def print_azure_app_secrets(G, domain_filter=None):
    console.rule("[bold magenta]Azure Application Secrets/Certificates Exposure[/bold magenta]")
    found = False
    # Having keyCredentials/passwordCredentials is normal. Report abuse surface:
    # principals who can add secrets/certs/owners, or own the app.
    abuse_rights = {
        'owns', 'addsecret', 'addcertificate', 'addowner',
        'genericall', 'writeowner', 'writedacl', 'genericwrite',
    }
    for n, d in G.nodes(data=True):
        if not d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if d['type'].lower() not in ('azure application', 'azure service principal'):
            continue
        incoming = list(G.in_edges(n, data=True))
        abuse_edges = [
            (u, edata.get('label'))
            for u, _, edata in incoming
            if (edata.get('label') or '').lower() in abuse_rights
        ]
        if not abuse_edges:
            continue
        found = True
        console.print(
            f"[red]Azure app/SP credential abuse path[/red]: "
            f"[bold cyan]{d['name']}[/bold cyan]"
        )
        for u, label in abuse_edges:
            console.print(f"  → [green]{G.nodes[u]['name']}[/green] --[{label}]-->")
        add_finding(
            "Azure App Secrets",
            f"Credential control path on {d['name']}: "
            + ", ".join(f"{G.nodes[u]['name']}:{lab}" for u, lab in abuse_edges[:5]),
        )
    if found:
        print_abuse_panel("Azure App Secrets")
    else:
        console.print(
            "[green]No Azure app/SP secret-control abuse paths detected "
            "(credential presence alone is not reported)[/green]"
        )
def print_azure_mfa_bypass(G, domain_filter=None):
    console.rule("[bold magenta]Azure MFA Bypass Risks[/bold magenta]")
    found = False
    unknown = 0
    for n, d in G.nodes(data=True):
        if not d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if d['type'].lower() != 'azure user':
            continue
        props = d.get('props') or {}
        # Only report when MFA is explicitly disabled / not enforced.
        # Missing fields are common in AzureHound exports and are NOT findings.
        mfa_state = None
        sar = props.get('strongAuthenticationRequirements')
        if isinstance(sar, dict):
            mfa_state = sar.get('state') or sar.get('State')
        elif isinstance(sar, list) and sar:
            # Some exports use a list of requirement objects
            for item in sar:
                if isinstance(item, dict) and item.get('state'):
                    mfa_state = item.get('state')
                    break
        enrolled = props.get('mfaEnrolled')
        if enrolled is None:
            enrolled = props.get('MfaEnrolled')
        has_explicit = mfa_state is not None or enrolled is not None
        if not has_explicit:
            unknown += 1
            continue
        mfa_enabled = (
            (isinstance(mfa_state, str) and mfa_state.lower() in ('enforced', 'enabled'))
            or enrolled is True
        )
        if not mfa_enabled:
            found = True
            console.print(f"[yellow]Azure user without MFA[/yellow]: [green]{d['name']}[/green]")
            add_finding("Azure MFA Bypass", f"User without MFA: {d['name']}")
    if found:
        print_abuse_panel("Azure MFA Bypass")
    elif unknown and not found:
        console.print(
            f"[dim]MFA state not present in data for {unknown} Azure user(s); "
            f"not flagging as bypass (unknown ≠ disabled)[/dim]"
        )
    else:
        console.print("[green]No explicitly MFA-disabled Azure users detected[/green]")
        
def print_azure_guest_access(G, domain_filter=None):
    console.rule("[bold magenta]Azure Guest User Access Risks[/bold magenta]")
    found = False
    elev_labels = {
        'hasrole', 'owns', 'genericall', 'genericwrite', 'writedacl', 'writeowner',
        'addsecret', 'addcertificate', 'addowner', 'addmembers', 'resetpassword',
    }
    for n, d in G.nodes(data=True):
        if not d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if d['type'].lower() == 'azure user':
            props = d.get('props', {}) or {}
            user_type = str(
                props.get('userType') or props.get('usertype') or props.get('UserType') or ''
            ).lower()
            if user_type != 'guest':
                continue
            elev = [
                (v, edata.get('label'))
                for _, v, edata in G.out_edges(n, data=True)
                if (edata.get('label') or '').lower() in elev_labels
            ]
            if not elev:
                continue
            found = True
            console.print(
                f"[yellow]Azure guest with elevated access[/yellow]: "
                f"[green]{d['name']}[/green]"
            )
            for v, lab in elev:
                console.print(
                    f"  → --[{lab}]--> [cyan]{G.nodes[v].get('name', v)}[/cyan]"
                )
            add_finding(
                "Azure Guest Access",
                f"Guest user with elevated access: {d['name']}",
            )
    if found:
        print_abuse_panel("Azure Guest Access")
    else:
        console.print("[green]No Azure guest users with elevated access detected[/green]")

def print_azure_service_principal_abuse(G, domain_filter=None):
    console.rule("[bold magenta]Azure Service Principal Abuse Risks[/bold magenta]")
    found = False
    for n, d in G.nodes(data=True):
        if not d.get('is_azure', False):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if d['type'].lower() == 'azure service principal':
            incoming = list(G.in_edges(n, data=True))
            dangerous_rights = {'genericall', 'owns', 'writedacl', 'writeowner', 'addsecret', 'addcertificate', 'addowner', 'execute', 'canread', 'canwrite', 'candelete'}
            for u, _, edata in incoming:
                if edata.get('label', '').lower() in dangerous_rights:  # Fixed: added .lower() for case-insensitive comparison
                    found = True
                    console.print(f"[red]Azure SP with dangerous rights[/red]: [bold cyan]{d['name']}[/bold cyan]")
                    console.print(f"  → [green]{G.nodes[u]['name']}[/green] --[{edata['label']}]-->")
                    add_finding("Azure Service Principal Abuse", f"SP abuse: {d['name']}")
                    break
    if found:
        print_abuse_panel("Azure Service Principal Abuse")
    else:
        console.print("[green]No Azure service principals with abuse potential detected[/green]")

# ────────────────────────────────────────────────
# Logging / profiles / inventory / path remediation
# ────────────────────────────────────────────────
def setup_run_logging(log_file: Optional[str] = None) -> Optional[str]:
    """Attach a file handler for run auditability. Returns resolved log path."""
    if not log_file:
        return None
    path = os.path.abspath(log_file)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    root = logging.getLogger()
    # Avoid duplicate handlers when tests call setup repeatedly
    for h in list(root.handlers):
        if getattr(h, "_bloodbash_run_log", False):
            root.removeHandler(h)
            h.close()
    handler = logging.FileHandler(path, encoding="utf-8")
    handler._bloodbash_run_log = True  # type: ignore[attr-defined]
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root.setLevel(logging.INFO)
    logger.setLevel(logging.INFO)
    root.addHandler(handler)
    logger.info("BloodBash v%s run log started", __version__)
    return path


def _builtin_profiles_dir() -> Path:
    try:
        base = Path(__file__).resolve().parent
    except NameError:
        # BloodBash is often exec()'d in tests without __file__
        base = Path.cwd()
    return base / "profiles"


def load_analysis_profile(profile_path: str) -> dict:
    """Load a YAML analysis profile (PlumHound TaskList analogue)."""
    path = Path(profile_path)
    if not path.is_file():
        # Allow short names that resolve under profiles/
        candidate = _builtin_profiles_dir() / profile_path
        if not candidate.suffix:
            candidate = candidate.with_suffix(".yaml")
        if candidate.is_file():
            path = candidate
        else:
            raise FileNotFoundError(f"Profile not found: {profile_path}")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Profile must be a YAML mapping: {path}")
    logger.info("Loaded analysis profile: %s", path)
    return data


# High-signal checks for --quick-wins (engagement day-0 triage).
# Intentionally not --all: skips heavy inventory/Azure dumps and slow deep analysis.
QUICK_WINS_CHECKS = (
    "dcsync",
    "adcs",
    "dangerous_permissions",
    "rbcd",
    "kerberoastable",
    "as_rep_roastable",
    "privileged_roast",
    "unconstrained_delegation",
    "constrained_delegation",
    "shadow_credentials",
    "laps",
    "password_descriptions",
    "password_not_required",
    "sessions",
    "shortest_paths",
    "path_break",
    "trust",  # domain trusts / SID filtering
)


def apply_quick_wins_to_args(args):
    """Enable the curated quick-wins check set (does not set --all)."""
    for key in QUICK_WINS_CHECKS:
        if hasattr(args, key):
            setattr(args, key, True)
    # Fast pathfinding + readable summary by default for this mode
    if hasattr(args, "fast"):
        args.fast = True
    if hasattr(args, "verbose") and not getattr(args, "verbose", False):
        args.verbose = True
    if hasattr(args, "all_findings"):
        args.all_findings = True
    if hasattr(args, "busiest_paths") and not getattr(args, "busiest_paths", None):
        args.busiest_paths = "short"
    if hasattr(args, "all"):
        # Explicitly avoid pulling every module
        args.all = False
    return args


def cli_has_explicit_analysis_intent(args) -> bool:
    """True when the user already picked a mode/check (skip auto quick-wins)."""
    if getattr(args, "all", False) or getattr(args, "quick_wins", False):
        return True
    if getattr(args, "profile", None):
        return True
    if getattr(args, "list_domains", False):
        return True
    if getattr(args, "wizard", False):
        return True
    return any(
        [
            getattr(args, "shortest_paths", False),
            getattr(args, "dangerous_permissions", False),
            getattr(args, "adcs", False),
            getattr(args, "gpo_abuse", False),
            getattr(args, "dcsync", False),
            getattr(args, "rbcd", False),
            getattr(args, "sessions", False),
            getattr(args, "kerberoastable", False),
            getattr(args, "as_rep_roastable", False),
            getattr(args, "privileged_roast", False),
            getattr(args, "sid_history", False),
            getattr(args, "unconstrained_delegation", False),
            getattr(args, "password_descriptions", False),
            getattr(args, "password_never_expires", False),
            getattr(args, "password_not_required", False),
            getattr(args, "shadow_credentials", False),
            getattr(args, "gpo_parsing", False),
            getattr(args, "constrained_delegation", False),
            getattr(args, "laps", False),
            getattr(args, "azure_privileged_roles", False),
            getattr(args, "azure_app_secrets", False),
            getattr(args, "azure_mfa_bypass", False),
            getattr(args, "azure_guest_access", False),
            getattr(args, "azure_sp_abuse", False),
            getattr(args, "owned", None),
            getattr(args, "path_from", None),
            getattr(args, "path_to", None),
            getattr(args, "inspect", None),
            getattr(args, "export_bh", False),
            getattr(args, "dot", None),
            getattr(args, "deep_analysis", False),
            getattr(args, "gpo_content_dir", None),
            getattr(args, "busiest_paths", None),
            getattr(args, "path_break", False),
            getattr(args, "trust", False),
            getattr(args, "password_age", False),
            getattr(args, "stale_accounts", False),
            getattr(args, "privilege_inventory", False),
            getattr(args, "owned_inventory", False),
            getattr(args, "inventory", False),
            getattr(args, "report_pack", None),
            getattr(args, "csv_pack", None),
            getattr(args, "export_zip", None),
            getattr(args, "from_user", None),
            getattr(args, "from_user_export", None) is not None,
        ]
    )


def run_setup_wizard(args):
    """Interactive first-run picker; mutates args in place."""
    console.print(
        Panel(
            "[bold]BloodBash setup wizard[/bold]\n"
            "[dim]Pick a mode — same flags you would pass on the CLI.[/dim]",
            border_style="bright_blue",
            title="Wizard",
        )
    )
    try:
        raw_dir = input(f"Data directory or zip [{args.directory}]: ").strip()
    except EOFError:
        raw_dir = ""
    if raw_dir:
        args.directory = raw_dir

    console.print(
        "\n[bold]Mode[/bold]\n"
        "  [cyan]1[/cyan]  Quick wins — day-0 triage (recommended)\n"
        "  [cyan]2[/cyan]  Full analysis (--all --fast)\n"
        "  [cyan]3[/cyan]  Compromise dossier (--from-user)\n"
        "  [cyan]4[/cyan]  Profile: hygiene\n"
        "  [cyan]5[/cyan]  Profile: adcs-heavy\n"
        "  [cyan]6[/cyan]  Profile: quick-wins\n"
    )
    try:
        choice = (input("Choice [1]: ").strip() or "1")
    except EOFError:
        choice = "1"

    if choice == "2":
        args.all = True
        args.fast = True
    elif choice == "3":
        try:
            user = input("Foothold username (sam or UPN): ").strip()
        except EOFError:
            user = ""
        if not user:
            console.print("[red]No username — falling back to quick-wins.[/red]")
            args.quick_wins = True
        else:
            args.from_user = user
            try:
                exp = (input("Export dossier pack? [Y/n]: ").strip() or "y").lower()
            except EOFError:
                exp = "y"
            if exp not in ("n", "no"):
                args.from_user_export = ""
    elif choice == "4":
        args.profile = "hygiene"
    elif choice == "5":
        args.profile = "adcs-heavy"
    elif choice == "6":
        args.profile = "quick-wins"
    else:
        args.quick_wins = True

    try:
        domain = input("Domain / tenant filter (blank = all): ").strip()
    except EOFError:
        domain = ""
    if domain:
        args.domain = domain

    console.print(
        f"\n[green]Wizard ready:[/green] directory=[cyan]{args.directory}[/cyan] "
        f"mode choice={choice}"
        + (f" domain={args.domain}" if args.domain else "")
        + "\n"
    )
    return args


def print_approachability_footer(*, auto_default: bool = False) -> None:
    """Short next-step tip after a run (new-user approachability)."""
    if auto_default:
        console.print(
            "[dim]Tip: default is quick-wins triage. "
            "Full scan: [cyan]--all[/cyan] · foothold: [cyan]--from-user USER[/cyan] · "
            "all flags: [cyan]--help-advanced[/cyan][/dim]"
        )
    else:
        console.print(
            "[dim]Tip: foothold → [cyan]--from-user USER[/cyan] · "
            "triage → [cyan]--quick-wins[/cyan] · "
            "all flags → [cyan]--help-advanced[/cyan][/dim]"
        )


def apply_profile_to_args(args, profile: dict):
    """Merge profile keys into argparse namespace (CLI flags win when already set)."""
    if not profile:
        return args
    check_flags = {
        "shortest_paths", "dangerous_permissions", "adcs", "gpo_abuse", "dcsync",
        "rbcd", "sessions", "kerberoastable", "as_rep_roastable", "privileged_roast",
        "sid_history",
        "unconstrained_delegation", "password_descriptions", "password_never_expires",
        "password_not_required", "shadow_credentials", "gpo_parsing",
        "constrained_delegation", "laps", "azure_privileged_roles", "azure_app_secrets",
        "azure_mfa_bypass", "azure_guest_access", "azure_sp_abuse", "deep_analysis",
        "password_age", "stale_accounts", "privilege_inventory", "owned_inventory",
        "inventory", "path_break", "busiest_paths", "trust",
    }
    checks = profile.get("checks") or profile.get("flags") or []
    if isinstance(checks, list):
        for raw in checks:
            key = str(raw).strip().lstrip("-").replace("-", "_")
            if key in check_flags and not getattr(args, key, False):
                # busiest_paths is a mode string, not a bare boolean
                if key == "busiest_paths":
                    setattr(args, key, "short")
                else:
                    setattr(args, key, True)
    for key in check_flags:
        if key in profile and not getattr(args, key, False):
            setattr(args, key, profile[key])
    # Scalar options: profile fills defaults only when CLI left them unset/default
    scalar_defaults = {
        "all": False,
        "fast": False,
        "verbose": False,
        "indirect": False,
        "domain": None,
        "owned": None,
        "export": None,
        "export_bh": False,
        "dot": None,
        "db": None,
        "path_from": None,
        "path_to": None,
        "inspect": None,
        "gpo_content_dir": None,
        "busiest_paths": None,
        "busiest_paths_top": 5,
        "path_break": False,
        "path_break_top": 15,
        "inventory": False,
        "password_age": False,
        "stale_accounts": False,
        "privilege_inventory": False,
        "owned_inventory": False,
        "report_pack": None,
        "export_zip": None,
        "log_file": None,
        "all_findings": False,
    }
    for key, default in scalar_defaults.items():
        if key not in profile:
            continue
        if not hasattr(args, key):
            continue
        current = getattr(args, key)
        if current == default or current is None or current is False:
            setattr(args, key, profile[key])
    # Profile-friendly aliases
    if profile.get("report_pack") and not getattr(args, "report_pack", None):
        args.report_pack = profile["report_pack"]
    if profile.get("export_dir") and not getattr(args, "report_pack", None):
        args.report_pack = profile["export_dir"]
    if profile.get("zip") and not getattr(args, "export_zip", None):
        args.export_zip = profile["zip"]
    return args


def parse_ad_timestamp(value) -> Optional[float]:
    """Parse SharpHound pwdlastset/lastlogon values.

    Supports unix seconds, unix milliseconds, and Windows FILETIME (100ns since 1601).
    """
    if value is None:
        return None
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    if v in (0, -1):
        return None
    # FILETIME is ~1e17 for modern dates; unix ms is ~1e12; unix seconds ~1e9
    if v >= 10_000_000_000_000:  # >= 1e13 → FILETIME (100-ns ticks)
        return (v / 10_000_000.0) - 11644473600.0
    if v >= 100_000_000_000:  # >= 1e11 → unix milliseconds
        return v / 1000.0
    return float(v)


def _days_since(ts: Optional[float], now: Optional[float] = None) -> Optional[float]:
    if ts is None:
        return None
    now = time.time() if now is None else now
    return max(0.0, (now - ts) / 86400.0)


def _domain_matches(d: dict, domain_filter: Optional[str]) -> bool:
    """Case-insensitive domain / tenant filter.

    SharpHound stores ``domain`` as the DNS name (often mixed/lower case in
    some collectors); CLI users commonly pass ``CORP.LOCAL``. Exact string
    equality previously zeroed every property-based check.
    """
    if not domain_filter:
        return True
    props = d.get("props") or {}
    df = str(domain_filter).strip().lower()
    if not df:
        return True
    for key in ("domain", "Domain", "tenantId", "tenantid", "TenantId"):
        val = props.get(key)
        if val is not None and str(val).strip().lower() == df:
            return True
    # Fallback: match UPN / name suffix (USER@CORP.LOCAL)
    name = d.get("name") or props.get("name") or props.get("Name") or ""
    if isinstance(name, str) and "@" in name:
        if name.rsplit("@", 1)[-1].strip().lower() == df:
            return True
    return False


def _priority_high_value_targets(G, domain_filter=None, limit=5):
    targets = get_high_value_targets(G, domain_filter)
    priority_kw = (
        "domain admins", "enterprise admins", "schema admins", "administrators",
        "krbtgt", "global admin", "privileged role admin",
    )
    prioritized = [t for t in targets if any(k in t[1].lower() for k in priority_kw)]
    # Prefer exact Builtin Administrators / DA / EA first
    def _rank(t):
        name = t[1].lower()
        if "domain admins" in name:
            return 0
        if "enterprise admins" in name:
            return 1
        if _is_builtin_administrators_name(t[1]) or name.startswith("administrators@"):
            return 2
        if "krbtgt" in name:
            return 3
        return 4
    prioritized = sorted(prioritized or targets, key=_rank)
    return prioritized[:limit]


def _edge_label(G, u, v) -> str:
    edges = G.get_edge_data(u, v)
    if not edges:
        return "???"
    return next(iter(edges.values())).get("label", "???")


def _path_edge_keys(G, path) -> List[Tuple[str, str, str]]:
    keys = []
    for i in range(len(path) - 1):
        u, v = path[i], path[i + 1]
        keys.append((u, v, _edge_label(G, u, v)))
    return keys


def collect_paths_to_high_value(
    G,
    domain_filter=None,
    mode: str = "short",
    max_targets: int = 3,
    max_sources: int = 200,
    cutoff: int = 10,
    now: Optional[float] = None,
) -> List[dict]:
    """Collect attack paths from users to priority high-value targets."""
    del now  # reserved for future time-aware scoring
    users = [
        n for n, d in G.nodes(data=True)
        if d.get("type", "").lower() in ("user", "azure user") and _domain_matches(d, domain_filter)
    ]
    targets = _priority_high_value_targets(G, domain_filter, limit=max_targets)
    results = []
    mode = (mode or "short").lower()
    for tid, tname, ttype in targets:
        try:
            lengths = nx.single_source_shortest_path_length(G.reverse(copy=False), tid, cutoff=cutoff)
        except Exception:
            lengths = {}
        candidates = sorted(
            ((lengths[s], s) for s in users if s in lengths and s != tid),
            key=lambda x: x[0],
        )[:max_sources]
        for _, source in candidates:
            try:
                if mode == "all":
                    paths_iter = list(nx.all_simple_paths(G, source, tid, cutoff=min(cutoff, 8)))
                    # Cap explosion
                    paths_iter = paths_iter[:5]
                else:
                    paths_iter = [nx.shortest_path(G, source, tid)]
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            for path in paths_iter:
                results.append({
                    "source_id": source,
                    "source": G.nodes[source]["name"],
                    "target_id": tid,
                    "target": tname,
                    "target_type": ttype,
                    "length": len(path) - 1,
                    "path": path,
                    "path_str": " -> ".join(
                        f"{G.nodes[n]['name']}" + (
                            f" -[{_edge_label(G, path[i], path[i+1])}]>" if i < len(path) - 1 else ""
                        )
                        for i, n in enumerate(path)
                    ),
                })
    return results


def collect_busiest_paths(
    G,
    mode: str = "short",
    top: int = 5,
    domain_filter=None,
    fast: bool = False,
) -> List[dict]:
    """
    Rank intermediate principals by how many shortest (or all) paths to high-value
    targets pass through them (PlumHound/BlueHound-style busiest-path analysis).
    """
    if mode is True or not isinstance(mode, str) or mode.lower() not in ("short", "all"):
        mode = "short"
    else:
        mode = mode.lower()
    max_sources = 80 if fast else 200
    max_targets = 2 if fast else 3
    paths = collect_paths_to_high_value(
        G,
        domain_filter=domain_filter,
        mode=mode,
        max_targets=max_targets,
        max_sources=max_sources,
        cutoff=8 if fast else 10,
    )
    node_counts = Counter()
    node_targets = defaultdict(set)
    target_ids = {p["target_id"] for p in paths}
    for p in paths:
        intermediates = p["path"][1:-1]  # exclude source and final target
        for nid in intermediates:
            if nid in target_ids:
                continue
            node_counts[nid] += 1
            node_targets[nid].add(p["target"])
    # Also rank source users by path count (enablers with many routes)
    source_counts = Counter(p["source_id"] for p in paths)
    ranked = []
    for nid, count in node_counts.most_common(top):
        ranked.append({
            "kind": "intermediate",
            "id": nid,
            "name": G.nodes[nid]["name"],
            "type": G.nodes[nid].get("type", "?"),
            "path_count": count,
            "targets": sorted(node_targets[nid]),
        })
    # Fill with top sources if fewer intermediates
    if len(ranked) < top:
        for sid, count in source_counts.most_common(top):
            if any(r["id"] == sid for r in ranked):
                continue
            ranked.append({
                "kind": "source",
                "id": sid,
                "name": G.nodes[sid]["name"],
                "type": G.nodes[sid].get("type", "?"),
                "path_count": count,
                "targets": sorted({p["target"] for p in paths if p["source_id"] == sid}),
            })
            if len(ranked) >= top:
                break
    return ranked[:top]


# Path-break: prefer actionable abuse edges over default group membership noise.
_PATH_BREAK_ACTIONABLE = frozenset({
    "forcechangepassword", "genericall", "genericwrite", "writedacl", "writeowner",
    "owns", "addkeycredentiallink", "writeaccountrestrictions", "addallowedtoact",
    "allowedtoact", "canrdp", "hassession", "adminto", "localadmin",
    "allextendedrights", "addmember", "addself",
})


def _path_break_edge_score(G, u, v, label: str, paths_broken: int) -> float:
    """Higher is better remediation candidate."""
    lab = (label or "").lower()
    score = float(paths_broken)
    if lab in _PATH_BREAK_ACTIONABLE or lab.replace("_", "") in _PATH_BREAK_ACTIONABLE:
        score += 1000.0
    if lab in ("memberof", "member_of", "member"):
        # Membership edges are rarely the best remediation vs ACL/session rights
        uname = (G.nodes.get(u) or {}).get("name") or ""
        vname = (G.nodes.get(v) or {}).get("name") or ""
        score -= 200.0
        if _is_default_high_priv_name(uname) or _is_default_high_priv_name(vname):
            # e.g. Administrator → Domain Admins — almost never the right "break"
            score -= 800.0
        if _is_classic_high_value_name(vname):
            score -= 100.0
    return score


def collect_path_breaks(
    G,
    domain_filter=None,
    top: int = 15,
    fast: bool = False,
) -> List[dict]:
    """
    Identify edges whose removal would break the most collected attack paths
    (PlumHound Analyze Path / path-destroyer style remediation hints).

    Prefers non-default ACL / session / RDP edges over MemberOf between built-in
    high-priv principals (e.g. do not recommend "remove Administrator from DA").
    """
    paths = collect_paths_to_high_value(
        G,
        domain_filter=domain_filter,
        mode="short",
        max_targets=2 if fast else 3,
        max_sources=60 if fast else 150,
        cutoff=8 if fast else 10,
    )
    edge_paths = defaultdict(set)  # edge_key -> set of path instance ids
    edge_examples = {}
    for p in paths:
        path_id = (
            p.get("source_id"),
            p.get("target_id"),
            tuple(p.get("path") or ()),
        )
        for u, v, label in _path_edge_keys(G, p["path"]):
            key = (u, v, label)
            edge_paths[key].add(path_id)
            if key not in edge_examples:
                edge_examples[key] = p
    scored = []
    for (u, v, label), path_ids in edge_paths.items():
        broken = len(path_ids)
        scored.append(((u, v, label), broken, _path_break_edge_score(G, u, v, label, broken)))
    scored.sort(key=lambda x: (-x[2], -x[1]))
    ranked = []
    for (u, v, label), broken, _sc in scored:
        example = edge_examples[(u, v, label)]
        uname = resolve_principal_display_name(G, u)
        vname = resolve_principal_display_name(G, v)
        lab_l = (label or "").lower()
        non_actionable = (
            lab_l in ("memberof", "member_of", "member")
            and (
                _is_default_high_priv_name(uname)
                or _is_default_high_priv_name(vname)
            )
        )
        note = " [default membership — low actionability]" if non_actionable else ""
        ranked.append({
            "from_id": u,
            "to_id": v,
            "from": uname,
            "to": vname,
            "relationship": label,
            "paths_broken": broken,
            "example_source": example["source"],
            "example_target": example["target"],
            "non_actionable": non_actionable,
            "recommendation": (
                f"Remove relationship {label} between {uname} and "
                f"{vname} (breaks {broken} path(s) toward high-value){note}"
            ),
        })
        if len(ranked) >= top:
            break
    return ranked


def print_busiest_paths(G, mode="short", top=5, domain_filter=None, fast=False):
    console.rule("[bold magenta]Busiest Paths to High-Value Targets[/bold magenta]")
    ranked = collect_busiest_paths(G, mode=mode, top=top, domain_filter=domain_filter, fast=fast)
    if not ranked:
        console.print("[yellow]No busiest paths found (no user paths to high-value targets)[/yellow]")
        return ranked
    table = Table(title=f"Top {top} busiest principals ({mode})", show_header=True, header_style="bold red")
    table.add_column("Rank", justify="right")
    table.add_column("Principal", style="cyan")
    table.add_column("Type")
    table.add_column("Kind")
    table.add_column("Path count", justify="right", style="red")
    table.add_column("Targets", style="green")
    for i, row in enumerate(ranked, 1):
        table.add_row(
            str(i),
            row["name"],
            str(row["type"]),
            row["kind"],
            str(row["path_count"]),
            ", ".join(row["targets"][:3]),
        )
    console.print(table)
    add_finding("Busiest Paths", f"Top principal {ranked[0]['name']} on {ranked[0]['path_count']} path(s)", score=7)
    return ranked


def print_path_breaks(G, domain_filter=None, top=15, fast=False):
    console.rule("[bold magenta]Path Break Remediation (edges to remove)[/bold magenta]")
    ranked = collect_path_breaks(G, domain_filter=domain_filter, top=top, fast=fast)
    if not ranked:
        console.print("[yellow]No path-break recommendations (no attack paths found)[/yellow]")
        return ranked
    for i, row in enumerate(ranked, 1):
        tag = " [dim](low actionability)[/dim]" if row.get("non_actionable") else ""
        console.print(
            f"  [bold]{i}.[/bold] Removing [yellow]{row['relationship']}[/yellow] between "
            f"[cyan]{row['from']}[/cyan] and [cyan]{row['to']}[/cyan] breaks "
            f"[red]{row['paths_broken']}[/red] path(s) "
            f"[dim](e.g. {row['example_source']} → {row['example_target']})[/dim]{tag}"
        )
    # Prefer first actionable edge for the findings table
    pick = next((r for r in ranked if not r.get("non_actionable")), ranked[0])
    add_finding(
        "Path Break",
        f"{pick['relationship']} {pick['from']} → {pick['to']} "
        f"breaks {pick['paths_broken']} path(s)",
        score=8 if not pick.get("non_actionable") else 5,
    )
    return ranked


def _assign_age_bucket(days: Optional[float], bucket_defs) -> str:
    if days is None:
        return "Never set / unknown"
    for label, lo, hi in bucket_defs:
        if label.startswith("<"):
            if hi is not None and lo <= days < hi:
                return label
        else:
            if days > lo and (hi is None or days <= hi):
                return label
    if days >= 30:
        return "30 days – 6 months"
    return "Other"


def collect_password_age_rows(G, domain_filter=None, now: Optional[float] = None) -> List[dict]:
    now = time.time() if now is None else now
    rows = []
    for n, d in G.nodes(data=True):
        if d.get("is_azure", False) or d.get("type", "").lower() != "user":
            continue
        if not _domain_matches(d, domain_filter):
            continue
        props = d.get("props") or {}
        ts = parse_ad_timestamp(_prop_raw_ci(props, ["pwdlastset", "pwdLastSet", "passwordlastset"]))
        days = _days_since(ts, now)
        bucket = _assign_age_bucket(days, PASSWORD_AGE_BUCKETS) if days is not None else "Never set / unknown"
        rows.append({
            "name": d["name"],
            "enabled": bool(props.get("enabled", props.get("Enabled", True))),
            "pwdlastset_unix": ts,
            "days_old": None if days is None else round(days, 1),
            "bucket": bucket,
        })
    return rows


def collect_stale_account_rows(G, domain_filter=None, now: Optional[float] = None) -> List[dict]:
    now = time.time() if now is None else now
    rows = []
    for n, d in G.nodes(data=True):
        if d.get("is_azure", False) or d.get("type", "").lower() != "user":
            continue
        if not _domain_matches(d, domain_filter):
            continue
        props = d.get("props") or {}
        ts = parse_ad_timestamp(
            _prop_raw_ci(props, ["lastlogontimestamp", "lastLogonTimestamp", "lastlogon", "lastLogon"])
        )
        days = _days_since(ts, now)
        if days is None:
            bucket = "Never active / unknown"
        elif days <= 180:
            bucket = "Active < 6 months"
        else:
            bucket = "Inactive > 6 months"
            for label, lo, hi in STALE_ACCOUNT_BUCKETS:
                if days > lo and (hi is None or days <= hi):
                    bucket = label
        rows.append({
            "name": d["name"],
            "enabled": bool(props.get("enabled", props.get("Enabled", True))),
            "lastlogon_unix": ts,
            "days_inactive": None if days is None else round(days, 1),
            "bucket": bucket,
        })
    return rows


def collect_privilege_inventory(G, domain_filter=None) -> List[dict]:
    rows = []
    for n, d in G.nodes(data=True):
        if d.get("type", "").lower() != "group":
            continue
        if not _domain_matches(d, domain_filter):
            continue
        name = d.get("name", "")
        nl = name.lower()
        if not any(k in nl for k in PRIVILEGE_GROUP_KEYWORDS) and not get_bool_prop_ci(d.get("props") or {}, ["highvalue", "HighValue"]):
            continue
        members = []
        for pred in G.predecessors(n):
            edge_data = G.get_edge_data(pred, n) or {}
            if any((ed or {}).get("label") == "MemberOf" for ed in edge_data.values()):
                members.append(G.nodes[pred]["name"])
        rows.append({
            "group": name,
            "type": d.get("type"),
            "member_count": len(members),
            "members": sorted(members),
            "highvalue": get_bool_prop_ci(d.get("props") or {}, ["highvalue", "HighValue"]),
        })
    rows.sort(key=lambda r: (-r["member_count"], r["group"]))
    return rows


def collect_owned_inventory(G, owned_str: str, domain_filter=None) -> List[dict]:
    if not owned_str:
        return []
    owned_list = [o.strip() for o in owned_str.split(",") if o.strip()]
    owned_oids = []
    for o in owned_list:
        for oid, d in G.nodes(data=True):
            uname = d.get("name", "")
            if uname.upper().split("@")[0] == o.upper() or uname.upper() == o.upper():
                if _domain_matches(d, domain_filter):
                    owned_oids.append(oid)
                    break
    rows = []
    for oid in owned_oids:
        d = G.nodes[oid]
        admin_to = []
        member_of = []
        for _, v, ed in G.out_edges(oid, data=True):
            label = (ed or {}).get("label", "")
            if label in ("AdminTo", "LocalAdmin", "GenericAll"):
                admin_to.append(f"{G.nodes[v]['name']} [{label}]")
            if label == "MemberOf":
                member_of.append(G.nodes[v]["name"])
        rows.append({
            "name": d.get("name"),
            "type": d.get("type"),
            "admin_to": sorted(admin_to),
            "member_of": sorted(member_of),
            "admin_to_count": len(admin_to),
            "member_of_count": len(member_of),
        })
    return rows


def collect_structural_inventory(G, domain_filter=None) -> Dict[str, List[dict]]:
    domains, dcs, trusts, computers, users = [], [], [], [], []
    for n, d in G.nodes(data=True):
        if not _domain_matches(d, domain_filter):
            continue
        typ = d.get("type", "").lower()
        props = d.get("props") or {}
        row = {"name": d.get("name"), "type": d.get("type")}
        if typ == "domain":
            domains.append(row)
        elif typ == "computer":
            computers.append(row)
            name = (d.get("name") or "").lower()
            if "domain controller" in name or get_bool_prop_ci(props, ["isdc", "IsDC"]) or "dc=" in str(props.get("distinguishedname", "")).lower() and "ou=domain controllers" in str(props.get("distinguishedname", "")).lower():
                dcs.append(row)
            # Common DC naming / highvalue
            if get_bool_prop_ci(props, ["highvalue"]) and typ == "computer":
                if row not in dcs:
                    dcs.append(row)
        elif typ == "user":
            users.append(row)
    for u, v, ed in G.edges(data=True):
        label = (ed or {}).get("label", "")
        if label and "trust" in label.lower():
            if _domain_matches(G.nodes[u], domain_filter) or _domain_matches(G.nodes[v], domain_filter):
                trusts.append({
                    "from": G.nodes[u]["name"],
                    "to": G.nodes[v]["name"],
                    "type": label,
                })
    # Domain Trusts[] prop edges may already be graph edges from build_graph
    return {
        "domains": domains,
        "domain_controllers": dcs,
        "trusts": trusts,
        "users_count": [{"count": len(users)}],
        "computers_count": [{"count": len(computers)}],
    }


def print_password_age_inventory(G, domain_filter=None, now: Optional[float] = None):
    console.rule("[bold magenta]Password Age Inventory (AD)[/bold magenta]")
    rows = collect_password_age_rows(G, domain_filter=domain_filter, now=now)
    if not rows:
        console.print("[yellow]No user objects for password-age inventory[/yellow]")
        return rows
    counts = Counter(r["bucket"] for r in rows)
    table = Table(title="Password age buckets", show_header=True, header_style="bold magenta")
    table.add_column("Bucket", style="cyan")
    table.add_column("Count", justify="right")
    for label, _, _ in PASSWORD_AGE_BUCKETS:
        table.add_row(label, str(counts.get(label, 0)))
    table.add_row("Never set / unknown", str(counts.get("Never set / unknown", 0)))
    table.add_row("30 days – 6 months", str(counts.get("30 days – 6 months", 0)))
    console.print(table)
    interesting = sum(counts[b] for b in counts if b.startswith(">") or b == "Never set / unknown")
    if interesting:
        add_finding("Password Age", f"{interesting} users with old/unknown passwords", score=5)
        # show a few oldest
        old = [r for r in rows if r.get("days_old") is not None]
        old.sort(key=lambda r: r["days_old"], reverse=True)
        for r in old[:10]:
            console.print(f"  • [cyan]{r['name']}[/cyan] — {r['days_old']} days ({r['bucket']})")
    else:
        console.print("[green]No extreme password-age outliers in ladders[/green]")
    return rows


def print_stale_account_inventory(G, domain_filter=None, now: Optional[float] = None):
    console.rule("[bold magenta]Stale / Inactive Account Inventory (AD)[/bold magenta]")
    rows = collect_stale_account_rows(G, domain_filter=domain_filter, now=now)
    if not rows:
        console.print("[yellow]No user objects for stale-account inventory[/yellow]")
        return rows
    counts = Counter(r["bucket"] for r in rows)
    table = Table(title="Inactivity buckets", show_header=True, header_style="bold magenta")
    table.add_column("Bucket", style="cyan")
    table.add_column("Count", justify="right")
    for label in ["Active < 6 months", "Never active / unknown"] + [b[0] for b in STALE_ACCOUNT_BUCKETS]:
        table.add_row(label, str(counts.get(label, 0)))
    console.print(table)
    stale = sum(v for k, v in counts.items() if k.startswith("Inactive") or k.startswith("Never"))
    if stale:
        add_finding("Stale Accounts", f"{stale} inactive/never-active users", score=4)
        show = [r for r in rows if r["bucket"] != "Active < 6 months"][:15]
        for r in show:
            days = r["days_inactive"] if r["days_inactive"] is not None else "?"
            console.print(f"  • [cyan]{r['name']}[/cyan] — {days} days inactive ({r['bucket']})")
    else:
        console.print("[green]No stale accounts detected in ladders[/green]")
    return rows


def print_privilege_inventory(G, domain_filter=None):
    console.rule("[bold magenta]Privilege Group Inventory[/bold magenta]")
    rows = collect_privilege_inventory(G, domain_filter=domain_filter)
    if not rows:
        console.print("[yellow]No privilege groups matched[/yellow]")
        return rows
    for r in rows:
        console.print(
            f"  • [cyan]{r['group']}[/cyan] — [red]{r['member_count']}[/red] members"
            + (" [yellow](highvalue)[/yellow]" if r["highvalue"] else "")
        )
        for m in r["members"][:8]:
            console.print(f"      - [green]{m}[/green]")
        if r["member_count"] > 8:
            console.print(f"      [dim]... and {r['member_count'] - 8} more[/dim]")
    add_finding("Privilege Inventory", f"{len(rows)} privileged groups inventoried", score=6)
    return rows


def print_owned_inventory(G, owned_str, domain_filter=None):
    console.rule("[bold magenta]Owned Principal Inventory[/bold magenta]")
    rows = collect_owned_inventory(G, owned_str, domain_filter=domain_filter)
    if not rows:
        console.print("[yellow]No owned principals resolved for inventory[/yellow]")
        return rows
    for r in rows:
        console.print(f"  [bold cyan]{r['name']}[/bold cyan] ({r['type']})")
        console.print(f"    AdminTo/control: {r['admin_to_count']}")
        for a in r["admin_to"][:10]:
            console.print(f"      - [yellow]{a}[/yellow]")
        console.print(f"    MemberOf: {r['member_of_count']}")
        for m in r["member_of"][:10]:
            console.print(f"      - [green]{m}[/green]")
    add_finding("Owned Inventory", f"Inventory for {len(rows)} owned principal(s)", score=7)
    return rows


def print_structural_inventory(G, domain_filter=None):
    console.rule("[bold magenta]Structural Inventory[/bold magenta]")
    data = collect_structural_inventory(G, domain_filter=domain_filter)
    console.print(f"  Domains: [cyan]{len(data['domains'])}[/cyan]")
    for d in data["domains"][:20]:
        console.print(f"    • {d['name']}")
    console.print(f"  Domain Controllers (heuristic): [cyan]{len(data['domain_controllers'])}[/cyan]")
    for d in data["domain_controllers"][:20]:
        console.print(f"    • {d['name']}")
    console.print(f"  Trust edges: [cyan]{len(data['trusts'])}[/cyan]")
    for t in data["trusts"][:20]:
        console.print(f"    • {t['from']} -[{t['type']}]-> {t['to']}")
    return data


# ────────────────────────────────────────────────
# Compromise dossier (--from-user / --compromise)
# ────────────────────────────────────────────────
# Outbound edge labels of interest for foothold capability analysis
COMPROMISE_RIGHT_LABELS = (
    "AdminTo", "LocalAdmin", "CanRDP", "ExecuteDCOM", "GenericAll", "GenericWrite",
    "WriteDacl", "WriteOwner", "Owns", "ForceChangePassword", "ResetPassword",
    "AddMember", "AddKeyCredentialLink", "AllowedToAct", "HasSession",
    "GetChanges", "GetChangesAll", "AllExtendedRights", "WriteProperty",
    "WriteAccountRestrictions", "AddAllowedToAct",
    "MemberOf",  # membership handled separately but kept for completeness
)
# Rights shown in the high-level summary counts (order preserved)
COMPROMISE_SUMMARY_RIGHTS = (
    "LocalAdmin", "AdminTo", "CanRDP", "ExecuteDCOM", "GenericAll", "GenericWrite",
    "WriteDacl", "WriteOwner", "ForceChangePassword", "ResetPassword", "AddMember",
    "HasSession", "AllowedToAct", "AddKeyCredentialLink", "GetChanges", "GetChangesAll",
    "AllExtendedRights", "WriteAccountRestrictions", "AddAllowedToAct",
)


def resolve_principal_oid(G, identifier: str, domain_filter=None) -> Optional[str]:
    """Resolve a user/computer/group name or object id to a graph node id."""
    if not identifier:
        return None
    ident = identifier.strip()
    ident_u = ident.upper()
    ident_short = ident_u.split("@")[0]
    # Exact OID
    if ident in G:
        return ident
    candidates = []
    for oid, d in G.nodes(data=True):
        if not _domain_matches(d, domain_filter):
            continue
        name = d.get("name") or ""
        name_u = name.upper()
        short = name_u.split("@")[0]
        if name_u == ident_u or short == ident_short or oid.upper() == ident_u:
            candidates.append(oid)
    if not candidates:
        # Fuzzy: substring match (prefer User type)
        for oid, d in G.nodes(data=True):
            if not _domain_matches(d, domain_filter):
                continue
            name_u = (d.get("name") or "").upper()
            if ident_short and ident_short in name_u.split("@")[0]:
                candidates.append(oid)
    if not candidates:
        return None
    # Prefer User > Computer > Group
    type_rank = {"user": 0, "azure user": 0, "computer": 1, "group": 2, "azure group": 2}

    def rank(oid):
        t = (G.nodes[oid].get("type") or "").lower()
        return (type_rank.get(t, 9), G.nodes[oid].get("name") or "")

    candidates.sort(key=rank)
    return candidates[0]


_MEMBERSHIP_EDGE_LABELS = frozenset({
    "memberof",
    "member_of",
    "member",
    "ismemberof",
    "hasmember",
})


def _is_groupish_type(gtype: str) -> bool:
    """Whether to continue MemberOf nesting through this node type."""
    t = (gtype or "").lower().strip()
    if not t or t in ("unknown", "base", "?"):
        return True
    if "group" in t:  # Group, Azure Group, Local Group, …
        return True
    # Foreign security principals often nest into domain groups
    if "foreign" in t or t in ("fsp", "foreignsecurityprincipal"):
        return True
    return False


def collect_nested_groups(G, start_oid: str, max_depth: int = 25) -> Dict[str, Any]:
    """
    Walk MemberOf (and alias) edges from start_oid to collect effective group membership.

    Sources:
      - Outbound MemberOf / Member edges (BloodHound direction: principal → group)
      - Inbound HasMember / Member edges (some exporters reverse the relationship)

    Continues nesting through group-like types (incl. Unknown placeholders used for
    well-known SIDs). Returns direct groups, effective groups (incl. nested), depth map.
    """
    if start_oid not in G:
        return {
            "direct": [],
            "effective": [],
            "direct_count": 0,
            "effective_count": 0,
            "depth_map": {},
        }
    direct: List[dict] = []
    effective: List[dict] = []
    depth_map = {start_oid: 0}
    seen = {start_oid}
    queue = [(start_oid, 0)]

    def _visit_group(v, depth: int) -> None:
        if v in seen or v not in G:
            return
        seen.add(v)
        depth_map[v] = depth
        nd = G.nodes[v] or {}
        gname = nd.get("name", v)
        gtype = nd.get("type", "?")
        entry = {"id": v, "name": gname, "type": gtype, "depth": depth}
        if depth == 1:
            direct.append(entry)
        effective.append(entry)
        if depth < max_depth and _is_groupish_type(str(gtype)):
            queue.append((v, depth))

    while queue:
        cur, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        # Outbound: principal/group → MemberOf → parent group
        for _, v, ed in G.out_edges(cur, data=True):
            lab = ((ed or {}).get("label") or "").lower().replace(" ", "")
            # MemberOf / IsMemberOf = upward to parent group
            # Skip outbound HasMember (that is group → child member)
            if lab in ("memberof", "member_of", "ismemberof"):
                _visit_group(v, depth + 1)
            elif lab == "member" and _is_groupish_type(
                str((G.nodes.get(v) or {}).get("type") or "")
            ):
                # Ambiguous "Member" edge: treat as MemberOf when target is group-like
                _visit_group(v, depth + 1)
        # Inbound reverse edges: group -HasMember→ principal
        for u, _, ed in G.in_edges(cur, data=True):
            lab = ((ed or {}).get("label") or "").lower().replace(" ", "")
            if lab == "hasmember":
                _visit_group(u, depth + 1)

    direct.sort(key=lambda x: (x.get("name") or "").lower())
    effective.sort(key=lambda x: (x.get("depth", 0), (x.get("name") or "").lower()))
    return {
        "direct": direct,
        "effective": effective,
        "direct_count": len(direct),
        "effective_count": len(effective),
        "depth_map": depth_map,
    }


def collect_outbound_rights_for_principals(
    G,
    principal_oids: Sequence[str],
    include_labels: Optional[Sequence[str]] = None,
) -> Dict[str, List[dict]]:
    """
    Collect outbound edges of interest from a set of principals (user + nested groups).
    Returns mapping right_label -> list of {target, target_type, via, via_name}.
    """
    labels = set(include_labels or COMPROMISE_RIGHT_LABELS)
    labels.discard("MemberOf")  # membership handled separately
    by_right: Dict[str, List[dict]] = defaultdict(list)
    seen = set()  # (label, target, via)
    for src in principal_oids:
        if src not in G:
            continue
        src_name = G.nodes[src].get("name", src)
        for _, tgt, ed in G.out_edges(src, data=True):
            lab = (ed or {}).get("label") or ""
            if lab not in labels:
                # case-insensitive match for safety
                if lab.lower() not in {x.lower() for x in labels}:
                    continue
                # normalize to canonical casing if possible
                for canon in labels:
                    if canon.lower() == lab.lower():
                        lab = canon
                        break
            key = (lab, tgt, src)
            if key in seen:
                continue
            seen.add(key)
            by_right[lab].append({
                "target_id": tgt,
                "target": G.nodes[tgt].get("name", tgt),
                "target_type": G.nodes[tgt].get("type", "?"),
                "via_id": src,
                "via": src_name,
                "relationship": lab,
            })
    for lab in by_right:
        by_right[lab].sort(key=lambda r: (r["target"].lower(), r["via"].lower()))
    return dict(by_right)


def collect_paths_from_principal(
    G,
    source_oid: str,
    domain_filter=None,
    max_targets: int = 15,
    max_paths_per_target: int = 5,
    cutoff: int = 12,
    fast: bool = False,
) -> List[dict]:
    """Shortest paths from a compromised principal to high-value targets (outbound)."""
    if source_oid not in G:
        return []
    targets = _priority_high_value_targets(
        G, domain_filter, limit=3 if fast else max_targets
    )
    # Also include remaining high-value if not fast
    if not fast:
        all_hv = get_high_value_targets(G, domain_filter)
        seen_t = {t[0] for t in targets}
        for t in all_hv:
            if t[0] not in seen_t:
                targets.append(t)
            if len(targets) >= max_targets:
                break
    results = []
    src_name = G.nodes[source_oid].get("name", source_oid)
    for tid, tname, ttype in targets:
        if tid == source_oid:
            continue
        try:
            if not nx.has_path(G, source_oid, tid):
                continue
            path = nx.shortest_path(G, source_oid, tid)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
        if len(path) - 1 > cutoff:
            continue
        hop_labels = []
        for i in range(len(path) - 1):
            hop_labels.append(_edge_label(G, path[i], path[i + 1]))
        path_str = " -> ".join(
            f"{G.nodes[path[i]]['name']}"
            + (f" -[{hop_labels[i]}]>" if i < len(path) - 1 else "")
            for i in range(len(path))
        )
        results.append({
            "source": src_name,
            "source_id": source_oid,
            "target": tname,
            "target_id": tid,
            "target_type": ttype,
            "length": len(path) - 1,
            "path": path,
            "path_str": path_str,
            "relationships": hop_labels,
        })
        if fast and len(results) >= max_paths_per_target:
            break
    results.sort(key=lambda r: (r["length"], r["target"].lower()))
    return results[: max_targets * max_paths_per_target]


# Rights that imply immediate abuse impact even without a path to Domain Admins.
IMPACT_RIGHT_LABELS = frozenset({
    "genericall", "genericwrite", "writedacl", "writeowner", "owns",
    "forcechangepassword", "resetpassword", "addmember", "addkeycredentiallink",
    "allextendedrights", "writeaccountrestrictions", "addallowedtoact",
    "adminto", "localadmin", "allowedtoact",
})
IMPACT_TARGET_TYPES = frozenset({
    "user", "computer", "gpo", "group", "domain",
    "certificate template", "enterprise ca",
})


def collect_impact_edges_from_rights(rights: Dict[str, List[dict]]) -> List[dict]:
    """High-signal abuse edges from an outbound rights map (not only HV paths)."""
    impact = []
    for lab, rows in (rights or {}).items():
        if (lab or "").lower() not in IMPACT_RIGHT_LABELS:
            continue
        for r in rows:
            ttype = str(r.get("target_type") or "").lower()
            if ttype not in IMPACT_TARGET_TYPES:
                continue
            impact.append(
                {
                    "right": lab,
                    "target": r.get("target"),
                    "target_type": r.get("target_type"),
                    "via": r.get("via"),
                }
            )
    impact.sort(
        key=lambda x: (
            str(x.get("target_type") or "").lower(),
            str(x.get("target") or "").lower(),
            str(x.get("right") or "").lower(),
        )
    )
    return impact


def build_compromise_dossier(
    G,
    principal: str,
    domain_filter=None,
    fast: bool = False,
    max_path_targets: int = 15,
) -> Optional[dict]:
    """
    Build a full compromise dossier for one principal:
    identity, membership (direct+nested), outbound rights, paths to HV, summary counts.
    """
    oid = resolve_principal_oid(G, principal, domain_filter)
    if not oid:
        return None
    d = G.nodes[oid]
    membership = collect_nested_groups(G, oid)
    # Effective principals for rights = self + all nested groups
    principal_oids = [oid] + [g["id"] for g in membership["effective"]]
    rights = collect_outbound_rights_for_principals(G, principal_oids)
    impact_edges = collect_impact_edges_from_rights(rights)
    paths = collect_paths_from_principal(
        G,
        oid,
        domain_filter=domain_filter,
        max_targets=5 if fast else max_path_targets,
        max_paths_per_target=3 if fast else 5,
        cutoff=8 if fast else 12,
        fast=fast,
    )
    counts = {
        "direct_groups": membership["direct_count"],
        "effective_groups": membership["effective_count"],
        "paths_to_high_value": len(paths),
        "impact_edges": len(impact_edges),
    }
    for lab in COMPROMISE_SUMMARY_RIGHTS:
        counts[lab] = len(rights.get(lab, []))
    # Any other rights found
    for lab, rows in rights.items():
        if lab not in counts:
            counts[lab] = len(rows)

    props = d.get("props") or {}
    return {
        "query": principal,
        "resolved_id": oid,
        "name": d.get("name"),
        "type": d.get("type"),
        "domain": props.get("domain") or props.get("tenantId"),
        "is_azure": bool(d.get("is_azure")),
        "enabled": props.get("enabled", props.get("Enabled")),
        "highvalue": get_bool_prop_ci(props, ["highvalue", "HighValue"]),
        "membership": membership,
        "rights": rights,
        "impact_edges": impact_edges,
        "paths_to_high_value": paths,
        "counts": counts,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "BloodBash",
        "version": __version__,
        "organization": __org__,
    }


def print_compromise_dossier(dossier: dict, detail_limit: int = 25) -> None:
    """Structured console report for a compromise dossier."""
    if not dossier:
        console.print("[yellow]No compromise dossier to print[/yellow]")
        return
    name = dossier.get("name") or dossier.get("query")
    console.rule(f"[bold magenta]Compromise Dossier: {name}[/bold magenta]")
    console.print(
        f"[bold cyan]{name}[/bold cyan]  ({dossier.get('type')})  "
        f"[dim]id={dossier.get('resolved_id')} domain={dossier.get('domain')}[/dim]"
    )
    if dossier.get("enabled") is False:
        console.print("[yellow]Account appears disabled[/yellow]")
    if dossier.get("highvalue"):
        console.print("[red]Marked highvalue in collector data[/red]")

    # ── Summary counts ──
    counts = dossier.get("counts") or {}
    table = Table(
        title="Capability summary (outbound)",
        show_header=True,
        header_style="bold red",
    )
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="red")
    table.add_row("Direct group membership", str(counts.get("direct_groups", 0)))
    table.add_row("Effective groups (nested)", str(counts.get("effective_groups", 0)))
    table.add_row("Paths to high-value", str(counts.get("paths_to_high_value", 0)))
    table.add_row("Direct impact edges", str(counts.get("impact_edges", 0)))
    for lab in COMPROMISE_SUMMARY_RIGHTS:
        n = counts.get(lab, 0)
        if n:
            table.add_row(lab, str(n))
    # Extra rights not in summary list
    for lab, n in sorted(counts.items()):
        if lab in (
            "direct_groups",
            "effective_groups",
            "paths_to_high_value",
            "impact_edges",
        ):
            continue
        if lab in COMPROMISE_SUMMARY_RIGHTS:
            continue
        if n:
            table.add_row(lab, str(n))
    console.print(table)

    # ── Membership ──
    mem = dossier.get("membership") or {}
    console.print("\n[bold]Direct group membership[/bold]")
    direct = mem.get("direct") or []
    if not direct:
        console.print("  [dim](none)[/dim]")
    for g in direct[:detail_limit]:
        console.print(f"  • [green]{g['name']}[/green] ({g.get('type')})")
    if len(direct) > detail_limit:
        console.print(f"  [dim]... and {len(direct) - detail_limit} more[/dim]")

    console.print("\n[bold]Effective / nested groups[/bold]")
    effective = mem.get("effective") or []
    nested_only = [g for g in effective if g.get("depth", 1) > 1]
    if not nested_only and effective:
        console.print("  [dim](no nested groups beyond direct membership)[/dim]")
    for g in nested_only[:detail_limit]:
        console.print(
            f"  • [cyan]depth {g['depth']}[/cyan] [green]{g['name']}[/green] ({g.get('type')})"
        )
    if len(nested_only) > detail_limit:
        console.print(f"  [dim]... and {len(nested_only) - detail_limit} more[/dim]")

    # ── Rights breakdown ──
    rights = dossier.get("rights") or {}
    console.print("\n[bold]Outbound rights breakdown[/bold]")
    if not rights:
        console.print("  [dim](no outbound AdminTo/RDP/ACL rights found)[/dim]")
    for lab in list(COMPROMISE_SUMMARY_RIGHTS) + sorted(
        set(rights.keys()) - set(COMPROMISE_SUMMARY_RIGHTS)
    ):
        rows = rights.get(lab) or []
        if not rows:
            continue
        console.print(f"  [yellow]{lab}[/yellow] ([red]{len(rows)}[/red])")
        for r in rows[:detail_limit]:
            via = r.get("via") or ""
            via_note = f" [dim]via {via}[/dim]" if via and via != dossier.get("name") else ""
            console.print(
                f"    → [cyan]{r['target']}[/cyan] ({r.get('target_type')}){via_note}"
            )
        if len(rows) > detail_limit:
            console.print(f"    [dim]... and {len(rows) - detail_limit} more[/dim]")

    # ── Direct impact (GPO/user/computer abuse without DA path) ──
    impact = dossier.get("impact_edges") or []
    console.print("\n[bold]Direct impact edges (abuse without HV path)[/bold]")
    if not impact:
        console.print("  [dim](no high-impact write/reset/admin edges found)[/dim]")
    for r in impact[:detail_limit]:
        via = r.get("via") or ""
        via_note = f" [dim]via {via}[/dim]" if via and via != name else ""
        console.print(
            f"  • [yellow]{r.get('right')}[/yellow] → "
            f"[red]{r.get('target')}[/red] ({r.get('target_type')}){via_note}"
        )
    if len(impact) > detail_limit:
        console.print(f"  [dim]... and {len(impact) - detail_limit} more impact edges[/dim]")

    # ── Paths to HV ──
    paths = dossier.get("paths_to_high_value") or []
    console.print("\n[bold]Attack paths to high-value targets[/bold]")
    if not paths:
        console.print("  [dim](no path to high-value targets found within limits)[/dim]")
    for p in paths[:detail_limit]:
        console.print(
            f"  [dim]len {p['length']}[/dim] → [bold red]{p['target']}[/bold red] "
            f"({p.get('target_type')})"
        )
        console.print(f"    {p.get('path_str')}")
    if len(paths) > detail_limit:
        console.print(f"  [dim]... and {len(paths) - detail_limit} more paths[/dim]")

    add_finding(
        "Compromise Dossier",
        f"{name}: {counts.get('effective_groups', 0)} groups, "
        f"{counts.get('LocalAdmin', 0) + counts.get('AdminTo', 0)} admin rights, "
        f"{counts.get('CanRDP', 0)} RDP, {counts.get('paths_to_high_value', 0)} HV paths, "
        f"{counts.get('impact_edges', 0)} impact edges",
        score=8,
    )


def export_compromise_dossier(dossier: dict, export_dir: str) -> List[str]:
    """
    Write a per-principal compromise pack:
      summary.md, counts.csv, membership_*.txt, rights/*.txt, paths_*.txt/csv, dossier.json
    """
    if not dossier:
        return []
    export_dir = os.path.abspath(export_dir)
    os.makedirs(export_dir, exist_ok=True)
    rights_dir = os.path.join(export_dir, "rights")
    os.makedirs(rights_dir, exist_ok=True)
    written: List[str] = []
    name = dossier.get("name") or dossier.get("query") or "principal"
    counts = dossier.get("counts") or {}
    mem = dossier.get("membership") or {}
    rights = dossier.get("rights") or {}
    paths = dossier.get("paths_to_high_value") or []

    # summary.md
    summary_path = os.path.join(export_dir, "summary.md")
    lines = [
        f"# Compromise Dossier: {name}",
        "",
        f"- **Resolved:** `{dossier.get('name')}` ({dossier.get('type')})",
        f"- **Object ID:** `{dossier.get('resolved_id')}`",
        f"- **Domain / tenant:** `{dossier.get('domain')}`",
        f"- **Generated:** {dossier.get('generated_at')}",
        f"- **Tool:** BloodBash v{dossier.get('version', __version__)} ({dossier.get('organization', __org__)})",
        "",
        "## Summary counts",
        "",
        "| Metric | Count |",
        "|--------|------:|",
        f"| Direct groups | {counts.get('direct_groups', 0)} |",
        f"| Effective groups (nested) | {counts.get('effective_groups', 0)} |",
        f"| Paths to high-value | {counts.get('paths_to_high_value', 0)} |",
    ]
    for lab in COMPROMISE_SUMMARY_RIGHTS:
        n = counts.get(lab, 0)
        if n:
            lines.append(f"| {lab} | {n} |")
    for lab, n in sorted(counts.items()):
        if lab in COMPROMISE_SUMMARY_RIGHTS or lab in (
            "direct_groups", "effective_groups", "paths_to_high_value",
        ):
            continue
        if n:
            lines.append(f"| {lab} | {n} |")
    lines += ["", "## Files", "", "- `membership_direct.txt`", "- `membership_effective.txt`",
              "- `rights/*.txt`", "- `adminto_hosts.txt` / `adminto_hosts.csv` (bulk AdminTo host list)",
              "- `paths_to_high_value.txt`", "- `paths_to_high_value.csv`",
              "- `counts.csv`", "- `dossier.json`", ""]
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    written.append(summary_path)

    # counts.csv
    counts_path = os.path.join(export_dir, "counts.csv")
    write_csv_file(counts_path, ["Metric", "Count"], [[k, v] for k, v in sorted(counts.items())])
    written.append(counts_path)

    # membership lists
    direct_path = os.path.join(export_dir, "membership_direct.txt")
    with open(direct_path, "w", encoding="utf-8") as f:
        for g in mem.get("direct") or []:
            f.write(f"{g['name']}\t{g.get('type', '')}\tdepth={g.get('depth', 1)}\n")
    written.append(direct_path)

    effective_path = os.path.join(export_dir, "membership_effective.txt")
    with open(effective_path, "w", encoding="utf-8") as f:
        for g in mem.get("effective") or []:
            f.write(f"{g['name']}\t{g.get('type', '')}\tdepth={g.get('depth', 1)}\n")
    written.append(effective_path)

    # rights per label
    for lab, rows in sorted(rights.items()):
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", lab)
        rpath = os.path.join(rights_dir, f"{safe}.txt")
        with open(rpath, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(
                    f"{r['target']}\t{r.get('target_type', '')}\t"
                    f"via={r.get('via', '')}\t{r.get('relationship', lab)}\n"
                )
        written.append(rpath)
        # also CSV per right
        cpath = os.path.join(rights_dir, f"{safe}.csv")
        write_csv_file(
            cpath,
            ["Target", "TargetType", "Via", "Relationship"],
            [[r["target"], r.get("target_type"), r.get("via"), r.get("relationship")] for r in rows],
        )
        written.append(cpath)

    # Bulk AdminTo / LocalAdmin host list (operator-friendly flat list)
    admin_hosts = []
    seen_hosts = set()
    for lab in ("AdminTo", "LocalAdmin"):
        for r in rights.get(lab) or []:
            t = r.get("target") or ""
            if not t or t in seen_hosts:
                continue
            ttype = str(r.get("target_type") or "").lower()
            looks_like_host = ("$" in t or "." in t or t.upper().endswith("$"))
            if ttype not in ("computer", "?", "") and not looks_like_host:
                continue
            seen_hosts.add(t)
            admin_hosts.append({
                "host": t,
                "right": r.get("relationship") or lab,
                "via": r.get("via") or "",
            })
    admin_hosts.sort(key=lambda x: x["host"].lower())
    hosts_txt = os.path.join(export_dir, "adminto_hosts.txt")
    with open(hosts_txt, "w", encoding="utf-8") as f:
        f.write(f"# Bulk AdminTo/LocalAdmin hosts for {dossier.get('name')}\n")
        f.write(f"# Count: {len(admin_hosts)}\n")
        for h in admin_hosts:
            f.write(f"{h['host']}\n")
    written.append(hosts_txt)
    hosts_csv = os.path.join(export_dir, "adminto_hosts.csv")
    write_csv_file(
        hosts_csv,
        ["Host", "Right", "Via"],
        [[h["host"], h["right"], h["via"]] for h in admin_hosts],
    )
    written.append(hosts_csv)

    # paths
    paths_txt = os.path.join(export_dir, "paths_to_high_value.txt")
    with open(paths_txt, "w", encoding="utf-8") as f:
        if not paths:
            f.write("(none)\n")
        for p in paths:
            f.write(f"[{p['length']}] {p['source']} => {p['target']} ({p.get('target_type')})\n")
            f.write(f"  {p.get('path_str')}\n\n")
    written.append(paths_txt)

    paths_csv = os.path.join(export_dir, "paths_to_high_value.csv")
    write_csv_file(
        paths_csv,
        ["Length", "Source", "Target", "TargetType", "Path"],
        [[p["length"], p["source"], p["target"], p.get("target_type"), p.get("path_str")] for p in paths],
    )
    written.append(paths_csv)

    # full JSON (drop non-serializable path node id lists ok - they're strings)
    json_path = os.path.join(export_dir, "dossier.json")
    serializable = dict(dossier)
    # path lists of node ids are fine as JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2, default=str)
    written.append(json_path)

    # plain README for operators who want txt only
    readme = os.path.join(export_dir, "README.txt")
    with open(readme, "w", encoding="utf-8") as f:
        f.write(f"Compromise dossier for {name}\n")
        f.write(f"Generated by BloodBash v{__version__} ({__org__})\n\n")
        f.write("Quick counts:\n")
        for k, v in sorted(counts.items()):
            if v:
                f.write(f"  {k}: {v}\n")
        f.write("\nSee summary.md and rights/ for full lists.\n")
    written.append(readme)

    console.print(f"[green]Compromise dossier exported:[/green] {export_dir} ({len(written)} files)")
    logger.info("Compromise dossier for %s written to %s", name, export_dir)
    return written


def run_compromise_dossiers(
    G,
    principals: str,
    domain_filter=None,
    export_dir: Optional[str] = None,
    fast: bool = False,
) -> List[dict]:
    """
    Build/print/export dossiers for one or more comma-separated principals.
    """
    names = [p.strip() for p in (principals or "").split(",") if p.strip()]
    if not names:
        console.print("[yellow]No principal provided for compromise dossier[/yellow]")
        return []
    dossiers = []
    for name in names:
        dossier = build_compromise_dossier(
            G, name, domain_filter=domain_filter, fast=fast
        )
        if not dossier:
            console.print(f"[red]Principal not found:[/red] {name}")
            continue
        print_compromise_dossier(dossier)
        if export_dir is not None:
            # Per-principal subdir when multiple names or explicit export root
            safe = re.sub(r"[^A-Za-z0-9._@-]+", "_", dossier.get("name") or name).strip("._")
            if not safe or safe in (".", "..") or ".." in safe:
                safe = "principal"
            root = os.path.abspath(export_dir or "compromise-dossiers")
            if len(names) == 1 and export_dir:
                out = root
            else:
                out = os.path.join(root, safe)
            # Ensure we never write outside the export root
            out_abs = os.path.abspath(out)
            if os.path.commonpath([root, out_abs]) != root:
                out_abs = os.path.join(root, "principal")
            export_compromise_dossier(dossier, out_abs)
        dossiers.append(dossier)
    return dossiers


# ────────────────────────────────────────────────
# Multi-report HTML suite / CSV sections / zip pack
# ────────────────────────────────────────────────
HTML_TABLE_SORT_JS = """
<script>
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('table.sortable').forEach(function (table) {
    const heads = table.querySelectorAll('th');
    heads.forEach(function (th, colIdx) {
      th.style.cursor = 'pointer';
      th.title = 'Click to sort';
      th.addEventListener('click', function () {
        const tbody = table.tBodies[0];
        if (!tbody) return;
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const asc = th.getAttribute('data-sort') !== 'asc';
        heads.forEach(h => h.removeAttribute('data-sort'));
        th.setAttribute('data-sort', asc ? 'asc' : 'desc');
        rows.sort(function (a, b) {
          const ta = (a.children[colIdx] && a.children[colIdx].innerText || '').trim();
          const tb = (b.children[colIdx] && b.children[colIdx].innerText || '').trim();
          const na = parseFloat(ta), nb = parseFloat(tb);
          let cmp;
          if (!isNaN(na) && !isNaN(nb) && ta !== '' && tb !== '') cmp = na - nb;
          else cmp = ta.localeCompare(tb, undefined, {numeric: true, sensitivity: 'base'});
          return asc ? cmp : -cmp;
        });
        rows.forEach(r => tbody.appendChild(r));
      });
    });
  });
});
</script>
"""

HTML_REPORT_CSS = """
:root { --bg: #0f1419; --card: #1a2332; --text: #e7ecf3; --muted: #9aa7b8; --accent: #3dbbdb; --border: #2c3a4f; --danger: #ff6b6b; }
* { box-sizing: border-box; }
body { font-family: Segoe UI, system-ui, sans-serif; margin: 0; background: var(--bg); color: var(--text); }
header, footer { background: var(--card); border-bottom: 1px solid var(--border); padding: 1rem 1.5rem; }
footer { border-top: 1px solid var(--border); border-bottom: none; margin-top: 2rem; color: var(--muted); font-size: 0.9rem; }
main { padding: 1.5rem; max-width: 1200px; margin: 0 auto; }
h1, h2 { color: var(--accent); }
a { color: var(--accent); }
.meta { color: var(--muted); margin-bottom: 1rem; }
.cards { display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 1rem 0; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem 1rem; min-width: 160px; }
.card strong { display: block; font-size: 1.4rem; color: var(--danger); }
table { width: 100%; border-collapse: collapse; background: var(--card); margin: 1rem 0; }
th, td { border: 1px solid var(--border); padding: 0.45rem 0.6rem; text-align: left; vertical-align: top; }
th { background: #243044; position: sticky; top: 0; }
tr:nth-child(even) { background: rgba(255,255,255,0.02); }
.nav a { margin-right: 0.75rem; }
.badge { display: inline-block; background: #243044; border-radius: 999px; padding: 0.1rem 0.5rem; font-size: 0.85rem; color: var(--muted); }
"""


def render_html_page(title: str, body_html: str, nav_links: Optional[List[Tuple[str, str]]] = None) -> str:
    nav = ""
    if nav_links:
        links = " ".join(f'<a href="{escape(href)}">{escape(label)}</a>' for label, href in nav_links)
        nav = f'<div class="nav">{links}</div>'
    today = date.today().isoformat()
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{escape(title)} — BloodBash / {escape(__org__)}</title>
  <style>{HTML_REPORT_CSS}</style>
</head>
<body>
<header>
  <div class="badge">{escape(__org__)} open source</div>
  <h1>{escape(title)}</h1>
  <div class="meta">BloodBash v{escape(__version__)} · {escape(today)} ·
    <a href="{escape(__org_url__)}">{escape(__org_url__)}</a>
  </div>
  {nav}
</header>
<main>
{body_html}
</main>
<footer>
  Generated by BloodBash ({escape(__org__)}) · {escape(__project_url__)} · For authorized security testing only.
</footer>
{HTML_TABLE_SORT_JS}
</body>
</html>
"""


def _html_table(headers: Sequence[str], rows: Sequence[Sequence[Any]], sortable: bool = True) -> str:
    cls = "sortable" if sortable else ""
    thead = "".join(f"<th>{escape(str(h))}</th>" for h in headers)
    body_rows = []
    if not rows:
        body_rows.append(f"<tr><td colspan='{len(headers)}'>(none)</td></tr>")
    else:
        for row in rows:
            tds = "".join(f"<td>{escape(str(c) if c is not None else '')}</td>" for c in row)
            body_rows.append(f"<tr>{tds}</tr>")
    return f"<table class=\"{cls}\"><thead><tr>{thead}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"


def write_csv_file(path: str, headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(list(headers))
        for row in rows:
            w.writerow(list(row))
    return path


def build_inventory_export_data(
    G,
    domain_filter=None,
    owned: Optional[str] = None,
    busiest_mode: str = "short",
    busiest_top: int = 5,
    path_break_top: int = 15,
    fast: bool = False,
    include_paths: bool = True,
) -> dict:
    """Aggregate inventory + path remediation datasets for report packs."""
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "password_age": collect_password_age_rows(G, domain_filter),
        "stale_accounts": collect_stale_account_rows(G, domain_filter),
        "privilege_inventory": collect_privilege_inventory(G, domain_filter),
        "structural": collect_structural_inventory(G, domain_filter),
        "owned_inventory": collect_owned_inventory(G, owned or "", domain_filter) if owned else [],
        "busiest_paths": [],
        "path_breaks": [],
        "findings": [
            {"score": s, "category": c, "details": d}
            for s, c, d in sorted(global_findings, key=lambda x: x[0], reverse=True)
        ],
        "high_value": [
            {"name": name, "type": typ}
            for _, name, typ in get_high_value_targets(G, domain_filter)
        ],
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
    }
    if include_paths:
        data["busiest_paths"] = collect_busiest_paths(
            G, mode=busiest_mode, top=busiest_top, domain_filter=domain_filter, fast=fast
        )
        data["path_breaks"] = collect_path_breaks(
            G, domain_filter=domain_filter, top=path_break_top, fast=fast
        )
    return data


def export_report_pack(
    G,
    export_dir: str,
    domain_filter=None,
    owned: Optional[str] = None,
    busiest_mode: str = "short",
    busiest_top: int = 5,
    path_break_top: int = 15,
    fast: bool = False,
    include_paths: bool = True,
) -> List[str]:
    """
    Write a multi-page HTML report suite + per-section CSVs + index.html.
    Returns list of written file paths.
    """
    export_dir = os.path.abspath(export_dir)
    os.makedirs(export_dir, exist_ok=True)
    csv_dir = os.path.join(export_dir, "csv")
    os.makedirs(csv_dir, exist_ok=True)
    data = build_inventory_export_data(
        G,
        domain_filter=domain_filter,
        owned=owned,
        busiest_mode=busiest_mode,
        busiest_top=busiest_top,
        path_break_top=path_break_top,
        fast=fast,
        include_paths=include_paths,
    )
    written: List[str] = []
    pages = [
        ("index.html", "Report Index"),
        ("findings.html", "Prioritized Findings"),
        ("high_value.html", "High-Value Targets"),
        ("password_age.html", "Password Age Inventory"),
        ("stale_accounts.html", "Stale Accounts"),
        ("privilege_inventory.html", "Privilege Inventory"),
        ("structural.html", "Structural Inventory"),
        ("owned_inventory.html", "Owned Inventory"),
        ("busiest_paths.html", "Busiest Paths"),
        ("path_breaks.html", "Path Break Remediation"),
    ]
    nav = [(label, href) for href, label in pages]

    def write_page(filename: str, title: str, body: str):
        path = os.path.join(export_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(render_html_page(title, body, nav_links=nav))
        written.append(path)

    # Index
    cards = f"""
    <div class="cards">
      <div class="card"><span>Nodes</span><strong>{data['nodes']}</strong></div>
      <div class="card"><span>Edges</span><strong>{data['edges']}</strong></div>
      <div class="card"><span>Findings</span><strong>{len(data['findings'])}</strong></div>
      <div class="card"><span>High-value</span><strong>{len(data['high_value'])}</strong></div>
      <div class="card"><span>Busiest paths</span><strong>{len(data['busiest_paths'])}</strong></div>
      <div class="card"><span>Path breaks</span><strong>{len(data['path_breaks'])}</strong></div>
    </div>
    <h2>Reports</h2>
    <ul>
      {''.join(f'<li><a href="{escape(h)}">{escape(t)}</a></li>' for h, t in pages if h != 'index.html')}
      <li><a href="csv/">CSV exports</a></li>
    </ul>
    """
    write_page("index.html", "BloodBash Report Index", cards)

    # Findings
    f_rows = [[f["score"], f["category"], f["details"]] for f in data["findings"]]
    write_page("findings.html", "Prioritized Findings", _html_table(["Severity", "Category", "Details"], f_rows))
    written.append(write_csv_file(os.path.join(csv_dir, "findings.csv"), ["Severity", "Category", "Details"], f_rows))

    hv_rows = [[h["name"], h["type"]] for h in data["high_value"]]
    write_page("high_value.html", "High-Value Targets", _html_table(["Name", "Type"], hv_rows))
    written.append(write_csv_file(os.path.join(csv_dir, "high_value.csv"), ["Name", "Type"], hv_rows))

    pa_rows = [[r["name"], r["enabled"], r["days_old"], r["bucket"]] for r in data["password_age"]]
    write_page("password_age.html", "Password Age Inventory", _html_table(["User", "Enabled", "Days old", "Bucket"], pa_rows))
    written.append(write_csv_file(os.path.join(csv_dir, "password_age.csv"), ["User", "Enabled", "Days old", "Bucket"], pa_rows))

    sa_rows = [[r["name"], r["enabled"], r["days_inactive"], r["bucket"]] for r in data["stale_accounts"]]
    write_page("stale_accounts.html", "Stale Accounts", _html_table(["User", "Enabled", "Days inactive", "Bucket"], sa_rows))
    written.append(write_csv_file(os.path.join(csv_dir, "stale_accounts.csv"), ["User", "Enabled", "Days inactive", "Bucket"], sa_rows))

    priv_rows = [[r["group"], r["member_count"], "; ".join(r["members"][:50]), r["highvalue"]] for r in data["privilege_inventory"]]
    write_page(
        "privilege_inventory.html",
        "Privilege Inventory",
        _html_table(["Group", "Members", "Member list", "HighValue"], priv_rows),
    )
    written.append(write_csv_file(
        os.path.join(csv_dir, "privilege_inventory.csv"),
        ["Group", "Members", "Member list", "HighValue"],
        priv_rows,
    ))

    st = data["structural"]
    struct_body = (
        "<h2>Domains</h2>" + _html_table(["Name", "Type"], [[x["name"], x["type"]] for x in st["domains"]])
        + "<h2>Domain Controllers</h2>" + _html_table(["Name", "Type"], [[x["name"], x["type"]] for x in st["domain_controllers"]])
        + "<h2>Trusts</h2>" + _html_table(["From", "To", "Type"], [[x["from"], x["to"], x["type"]] for x in st["trusts"]])
    )
    write_page("structural.html", "Structural Inventory", struct_body)
    written.append(write_csv_file(
        os.path.join(csv_dir, "domains.csv"),
        ["Name", "Type"],
        [[x["name"], x["type"]] for x in st["domains"]],
    ))

    owned_rows = [[
        r["name"], r["type"], r["admin_to_count"], "; ".join(r["admin_to"][:30]),
        r["member_of_count"], "; ".join(r["member_of"][:30]),
    ] for r in data["owned_inventory"]]
    write_page(
        "owned_inventory.html",
        "Owned Inventory",
        _html_table(["Name", "Type", "AdminTo#", "AdminTo", "MemberOf#", "MemberOf"], owned_rows),
    )
    written.append(write_csv_file(
        os.path.join(csv_dir, "owned_inventory.csv"),
        ["Name", "Type", "AdminTo#", "AdminTo", "MemberOf#", "MemberOf"],
        owned_rows,
    ))

    bp_rows = [[r.get("kind"), r.get("name"), r.get("type"), r.get("path_count"), ", ".join(r.get("targets") or [])] for r in data["busiest_paths"]]
    write_page("busiest_paths.html", "Busiest Paths", _html_table(["Kind", "Principal", "Type", "Path count", "Targets"], bp_rows))
    written.append(write_csv_file(
        os.path.join(csv_dir, "busiest_paths.csv"),
        ["Kind", "Principal", "Type", "Path count", "Targets"],
        bp_rows,
    ))

    pb_rows = [[r["relationship"], r["from"], r["to"], r["paths_broken"], r["recommendation"]] for r in data["path_breaks"]]
    write_page(
        "path_breaks.html",
        "Path Break Remediation",
        _html_table(["Relationship", "From", "To", "Paths broken", "Recommendation"], pb_rows),
    )
    written.append(write_csv_file(
        os.path.join(csv_dir, "path_breaks.csv"),
        ["Relationship", "From", "To", "Paths broken", "Recommendation"],
        pb_rows,
    ))

    # Manifest for zip tooling
    manifest_path = os.path.join(export_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({
            "tool": "BloodBash",
            "version": __version__,
            "organization": __org__,
            "files": [os.path.relpath(p, export_dir) for p in written if p.startswith(export_dir)],
            "generated_at": data["generated_at"],
        }, f, indent=2)
    written.append(manifest_path)
    console.print(f"[green]Report pack written:[/green] {export_dir} ({len(written)} files)")
    logger.info("Report pack written to %s (%d files)", export_dir, len(written))
    return written


def export_zip_pack(source_dir: str, zip_path: str) -> str:
    """Zip a report pack directory into a single deliverable archive."""
    source_dir = os.path.abspath(source_dir)
    zip_path = os.path.abspath(zip_path)
    parent = os.path.dirname(zip_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(source_dir):
            for name in files:
                full = os.path.join(root, name)
                arc = os.path.relpath(full, source_dir)
                zf.write(full, arcname=arc)
    console.print(f"[green]Exported report zip:[/green] {zip_path}")
    logger.info("Exported report zip %s", zip_path)
    return zip_path


def _node_enabled(props) -> bool:
    if _prop_raw_ci(props, ["enabled", "Enabled"]) is None:
        return True
    return get_bool_prop_ci(props, ["enabled", "Enabled"], default=True)


def collect_csv_pack_datasets(G, domain_filter=None) -> Dict[str, Tuple[List[str], List[List[Any]]]]:
    """PlumHound-style multi-CSV datasets: name -> (headers, rows)."""
    datasets: Dict[str, Tuple[List[str], List[List[Any]]]] = {}

    # Domains
    domain_rows = []
    for n, d in G.nodes(data=True):
        if d.get("is_azure"):
            continue
        if str(d.get("type") or "").lower() != "domain":
            continue
        if not _domain_matches(d, domain_filter):
            continue
        domain_rows.append([d.get("name") or n, str(d.get("type"))])
    for r in list_domains(G):
        if r["kind"] == "AD Domain" and not any(x[0] == r["name"] for x in domain_rows):
            if domain_filter and str(r["name"]).lower() != str(domain_filter).lower():
                continue
            domain_rows.append([r["name"], "Domain"])
    datasets["domains.csv"] = (["Name", "Type"], domain_rows)

    # Domain Admins (nested members of DA-style groups)
    da_rows = []
    for n, d in G.nodes(data=True):
        if d.get("is_azure"):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if str(d.get("type") or "").lower() not in ("user", "computer", "group"):
            continue
        is_priv, groups = is_member_of_privileged_group(G, n)
        if not is_priv:
            continue
        da_like = [g for g in groups if "domain admins" in g.lower() or "enterprise admins" in g.lower()]
        if not da_like and not any("domain admins" in (d.get("name") or "").lower() for _ in [0]):
            # still include if nested into any priv group matched above
            da_like = groups[:3]
        props = d.get("props") or {}
        da_rows.append([
            d.get("name") or n,
            d.get("type"),
            _node_enabled(props),
            "; ".join(da_like or groups[:5]),
        ])
    datasets["domain_admins.csv"] = (
        ["Name", "Type", "Enabled", "ViaGroups"],
        sorted(da_rows, key=lambda r: str(r[0]).lower()),
    )

    # Users / computers / groups inventory
    user_rows, comp_rows, group_rows = [], [], []
    for n, d in G.nodes(data=True):
        if d.get("is_azure"):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        props = d.get("props") or {}
        typ = str(d.get("type") or "").lower()
        name = d.get("name") or n
        if typ == "user":
            user_rows.append([
                name,
                _node_enabled(props),
                get_bool_prop_ci(props, ["admincount", "adminCount"]),
                _user_has_spn(props),
                get_bool_prop_ci(props, ["dontreqpreauth", "dontReqPreauth"]),
                get_bool_prop_ci(props, ["passwordneverexpires", "pwdneverexpires"]),
                get_bool_prop_ci(props, ["passwordnotrequired", "passwordnotreqd"]),
            ])
        elif typ == "computer":
            comp_rows.append([
                name,
                _node_enabled(props),
                _has_laps_enabled(props),
                is_domain_controller(G, n),
                _prop_raw_ci(props, ["operatingsystem", "OperatingSystem"]) or "",
            ])
        elif typ == "group":
            member_count = sum(
                1
                for u, _, ed in G.in_edges(n, data=True)
                if (ed.get("label") or "").lower() in ("memberof", "member")
            )
            group_rows.append([
                name,
                get_bool_prop_ci(props, ["highvalue", "HighValue"]),
                get_bool_prop_ci(props, ["admincount", "adminCount"]),
                member_count,
            ])
    datasets["users.csv"] = (
        ["Name", "Enabled", "AdminCount", "HasSPN", "DontReqPreauth", "PwdNeverExpires", "PwdNotRequired"],
        sorted(user_rows, key=lambda r: str(r[0]).lower()),
    )
    datasets["computers.csv"] = (
        ["Name", "Enabled", "HasLAPS", "IsDC", "OperatingSystem"],
        sorted(comp_rows, key=lambda r: str(r[0]).lower()),
    )
    datasets["groups.csv"] = (
        ["Name", "HighValue", "AdminCount", "InboundMemberEdges"],
        sorted(group_rows, key=lambda r: str(r[0]).lower()),
    )

    # Credential hygiene CSVs
    kerb_rows, asrep_rows, pne_rows = [], [], []
    for n, d in G.nodes(data=True):
        if d.get("is_azure") or str(d.get("type") or "").lower() != "user":
            continue
        if not _domain_matches(d, domain_filter):
            continue
        props = d.get("props") or {}
        if not _node_enabled(props):
            continue
        name = d.get("name") or n
        if name.upper().startswith("KRBTGT"):
            continue
        if _user_has_spn(props) and not get_bool_prop_ci(props, ["sensitive", "Sensitive"]):
            kerb_rows.append([name, format_privilege_context_tags(d).strip()])
        if get_bool_prop_ci(props, ["dontreqpreauth", "dontReqPreauth"]):
            asrep_rows.append([name, format_privilege_context_tags(d).strip()])
        pne = get_bool_prop_ci(props, ["passwordneverexpires", "pwdneverexpires"])
        if not pne:
            uac = _prop_raw_ci(props, ["useraccountcontrol", "UserAccountControl"])
            try:
                pne = bool(int(uac) & 0x10000)
            except (TypeError, ValueError):
                pass
        if pne:
            pne_rows.append([name])
    datasets["kerberoastable.csv"] = (["Name", "Tags"], kerb_rows)
    datasets["asrep_roastable.csv"] = (["Name", "Tags"], asrep_rows)
    datasets["password_never_expires.csv"] = (["Name"], pne_rows)

    # LAPS not enabled
    laps_missing = []
    for n, d in G.nodes(data=True):
        if d.get("is_azure") or str(d.get("type") or "").lower() != "computer":
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if not _has_laps_enabled(d.get("props") or {}):
            laps_missing.append([d.get("name") or n])
    datasets["laps_not_enabled.csv"] = (["Computer"], laps_missing)

    # Local admins (users) — AdminTo / LocalAdmin edges from user -> computer
    la_rows = []
    for u, v, ed in G.edges(data=True):
        label = (ed.get("label") or "").lower()
        if label not in ("adminto", "localadmin"):
            continue
        ud, vd = G.nodes.get(u) or {}, G.nodes.get(v) or {}
        if ud.get("is_azure") or vd.get("is_azure"):
            continue
        if str(vd.get("type") or "").lower() != "computer":
            continue
        if str(ud.get("type") or "").lower() not in ("user", "group"):
            continue
        if domain_filter and not (
            _domain_matches(ud, domain_filter) or _domain_matches(vd, domain_filter)
        ):
            continue
        la_rows.append([
            ud.get("name") or u,
            ud.get("type"),
            ed.get("label") or label,
            vd.get("name") or v,
        ])
    datasets["local_admins_users.csv"] = (
        ["Principal", "PrincipalType", "Right", "Computer"],
        sorted(la_rows, key=lambda r: (str(r[0]).lower(), str(r[3]).lower())),
    )

    # User sessions — HasSession computer -> user (BloodHound direction)
    sess_rows = []
    for u, v, ed in G.edges(data=True):
        if (ed.get("label") or "").lower() != "hassession":
            continue
        ud, vd = G.nodes.get(u) or {}, G.nodes.get(v) or {}
        # Normalize to Computer, User
        if str(ud.get("type") or "").lower() == "computer":
            comp, user = ud, vd
        elif str(vd.get("type") or "").lower() == "computer":
            comp, user = vd, ud
        else:
            continue
        if domain_filter and not (
            _domain_matches(comp, domain_filter) or _domain_matches(user, domain_filter)
        ):
            continue
        sess_rows.append([comp.get("name") or "", user.get("name") or ""])
    datasets["user_sessions.csv"] = (
        ["Computer", "User"],
        sorted(sess_rows, key=lambda r: (str(r[0]).lower(), str(r[1]).lower())),
    )

    # Over-privileged broad principals (PlumHound Everyone / Auth Users / Domain Users)
    OVERPRIV_PRINCIPAL_NEEDLES = (
        ("everyone", "relationships_everyone.csv"),
        ("authenticated users", "relationships_authenticated_users.csv"),
        ("pre-windows 2000", "relationships_pre_windows_2000.csv"),
        ("domain users", "relationships_domain_users.csv"),
        ("domain computers", "relationships_domain_computers.csv"),
        ("users@", "relationships_users_group.csv"),
        ("guests@", "relationships_guests.csv"),
    )
    MEMBERSHIP_LABELS = frozenset({"memberof", "member", "member_of", "contains", "gplink", "linkedto"})
    over_all: List[List[Any]] = []
    per_file_rows: Dict[str, List[List[Any]]] = {fn: [] for _, fn in OVERPRIV_PRINCIPAL_NEEDLES}
    for u, v, ed in G.edges(data=True):
        label = ed.get("label") or ""
        label_l = label.lower()
        if label_l in MEMBERSHIP_LABELS:
            continue
        ud, vd = G.nodes.get(u) or {}, G.nodes.get(v) or {}
        if ud.get("is_azure") or vd.get("is_azure"):
            continue
        if domain_filter and not (
            _domain_matches(ud, domain_filter) or _domain_matches(vd, domain_filter)
        ):
            continue
        src_name = ud.get("name") or str(u)
        src_l = src_name.lower()
        dst_name = vd.get("name") or str(v)
        matched_file = None
        for needle, fname in OVERPRIV_PRINCIPAL_NEEDLES:
            if needle in src_l:
                matched_file = fname
                break
        if not matched_file:
            continue
        row = [src_name, label, dst_name, vd.get("type") or ""]
        per_file_rows[matched_file].append(row)
        over_all.append(row + [matched_file])
    rel_headers = ["Principal", "Relationship", "Target", "TargetType"]
    for _, fname in OVERPRIV_PRINCIPAL_NEEDLES:
        rows = sorted(per_file_rows[fname], key=lambda r: (str(r[0]).lower(), str(r[2]).lower(), str(r[1]).lower()))
        datasets[fname] = (rel_headers, rows)
    datasets["overprivileged_relationships.csv"] = (
        ["Principal", "Relationship", "Target", "TargetType", "SourceFile"],
        sorted(over_all, key=lambda r: (str(r[0]).lower(), str(r[2]).lower())),
    )

    # Computer AdminTo Computer (lateral movement via machine accounts)
    c2c_rows: List[List[Any]] = []
    for u, v, ed in G.edges(data=True):
        label = (ed.get("label") or "").lower()
        if label not in ("adminto", "localadmin"):
            continue
        ud, vd = G.nodes.get(u) or {}, G.nodes.get(v) or {}
        if str(ud.get("type") or "").lower() != "computer":
            continue
        if str(vd.get("type") or "").lower() != "computer":
            continue
        if ud.get("is_azure") or vd.get("is_azure"):
            continue
        if domain_filter and not (
            _domain_matches(ud, domain_filter) or _domain_matches(vd, domain_filter)
        ):
            continue
        c2c_rows.append([
            ud.get("name") or u,
            ed.get("label") or "AdminTo",
            vd.get("name") or v,
        ])
    datasets["computer_adminto_computer.csv"] = (
        ["SourceComputer", "Right", "TargetComputer"],
        sorted(c2c_rows, key=lambda r: (str(r[0]).lower(), str(r[2]).lower())),
    )

    # Bulk AdminTo host lists (principals with outbound AdminTo counts)
    bulk_map: Dict[str, List[str]] = defaultdict(list)
    bulk_type: Dict[str, str] = {}
    for u, v, ed in G.edges(data=True):
        if (ed.get("label") or "").lower() not in ("adminto", "localadmin"):
            continue
        ud, vd = G.nodes.get(u) or {}, G.nodes.get(v) or {}
        if str(vd.get("type") or "").lower() != "computer":
            continue
        if ud.get("is_azure") or vd.get("is_azure"):
            continue
        if domain_filter and not (
            _domain_matches(ud, domain_filter) or _domain_matches(vd, domain_filter)
        ):
            continue
        src = ud.get("name") or str(u)
        bulk_map[src].append(vd.get("name") or str(v))
        bulk_type[src] = str(ud.get("type") or "")
    bulk_rows = []
    for src, hosts in bulk_map.items():
        hosts_u = sorted(set(hosts), key=str.lower)
        bulk_rows.append([
            src,
            bulk_type.get(src, ""),
            len(hosts_u),
            "; ".join(hosts_u[:50]) + (f" (+{len(hosts_u) - 50})" if len(hosts_u) > 50 else ""),
        ])
    bulk_rows.sort(key=lambda r: (-int(r[2]), str(r[0]).lower()))
    datasets["bulk_adminto_hosts.csv"] = (
        ["Principal", "PrincipalType", "HostCount", "Hosts"],
        bulk_rows,
    )

    # Dual: privileged (DA/EA nested) AND has AdminTo/local admin (tiering violation)
    dual_rows: List[List[Any]] = []
    for n, d in G.nodes(data=True):
        if d.get("is_azure"):
            continue
        if not _domain_matches(d, domain_filter):
            continue
        if str(d.get("type") or "").lower() not in ("user", "computer"):
            continue
        is_priv, groups = is_member_of_privileged_group(G, n)
        if not is_priv:
            continue
        admin_targets = []
        for _, v, ed in G.out_edges(n, data=True):
            if (ed.get("label") or "").lower() not in ("adminto", "localadmin"):
                continue
            vd = G.nodes.get(v) or {}
            if str(vd.get("type") or "").lower() == "computer":
                admin_targets.append(vd.get("name") or str(v))
        if not admin_targets:
            continue
        dual_rows.append([
            d.get("name") or n,
            d.get("type"),
            "; ".join(groups[:5]),
            len(admin_targets),
            "; ".join(sorted(set(admin_targets), key=lambda s: str(s).lower())[:30]),
        ])
    datasets["dual_privileged_and_local_admin.csv"] = (
        ["Principal", "Type", "PrivGroups", "AdminToCount", "AdminToHosts"],
        sorted(dual_rows, key=lambda r: (-int(r[3]), str(r[0]).lower())),
    )

    return datasets


def export_csv_pack(G, export_dir: str, domain_filter=None) -> List[str]:
    """
    PlumHound-style multi-CSV report pack: one CSV per inventory task + index.csv.
    """
    export_dir = os.path.abspath(export_dir)
    os.makedirs(export_dir, exist_ok=True)
    datasets = collect_csv_pack_datasets(G, domain_filter)
    written: List[str] = []
    index_rows: List[List[Any]] = []
    for filename, (headers, rows) in sorted(datasets.items()):
        path = os.path.join(export_dir, filename)
        write_csv_file(path, headers, rows)
        written.append(path)
        index_rows.append([filename, len(rows), ", ".join(headers)])
    index_path = os.path.join(export_dir, "index.csv")
    write_csv_file(index_path, ["File", "RowCount", "Columns"], index_rows)
    written.append(index_path)
    readme = os.path.join(export_dir, "README.txt")
    with open(readme, "w", encoding="utf-8") as f:
        f.write(
            f"BloodBash PlumHound-style CSV pack v{__version__} ({__org__})\n"
            f"Generated: {datetime.now(timezone.utc).isoformat()}\n"
            f"Files: {len(datasets)} datasets + index.csv\n"
            f"Use index.csv as a report index (similar to PlumHound REPORT-INDEX).\n"
        )
    written.append(readme)
    console.print(
        f"[green]CSV pack written:[/green] {export_dir} "
        f"({len(datasets)} datasets, {len(written)} files)"
    )
    logger.info("CSV pack written to %s (%d files)", export_dir, len(written))
    return written


# ────────────────────────────────────────────────
# Export
# ────────────────────────────────────────────────
def build_export_report(G, domain_filter=None):
    """Structured report shared by all --export formats (md/json/html/csv/yaml)."""
    high_value = [
        {"name": name, "type": typ}
        for _, name, typ in get_high_value_targets(G, domain_filter)
    ]
    collapsed = collapse_findings(global_findings)
    findings = [
        {"score": score, "category": cat, "details": det}
        for score, cat, det in collapsed
    ]
    return {
        "tool": "BloodBash",
        "version": __version__,
        "organization": __org__,
        "organization_url": __org_url__,
        "project_url": __project_url__,
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "high_value": high_value,
        "findings": findings,
        "findings_raw_count": len(global_findings),
        "findings_collapsed_count": len(collapsed),
    }

def export_results(G, output_prefix="bloodbash", format_type="md", domain_filter=None):
    report = build_export_report(G, domain_filter)
    if format_type == "md":
        path = f"{output_prefix}.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# BloodBash Report\n\n")
            f.write(f"**{__org__}** open source · BloodBash v{__version__}  \n")
            f.write(f"{__org_url__}  \n")
            f.write(f"{__project_url__}\n\n")
            f.write(f"Nodes: {report['nodes']}  \nEdges: {report['edges']}\n\n")

            f.write("## High-Value Targets\n")
            if report["high_value"]:
                for hv in report["high_value"]:
                    f.write(f"- {hv['name']} ({hv['type']})\n")
            else:
                f.write("- (none)\n")
            f.write("\n## Prioritized Findings\n")
            if report["findings"]:
                for finding in report["findings"]:
                    f.write(
                        f"- **[{finding['score']}] {finding['category']}**: {finding['details']}\n"
                    )
            else:
                f.write("- (none)\n")
        console.print(f"[green]Exported Markdown:[/green] {path}")
    elif format_type == "json":
        path = f"{output_prefix}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"[green]Exported JSON:[/green] {path}")
    elif format_type == "html":
        path = f"{output_prefix}.html"
        f_rows = [[f["score"], f["category"], f["details"]] for f in report["findings"]]
        hv_rows = [[h["name"], h["type"]] for h in report["high_value"]]
        body = (
            f"<p class='meta'>Nodes: {report['nodes']} | Edges: {report['edges']}</p>"
            "<h2>High-Value Targets</h2>"
            + _html_table(["Name", "Type"], hv_rows)
            + "<h2>Prioritized Findings</h2>"
            + _html_table(["Severity", "Category", "Details"], f_rows)
        )
        html = render_html_page("BloodBash Report", body)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        console.print(f"[green]Exported HTML:[/green] {path}")
    elif format_type == "csv":
        # General findings report (not LocalAdmin-only sessions stub)
        path = f"{output_prefix}.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Severity", "Category", "Details"])
            for finding in report["findings"]:
                writer.writerow([finding["score"], finding["category"], finding["details"]])
        console.print(f"[green]Exported CSV:[/green] {path}")
    elif format_type == "yaml":
        path = f"{output_prefix}.yaml"
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(report, f, default_flow_style=False)
        console.print(f"[green]Exported YAML:[/green] {path}")

def export_bloodhound_compatible(G, output_prefix="bloodbash_bh"):
    path = f"{output_prefix}.json"
    nodes_list = []
    for oid, data in G.nodes(data=True):
        nodes_list.append({"objectid": oid, "name": data.get('name'), "type": data.get('type'), "properties": data.get('props', {}), "is_azure": data.get('is_azure', False)})
    rels_list = []
    for u, v, data in G.edges(data=True):
        rels_list.append({"start": u, "end": v, "type": data.get('label')})
    bh_data = {
        "meta": {
            "version": __version__,
            "generator": "BloodBash",
            "organization": __org__,
            "organization_url": __org_url__,
            "project_url": __project_url__,
        },
        "nodes": nodes_list,
        "relationships": rels_list,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(bh_data, f, indent=2)
    console.print(f"[green]Exported BloodHound-compatible JSON:[/green] {path}")

def export_to_dot(G, dot_path, domain_filter=None):
    with open(dot_path, "w", encoding="utf-8") as f:
        f.write("digraph BloodBash {\n  rankdir=LR;\n  node [shape=box];\n")
        for n, d in G.nodes(data=True):
            if not _domain_matches(d, domain_filter):
                continue
            color = "red" if any(k in d['name'].lower() for k in ['admin', 'krbtgt', 'ca', 'template', 'global admin']) else "blue"
            f.write(f'  "{d["name"]}" [label="{d["name"]}\\n{d["type"]}", color={color}];\n')
        for u, v, d in G.edges(data=True):
            if domain_filter and not (_domain_matches(G.nodes[u], domain_filter) or _domain_matches(G.nodes[v], domain_filter)):
                continue
            f.write(f'  "{G.nodes[u]["name"]}" -> "{G.nodes[v]["name"]}" [label="{d.get("label", "?")}"];\n')
        f.write("}\n")
    console.print(f"[green]Exported Graphviz DOT:[/green] {dot_path}")
    console.print(f"[dim]Render with: dot -Tpng {dot_path} -o graph.png[/dim]")

# ────────────────────────────────────────────────
# Structured CLI help (Rich tables)
# ────────────────────────────────────────────────
HELP_TABLE_SECTIONS = [
    (
        "Input",
        [
            ("directory", "SharpHound / AzureHound JSON directory or .zip", "positional; default: ."),
        ],
    ),
    (
        "Run mode",
        [
            ("--quick-wins", "High-signal day-0 triage (also the default)", "DCSync, ADCS, roast, RBCD, LAPS, paths…"),
            ("--all", "Full attack analysis (AD+Azure)", "auto --fast on large graphs; inventory via --inventory"),
            ("--profile FILE|name", "YAML analysis profile", "quick, quick-wins, adcs-heavy, hygiene, or path"),
            ("--wizard", "Interactive mode picker", "first-run friendly"),
            ("--fast", "Limit heavy pathfinding", "top DA/EA-style targets only"),
            ("--verbose", "Print verbose graph summary", ""),
            ("--debug", "Verbose parse/build logging", "troubleshooting"),
            ("--all-findings", "End with a full findings table (every row)", "always prints, even if empty"),
            ("-h, --help", "Short help: start here + cheat sheet", ""),
            ("--help-advanced", "Full flag tables + all examples", ""),
        ],
    ),
    (
        "AD privilege & abuse checks",
        [
            ("--dcsync", "GetChanges + GetChangesAll (unexpected vs nested DA/EA)", ""),
            ("--dangerous-permissions", "Dangerous ACLs on high-value objects", ""),
            ("--rbcd", "RBCD configured + who can configure AllowedToAct", ""),
            ("--gpo-abuse", "Weak / abusable GPO permissions", ""),
            ("--sid-history", "SID history abuse candidates", ""),
            ("--unconstrained-delegation", "Unconstrained delegation", "DC vs non-DC sections"),
            ("--constrained-delegation", "Constrained delegation (S4U)", ""),
            ("--sessions", "LocalAdmin / RDP / DCOM / session summary", ""),
            ("--laps", "LAPS coverage (haslaps) + ReadLAPSPassword readers", ""),
            ("--shadow-credentials", "AddKeyCredentialLink / shadow cred paths", ""),
        ],
    ),
    (
        "AD credentials",
        [
            ("--kerberoastable", "Users with SPNs (Kerberoast)", "AdminCount/OWNED/LASTLOG tags"),
            ("--as-rep-roastable", "Users with DONT_REQ_PREAUTH (AS-REP roast)", "AdminCount/OWNED/LASTLOG tags"),
            ("--privileged-roast", "Kerberoast/AS-REP users nested into DA/EA/…", "high priority"),
            ("--password-descriptions", "Passwords / secrets in descriptions", ""),
            ("--password-never-expires", "PasswordNeverExpires users", ""),
            ("--password-not-required", "PasswordNotRequired users", ""),
        ],
    ),
    (
        "ADCS & GPO content",
        [
            ("--adcs", "Certificate template ESC1–ESC8 (+ESC9/13 when present)", ""),
            ("--gpo-parsing", "GPO metadata / linked GPO signals", ""),
            ("--gpo-content-dir DIR", "Parse GPO XML (tasks, scripts, cPassword)", "SYSVOL export dir"),
        ],
    ),
    (
        "Azure / Entra",
        [
            ("--azure-privileged-roles", "Privileged directory roles", ""),
            ("--azure-app-secrets", "App / SP credential control paths", ""),
            ("--azure-mfa-bypass", "Explicit MFA disable signals", ""),
            ("--azure-guest-access", "Guest user exposure", ""),
            ("--azure-sp-abuse", "Service principal abuse rights", ""),
        ],
    ),
    (
        "Paths & remediation",
        [
            ("--shortest-paths", "Shortest paths to high-value targets", ""),
            ("--busiest-paths [short|all]", "Rank principals on the most paths to HV", "default mode: short"),
            ("--busiest-paths-top N", "How many busiest principals to show", "default: 5"),
            ("--path-break", "Edges to remove to break the most paths", "remediation hints"),
            ("--path-break-top N", "How many path-break edges to show", "default: 15"),
            ("--owned a,b", "Shortest paths *to* owned principals", "inbound to foothold"),
            ("--from-user / --compromise USER", "Compromise dossier for USER (outbound)", "membership, rights, HV paths"),
            ("--from-user-export [DIR]", "Export dossier + adminto_hosts lists", "default: compromise-<user>/"),
            ("--path-from SRC", "Arbitrary path sources", "use with --path-to"),
            ("--path-to DST", "Arbitrary path targets", "use with --path-from"),
            ("--indirect", "Include group-mediated paths/rights", ""),
            ("--deep-analysis", "Slow group nesting + cycle detection", ""),
        ],
    ),
    (
        "Inventory",
        [
            ("--inventory", "Structural + password-age + stale + privilege", "ops inventory pack"),
            ("--password-age", "Password age bucket inventory", "<1d … >20y ladders"),
            ("--stale-accounts", "Inactive / never-active account inventory", ""),
            ("--privilege-inventory", "Privileged group membership tables", ""),
            ("--owned-inventory", "AdminTo / MemberOf for --owned principals", "requires --owned"),
        ],
    ),
    (
        "Export & deliverables",
        [
            ("--export [fmt]", "Write findings report", "md|json|html|csv|yaml (default md)"),
            ("--export-bh", "BloodHound-compatible full graph JSON", ""),
            ("--dot [FILE]", "Graphviz DOT export", "default: bloodbash.dot"),
            ("--report-pack DIR", "Multi-page HTML suite + CSVs + index.html", ""),
            ("--csv-pack DIR", "PlumHound-style multi-CSV inventory pack", "index.csv + overpriv + AdminTo"),
            ("--export-zip [FILE]", "Zip --report-pack or --csv-pack", "default: bloodbash-reports.zip"),
            ("--all-findings", "Print complete findings table at end of run", "not limited to top 20"),
            ("--log-file [FILE]", "Write a run audit log", "default: bloodbash.log"),
        ],
    ),
    (
        "Filters & utilities",
        [
            ("--domain X", "Filter to one AD domain or Azure tenantId", ""),
            ("--list-domains", "List domains/tenants in collection and exit", ""),
            ("--db FILE", "Graph SQLite path (default: auto-cache by fingerprint)", "skip re-ingest on hit"),
            ("--cache-dir DIR", "Auto graph-cache directory", "default: ~/.cache/bloodbash"),
            ("--no-cache", "Always re-ingest; do not read/write graph cache", ""),
            ("--rebuild-cache", "Force rebuild and refresh the graph cache", ""),
            ("--inspect NODE", "Dump props + edges for node(s)", "comma-separated"),
        ],
    ),
]

# Start-here + cheat sheet for short --help (new-user approachability).
# Use {prog} as a placeholder for the executable name.
HELP_START_HERE = [
    ("1. Day-0 triage (default)", "{prog} ./sharpout"),
    ("   same as --quick-wins", "{prog} ./sharpout --quick-wins"),
    ("2. Just owned a user", "{prog} ./sharpout --from-user alice --from-user-export"),
    ("3. Full analysis", "{prog} ./sharpout --all --fast"),
]

HELP_CHEAT_SHEET = [
    ("Default / quick wins", "{prog} DIR"),
    ("Full scan", "{prog} DIR --all --fast"),
    ("Compromise dossier", "{prog} DIR --from-user USER --from-user-export"),
    ("One domain", "{prog} DIR --quick-wins --domain CORP.LOCAL"),
    ("Built-in profile", "{prog} DIR --profile hygiene"),
    ("Interactive wizard", "{prog} DIR --wizard"),
    ("List domains", "{prog} DIR --list-domains"),
    ("All flags + examples", "{prog} --help-advanced"),
]

# Categorized example commands shown in --help-advanced (and mirrored in README).
HELP_EXAMPLE_SECTIONS = [
    (
        "Examples — basics",
        [
            ("Show short help", "{prog} --help"),
            ("Show full help", "{prog} --help-advanced"),
            ("Default = quick wins", "{prog} ./sharpout"),
            ("Quick wins (explicit)", "{prog} ./sharpout --quick-wins"),
            ("Quick wins + one domain", "{prog} ./sharpout --quick-wins --domain CORP.LOCAL"),
            ("Interactive wizard", "{prog} ./sharpout --wizard"),
            ("Full analysis (AD + Azure)", "{prog} ./sharpout --all"),
            ("Full analysis, large env", "{prog} ./sharpout --all --fast"),
            ("Quiet-ish: one domain only", "{prog} ./sharpout --all --domain CORP.LOCAL"),
            ("List domains / tenants", "{prog} ./sharpout --list-domains"),
            ("Zip input", "{prog} ./2024-collection.zip --quick-wins"),
            ("Sample AD lab data", "{prog} SampleSharphoundADData --quick-wins"),
            ("Sample Azure data", "{prog} SampleAzurehoundData --azure-privileged-roles --azure-guest-access"),
        ],
    ),
    (
        "Examples — compromise dossier (foothold / newly owned user)",
        [
            ("Dossier: what can alice do?", "{prog} ./sharpout --from-user alice"),
            ("Alias --compromise", "{prog} ./sharpout --compromise alice@corp.local"),
            ("Dossier + export pack (txt/csv/json + adminto_hosts)", "{prog} ./sharpout --from-user alice --from-user-export"),
            ("Export to custom directory", "{prog} ./sharpout --from-user alice --from-user-export ./alice-dossier"),
            ("Multiple footholds", "{prog} ./sharpout --from-user alice,bob,svc_backup --from-user-export ./footholds"),
            ("Dossier + full findings table", "{prog} ./sharpout --from-user alice --all-findings"),
            ("Dossier + domain filter", "{prog} ./sharpout --from-user alice --domain CORP.LOCAL --from-user-export"),
            ("Dossier on sample data", "{prog} SampleSharphoundADData --from-user SCOTT --from-user-export ./scott-out --fast"),
            ("Inbound paths TO owned loot (not outbound)", "{prog} ./sharpout --owned alice --owned-inventory"),
            ("Contrast: path from alice to DA", "{prog} ./sharpout --path-from alice --path-to 'domain admins'"),
        ],
    ),
    (
        "Examples — attack paths & remediation",
        [
            ("Shortest paths to high-value", "{prog} ./sharpout --shortest-paths"),
            ("Busiest paths (short)", "{prog} ./sharpout --busiest-paths short --busiest-paths-top 10"),
            ("Busiest paths (all lengths)", "{prog} ./sharpout --busiest-paths all --busiest-paths-top 5"),
            ("Path-break remediation", "{prog} ./sharpout --path-break --path-break-top 20"),
            ("Paths + remediation pack", "{prog} ./sharpout --busiest-paths short --path-break --fast --report-pack ./path-reports"),
            ("Custom source → target", "{prog} ./sharpout --path-from helpdesk --path-to 'domain admins@corp.local'"),
            ("Indirect / group-mediated edges", "{prog} ./sharpout --shortest-paths --indirect"),
            ("Deep group nesting + cycles", "{prog} ./sharpout --deep-analysis"),
            ("Inspect one node", "{prog} ./sharpout --inspect alice@corp.local"),
        ],
    ),
    (
        "Examples — selective AD checks",
        [
            ("Critical trio", "{prog} ./sharpout --dcsync --adcs --dangerous-permissions"),
            ("Credential abuse", "{prog} ./sharpout --kerberoastable --as-rep-roastable --password-descriptions"),
            ("Privileged roast (DA/EA nested)", "{prog} ./sharpout --privileged-roast"),
            ("Delegation suite", "{prog} ./sharpout --unconstrained-delegation --constrained-delegation --rbcd"),
            ("Shadow credentials", "{prog} ./sharpout --shadow-credentials"),
            ("Password hygiene", "{prog} ./sharpout --password-never-expires --password-not-required --password-age"),
            ("Sessions / local admin surface", "{prog} ./sharpout --sessions"),
            ("LAPS coverage + password readers", "{prog} ./sharpout --laps"),
            ("GPO abuse + XML content", "{prog} ./sharpout --gpo-abuse --gpo-content-dir ./sysvol-gpo-xml"),
            ("SID history", "{prog} ./sharpout --sid-history"),
            ("All findings table (no top-20 cap)", "{prog} ./sharpout --dcsync --adcs --all-findings"),
        ],
    ),
    (
        "Examples — inventory, profiles, deliverables",
        [
            ("List domains / tenants and exit", "{prog} ./sharpout --list-domains"),
            ("Full inventory", "{prog} ./sharpout --inventory"),
            ("Stale + password-age only", "{prog} ./sharpout --stale-accounts --password-age"),
            ("Privilege group inventory", "{prog} ./sharpout --privilege-inventory"),
            ("Built-in profile: quick", "{prog} ./sharpout --profile quick"),
            ("Built-in profile: ADCS-heavy", "{prog} ./sharpout --profile adcs-heavy"),
            ("Built-in profile: hygiene", "{prog} ./sharpout --profile hygiene"),
            ("Custom profile file", "{prog} ./sharpout --profile ./my-engagement.yaml"),
            ("HTML report pack + zip", "{prog} ./sharpout --inventory --busiest-paths short --path-break --report-pack ./reports --export-zip bloodbash-reports.zip"),
            ("PlumHound-style multi-CSV pack", "{prog} ./sharpout --csv-pack ./ph-reports"),
            ("CSV pack + zip deliverable", "{prog} ./sharpout --csv-pack ./ph-reports --export-zip ph-reports.zip"),
            ("Markdown / HTML / CSV export", "{prog} ./sharpout --all --export=html"),
            ("JSON export + BH graph + DOT", "{prog} ./sharpout --all --export=json --export-bh --dot graph.dot"),
            ("Auto graph cache (default)", "{prog} ./sharpout --dcsync  # second run reuses cache"),
            ("Different checks, same cache", "{prog} ./sharpout --kerberoastable"),
            ("Force rebuild cache", "{prog} ./sharpout --all --rebuild-cache"),
            ("Disable cache", "{prog} ./sharpout --all --no-cache"),
            ("Explicit SQLite path", "{prog} ./sharpout --all --db bloodbash.db"),
            ("Re-open explicit DB if sources gone", "{prog} . --db bloodbash.db --from-user alice"),
            ("Custom cache directory", "{prog} ./sharpout --cache-dir /tmp/bb-cache --all"),
            ("Run log", "{prog} ./sharpout --all --log-file ./bloodbash.log"),
        ],
    ),

    (
        "Examples — Azure / Entra",
        [
            ("Privileged roles", "{prog} ./azureout --azure-privileged-roles"),
            ("App secrets / SP control paths", "{prog} ./azureout --azure-app-secrets --azure-sp-abuse"),
            ("MFA + guests", "{prog} ./azureout --azure-mfa-bypass --azure-guest-access"),
            ("All Azure checks", "{prog} ./azureout --azure-privileged-roles --azure-app-secrets --azure-mfa-bypass --azure-guest-access --azure-sp-abuse --all-findings"),
            ("Sample AzureHound file", "{prog} SampleAzurehoundData --azure-privileged-roles --azure-guest-access --all-findings"),
        ],
    ),
]


def _display_prog_name(prog: Optional[str] = None) -> str:
    """CLI name for help examples — prefer binary-style ``bloodbash``, not ``BloodBash.py``."""
    raw = prog if prog else (os.path.basename(sys.argv[0]) if sys.argv else "bloodbash")
    name = os.path.basename(str(raw)).strip() or "bloodbash"
    lower = name.lower()
    for suf in (".py", ".exe"):
        if lower.endswith(suf):
            name = name[: -len(suf)]
            lower = name.lower()
            break
    if lower in ("bloodbash",) or name == "BloodBash":
        return "bloodbash"
    # Release assets: bloodbash-linux-x64 / bloodbash-windows-x64 → bloodbash
    if lower.startswith("bloodbash"):
        return "bloodbash"
    return name or "bloodbash"


def print_structured_help(prog: Optional[str] = None, advanced: bool = False) -> None:
    """Print Rich help. Default is short (start-here); advanced=True for full tables."""
    prog = _display_prog_name(prog)
    console.print(
        Panel(
            f"[bold cyan]BloodBash v{__version__}[/bold cyan]  ·  [bold]{__org__}[/bold]\n"
            f"[dim]Offline SharpHound & AzureHound analyzer — no Neo4j required[/dim]\n"
            f"[dim]{__org_url__}[/dim]\n"
            f"[dim]{__project_url__}[/dim]",
            title="Help" if not advanced else "Help (advanced)",
            border_style="bright_blue",
        )
    )
    console.print(
        f"[bold]Usage[/bold]:  [cyan]{prog}[/cyan] "
        f"[yellow]\\[options][/yellow] [green]\\[directory][/green]\n"
    )

    if not advanced:
        console.print(
            "[bold green]Start with these 3[/bold green]\n"
            "[dim]No flags needed for day-0 triage — bare directory = --quick-wins.[/dim]\n"
        )
        start = Table(
            show_header=True,
            header_style="bold green",
            border_style="green",
            expand=True,
            title="Getting started",
        )
        start.add_column("Goal", style="green", max_width=32, overflow="fold")
        start.add_column("Command", style="cyan", overflow="fold")
        for goal, cmd in HELP_START_HERE:
            start.add_row(goal, cmd.format(prog=prog))
        console.print(start)
        console.print()

        cheat = Table(
            show_header=True,
            header_style="bold magenta",
            border_style="bright_blue",
            expand=True,
            title="Cheat sheet",
        )
        cheat.add_column("Task", style="white", max_width=28, overflow="fold")
        cheat.add_column("Command", style="cyan", overflow="fold")
        for task, cmd in HELP_CHEAT_SHEET:
            cheat.add_row(task, cmd.format(prog=prog))
        console.print(cheat)
        console.print()

        console.print(
            "[dim]Foothold? [cyan]--from-user USER[/cyan] (outbound dossier). "
            "[cyan]--owned[/cyan] is inbound paths *to* a principal.\n"
            f"All flags + every example: [cyan]{prog} --help-advanced[/cyan]  ·  "
            f"Cookbook: docs/cookbook.md[/dim]"
        )
        console.print(
            f"[dim]For authorized security testing / red teaming only. "
            f"BloodBash by {__org__}.[/dim]"
        )
        return

    console.print(
        "[dim]Bare directory (no check flags) runs [cyan]--quick-wins[/cyan] triage. "
        "Use [cyan]--all[/cyan] for every module.\n"
        "Engagement foothold? [cyan]--from-user USER[/cyan] (outbound dossier). "
        "[cyan]--owned[/cyan] is inbound paths *to* a principal.[/dim]\n"
    )

    for title, rows in HELP_TABLE_SECTIONS:
        table = Table(
            title=title,
            show_header=True,
            header_style="bold magenta",
            border_style="bright_blue",
            expand=True,
            pad_edge=False,
        )
        table.add_column("Flag / argument", style="cyan", no_wrap=True, overflow="fold")
        table.add_column("Description", style="white", overflow="fold")
        table.add_column("Notes / values", style="dim", overflow="fold")
        for flag, desc, notes in rows:
            table.add_row(flag, desc, notes or "—")
        console.print(table)
        console.print()

    for title, rows in HELP_EXAMPLE_SECTIONS:
        examples = Table(
            title=title,
            show_header=True,
            header_style="bold green",
            border_style="green",
            expand=True,
        )
        examples.add_column("Scenario", style="green", no_wrap=False, max_width=36, overflow="fold")
        examples.add_column("Command", style="cyan", overflow="fold")
        for scenario, cmd in rows:
            examples.add_row(scenario, cmd.format(prog=prog))
        console.print(examples)
        console.print()

    console.print(
        "[dim]Tip: --from-user = what the foothold can do (outbound). "
        "--owned = who can reach that principal (inbound).[/dim]"
    )
    console.print(
        f"[dim]For authorized security testing / red teaming only. "
        f"BloodBash by {__org__}.[/dim]"
    )


class StructuredHelpArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that renders --help as categorized Rich tables."""

    def print_help(self, file=None):
        print_structured_help(prog=self.prog)

    def format_help(self):
        # Used by some callers; return a plain-text hint (tables go to console).
        return (
            f"BloodBash v{__version__} structured help — run with --help "
            f"for Rich tables. {__org_url__}\n"
        )

    def error(self, message):
        console.print(f"[bold red]error:[/bold red] {message}\n")
        self.print_help()
        self.exit(2)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = StructuredHelpArgumentParser(
        prog=_display_prog_name(),
        description=(
            f"BloodBash v{__version__} by {__org__} — offline SharpHound & AzureHound analyzer "
            f"({__org_url__})"
        ),
        add_help=True,
    )

    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Path to SharpHound & AzureHound JSON files or zip archive.",
    )
    parser.add_argument(
        "--merge",
        nargs="+",
        metavar="PATH",
        help="Additional SharpHound/AzureHound dirs or zips to merge (multi-domain/forest)",
    )
    parser.add_argument(
        "--trust",
        action="store_true",
        help="Domain trust / SID-filtering abuse checks",
    )
    parser.add_argument("--shortest-paths", action="store_true", help="Shortest paths to high-value targets")
    parser.add_argument("--dangerous-permissions", action="store_true", help="Dangerous ACLs on high-value objects")
    parser.add_argument("--adcs", action="store_true", help="ADCS ESC template vulnerabilities")
    parser.add_argument("--gpo-abuse", action="store_true", help="Weak / abusable GPO permissions")
    parser.add_argument("--dcsync", action="store_true", help="DCSync GetChanges+GetChangesAll rights")
    parser.add_argument("--rbcd", action="store_true", help="Resource-based constrained delegation")
    parser.add_argument("--sessions", action="store_true", help="LocalAdmin / RDP / DCOM / session summary")
    parser.add_argument("--kerberoastable", action="store_true", help="Kerberoastable accounts")
    parser.add_argument("--as-rep-roastable", action="store_true", help="AS-REP roastable accounts")
    parser.add_argument(
        "--privileged-roast",
        action="store_true",
        help="Kerberoast/AS-REP users nested into Domain Admins / Enterprise Admins / other priv groups",
    )
    parser.add_argument("--sid-history", action="store_true", help="SID history abuse candidates")
    parser.add_argument("--unconstrained-delegation", action="store_true", help="Unconstrained delegation")
    parser.add_argument("--password-descriptions", action="store_true", help="Passwords in descriptions")
    parser.add_argument("--password-never-expires", action="store_true", help="PasswordNeverExpires users")
    parser.add_argument("--password-not-required", action="store_true", help="PasswordNotRequired users")
    parser.add_argument("--shadow-credentials", action="store_true", help="Shadow credential paths")
    parser.add_argument("--gpo-parsing", action="store_true", help="GPO metadata analysis")
    parser.add_argument(
        "--gpo-content-dir",
        type=str,
        default=None,
        help="Directory containing GPO XML reports for full content analysis",
    )
    parser.add_argument("--constrained-delegation", action="store_true", help="Constrained delegation")
    parser.add_argument("--laps", action="store_true", help="LAPS deployment status")
    parser.add_argument("--azure-privileged-roles", action="store_true", help="Azure privileged roles")
    parser.add_argument("--azure-app-secrets", action="store_true", help="Azure app/SP secrets control")
    parser.add_argument("--azure-mfa-bypass", action="store_true", help="Azure MFA bypass signals")
    parser.add_argument("--azure-guest-access", action="store_true", help="Azure guest access")
    parser.add_argument("--azure-sp-abuse", action="store_true", help="Azure service principal abuse")
    parser.add_argument("--verbose", action="store_true", help="Verbose graph summary")
    parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "Full attack-path analysis (AD+Azure). Auto --fast on large graphs; "
            "inventory modules require --inventory (not included)"
        ),
    )
    parser.add_argument(
        "--quick-wins",
        action="store_true",
        help=(
            "Run high-signal day-0 triage only: unexpected DCSync, ADCS, dangerous ACLs, "
            "RBCD (+ can configure), privileged roast, unconstrained (non-DC), shadow creds, "
            "LAPS readers, sessions, short paths + path-break (implies --fast). "
            "Also applied automatically when no check flags are given."
        ),
    )
    parser.add_argument(
        "--wizard",
        action="store_true",
        help="Interactive setup: pick quick-wins / full / dossier / profile",
    )
    parser.add_argument(
        "--help-advanced",
        action="store_true",
        help="Show full flag tables and all example commands, then exit",
    )
    parser.add_argument(
        "--all-findings",
        action="store_true",
        help="At end of run, print a table of every finding (always shown, even if empty)",
    )
    parser.add_argument(
        "--export",
        nargs="?",
        const="md",
        choices=["md", "json", "html", "csv", "yaml"],
        help="Export results (md|json|html|csv|yaml)",
    )
    parser.add_argument("--export-bh", action="store_true", help="Export BloodHound-compatible graph JSON")
    parser.add_argument("--dot", nargs="?", const="bloodbash.dot", help="Export Graphviz DOT file")
    parser.add_argument("--fast", action="store_true", help="Fast mode (limit heavy pathfinding)")
    parser.add_argument("--domain", help="Filter by domain (AD) or tenantId (Azure)")
    parser.add_argument(
        "--list-domains",
        action="store_true",
        help="List AD domains / Azure tenants in the collection and exit",
    )
    parser.add_argument("--indirect", action="store_true", help="Include indirect paths/permissions")
    parser.add_argument(
        "--db",
        help=(
            "SQLite path for the graph snapshot (default: auto-cache under "
            "~/.cache/bloodbash/ keyed by collection fingerprint)"
        ),
    )
    parser.add_argument(
        "--cache-dir",
        metavar="DIR",
        help="Directory for automatic graph cache files (default: ~/.cache/bloodbash)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable graph cache load/save (always re-ingest JSON/zip)",
    )
    parser.add_argument(
        "--rebuild-cache",
        action="store_true",
        help="Force re-ingest and overwrite the graph cache for this collection",
    )
    parser.add_argument("--owned", help="Comma-separated owned principals (find paths *to* them)")
    parser.add_argument(
        "--from-user",
        "--compromise",
        dest="from_user",
        metavar="USER",
        help=(
            "Compromise dossier for USER (outbound): membership, nested groups, "
            "AdminTo/RDP/ACL counts, paths to high-value. Comma-separated for multiple."
        ),
    )
    parser.add_argument(
        "--from-user-export",
        nargs="?",
        const="",
        metavar="DIR",
        help=(
            "Export compromise dossier to DIR (txt/csv/json lists). "
            "If DIR omitted, writes compromise-<user>/ under the cwd."
        ),
    )
    parser.add_argument("--path-from", help="Comma-separated source principals for arbitrary paths")
    parser.add_argument("--path-to", help="Comma-separated target principals for arbitrary paths")
    parser.add_argument("--inspect", help="Comma-separated nodes to inspect (full props + edges)")
    parser.add_argument("--deep-analysis", action="store_true", help="Enable full (slow) group cycle detection")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output for troubleshooting")
    parser.add_argument(
        "--busiest-paths",
        nargs="?",
        const="short",
        choices=["short", "all"],
        help="Rank principals on the most paths to high-value targets (short|all)",
    )
    parser.add_argument("--busiest-paths-top", type=int, default=5, help="Top N busiest principals (default 5)")
    parser.add_argument(
        "--path-break",
        action="store_true",
        help="Recommend edges to remove to break the most attack paths",
    )
    parser.add_argument("--path-break-top", type=int, default=15, help="Top N path-break edges (default 15)")
    parser.add_argument("--password-age", action="store_true", help="Password age inventory ladders")
    parser.add_argument("--stale-accounts", action="store_true", help="Inactive / never-active account inventory")
    parser.add_argument("--privilege-inventory", action="store_true", help="Privileged group membership inventory")
    parser.add_argument(
        "--owned-inventory",
        action="store_true",
        help="Inventory AdminTo/MemberOf for --owned principals",
    )
    parser.add_argument(
        "--inventory",
        action="store_true",
        help="Run structural + password-age + stale + privilege inventories",
    )
    parser.add_argument(
        "--report-pack",
        metavar="DIR",
        help="Multi-page HTML suite + CSVs + index.html",
    )
    parser.add_argument(
        "--csv-pack",
        metavar="DIR",
        help="PlumHound-style multi-CSV inventory pack (domains, DA, roastables, LAPS, sessions, …)",
    )
    parser.add_argument(
        "--export-zip",
        nargs="?",
        const="bloodbash-reports.zip",
        metavar="FILE",
        help="Zip the report pack into a single deliverable (default bloodbash-reports.zip)",
    )
    parser.add_argument(
        "--profile",
        metavar="FILE",
        help="YAML analysis profile (path or built-in name under profiles/)",
    )
    parser.add_argument(
        "--log-file",
        nargs="?",
        const="bloodbash.log",
        metavar="FILE",
        help="Write a run log file (default bloodbash.log)",
    )
    return parser


# ────────────────────────────────────────────────
# Main execution
# ────────────────────────────────────────────────
def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    global_findings.clear()
    auto_default_quick_wins = False

    if getattr(args, "help_advanced", False):
        print_structured_help(prog=parser.prog, advanced=True)
        sys.exit(0)

    if getattr(args, "wizard", False):
        run_setup_wizard(args)

    if args.profile:
        try:
            profile = load_analysis_profile(args.profile)
            apply_profile_to_args(args, profile)
            console.print(f"[green]Loaded profile:[/green] {args.profile}")
        except Exception as e:
            console.print(f"[red]Failed to load profile {args.profile}: {e}[/red]")
            sys.exit(2)

    if getattr(args, "quick_wins", False):
        if args.all:
            console.print(
                "[yellow]--quick-wins ignored because --all was also set "
                "(running full analysis).[/yellow]"
            )
        else:
            apply_quick_wins_to_args(args)
            console.print(
                "[green]Quick wins mode:[/green] high-signal triage checks "
                f"({len(QUICK_WINS_CHECKS)} modules, --fast)"
            )
    elif not args.all and not cli_has_explicit_analysis_intent(args):
        # Bare directory (or only filters like --domain/--verbose) → day-0 triage
        apply_quick_wins_to_args(args)
        args.quick_wins = True
        auto_default_quick_wins = True
        console.print(
            "[green]Default mode:[/green] quick-wins triage "
            f"({len(QUICK_WINS_CHECKS)} modules, --fast). "
            "Use [cyan]--all[/cyan] for full analysis."
        )

    log_path = setup_run_logging(args.log_file)
    if log_path:
        console.print(f"[dim]Run log:[/dim] {log_path}")

    DEBUG = args.debug
    if DEBUG:
        console.print("[bold blue]=== DEBUG MODE ENABLED ===[/bold blue]")
    start_time = time.time()
    logger.info("Starting analysis directory=%s", args.directory)

    paths = [args.directory]
    if getattr(args, "merge", None):
        paths.extend(args.merge)
    G, name_to_oid, cache_info = load_or_build_graph(
        paths,
        db_path=args.db if getattr(args, "db", None) else None,
        cache_dir=getattr(args, "cache_dir", None),
        no_cache=bool(getattr(args, "no_cache", False)),
        rebuild_cache=bool(getattr(args, "rebuild_cache", False)),
        debug=DEBUG,
    )
    if DEBUG and cache_info:
        console.print(
            f"[blue]DEBUG: graph cache hit={cache_info.get('cache_hit')} "
            f"path={cache_info.get('cache_path')} "
            f"fp={(cache_info.get('fingerprint') or '')[:16]}[/blue]"
        )

    print_collection_health(G)

    if args.list_domains:
        print_list_domains(G)
        return

    run_inventory = bool(args.inventory)
    if run_inventory:
        args.password_age = True
        args.stale_accounts = True
        args.privilege_inventory = True

    # Large-graph enterprise defaults: --all auto-enables --fast (pathfinding caps)
    n_nodes = G.number_of_nodes()
    n_edges = G.number_of_edges()
    large_graph = n_nodes >= LARGE_GRAPH_NODES or n_edges >= LARGE_GRAPH_EDGES
    if args.all and large_graph and not args.fast:
        args.fast = True
        console.print(
            f"[yellow]Large graph ({n_nodes} nodes / {n_edges} edges): "
            f"auto-enabled --fast for --all (pathfinding + ACL display caps)[/yellow]"
        )

    # Suppress empty detector headers under broad triage modes
    set_quiet_empty_sections(
        bool(args.all or getattr(args, "quick_wins", False))
    )

    selected_checks = any([
        args.shortest_paths, args.dangerous_permissions, args.adcs, args.gpo_abuse,
        args.dcsync, args.rbcd, args.sessions, args.kerberoastable, args.as_rep_roastable,
        args.privileged_roast,
        args.sid_history, args.unconstrained_delegation, args.password_descriptions,
        args.password_never_expires, args.password_not_required, args.shadow_credentials,
        args.gpo_parsing, args.constrained_delegation, args.laps,
        args.azure_privileged_roles, args.azure_app_secrets, args.azure_mfa_bypass,
        args.azure_guest_access, args.azure_sp_abuse, args.owned, args.path_from,
        args.path_to, args.inspect, args.export_bh, args.dot, args.deep_analysis,
        args.gpo_content_dir, args.busiest_paths, args.path_break, args.password_age,
        args.stale_accounts, args.privilege_inventory, args.owned_inventory,
        args.inventory, args.report_pack, args.csv_pack, args.export_zip, args.from_user,
        getattr(args, "from_user_export", None) is not None,
        getattr(args, "trust", False),
    ])
    run_all = args.all or not selected_checks
    # Pure compromise-dossier run should not pull in default "run everything"
    if args.from_user and not args.all:
        # If only from-user (+ export/log/domain/fast) selected, skip run_all bulk checks
        only_dossier = not any([
            args.shortest_paths, args.dangerous_permissions, args.adcs, args.gpo_abuse,
            args.dcsync, args.rbcd, args.sessions, args.kerberoastable, args.as_rep_roastable,
            args.privileged_roast,
            args.sid_history, args.unconstrained_delegation, args.password_descriptions,
            args.password_never_expires, args.password_not_required, args.shadow_credentials,
            args.gpo_parsing, args.constrained_delegation, args.laps,
            args.azure_privileged_roles, args.azure_app_secrets, args.azure_mfa_bypass,
            args.azure_guest_access, args.azure_sp_abuse, args.owned, args.path_from,
            args.path_to, args.inspect, args.export_bh, args.dot, args.deep_analysis,
            args.gpo_content_dir, args.busiest_paths, args.path_break, args.password_age,
            args.stale_accounts, args.privilege_inventory, args.owned_inventory,
            args.inventory, args.report_pack, args.csv_pack,
        ])
        if only_dossier:
            run_all = False

    if args.from_user and not args.all and not any([
        args.shortest_paths, args.dangerous_permissions, args.adcs, args.gpo_abuse,
        args.dcsync, args.rbcd, args.sessions, args.kerberoastable, args.as_rep_roastable,
        args.privileged_roast,
        args.sid_history, args.unconstrained_delegation, args.password_descriptions,
        args.password_never_expires, args.password_not_required, args.shadow_credentials,
        args.gpo_parsing, args.constrained_delegation, args.laps,
        args.azure_privileged_roles, args.azure_app_secrets, args.azure_mfa_bypass,
        args.azure_guest_access, args.azure_sp_abuse, args.owned, args.path_from,
        args.inspect, args.export_bh, args.dot, args.deep_analysis, args.gpo_content_dir,
        args.busiest_paths, args.path_break, args.password_age, args.stale_accounts,
        args.privilege_inventory, args.owned_inventory, args.inventory, args.report_pack,
        args.csv_pack,
    ]):
        mode_str = f"Compromise dossier (--from-user {args.from_user})"
    elif args.all:
        mode_str = "Full attack analysis (AD + Azure) (--all"
        if args.fast:
            mode_str += ", --fast"
        mode_str += "; inventory via --inventory)"
    elif getattr(args, "quick_wins", False):
        if auto_default_quick_wins:
            mode_str = "Quick wins (default triage — use --all for full analysis)"
        else:
            mode_str = "Quick wins (high-signal triage) (--quick-wins)"
    elif selected_checks:
        mode_str = "Selected checks (including AD and Azure features)"
    else:
        mode_str = "Default (verbose summary + common checks)"
    if DEBUG:
        mode_str += " [DEBUG]"
    print_intro_banner(mode_str)
    if args.verbose or run_all:
        print_verbose_summary(G, args.domain)
    if args.shortest_paths or run_all:
        print_shortest_paths(G, fast=args.fast, domain_filter=args.domain, indirect=args.indirect)
    if args.dangerous_permissions or run_all:
        print_dangerous_permissions(
            G, args.domain, args.indirect, fast=bool(args.fast or large_graph)
        )
        print_interesting_acl_abuse(G, args.domain)
        print_broad_principal_acls(G, args.domain)
    if args.adcs or run_all:
        print_adcs_vulnerabilities(G, args.domain)
    if args.gpo_abuse or run_all:
        print_gpo_abuse(G, args.domain)
    if args.dcsync or run_all:
        print_dcsync_rights(G, args.domain)
    if args.rbcd or run_all:
        print_rbcd(G, args.domain)
        # Can-configure RBCD walks every computer ACL — expensive on enterprise graphs.
        # Skip under large/fast --all unless --deep-analysis or explicit --rbcd without --all.
        skip_cfg_rbcd = (
            bool(run_all)
            and (bool(args.fast) or large_graph)
            and not bool(getattr(args, "deep_analysis", False))
            and not (bool(args.rbcd) and not bool(args.all))
        )
        if skip_cfg_rbcd:
            console.print(
                "[dim]Skipping can-configure RBCD on large/fast --all "
                "(pass --rbcd without --all, or --deep-analysis, to run)[/dim]"
            )
        else:
            print_can_configure_rbcd(G, args.domain)
    if args.sessions or run_all:
        print_sessions_localadmin(G, args.domain, fast=bool(getattr(args, "fast", False)))
    if args.kerberoastable or run_all:
        print_kerberoastable(G, args.domain)
    if args.as_rep_roastable or run_all:
        print_as_rep_roastable(G, args.domain)
    if args.privileged_roast or run_all:
        print_privileged_roast_targets(G, args.domain)
    if args.sid_history or run_all:
        print_sid_history_abuse(G, args.domain)
    if args.unconstrained_delegation or run_all:
        print_unconstrained_delegation(G, args.domain)
    if args.password_descriptions or run_all:
        print_password_in_descriptions(G, args.domain)
    if args.password_never_expires or run_all:
        print_password_never_expires(G, args.domain)
    if args.password_not_required or run_all:
        print_password_not_required(G, args.domain)
    if args.shadow_credentials or run_all:
        print_shadow_credentials(G, args.domain)
    if args.gpo_parsing or run_all:
        print_gpo_content_parsing(G, args.domain)
    if args.constrained_delegation or run_all:
        print_constrained_delegation(G, args.domain)
    if args.laps or run_all:
        print_laps_status(G, args.domain)
        print_laps_readers(G, args.domain)
    # Skip empty Azure sections on pure SharpHound graphs under --all.
    # Explicit --azure-* flags still run (and report "none") so users can force them.
    _has_azure = graph_has_azure(G)
    _run_azure = lambda explicit: bool(explicit) or (bool(run_all) and _has_azure)
    if not _has_azure and run_all and not any(
        [
            args.azure_privileged_roles,
            args.azure_app_secrets,
            args.azure_mfa_bypass,
            args.azure_guest_access,
            args.azure_sp_abuse,
        ]
    ):
        console.print(
            "[dim]No Azure/Entra objects in collection — skipping Azure checks "
            "(pass --azure-* to force)[/dim]"
        )
    if _run_azure(args.azure_privileged_roles):
        print_azure_privileged_roles(G, args.domain)
    if _run_azure(args.azure_app_secrets):
        print_azure_app_secrets(G, args.domain)
    if _run_azure(args.azure_mfa_bypass):
        print_azure_mfa_bypass(G, args.domain)
    if _run_azure(args.azure_guest_access):
        print_azure_guest_access(G, args.domain)
    if _run_azure(args.azure_sp_abuse):
        print_azure_service_principal_abuse(G, args.domain)
    if args.owned:
        print_paths_to_owned(G, args.owned, args.domain)
    if args.from_user:
        export_root = None
        if args.from_user_export is not None:
            if args.from_user_export == "":
                # Default directory derived from first principal
                first = args.from_user.split(",")[0].strip()
                safe = re.sub(r"[^A-Za-z0-9._@-]+", "_", first) or "principal"
                export_root = os.path.join(os.getcwd(), f"compromise-{safe}")
            else:
                export_root = args.from_user_export
        run_compromise_dossiers(
            G,
            args.from_user,
            domain_filter=args.domain,
            export_dir=export_root,
            fast=args.fast,
        )
    elif args.from_user_export is not None and not args.from_user:
        console.print("[yellow]--from-user-export requires --from-user / --compromise[/yellow]")
    if args.path_from and args.path_to:
        print_arbitrary_paths(G, args.path_from, args.path_to, args.domain)
    if args.inspect:
        for ident in [x.strip() for x in args.inspect.split(',') if x.strip()]:
            inspect_node(G, ident, args.domain)
    if args.gpo_content_dir:
        print_gpo_content_analysis(G, args.gpo_content_dir, args.domain)

    # Inventory is opt-in via --inventory / explicit flags (not auto on --all)
    if args.password_age or run_inventory:
        print_password_age_inventory(G, args.domain)
    if args.stale_accounts or run_inventory:
        print_stale_account_inventory(G, args.domain)
    if args.privilege_inventory or run_inventory:
        print_privilege_inventory(G, args.domain)
    if run_inventory:
        print_structural_inventory(G, args.domain)
    if args.owned_inventory and args.owned:
        print_owned_inventory(G, args.owned, args.domain)
    elif args.owned_inventory and not args.owned:
        console.print("[yellow]--owned-inventory requires --owned[/yellow]")

    busiest_mode = args.busiest_paths if args.busiest_paths else ("short" if run_all else None)
    if busiest_mode is True or (isinstance(busiest_mode, str) and busiest_mode.lower() not in ("short", "all")):
        busiest_mode = "short"
    if busiest_mode:
        print_busiest_paths(
            G,
            mode=busiest_mode,
            top=args.busiest_paths_top,
            domain_filter=args.domain,
            fast=args.fast,
        )
    if args.path_break or run_all:
        print_path_breaks(
            G,
            domain_filter=args.domain,
            top=args.path_break_top,
            fast=args.fast,
        )

    # Trusts: quick-wins / --trust / full run
    if getattr(args, "trust", False) or run_all:
        print_trust_abuse(G, args.domain)
    # Stats always useful on --all; deep group nesting only with --deep-analysis
    if run_all:
        print_stats_dashboard(G, args.domain)
        if args.deep_analysis:
            print_group_analysis(G, args.domain, deep_analysis=True)
    elif args.deep_analysis:
        print_group_analysis(G, args.domain, deep_analysis=True)
    if args.export:
        export_results(G, format_type=args.export, domain_filter=args.domain)

    report_dir = args.report_pack
    if args.export_zip and not report_dir and not args.csv_pack:
        report_dir = os.path.join(os.getcwd(), "bloodbash-report-pack")
    if report_dir:
        export_report_pack(
            G,
            report_dir,
            domain_filter=args.domain,
            owned=args.owned,
            busiest_mode=busiest_mode or "short",
            busiest_top=args.busiest_paths_top,
            path_break_top=args.path_break_top,
            fast=args.fast,
            include_paths=True,
        )
    if args.csv_pack:
        export_csv_pack(G, args.csv_pack, domain_filter=args.domain)
    if args.export_zip:
        zip_target = args.export_zip
        zip_src = report_dir or args.csv_pack
        if zip_src:
            export_zip_pack(zip_src, zip_target)
        else:
            console.print("[yellow]--export-zip requires --report-pack or --csv-pack[/yellow]")

    if args.export_bh:
        export_bloodhound_compatible(G)
    if args.dot:
        export_to_dot(G, args.dot, args.domain)
    print_prioritized_findings(show_all=bool(getattr(args, "all_findings", False)))
    elapsed = time.time() - start_time
    logger.info("Completed in %.2f seconds with %d findings", elapsed, len(global_findings))
    console.print(f"\n[italic green]Completed in {elapsed:.2f} seconds[/italic green]")
    console.rule(
        f"[bold cyan]BloodBash by {__org__}[/bold cyan]  ·  [dim]{__org_url__}[/dim]",
        style="cyan",
    )
    print_approachability_footer(auto_default=auto_default_quick_wins)
    if DEBUG:
        console.print(f"[bold blue]DEBUG: Total findings: {len(global_findings)}[/bold blue]")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        try:
            console.print("\n[yellow]Interrupted by user[/yellow]")
        except Exception:
            pass
        sys.exit(130)
