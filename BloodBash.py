#!/usr/bin/env python3

import json
import os
import sys
import argparse
import networkx as nx
from collections import defaultdict
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

__version__ = "1.3.1"  

console = Console()
# ────────────────────────────────────────────────
# Severity Scoring
# ────────────────────────────────────────────────
SEVERITY_SCORES = {
    "ESC1-ESC8": 10, "DCSync": 10, "RBCD": 9, "Dangerous Permissions": 9,
    "SID History Abuse": 8, "GPO Abuse": 7, "Kerberoastable": 5,
    "AS-REP Roastable": 5, "Shortest Paths": 6, "Password Never Expires": 4,
    "Password Not Required": 8, "Shadow Credentials": 8, "GPO Content": 7,
    "Constrained Delegation": 7, "LAPS": 6, "Owned Paths": 9,
    "Arbitrary Paths": 6, "Trust Abuse": 7, "Deep Group Nesting": 6,
    # Azure-specific
    "Azure Privileged Roles": 10, "Azure App Secrets": 9, "Azure MFA Bypass": 8,
    "Azure Guest Access": 7, "Azure Service Principal Abuse": 8,
}
global_findings = []
def add_finding(category, details, score=None):
    if score is None:
        score = SEVERITY_SCORES.get(category, 5)
    global_findings.append((score, category, details))
def print_prioritized_findings():
    if not global_findings:
        return
    console.rule("[bold magenta]Prioritized Findings by Severity[/bold magenta]")
    sorted_findings = sorted(global_findings, key=lambda x: x[0], reverse=True)
    table = Table(title="Findings Summary", show_header=True, header_style="bold red")
    table.add_column("Severity Score", style="red", justify="right")
    table.add_column("Category", style="cyan")
    table.add_column("Details", style="yellow")
    for score, cat, det in sorted_findings[:20]:
        table.add_row(str(score), cat, det)
    console.print(table)
    if len(sorted_findings) > 20:
        console.print(f"[dim]... and {len(sorted_findings) - 20} more[/dim]")
# ────────────────────────────────────────────────
# Intro Banner
# ────────────────────────────────────────────────
def print_intro_banner(mode_str):
    console.rule(f"[bold magenta]BloodBash v{__version__} - SharpHound & AzureHound Offline Analyzer[/bold magenta]", style="magenta")
    console.print(Panel(
        f"""
                                                                                             
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
                                                                                             
Parses SharpHound, AzureHound, and BloodHound-Python JSON files → finds AD/Azure attack paths & misconfigurations
Mode: [cyan]{mode_str}[/cyan]
Supports both Active Directory (SharpHound/BloodHound-Python) and Azure AD (AzureHound) data.
For authorized security testing / red teaming only.
Use --help for all options.
""",
        title="Quick Overview",
        border_style="bright_blue",
        padding=(1, 2)
    ))
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
    # SharpHound AD types
    "users": "User", "computers": "Computer", "groups": "Group", "gpos": "GPO",
    "ous": "OU", "domains": "Domain", "containers": "Container",
    "certtemplates": "Certificate Template", "enterprisecas": "Enterprise CA",
    "rootcas": "Root CA", "aiacas": "AIA CA", "ntauthstores": "NTAuth Store",
    # AzureHound types (added support)
    "azureusers": "Azure User", "azuregroups": "Azure Group", "azureapplications": "Azure Application",
    "azureserviceprincipals": "Azure Service Principal", "azuretenants": "Azure Tenant",
    "azureroles": "Azure Role", "azuredevices": "Azure Device", "azurekeyvaults": "Azure Key Vault",
}
# ────────────────────────────────────────────────
# Abuse Suggestions Helper (Extended for Azure)
# ────────────────────────────────────────────────
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

def get_object_id(item):
    data = item.get('data')
    if isinstance(data, dict):
        oid = _get_prop_ci(data, ('id', 'objectid', 'objectId', 'ObjectId', 'ObjectIdentifier'))
        if oid:
            return oid
    oid = _get_prop_ci(item, ('ObjectIdentifier', 'objectid', 'objectId', 'ObjectId', 'id'))
    if oid:
        return oid
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
            # Skip directory entries (trailing slash)
            name = info.filename
            if not name or name.endswith('/'):
                # Still create nested dirs when needed via file members
                continue
            # Reject absolute paths and Windows drive letters in member names
            if name.startswith(('/', '\\')) or (len(name) > 1 and name[1] == ':'):
                raise ValueError(f"Zip entry has absolute path: {name!r}")
            dest = (extract_to / name).resolve()
            try:
                dest.relative_to(extract_to)
            except ValueError:
                raise ValueError(f"Zip entry escapes extract dir (Zip Slip): {name!r}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zip_ref.open(info) as src, open(dest, 'wb') as out:
                out.write(src.read())

def load_json_dir(directory, debug=False):
    nodes = {}
    try:
        path_obj = Path(directory)
        if path_obj.suffix.lower() == '.zip':
            if debug:
                print(f"Extracting {path_obj.name}...")
            
            extract_to = path_obj.parent / path_obj.stem
            
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
                        console.print(f"[blue]DEBUG: Top-level keys: {list(raw.keys())}[/blue]")
                    meta_type = raw.get("meta", {}).get("type", "").lower()
                    data = raw.get('data') or raw.get('Results') or raw.get('objects') or raw
                    if debug:
                        console.print(f"[blue]DEBUG: data type: {type(data)}, len if list: {len(data) if isinstance(data, list) else 'not list'}[/blue]")
                    if not isinstance(data, list):
                        data = [data] if data and isinstance(data, dict) else []
                    added = 0
                    for item in data:
                        if not isinstance(item, dict):
                            continue
                        # Detect Azure (case-insensitive checks, expanded)
                        item_lower = {k.lower(): v for k, v in item.items()}
                        is_azure = meta_type.startswith("azure") or any(k in ['@odata.context', 'odata.context', 'cloudanchorobject'] for k in item_lower.keys()) or any(v and isinstance(v, str) and ('microsoft.com' in v.lower() or 'azure' in v.lower()) for v in item_lower.values() if isinstance(v, str))
                        # Infer type for Azure using 'kind' field (from AzureHound structure)
                        if is_azure:
                            item['IsAzure'] = True
                            obj_type = "Unknown Azure"
                            kind = item.get('kind', '').lower()
                            if 'tenant' in kind:
                                obj_type = "Azure Tenant"
                            elif 'device' in kind:
                                obj_type = "Azure Device"
                            elif 'user' in kind:
                                obj_type = "Azure User"
                            elif 'group' in kind:
                                obj_type = "Azure Group"
                            elif 'role' in kind:
                                obj_type = "Azure Role"
                            elif 'application' in kind:
                                obj_type = "Azure Application"
                            elif 'serviceprincipal' in kind or 'sp' in kind:
                                obj_type = "Azure Service Principal"
                            elif 'keyvault' in kind:
                                obj_type = "Azure Key Vault"
                            # Fallback to 'type' field if available
                            if obj_type == "Unknown Azure":
                                typ = item.get('type') or item.get('Type')
                                if typ:
                                    obj_type = f"Azure {typ.title()}"
                        else:
                            obj_type = TYPE_FROM_META.get(meta_type, "Unknown")
                        item['ObjectType'] = obj_type
                        oid = get_object_id(item)
                        nodes[oid] = item
                        added += 1
                        if debug and added <= 3:  # Print first 3 items for inspection
                            console.print(f"[blue]DEBUG: Sample item keys: {list(item.keys())}[/blue]")
                            console.print(f"[blue]DEBUG: Sample item type: {obj_type}[/blue]")
                            console.print(f"[blue]DEBUG: Sample item sample data: {dict(list(item.get('data', {}).items())[:10])}[/blue]")
                    if debug:
                        console.print(f"[blue]DEBUG: {filename} → {added} objects added[/blue]")
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to parse {filename}: {e}[/yellow]")
                if debug:
                    console.print(f"[red]DEBUG: Full traceback for {filename}:[/red]\n{traceback.format_exc()}")
            progress.advance(task)
    console.print(f"[green]✓ Loaded {len(nodes)} objects from {len(files)} files[/green]")
    return nodes

def build_graph(nodes, db_path=None, debug=False):
    G = nx.MultiDiGraph()
    name_to_oid = {}
    relationship_edges = []
    placeholder_counter = 0
    if debug:
        console.print(f"[blue]DEBUG: Starting graph build with {len(nodes)} raw nodes[/blue]")
    with tqdm(total=len(nodes), desc="Building graph", unit="node") as pbar:
        for oid, node in nodes.items():
            is_azure = node.get('IsAzure', False)
            # For Azure, props are in node['data']
            props = node['data'] if is_azure and 'data' in node else node.get('Properties', node)
            name = props.get('name') or props.get('Name') or props.get('displayName') or oid
            name_norm = name.upper().split('@')[0]
            obj_type = node.get('ObjectType') or node.get('Type') or props.get('type') or 'Unknown'
            if not oid.startswith('rel_'):
                G.add_node(oid, name=name, type=obj_type, props=props, is_azure=is_azure)
                name_to_oid[name_norm] = oid
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
                if not isinstance(rels, list):
                    rels = [rels] if rels else []
                for rel in rels:
                    target = rel.get('ObjectIdentifier') if isinstance(rel, dict) else rel
                    if not target or target not in nodes:
                        continue
                    if key.lower() == 'allowedtoact':
                        # principal (listed) → AllowedToAct → resource (this node)
                        G.add_edge(target, oid, label=key)
                    else:
                        G.add_edge(oid, target, label=key)
            # SharpHound CE stores group membership on groups as Members
            # (not MemberOf on users). Emit member → MemberOf → group edges.
            members = None
            for nk in node.keys():
                if nk.lower() == 'members':
                    members = node[nk]
                    break
            if members is not None:
                if not isinstance(members, list):
                    members = [members] if members else []
                for rel in members:
                    member_id = None
                    if isinstance(rel, dict):
                        member_id = (
                            rel.get('ObjectIdentifier')
                            or rel.get('objectid')
                            or rel.get('ObjectId')
                            or rel.get('id')
                        )
                    else:
                        member_id = rel
                    if member_id and member_id in nodes:
                        G.add_edge(member_id, oid, label='MemberOf')
            # SharpHound CE nested session collections:
            # {Results: [{UserSID, ComputerSID}], Collected, FailureReason}
            # BloodHound edge: Computer -HasSession-> User
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
                    if user_sid and user_sid in nodes:
                        G.add_edge(oid, user_sid, label='HasSession')
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
                        if isinstance(member, dict):
                            mid = (
                                member.get('ObjectIdentifier')
                                or member.get('objectid')
                                or member.get('ObjectId')
                                or member.get('id')
                            )
                        else:
                            mid = member
                        if mid and mid in nodes:
                            G.add_edge(mid, oid, label=label)
            aces = node.get('Aces', [])
            for ace in aces:
                principal = ace.get('PrincipalSID') or ace.get('PrincipalObjectIdentifier')
                right = ace.get('RightName')
                if principal and right and principal in nodes:
                    G.add_edge(principal, oid, label=right)
            # Azure relationships (case-insensitive, expanded)
            azure_rels = ['MemberOf', 'HasRole', 'Owns', 'CanRead', 'CanWrite', 'CanDelete', 'Execute', 'AddMembers', 'ResetPassword', 'AddSecret', 'AddCertificate', 'AddOwner', 'GetChanges', 'GetChangesAll', 'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner']
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
                    target = rel.get('ObjectIdentifier') or rel.get('id') if isinstance(rel, dict) else rel
                    if target and target in nodes:
                        G.add_edge(oid, target, label=key)
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
                            if rel_type and target and target in nodes:
                                G.add_edge(oid, target, label=rel_type)
            pbar.update(1)
    if debug:
        console.print(f"[blue]DEBUG: Main graph build complete - {G.number_of_nodes()} nodes, {G.number_of_edges()} edges[/blue]")
    console.print("[cyan]Processing standalone relationships...[/cyan]")
    added = 0
    placeholders_added = 0
    for start, end, label in relationship_edges:
        start_norm = start.upper().split('@')[0]
        end_norm = end.upper().split('@')[0]
        start_oid = None
        if start in G.nodes:
            start_oid = start
        elif start_norm in name_to_oid:
            start_oid = name_to_oid[start_norm]
        else:
            start_oid = f"placeholder_{placeholder_counter}"
            placeholder_counter += 1
            G.add_node(start_oid, name=start, type='Unknown', props={}, is_azure=False)
            name_to_oid[start_norm] = start_oid
            placeholders_added += 1
        end_oid = None
        if end in G.nodes:
            end_oid = end
        elif end_norm in name_to_oid:
            end_oid = name_to_oid[end_norm]
        else:
            end_oid = f"placeholder_{placeholder_counter}"
            placeholder_counter += 1
            G.add_node(end_oid, name=end, type='Unknown', props={}, is_azure=False)
            name_to_oid[end_norm] = end_oid
            placeholders_added += 1
        if start_oid and end_oid:
            G.add_edge(start_oid, end_oid, label=label)
            added += 1
    console.print(f"[green]Added {added} relationship edges ({placeholders_added} placeholder nodes created)[/green]")
    console.print(f"[green]✓ Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges[/green]")
    if debug:
        console.print(f"[blue]DEBUG: Final graph stats - Nodes: {G.number_of_nodes()} | Edges: {G.number_of_edges()}[/blue]")
    if db_path:
        save_graph_to_db(G, db_path)
    return G, name_to_oid

def save_graph_to_db(G, db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS nodes (oid TEXT PRIMARY KEY, name TEXT, type TEXT, props TEXT, is_azure INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS edges (start_oid TEXT, end_oid TEXT, label TEXT)''')
    # Replace full snapshot: nodes upsert, edges must be cleared or they accumulate
    # on every re-save (no unique constraint on edges).
    c.execute('DELETE FROM edges')
    c.execute('DELETE FROM nodes')
    for n, d in G.nodes(data=True):
        c.execute(
            "INSERT INTO nodes VALUES (?, ?, ?, ?, ?)",
            (n, d['name'], d['type'], json.dumps(d['props']), int(d.get('is_azure', False))),
        )
    for u, v, d in G.edges(data=True):
        c.execute("INSERT INTO edges VALUES (?, ?, ?)", (u, v, d['label']))
    conn.commit()
    conn.close()
    console.print(f"[green]Graph saved to DB: {db_path}[/green]")
def load_graph_from_db(db_path):
    G = nx.MultiDiGraph()
    name_to_oid = {}
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT oid, name, type, props, is_azure FROM nodes")
    for oid, name, typ, props, is_azure in c.fetchall():
        G.add_node(oid, name=name, type=typ, props=json.loads(props), is_azure=bool(is_azure))
        name_to_oid[name.upper().split('@')[0]] = oid
    c.execute("SELECT start_oid, end_oid, label FROM edges")
    for u, v, label in c.fetchall():
        G.add_edge(u, v, label=label)
    conn.close()
    console.print(f"[green]Graph loaded from DB: {db_path}[/green]")
    return G, name_to_oid
# ────────────────────────────────────────────────
# VERBOSE SUMMARY (Extended for Azure)
# ────────────────────────────────────────────────
def print_verbose_summary(G, domain_filter=None):
    console.rule("[bold magenta]VERBOSE SUMMARY[/bold magenta]")
    types_count = defaultdict(int)
    azure_count = 0
    ad_count = 0
    for _, d in G.nodes(data=True):
        if domain_filter and d.get('props', {}).get('domain') != domain_filter and d.get('props', {}).get('tenantId') != domain_filter:
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
    users = [d['name'] for _, d in G.nodes(data=True) if d['type'].lower() in ['user', 'azure user'] and (not domain_filter or d.get('props', {}).get('domain') == domain_filter or d.get('props', {}).get('tenantId') == domain_filter)]
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

def get_bool_prop_ci(props, keys, default=False):
    if not isinstance(props, dict):
        return default
    for key in keys:
        for p_key in props:
            if p_key.lower() == key.lower():
                return bool(props[p_key])
    return default
def get_high_value_targets(G, domain_filter=None):
    ad_keywords = [
        'domain admins', 'enterprise admins', 'schema admins', 'administrators',
        'krbtgt', 'domain controllers', 'dnsadmins', 'enterprise key admins',
        'certificate template', 'enterprise ca', 'root ca', 'ntauth','dc'
    ]
    azure_keywords = [
        'global admin', 'user admin', 'application admin', 'exchange admin', 'sharepoint admin',
        'azure ad join', 'intune admin', 'security admin', 'conditional access admin', 'privileged role admin'
    ]
    targets = []
    for n, d in G.nodes(data=True):
        if domain_filter and d.get('props', {}).get('domain') != domain_filter and d.get('props', {}).get('tenantId') != domain_filter:
            continue
        name = d['name'].lower()
        typ = d['type'].lower()
        is_azure = d.get('is_azure', False)
        keywords = azure_keywords if is_azure else ad_keywords
        if any(k in name for k in keywords) or ('ca' in typ and not is_azure) or ('role' in typ and is_azure):
            targets.append((n, d['name'], d['type']))
    return sorted(targets, key=lambda x: x[1])
def format_path(G, path):
    if not path or len(path) < 1:
        return "[dim]Invalid path[/dim]"
    if len(path) == 1:
        return f"[bold cyan]{G.nodes[path[0]]['name']}[/bold cyan] (self)"
    parts = []
    for i in range(len(path)-1):
        u, v = path[i], path[i+1]
        edges = G.get_edge_data(u, v)
        label = next(iter(edges.values()))['label'] if edges else '???'
        parts.append(f"[bold cyan]{G.nodes[u]['name']}[/bold cyan] --[[yellow]{label}[/yellow]]-->")
    parts.append(f"[bold red]{G.nodes[path[-1]]['name']}[/bold red]")
    return " ".join(parts)
def get_indirect_paths(G, source, target, max_depth=5):
    paths = []
    try:
        for path in nx.all_simple_paths(G, source, target, cutoff=max_depth):
            if len(path) > 2:
                paths.append(path)
        return paths[:5]
    except nx.NetworkXNoPath:
        return []
# ────────────────────────────────────────────────
# All analysis functions (unchanged except where noted)
# ────────────────────────────────────────────────
def print_password_in_descriptions(G, domain_filter=None):
    console.rule("[bold magenta]Passwords in User Descriptions (AD)[/bold magenta]")
    found = False
    password_patterns = [r'password\s*:', r'pwd\s*:', r'pass\s*:', r'credentials\s*:', r'login\s*:', r'account\s*:', r'admin\s*:', r'secret\s*:', r'key\s*:']
    import re
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):  # Skip Azure for AD-specific checks
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
            continue
        if d['type'].lower() == 'user':
            props = d.get('props') or {}
            description = (props.get('description') or '').lower()
            if description:
                for pattern in password_patterns:
                    if re.search(pattern, description, re.IGNORECASE):
                        found = True
                        console.print(f"[yellow]Potential password in description[/yellow]: [green]{d['name']}[/green] - '{props.get('description')}'")
                        add_finding("Password in Description", f"User {d['name']} has potential password in description", score=6)
                        break
    if found:
        print_abuse_panel("Password in Description")
    else:
        console.print("[green]No passwords detected in user descriptions[/green]")

def print_password_never_expires(G, domain_filter=None):
    console.rule("[bold magenta]Users with 'Password Never Expires' Set (AD)[/bold magenta]")
    found = False
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
            continue
        if d['type'].lower() == 'user':
            props = d.get('props') or {}
            # SharpHound CE uses pwdneverexpires; also accept UAC DONT_EXPIRE_PASSWORD
            password_never_expires = get_bool_prop_ci(
                props, ['passwordneverexpires', 'PasswordNeverExpires', 'pwdneverexpires']
            )
            if not password_never_expires:
                uac_raw = props.get('useraccountcontrol') or props.get('UserAccountControl')
                try:
                    password_never_expires = bool(int(uac_raw) & 0x10000)
                except (TypeError, ValueError):
                    pass
            if password_never_expires:
                found = True
                uac_raw = props.get('useraccountcontrol') or props.get('UserAccountControl')
                uac_str = f" | UAC: {decode_uac(uac_raw)}" if uac_raw is not None else ""
                console.print(f"[yellow]Password Never Expires enabled[/yellow]: [green]{d['name']}[/green]{uac_str}")
                add_finding("Password Never Expires", f"User {d['name']} has 'Password Never Expires' set")
    if found:
        console.print(Panel("[bold yellow]Impact:[/bold yellow] Passwords may never expire, leading to old/weak passwords persisting indefinitely.\n[bold]Mitigation:[/bold] Review and enforce password policies; consider resetting passwords for affected accounts.\n[bold]Tools:[/bold] Use PowerShell (Get-ADUser) or AD tools to audit.", title="Abuse Suggestions: Password Never Expires", border_style="yellow"))
    else:
        console.print("[green]No users with 'Password Never Expires' found[/green]")

def print_password_not_required(G, domain_filter=None):
    console.rule("[bold magenta]Users with 'Password Not Required' Set (AD)[/bold magenta]")
    found = False
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
            continue
        if d['type'].lower() == 'user':
            props = d.get('props') or {}
            # SharpHound CE uses passwordnotreqd; also accept UAC PASSWD_NOTREQD
            password_not_required = get_bool_prop_ci(
                props, ['passwordnotrequired', 'PasswordNotRequired', 'passwordnotreqd']
            )
            if not password_not_required:
                uac_raw = props.get('useraccountcontrol') or props.get('UserAccountControl')
                try:
                    password_not_required = bool(int(uac_raw) & 0x20)
                except (TypeError, ValueError):
                    pass
            if password_not_required:
                found = True
                uac_raw = props.get('useraccountcontrol') or props.get('UserAccountControl')
                uac_str = f" | UAC: {decode_uac(uac_raw)}" if uac_raw is not None else ""
                console.print(f"[red]Password Not Required enabled[/red]: [green]{d['name']}[/green]{uac_str}")
                add_finding("Password Not Required", f"User {d['name']} has 'Password Not Required' set")
    if found:
        console.print(Panel("[bold red]Impact:[/bold red] No password required for login, enabling easy account takeover or unauthorized access.\n[bold]Abuse:[/bold] Log in without a password; escalate privileges if account has rights.\n[bold]Mitigation:[/bold] Enforce passwords; disable or monitor such accounts.\n[bold]Tools:[/bold] ADUC, PowerShell, or BloodHound for auditing.", title="Abuse Suggestions: Password Not Required", border_style="red"))
    else:
        console.print("[green]No users with 'Password Not Required' found[/green]")

def print_shadow_credentials(G, domain_filter=None):
    console.rule("[bold magenta]Shadow Credentials Detection (AD)[/bold magenta]")
    # Primary attack surface: rights to write KeyCredentialLink (AddKeyCredentialLink).
    # Existing KeyCredentialLink values are informational (often Windows Hello).
    found_abuse = False
    found_existing = False
    abuse_labels = {
        'addkeycredentiallink',
        'writeowner',  # can often lead to full control including key creds
    }
    targets = []
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
            continue
        if d.get('type', '').lower() not in ('user', 'computer'):
            continue
        targets.append(n)
    for tid in targets:
        tname = G.nodes[tid]['name']
        ttype = G.nodes[tid]['type']
        for u, _, edata in G.in_edges(tid, data=True):
            label = edata.get('label') or ''
            if label.lower() not in abuse_labels and label != 'AddKeyCredentialLink':
                # Exact AddKeyCredentialLink or aliases only for primary finding
                if label.lower() != 'addkeycredentiallink':
                    continue
            if label.lower() != 'addkeycredentiallink':
                continue
            found_abuse = True
            console.print(
                f"[red]Shadow Credentials abuse right[/red]: "
                f"[green]{G.nodes[u]['name']}[/green] --[{label}]--> "
                f"[cyan]{tname}[/cyan] ({ttype})"
            )
            add_finding(
                "Shadow Credentials",
                f"{G.nodes[u]['name']} can AddKeyCredentialLink on {tname}",
            )
    # Informational: objects that already have key credentials populated
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
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
            console.print(
                f"[yellow]Existing KeyCredentialLink[/yellow] (informational): "
                f"[green]{d['name']}[/green] — may be Windows Hello / legitimate device creds"
            )
    if found_abuse:
        print_abuse_panel("Shadow Credentials")
    if not found_abuse and not found_existing:
        console.print("[green]No Shadow Credentials abuse rights or existing KeyCredentialLink found[/green]")
    elif not found_abuse and found_existing:
        console.print(
            "[dim]No AddKeyCredentialLink abuse rights found; "
            "existing KeyCredentialLink entries listed above are informational only[/dim]"
        )

def print_gpo_content_parsing(G, domain_filter=None):
    console.rule("[bold magenta]GPO Content Parsing for Exploitable Settings (AD)[/bold magenta]")
    found = False
    exploitable_keys = ['taskname', 'scriptpath', 'scheduledtask', 'TaskName', 'ScriptPath', 'ScheduledTask']
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
            continue
        if d.get('type', '').lower() != 'gpo':
            continue
        name = d.get('name') or d.get('ObjectIdentifier', 'Unnamed GPO')
        props = d.get('props') or {}
        lower_props = {k.lower(): v for k, v in props.items()}
        found_keys = [k for k in exploitable_keys if k.lower() in lower_props and lower_props[k.lower()]]
        if found_keys:
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
        console.print("[green]No exploitable GPO content found[/green]")
        
def print_gpo_content_analysis(G, gpo_content_dir: str, domain_filter=None):
    console.rule("[bold magenta]GPO Content Analysis – Scheduled Tasks / Scripts / cPassword (AD)[/bold magenta]")
    if not gpo_content_dir or not Path(gpo_content_dir).is_dir():
        console.print("[yellow]--gpo-content-dir not provided or invalid. Skipping XML analysis.[/yellow]")
        return
    found_exploitable = False
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
        console.print("[green]No exploitable scheduled tasks, scripts, or cPasswords found in GPO XMLs[/green]")

def print_constrained_delegation(G, domain_filter=None):
    console.rule("[bold magenta]Constrained Delegation Detection (AD)[/bold magenta]")
    found = False
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
            continue
        if d['type'].lower() == 'computer':
            props = d.get('props') or {}
            # SharpHound CE: trustedtoauth, allowedtodelegate (and top-level AllowedToDelegate)
            trusted_to_auth = get_bool_prop_ci(
                props,
                ['trustedtoauthfordelegation', 'TrustedToAuthForDelegation', 'trustedtoauth'],
            )
            allowed_to_delegate_to = (
                props.get('msds-allowedtodelegateto')
                or props.get('allowedtodelegateto')
                or props.get('allowedtodelegate')
                or props.get('AllowedToDelegate')
                or []
            )
            if not isinstance(allowed_to_delegate_to, list):
                allowed_to_delegate_to = [allowed_to_delegate_to] if allowed_to_delegate_to else []
            if trusted_to_auth or allowed_to_delegate_to:
                found = True
                console.print(f"[yellow]Constrained Delegation enabled[/yellow]: [bold cyan]{d['name']}[/bold cyan]")
                if allowed_to_delegate_to:
                    console.print(f"  → Allowed to delegate to: {', '.join(allowed_to_delegate_to)}")
                add_finding("Constrained Delegation", f"Computer {d['name']} has Constrained Delegation")
    if found:
        print_abuse_panel("Constrained Delegation")
    else:
        console.print("[green]No Constrained Delegation found[/green]")

def print_laps_status(G, domain_filter=None):
    console.rule("[bold magenta]LAPS (Local Administrator Password Solution) Status (AD)[/bold magenta]")
    computers = [d for _, d in G.nodes(data=True) if d['type'].lower() == 'computer' and (not domain_filter or d.get('props', {}).get('domain') == domain_filter) and not d.get('is_azure', False)]
    if not computers:
        console.print("[green]No computers found[/green]")
        return
    found_enabled = False
    found_disabled = False
    for d in computers:
        props = d.get('props') or {}
        laps_password = props.get('ms-mcs-admpwd') or props.get('msMcsAdmPwd')
        if laps_password:
            found_enabled = True
            console.print(f"[green]LAPS enabled[/green]: [bold cyan]{d['name']}[/bold cyan]")
        else:
            found_disabled = True
            console.print(f"[yellow]LAPS not enabled[/yellow]: [bold cyan]{d['name']}[/bold cyan]")
            add_finding("LAPS", f"Computer {d['name']} does not have LAPS enabled")
    if found_enabled:
        console.print(Panel("[bold green]Impact:[/bold green] LAPS secures local admin passwords.\n[bold]Mitigation:[/bold] Ensure LAPS is enabled on all computers.\n[bold]Tools:[/bold] LAPS management tools, AD queries.", title="LAPS Enabled", border_style="green"))
    if found_disabled:
        console.print(Panel("[bold yellow]Impact:[/bold yellow] Local admin passwords may be weak or shared → easy compromise.\n[bold]Mitigation:[/bold] Enable LAPS to randomize and secure passwords.\n[bold]Tools:[/bold] LAPS deployment scripts.", title="LAPS Not Enabled", border_style="yellow"))

def print_unconstrained_delegation(G, domain_filter=None):
    console.rule("[bold magenta]Unconstrained Delegation Detection (AD)[/bold magenta]")
    found = False
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
            continue
        if d['type'].lower() == 'computer':
            props = d.get('props') or {}
            # SharpHound CE uses unconstraineddelegation
            trusted_for_delegation = get_bool_prop_ci(
                props,
                ['trustedfordelegation', 'TrustedForDelegation', 'unconstraineddelegation'],
            )
            if not trusted_for_delegation:
                uac_raw = props.get('useraccountcontrol') or props.get('UserAccountControl')
                try:
                    trusted_for_delegation = bool(int(uac_raw) & 0x80000)
                except (TypeError, ValueError):
                    pass
            if trusted_for_delegation:
                found = True
                console.print(f"[yellow]Unconstrained delegation enabled[/yellow]: [bold cyan]{d['name']}[/bold cyan]")
                add_finding("Unconstrained Delegation", f"Computer {d['name']} allows unconstrained delegation", score=8)
    if found:
        print_abuse_panel("Unconstrained Delegation")
    else:
        console.print("[green]No unconstrained delegation found[/green]")

def print_sid_history_abuse(G, domain_filter=None):
    console.rule("[bold magenta]SID History Abuse (AD)[/bold magenta]")
    found = False
    high_priv_groups = {'domain admins', 'enterprise admins', 'administrators', 'schema admins'}
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
            continue
        if d['type'].lower() != 'user':
            continue
        outgoing = list(G.out_edges(n, data=True))
        for u, v, edge_data in outgoing:
            if 'label' in edge_data and edge_data['label'].lower() == 'hassidhistory':
                group_name = G.nodes[v]['name'].lower()
                if any(hp in group_name for hp in high_priv_groups):
                    found = True
                    console.print(f"[yellow]SID History potential[/yellow]: [green]{d['name']}[/green] has SID history from [cyan]{G.nodes[v]['name']}[/cyan]")
                    add_finding("SID History Abuse", f"{d['name']} has SID history from {G.nodes[v]['name']}")
    if found:
        print_abuse_panel("SID History Abuse")
    else:
        console.print("[green]No obvious SID history abuse detected[/green]")

def print_adcs_vulnerabilities(G, domain_filter=None):
    """Detect AD CS misconfigs using SpecterOps ESC1–ESC8 naming.

    Labels follow Certified Pre-Owned / BloodHound CE semantics (not the prior
    swapped numbering). ESC8 (NTLM relay to HTTP enrollment) is only noted when
    explicit web-enrollment signals exist in the graph data.
    """
    console.rule("[bold magenta]ADCS ESC Vulnerabilities (ESC1–ESC8) (AD)[/bold magenta]")
    found = False
    # Common EKUs
    EKU_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2'
    EKU_SMART_CARD = '1.3.6.1.4.1.311.20.2.2'
    EKU_ANY_PURPOSE = '2.5.29.37.0'
    EKU_CERT_REQUEST_AGENT = '1.3.6.1.4.1.311.20.2.1'  # Enrollment Agent
    DANGEROUS_TEMPLATE_RIGHTS = {
        'GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite', 'WriteProperty',
    }
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
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
        ):
            if key in d and key not in props:
                props[key] = d[key]
        incoming = list(G.in_edges(n, data=True))
        rights = {edge_data.get('label') for _, _, edge_data in incoming if edge_data.get('label')}
        rights_ci = {r.lower() for r in rights}
        can_enroll = 'enroll' in rights_ci or 'autoenroll' in rights_ci
        enrollee_supplies = get_bool_prop_ci(
            props, ['enrolleesuppliessubject', 'EnrolleeSuppliesSubject']
        )
        requires_mgr_approval = get_bool_prop_ci(
            props, ['requiresmanagerapproval', 'RequiresManagerApproval'], default=False
        )
        no_approval = not requires_mgr_approval
        # ESC6: CA allows user-specified SAN
        editf_san2 = get_bool_prop_ci(
            props,
            [
                'editf_attributesubjectaltname2',
                'EDITF_ATTRIBUTESUBJECTALTNAME2',
                'isuserspecifiessanenabled',
                'IsUserSpecifiesSanEnabled',
            ],
        )
        ekus = props.get('ekus') or props.get('effectiveekus') or props.get('mspki-certificate-application-policy') or []
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
        has_any_purpose = EKU_ANY_PURPOSE in eku_set or len(eku_set) == 0
        has_cert_request_agent = EKU_CERT_REQUEST_AGENT in eku_set
        dangerous_on_object = {r for r in rights if r in DANGEROUS_TEMPLATE_RIGHTS}

        def _print_enrollers():
            for u, _, edge in incoming:
                if edge.get('label', '').lower() in ('enroll', 'autoenroll'):
                    console.print(f"  → [green]{G.nodes[u]['name']}[/green] can Enroll")

        def _print_right_holders(right_set):
            for u, _, edge in incoming:
                if edge.get('label') in right_set:
                    console.print(f"  → [green]{G.nodes[u]['name']}[/green] --[{edge['label']}]-->")

        # ── ESC1: ESS + client auth path + enroll + no manager approval ──
        if obj_type == 'certificate template' and can_enroll and enrollee_supplies and no_approval:
            # Prefer client-auth capable templates; still report ESS+enroll when EKU unknown
            if has_client_auth or not eku_set:
                found = True
                console.print(
                    f"[red]ESC1[/red]: [bold cyan]{name}[/bold cyan] "
                    f"(Enroll + EnrolleeSuppliesSubject + no manager approval"
                    f"{'' if has_client_auth or not eku_set else ''})"
                )
                _print_enrollers()
                add_finding("ESC1-ESC8", f"ESC1 on {name}")

        # ── ESC2: Any Purpose / no EKU + enroll + no approval (without ESS) ──
        if (
            obj_type == 'certificate template'
            and can_enroll
            and no_approval
            and not enrollee_supplies
            and has_any_purpose
        ):
            found = True
            console.print(
                f"[red]ESC2[/red]: [bold cyan]{name}[/bold cyan] "
                f"(Enroll + Any Purpose/no EKU + no manager approval)"
            )
            _print_enrollers()
            add_finding("ESC1-ESC8", f"ESC2 on {name}")

        # ── ESC3: Enrollment Agent (Certificate Request Agent EKU) ──
        if obj_type == 'certificate template' and has_cert_request_agent:
            found = True
            console.print(
                f"[red]ESC3[/red]: [bold cyan]{name}[/bold cyan] "
                f"(Certificate Request Agent / Enrollment Agent EKU)"
            )
            _print_enrollers()
            add_finding("ESC1-ESC8", f"ESC3 on {name}")

        # ── ESC4: Dangerous ACLs on certificate *template* ──
        if obj_type == 'certificate template' and dangerous_on_object:
            found = True
            console.print(
                f"[red]ESC4[/red]: [bold cyan]{name}[/bold cyan] "
                f"(dangerous rights on certificate template)"
            )
            _print_right_holders(dangerous_on_object)
            add_finding("ESC1-ESC8", f"ESC4 on {name}")

        # ── ESC5: Dangerous ACLs on other PKI objects (CA / NTAuth), not ManageCA ──
        if obj_type in ['enterprise ca', 'root ca', 'ntauth store']:
            esc5_rights = dangerous_on_object  # GenericAll etc. on PKI objects
            if esc5_rights:
                found = True
                console.print(
                    f"[red]ESC5[/red]: [bold cyan]{name}[/bold cyan] "
                    f"(dangerous rights on PKI object)"
                )
                _print_right_holders(esc5_rights)
                add_finding("ESC1-ESC8", f"ESC5 on {name}")

        # ── ESC6: CA allows requester-specified SAN ──
        if obj_type == 'enterprise ca' and editf_san2:
            found = True
            console.print(
                f"[red]ESC6[/red]: [bold cyan]{name}[/bold cyan] "
                f"(CA allows user-specified SAN / EDITF_ATTRIBUTESUBJECTALTNAME2)"
            )
            _print_enrollers()
            add_finding("ESC1-ESC8", f"ESC6 on {name}")

        # ── ESC7: ManageCA / ManageCertificates on CA ──
        if obj_type in ['enterprise ca', 'root ca']:
            manage_rights = {r for r in rights if r in ('ManageCA', 'ManageCertificates')}
            if manage_rights:
                found = True
                console.print(
                    f"[red]ESC7[/red]: [bold cyan]{name}[/bold cyan] "
                    f"(ManageCA/ManageCertificates on CA)"
                )
                _print_right_holders(manage_rights)
                add_finding("ESC1-ESC8", f"ESC7 on {name}")

        # ── ESC8: Web enrollment / HTTP AD CS (limited signal from JSON) ──
        if obj_type == 'enterprise ca':
            web_enroll = get_bool_prop_ci(
                props,
                [
                    'webenrollment',
                    'WebEnrollment',
                    'httpenrollment',
                    'HttpEnrollment',
                    'haswebenrollment',
                ],
            )
            if web_enroll:
                found = True
                console.print(
                    f"[red]ESC8[/red]: [bold cyan]{name}[/bold cyan] "
                    f"(web/HTTP enrollment enabled — NTLM relay risk)"
                )
                add_finding("ESC1-ESC8", f"ESC8 on {name}")
    if found:
        print_abuse_panel("ESC1-ESC8 (AD CS)")
    else:
        console.print("[green]No obvious ESC1–ESC8 misconfigurations detected[/green]")

def print_gpo_abuse(G, domain_filter=None):
    console.rule("[bold magenta]GPO Abuse Risks (AD)[/bold magenta]")
    found = False
    high_value_keywords = ['domain controllers', 'domain admins', 'enterprise admins', 'administrators', 'dc']
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
            continue
        if d['type'].lower() != 'gpo':
            continue
        name = d['name']
        incoming = list(G.in_edges(n, data=True))
        rights = {edge_data['label'].lower() for _, _, edge_data in incoming}
        dangerous = {'genericall', 'writedacl', 'writeowner', 'genericwrite'}
        dangerous_found = dangerous & rights
        if dangerous_found:
            is_high_risk = False
            linked_ous = []
            for _, target, edge_data in G.out_edges(n, data=True):
                if edge_data.get('label', '').lower() in ['gplink', 'linkedto']:
                    ou_name = G.nodes[target].get('name', '').lower()
                    linked_ous.append(ou_name)
                    if any(kw in ou_name for kw in high_value_keywords):
                        is_high_risk = True
            found = True
            risk_color = "[red]" if is_high_risk else "[yellow]"
            scope_note = f" (High-risk: Linked to {', '.join(linked_ous)})" if linked_ous else " (No links detected - low risk)"
            console.print(f"{risk_color}Weak GPO{risk_color}: [bold cyan]{name}[/bold cyan]{scope_note}")
            for u, _, edge in incoming:
                label_lower = edge['label'].lower()
                if label_lower in dangerous:
                    principal_name = G.nodes[u]['name']
                    console.print(f"  → [green]{principal_name}[/green] --[{edge['label']}]-->")
            add_finding("GPO Abuse", f"Weak GPO: {name}{scope_note}")
    if found:
        print_abuse_panel("GPO Abuse")
    else:
        console.print("[green]No dangerous GPO rights found[/green]")

def print_dcsync_rights(G, domain_filter=None):
    console.rule("[bold magenta]DCSync / Replication Rights (AD)[/bold magenta]")
    # Classic DCSync requires GetChanges + GetChangesAll together.
    # GetChangesInFilteredSet alone is RODC-related, not full DCSync.
    found = False
    domain_oids = [
        n for n, d in G.nodes(data=True)
        if d['type'] == 'Domain'
        and (not domain_filter or d.get('props', {}).get('domain') == domain_filter)
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
    default_priv_keywords = (
        'domain admins', 'enterprise admins', 'administrators',
        'domain controllers', 'enterprise domain controllers',
        'builtin\\administrators',
    )

    def _is_default_priv(name):
        nl = name.lower()
        return any(k in nl for k in default_priv_keywords)

    for domain_oid in domain_oids:
        domain_name = G.nodes[domain_oid]['name']
        # Collect rights per principal
        by_principal = defaultdict(set)
        for u, _, d in G.in_edges(domain_oid, data=True):
            label_lower = (d.get('label') or '').lower()
            by_principal[u].add(label_lower)
        for u, labels in by_principal.items():
            principal_name = G.nodes[u]['name']
            has_gc = bool(labels & get_changes_labels)
            has_gca = bool(labels & get_changes_all_labels)
            has_filtered = bool(labels & filtered_set_labels)
            if has_gc and has_gca:
                found = True
                if _is_default_priv(principal_name):
                    console.print(
                        f"[dim]Expected DCSync rights[/dim]: [cyan]{principal_name}[/cyan] "
                        f"on [cyan]{domain_name}[/cyan] (built-in high privilege)"
                    )
                else:
                    console.print(
                        f"[red]DCSync possible[/red]: [green]{principal_name}[/green] "
                        f"has GetChanges + GetChangesAll on [cyan]{domain_name}[/cyan]"
                    )
                    add_finding("DCSync", f"{principal_name} can DCSync on {domain_name}")
            elif has_gca and not has_gc:
                # Incomplete — note but do not call full DCSync
                console.print(
                    f"[yellow]Partial replication rights[/yellow]: [green]{principal_name}[/green] "
                    f"has GetChangesAll without GetChanges on [cyan]{domain_name}[/cyan]"
                )
                add_finding(
                    "DCSync",
                    f"{principal_name} has GetChangesAll only on {domain_name}",
                    score=6,
                )
                found = True
            elif has_filtered and not (has_gc and has_gca):
                console.print(
                    f"[dim]Filtered-set replication[/dim]: [cyan]{principal_name}[/cyan] "
                    f"on [cyan]{domain_name}[/cyan] (RODC-related, not full DCSync)"
                )
    if found:
        print_abuse_panel("DCSync")
    else:
        console.print("[green]No DCSync rights detected[/green]")

def print_rbcd(G, domain_filter=None):
    console.rule("[bold magenta]Resource-Based Constrained Delegation (RBCD) (AD)[/bold magenta]")
    # RBCD is msDS-AllowedToActOnBehalfOfOtherIdentity / AllowedToAct edges
    # (principal → AllowedToAct → resource). msDS-AllowedToDelegateTo is KCD,
    # handled by print_constrained_delegation — do not treat it as RBCD.
    found = False
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
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
        console.print("[green]No RBCD configured computers found[/green]")

def print_shortest_paths(G, fast=False, max_paths=10, target_filter=None, domain_filter=None, indirect=False):
    console.rule("[bold magenta]Shortest Paths to High-Value Targets[/bold magenta]")
    users = [n for n, d in G.nodes(data=True) if d['type'].lower() in ['user', 'azure user'] and (not domain_filter or d.get('props', {}).get('domain') == domain_filter or d.get('props', {}).get('tenantId') == domain_filter)]
    targets = get_high_value_targets(G, domain_filter)
    if target_filter:
        targets = [t for t in targets if target_filter.lower() in t[1].lower()]
    if not targets:
        console.print("[yellow]No high-value targets found (or none match filter)[/yellow]")
        return
    if not users:
        console.print("[yellow]No user objects found for path calculation[/yellow]")
        return
    if fast:
        console.print("[yellow]Fast mode enabled: Skipping shortest path computation[/yellow]")
        return
    for tid, tname, ttype in targets[:5]:
        console.print(f"\n[bold]Target:[/bold] [bold cyan]{tname}[/bold cyan] ({ttype})")
        count = 0
        for source in users:
            if source == tid or not nx.has_path(G, source, tid):
                continue
            try:
                path = nx.shortest_path(G, source, tid)
                path_length = len(path) - 1
                formatted_path = format_path(G, path)
                console.print(f"  [dim]→[/dim] (Length: {path_length}) {formatted_path}")
                count += 1
                if count >= max_paths:
                    break
            except nx.NetworkXNoPath:
                continue
        if indirect:
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
        if count == 0 and not indirect:
            connected_users = [u for u in users if nx.has_path(G, u, tid)]
            if not connected_users:
                console.print("    [dim]No paths found: Target may be disconnected from users[/dim]")
            else:
                console.print("    [dim]No paths found within limit[/dim]")
        add_finding("Shortest Paths", f"Paths to {tname}", score=6 if count > 0 else 0)

def print_dangerous_permissions(G, domain_filter=None, indirect=False):
    console.rule("[bold magenta]Dangerous Permissions on High-Value Objects[/bold magenta]")
    dangerous_rights = {'genericall', 'owns', 'writedacl', 'writeowner', 'allextendedrights', 'genericwrite', 'addmember', 'resetpassword', 'forcechangepassword', 'manageca', 'managecertificates', 'enroll', 'certificateenroll', 'writeproperty'}
    azure_dangerous = {'genericall', 'owns', 'writedacl', 'writeowner', 'addsecret', 'addcertificate', 'addowner', 'execute', 'canread', 'canwrite', 'candelete'}
    targets = get_high_value_targets(G, domain_filter)
    found = False
    if not targets:
        console.print("[yellow]No high-value targets found[/yellow]")
        return
    for tid, tname, ttype in targets:
        incoming = G.in_edges(tid, data=True)
        is_azure = G.nodes[tid].get('is_azure', False)
        rights_set = azure_dangerous if is_azure else dangerous_rights
        dangerous_edges = [(u, d['label']) for u, v, d in incoming if 'label' in d and d['label'].lower() in rights_set and u in G.nodes]
        if dangerous_edges:
            found = True
            console.print(f"\n[bold cyan]{tname} ({ttype}):[/bold cyan]")
            from collections import defaultdict
            rights_by_type = defaultdict(list)
            for principal_oid, right in dangerous_edges:
                rights_by_type[right].append(principal_oid)
            for right, principals in rights_by_type.items():
                principal_names = [G.nodes[p]['name'] for p in principals[:5]]
                count = len(principals)
                extra = f" ... and {count - 5} more" if count > 5 else ""
                console.print(f"  • [yellow]{right}[/yellow]: [green]{', '.join(principal_names)}{extra}[/green]")
            console.print(f"    [dim](Note: Only direct rights shown; indirect via groups not included)[/dim]")
            add_finding("Dangerous Permissions", f"Dangerous rights on {tname}")
    if indirect:
        console.print(f"\n[dim]Checking indirect dangerous permissions via groups...[/dim]")
        for tid, tname, ttype in targets:
            for u, v, d in G.edges(data=True):
                if v == tid and 'label' in d and d['label'].lower() in (azure_dangerous if G.nodes[tid].get('is_azure', False) else dangerous_rights):
                    group_name = G.nodes[u]['name']
                    if G.nodes[u]['type'].lower() in ['group', 'azure group']:
                        members = [m for m in G.predecessors(u) if any(edge_data.get('label') == 'MemberOf' for edge_data in (G.get_edge_data(m, u) or {}).values())]
                        if members:
                            console.print(f"  [yellow]Indirect via group {group_name}[/yellow]: {', '.join([G.nodes[m]['name'] for m in members[:3]])}")
    if found:
        print_abuse_panel("Dangerous Permissions")
    else:
        console.print("[green]No dangerous ACLs found on high-value objects[/green]")

def print_kerberoastable(G, domain_filter=None):
    console.rule("[bold magenta]Kerberoastable Accounts (AD)[/bold magenta]")
    found = False
    count = 0
    max_display = 20
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
            continue
        if d['type'].lower() != 'user':
            continue
        props = d.get('props', {})
        hasspn = get_bool_prop_ci(props, ['hasspn', 'hasSPN', 'has_spn'])
        sensitive = props.get('sensitive', props.get('Sensitive', False))
        enabled = props.get('enabled', props.get('Enabled', True))
        if hasspn and not sensitive and enabled:
            found = True
            uac_raw = props.get('useraccountcontrol') or props.get('UserAccountControl')
            uac_str = f" | UAC: {decode_uac(uac_raw)}" if uac_raw is not None else ""
            console.print(f"  • [cyan]{d['name']}[/cyan]{uac_str}")
            count += 1
            if count >= max_display:
                remaining = sum(1 for n_inner, d_inner in G.nodes(data=True) if d_inner.get('type', '').lower() == 'user' and get_bool_prop_ci(d_inner.get('props', {}), ['hasspn', 'hasSPN', 'has_spn']) and not d_inner.get('props', {}).get('sensitive', d_inner.get('props', {}).get('Sensitive', False)) and d_inner.get('props', {}).get('enabled', d_inner.get('props', {}).get('Enabled', True))) - max_display
                if remaining > 0:
                    console.print(f"  [dim]... and {remaining} more[/dim]")
                break
    if found:
        print_abuse_panel("Kerberoastable")
        add_finding("Kerberoastable", f"{count} accounts")
    else:
        console.print("[green]None found[/green]")

def print_as_rep_roastable(G, domain_filter=None):
    console.rule("[bold magenta]AS-REP Roastable Accounts (DONT_REQ_PREAUTH) (AD)[/bold magenta]")
    found = False
    count = 0
    max_display = 20
    for n, d in G.nodes(data=True):
        if d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('domain') != domain_filter:
            continue
        if d['type'].lower() != 'user':
            continue
        props = d.get('props', {})
        dontreqpreauth = get_bool_prop_ci(props, ['dontreqpreauth', 'dontReqPreauth', 'dont_req_preauth'])
        sensitive = props.get('sensitive', props.get('Sensitive', False))
        enabled = props.get('enabled', props.get('Enabled', True))
        if dontreqpreauth and not sensitive and enabled:
            found = True
            uac_raw = props.get('useraccountcontrol') or props.get('UserAccountControl')
            uac_str = f" | UAC: {decode_uac(uac_raw)}" if uac_raw is not None else ""
            console.print(f"  • [cyan]{d['name']}[/cyan]{uac_str}")
            count += 1
            if count >= max_display:
                remaining = sum(1 for n_inner, d_inner in G.nodes(data=True) if d_inner.get('type', '').lower() == 'user' and get_bool_prop_ci(d_inner.get('props', {}), ['dontreqpreauth', 'dontReqPreauth', 'dont_req_preauth']) and not d_inner.get('props', {}).get('sensitive', d_inner.get('props', {}).get('Sensitive', False)) and d_inner.get('props', {}).get('enabled', d_inner.get('props', {}).get('Enabled', True))) - max_display
                if remaining > 0:
                    console.print(f"  [dim]... and {remaining} more[/dim]")
                break
    if found:
        print_abuse_panel("AS-REP Roastable")
        add_finding("AS-REP Roastable", f"{count} accounts")
    else:
        console.print("[green]None found[/green]")

def print_sessions_localadmin(G, domain_filter=None):
    console.rule("[bold magenta]Session / LocalAdmin / RDP / DCOM Summary (AD)[/bold magenta]")
    computers = [n for n, d in G.nodes(data=True) if d['type'].lower() == 'computer' and (not domain_filter or d.get('props', {}).get('domain') == domain_filter) and not d.get('is_azure', False)]
    if not computers:
        console.print("[yellow]No computers found[/yellow]")
        return
    table = Table(title="Top Local Admins / RDP / DCOM", show_header=True, header_style="bold magenta")
    table.add_column("Principal", style="cyan")
    table.add_column("Rights", justify="right")
    table.add_column("Count", justify="right")
    table.add_column("Examples", style="green")
    from collections import defaultdict, Counter
    rights = ['LocalAdmin', 'CanRDP', 'ExecuteDCOM', 'GenericAll']
    counts = defaultdict(Counter)
    for u, v, d in G.edges(data=True):
        if v in computers and d.get('label') in rights:
            counts[d.get('label')][u] += 1
    for right, c in counts.items():
        for principal, count in c.most_common(5):
            examples = [G.nodes[v]['name'] for pu, v, ed in G.edges(data=True) if pu == principal and ed.get('label') == right][:3]
            table.add_row(G.nodes[principal]['name'], right, str(count), ", ".join(examples))
    console.print(table)
    console.print(f"[dim]Total computers: {len(computers)}[/dim]")

def print_paths_to_owned(G, owned_str, domain_filter=None):
    if not owned_str:
        return
    console.rule("[bold magenta]Shortest Paths to Owned Principals[/bold magenta]")
    owned_list = [o.strip() for o in owned_str.split(',') if o.strip()]
    owned_oids = []
    for o in owned_list:
        found = False
        for oid, d in G.nodes(data=True):
            if d['name'].upper().split('@')[0] == o.upper() and (not domain_filter or d.get('props', {}).get('domain') == domain_filter or d.get('props', {}).get('tenantId') == domain_filter):
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
            if d['name'].upper().split('@')[0] == sname.upper() and (not domain_filter or d.get('props', {}).get('domain') == domain_filter or d.get('props', {}).get('tenantId') == domain_filter):
                s_oid = oid
                break
        if not s_oid:
            console.print(f"[yellow]Source not found: {sname}[/yellow]")
            continue
        for tname in targets:
            t_oid = None
            for oid, d in G.nodes(data=True):
                if d['name'].upper().split('@')[0] == tname.upper() and (not domain_filter or d.get('props', {}).get('domain') == domain_filter or d.get('props', {}).get('tenantId') == domain_filter):
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

def print_trust_abuse(G, domain_filter=None):
    console.rule("[bold magenta]Domain Trust / Cross-Domain Abuse (AD) or Tenant Abuse (Azure)[/bold magenta]")
    found = False
    trust_labels = {'trustedby', 'trusts', 'foreignadmin', 'foreigngroup', 'memberof (cross-domain)'}
    azure_labels = {'tenantmember', 'cross-tenant'}
    for u, v, d in G.edges(data=True):
        label_lower = d.get('label', '').lower()
        is_azure = G.nodes[u].get('is_azure', False) or G.nodes[v].get('is_azure', False)
        labels = azure_labels if is_azure else trust_labels
        if any(t in label_lower for t in labels) or 'foreign' in label_lower:
            u_name = G.nodes[u]['name']
            v_name = G.nodes[v]['name']
            if domain_filter and domain_filter.lower() not in (u_name.lower() + v_name.lower()):
                continue
            found = True
            console.print(f"[yellow]Trust abuse possible[/yellow]: [green]{u_name}[/green] --[{d['label']}]--> [cyan]{v_name}[/cyan]")
            add_finding("Trust Abuse", f"{u_name} {d['label']} {v_name}", score=7)
    if not found:
        console.print("[green]No obvious cross-domain or cross-tenant abuse detected[/green]")

def inspect_node(G, identifier, domain_filter=None):
    console.rule(f"[bold magenta]Detailed Inspection: {identifier}[/bold magenta]")
    found = False
    for oid, d in G.nodes(data=True):
        name_norm = d['name'].upper().split('@')[0]
        if (oid == identifier or name_norm == identifier.upper()) and (not domain_filter or d.get('props', {}).get('domain') == domain_filter or d.get('props', {}).get('tenantId') == domain_filter):
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
    groups = [n for n, d in G.nodes(data=True) if d['type'].lower() in ['group', 'azure group'] and (not domain_filter or d.get('props', {}).get('domain') == domain_filter or d.get('props', {}).get('tenantId') == domain_filter)]
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

def print_stats_dashboard(G, domain_filter=None):
    console.rule("[bold magenta]AD & Azure Statistics Dashboard[/bold magenta]")
    filtered_nodes = [(n, d) for n, d in G.nodes(data=True) if not domain_filter or d.get('props', {}).get('domain') == domain_filter or d.get('props', {}).get('tenantId') == domain_filter]
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
        if domain_filter and d.get('props', {}).get('tenantId') != domain_filter:
            continue
        if d['type'].lower() == 'azure role':
            role_name = d['name'].lower()
            if any(pr in role_name for pr in privileged_roles):
                found = True
                console.print(f"[red]Privileged Azure role[/red]: [bold cyan]{d['name']}[/bold cyan]")
                incoming = list(G.in_edges(n, data=True))
                for u, _, edata in incoming:
                    if edata.get('label') == 'HasRole':
                        console.print(f"  → [green]{G.nodes[u]['name']}[/green] has this role")
                add_finding("Azure Privileged Roles", f"Privileged role: {d['name']}")
    if found:
        print_abuse_panel("Azure Privileged Roles")
    else:
        console.print("[green]No privileged Azure roles detected[/green]")
def print_azure_app_secrets(G, domain_filter=None):
    console.rule("[bold magenta]Azure Application Secrets/Certificates Exposure[/bold magenta]")
    found = False
    for n, d in G.nodes(data=True):
        if not d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('tenantId') != domain_filter:
            continue
        if d['type'].lower() == 'azure application':
            props = d.get('props', {})
            has_secrets = props.get('keyCredentials', []) or props.get('passwordCredentials', [])
            if has_secrets:
                found = True
                console.print(f"[red]Azure app with secrets/certificates[/red]: [bold cyan]{d['name']}[/bold cyan]")
                incoming = list(G.in_edges(n, data=True))
                for u, _, edata in incoming:
                    if edata.get('label') in ['Owns', 'AddSecret', 'AddCertificate']:
                        console.print(f"  → [green]{G.nodes[u]['name']}[/green] --[{edata['label']}]-->")
                add_finding("Azure App Secrets", f"App with secrets: {d['name']}")
    if found:
        print_abuse_panel("Azure App Secrets")
    else:
        console.print("[green]No Azure apps with exposed secrets/certificates[/green]")
def print_azure_mfa_bypass(G, domain_filter=None):
    console.rule("[bold magenta]Azure MFA Bypass Risks[/bold magenta]")
    found = False
    for n, d in G.nodes(data=True):
        if not d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('tenantId') != domain_filter:
            continue
        if d['type'].lower() == 'azure user':
            props = d.get('props', {})
            mfa_enabled = props.get('strongAuthenticationRequirements', {}).get('state') == 'Enforced' or props.get('mfaEnrolled', False)
            if not mfa_enabled:
                found = True
                console.print(f"[yellow]Azure user without MFA[/yellow]: [green]{d['name']}[/green]")
                add_finding("Azure MFA Bypass", f"User without MFA: {d['name']}")
    if found:
        print_abuse_panel("Azure MFA Bypass")
    else:
        console.print("[green]All Azure users have MFA enabled (or not detectable)[/green]")
        
def print_azure_guest_access(G, domain_filter=None):
    console.rule("[bold magenta]Azure Guest User Access Risks[/bold magenta]")
    found = False
    for n, d in G.nodes(data=True):
        if not d.get('is_azure', False):
            continue
        if domain_filter and d.get('props', {}).get('tenantId') != domain_filter:
            continue
        if d['type'].lower() == 'azure user':
            props = d.get('props', {})
            user_type = props.get('userType', '').lower()
            if user_type == 'guest':
                found = True
                console.print(f"[yellow]Azure guest user[/yellow]: [green]{d['name']}[/green]")
                outgoing = list(G.out_edges(n, data=True))
                for _, v, edata in outgoing:
                    if edata.get('label') == 'HasRole':
                        role_name = G.nodes[v]['name']
                        console.print(f"  → Has role: [cyan]{role_name}[/cyan]")
                add_finding("Azure Guest Access", f"Guest user: {d['name']}")
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
        if domain_filter and d.get('props', {}).get('tenantId') != domain_filter:
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
# Export
# ────────────────────────────────────────────────
def export_results(G, output_prefix="bloodbash", format_type="md", domain_filter=None):
    if format_type == "md":
        path = f"{output_prefix}.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write("# BloodBash Report\n\n")
            f.write("## High-Value Targets\n")
            for _, name, typ in get_high_value_targets(G, domain_filter):
                f.write(f"- {name} ({typ})\n")
            f.write("\n## Sample Paths\n")
            f.write("See console output for details.\n")
        console.print(f"[green]Exported Markdown:[/green] {path}")
    elif format_type == "json":
        path = f"{output_prefix}.json"
        summary = {"nodes": G.number_of_nodes(), "edges": G.number_of_edges(), "high_value": [{"name": d['name'], "type": d['type']} for _, d in G.nodes(data=True) if any(k in d['name'].lower() for k in ['admin', 'krbtgt', 'ca', 'template']) and (not domain_filter or d.get('props', {}).get('domain') == domain_filter or d.get('props', {}).get('tenantId') == domain_filter)]}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        console.print(f"[green]Exported JSON:[/green] {path}")
    elif format_type == "html":
        path = f"{output_prefix}.html"
        html = f"""<html><head><title>BloodBash Report</title><style>body {{ font-family: Arial; }} .red {{ color: red; }} .yellow {{ color: orange; }} .green {{ color: green; }} table {{ border-collapse: collapse; }} th, td {{ border: 1px solid black; padding: 5px; }}</style></head><body><h1>BloodBash Report</h1><h2>High-Value Targets</h2><ul>"""
        for _, name, typ in get_high_value_targets(G, domain_filter):
            html += f"<li>{escape(name)} ({escape(typ)})</li>"
        html += "</ul><h2>Prioritized Findings</h2><table><tr><th>Severity</th><th>Category</th><th>Details</th></tr>"
        for score, cat, det in sorted(global_findings, key=lambda x: x[0], reverse=True):
            html += f"<tr><td>{score}</td><td>{escape(cat)}</td><td>{escape(det)}</td></tr>"
        html += "</table></body></html>"
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        console.print(f"[green]Exported HTML:[/green] {path}")
    elif format_type == "csv":
        path = f"{output_prefix}_sessions.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Principal", "Count", "Examples"])
            computers = [n for n, d in G.nodes(data=True) if d['type'].lower() == 'computer' and (not domain_filter or d.get('props', {}).get('domain') == domain_filter) and not d.get('is_azure', False)]
            admin_edges = [(u, v, d) for u, v, d in G.edges(data=True) if d.get('label') == 'LocalAdmin' and v in computers]
            from collections import Counter
            counts = Counter(u for u, _, _ in admin_edges)
            for principal, count in counts.most_common(10):
                examples = [G.nodes[v]['name'] for pu, v, _ in admin_edges if pu == principal][:3]
                writer.writerow([G.nodes[principal]['name'], count, ", ".join(examples)])
        console.print(f"[green]Exported CSV:[/green] {path}")
    elif format_type == "yaml":
        path = f"{output_prefix}.yaml"
        summary = {"nodes": G.number_of_nodes(), "edges": G.number_of_edges(), "high_value": [{"name": d['name'], "type": d['type']} for _, d in G.nodes(data=True) if any(k in d['name'].lower() for k in ['admin', 'krbtgt', 'ca', 'template']) and (not domain_filter or d.get('props', {}).get('domain') == domain_filter or d.get('props', {}).get('tenantId') == domain_filter)], "findings": [{"score": s, "category": c, "details": d} for s, c, d in global_findings]}
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(summary, f, default_flow_style=False)
        console.print(f"[green]Exported YAML:[/green] {path}")

def export_bloodhound_compatible(G, output_prefix="bloodbash_bh"):
    path = f"{output_prefix}.json"
    nodes_list = []
    for oid, data in G.nodes(data=True):
        nodes_list.append({"objectid": oid, "name": data.get('name'), "type": data.get('type'), "properties": data.get('props', {}), "is_azure": data.get('is_azure', False)})
    rels_list = []
    for u, v, data in G.edges(data=True):
        rels_list.append({"start": u, "end": v, "type": data.get('label')})
    bh_data = {"meta": {"version": __version__, "generator": "BloodBash"}, "nodes": nodes_list, "relationships": rels_list}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bh_data, f, indent=2)
    console.print(f"[green]Exported BloodHound-compatible JSON:[/green] {path}")

def export_to_dot(G, dot_path, domain_filter=None):
    with open(dot_path, "w", encoding="utf-8") as f:
        f.write("digraph BloodBash {\n  rankdir=LR;\n  node [shape=box];\n")
        for n, d in G.nodes(data=True):
            if domain_filter and d.get('props', {}).get('domain') != domain_filter and d.get('props', {}).get('tenantId') != domain_filter:
                continue
            color = "red" if any(k in d['name'].lower() for k in ['admin', 'krbtgt', 'ca', 'template', 'global admin']) else "blue"
            f.write(f'  "{d["name"]}" [label="{d["name"]}\\n{d["type"]}", color={color}];\n')
        for u, v, d in G.edges(data=True):
            if domain_filter and (G.nodes[u].get('props', {}).get('domain') != domain_filter and G.nodes[u].get('props', {}).get('tenantId') != domain_filter) and (G.nodes[v].get('props', {}).get('domain') != domain_filter and G.nodes[v].get('props', {}).get('tenantId') != domain_filter):
                continue
            f.write(f'  "{G.nodes[u]["name"]}" -> "{G.nodes[v]["name"]}" [label="{d.get("label", "?")}"];\n')
        f.write("}\n")
    console.print(f"[green]Exported Graphviz DOT:[/green] {dot_path}")
    console.print(f"[dim]Render with: dot -Tpng {dot_path} -o graph.png[/dim]")

# ────────────────────────────────────────────────
# Main execution
# ────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="BloodBash - Advanced BloodHound & AzureHound Offline Analyzer")
    parser.add_argument('directory', nargs='?', default='.', help='Path to SharpHound & AzureHound JSON files or zip archive.')
    parser.add_argument('--shortest-paths', action='store_true')
    parser.add_argument('--dangerous-permissions', action='store_true')
    parser.add_argument('--adcs', action='store_true')
    parser.add_argument('--gpo-abuse', action='store_true')
    parser.add_argument('--dcsync', action='store_true')
    parser.add_argument('--rbcd', action='store_true')
    parser.add_argument('--sessions', action='store_true')
    parser.add_argument('--kerberoastable', action='store_true')
    parser.add_argument('--as-rep-roastable', action='store_true')
    parser.add_argument('--sid-history', action='store_true')
    parser.add_argument('--unconstrained-delegation', action='store_true')
    parser.add_argument('--password-descriptions', action='store_true')
    parser.add_argument('--password-never-expires', action='store_true')
    parser.add_argument('--password-not-required', action='store_true')
    parser.add_argument('--shadow-credentials', action='store_true')
    parser.add_argument('--gpo-parsing', action='store_true')
    parser.add_argument("--gpo-content-dir", type=str, default=None, help="Directory containing GPO XML reports for full content analysis")
    parser.add_argument('--constrained-delegation', action='store_true')
    parser.add_argument('--laps', action='store_true')
    parser.add_argument('--azure-privileged-roles', action='store_true')
    parser.add_argument('--azure-app-secrets', action='store_true')
    parser.add_argument('--azure-mfa-bypass', action='store_true')
    parser.add_argument('--azure-guest-access', action='store_true')
    parser.add_argument('--azure-sp-abuse', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--all', action='store_true')
    parser.add_argument('--export', nargs='?', const='md', choices=['md', 'json', 'html', 'csv', 'yaml'], help='Export results')
    parser.add_argument('--export-bh', action='store_true', help='Export full graph in BloodHound-compatible JSON format')
    parser.add_argument('--dot', nargs='?', const='bloodbash.dot', help='Export key subgraphs to Graphviz DOT file')
    parser.add_argument('--fast', action='store_true', help='Fast mode (skip heavy pathfinding)')
    parser.add_argument('--domain', help='Filter by domain (AD) or tenantId (Azure)')
    parser.add_argument('--indirect', action='store_true', help='Include indirect paths/permissions')
    parser.add_argument('--db', help='SQLite DB path for persistence (save/load graph)')
    parser.add_argument('--owned', help='Comma-separated owned principals (find paths to them)')
    parser.add_argument('--path-from', help='Comma-separated source principals for arbitrary paths')
    parser.add_argument('--path-to', help='Comma-separated target principals for arbitrary paths')
    parser.add_argument('--inspect', help='Comma-separated nodes to inspect (full props + edges)')
    parser.add_argument('--deep-analysis', action='store_true', help='Enable full (slow) group cycle detection')
    parser.add_argument('--debug', action='store_true', help='Enable verbose debug output for troubleshooting')
    args = parser.parse_args()
    DEBUG = args.debug
    if DEBUG:
        console.print("[bold blue]=== DEBUG MODE ENABLED ===[/bold blue]")
    start_time = time.time()
    if args.db and os.path.exists(args.db):
        G, name_to_oid = load_graph_from_db(args.db)
    else:
        nodes = load_json_dir(args.directory, debug=DEBUG)
        if not nodes:
            console.print("[red]No objects loaded. Exiting.[/red]")
            sys.exit(1)
        G, name_to_oid = build_graph(nodes, args.db if args.db else None, debug=DEBUG)
    if args.all:
        mode_str = "Full analysis (AD + Azure) (--all)"
    elif any([args.shortest_paths, args.dangerous_permissions, args.adcs, args.gpo_abuse, args.dcsync, args.rbcd, args.sessions, args.kerberoastable, args.as_rep_roastable, args.sid_history, args.unconstrained_delegation, args.password_descriptions, args.password_never_expires, args.password_not_required, args.shadow_credentials, args.gpo_parsing, args.constrained_delegation, args.laps, args.azure_privileged_roles, args.azure_app_secrets, args.azure_mfa_bypass, args.azure_guest_access, args.azure_sp_abuse, args.owned, args.path_from, args.path_to, args.inspect, args.export_bh, args.dot]):
        mode_str = "Selected checks (including AD and Azure features)"
    else:
        mode_str = "Default (verbose summary + common checks)"
    if DEBUG:
        mode_str += " [DEBUG]"
    print_intro_banner(mode_str)
    run_all = args.all or not any([args.shortest_paths, args.dangerous_permissions, args.adcs, args.gpo_abuse, args.dcsync, args.rbcd, args.sessions, args.kerberoastable, args.as_rep_roastable, args.sid_history, args.unconstrained_delegation, args.password_descriptions, args.password_never_expires, args.password_not_required, args.shadow_credentials, args.gpo_parsing, args.constrained_delegation, args.laps, args.azure_privileged_roles, args.azure_app_secrets, args.azure_mfa_bypass, args.azure_guest_access, args.azure_sp_abuse, args.owned, args.path_from, args.path_to, args.inspect, args.export_bh, args.dot])
    if args.verbose or run_all:
        print_verbose_summary(G, args.domain)
    if args.shortest_paths or run_all:
        print_shortest_paths(G, fast=args.fast, domain_filter=args.domain, indirect=args.indirect)
    if args.dangerous_permissions or run_all:
        print_dangerous_permissions(G, args.domain, args.indirect)
    if args.adcs or run_all:
        print_adcs_vulnerabilities(G, args.domain)
    if args.gpo_abuse or run_all:
        print_gpo_abuse(G, args.domain)
    if args.dcsync or run_all:
        print_dcsync_rights(G, args.domain)
    if args.rbcd or run_all:
        print_rbcd(G, args.domain)
    if args.sessions or run_all:
        print_sessions_localadmin(G, args.domain)
    if args.kerberoastable or run_all:
        print_kerberoastable(G, args.domain)
    if args.as_rep_roastable or run_all:
        print_as_rep_roastable(G, args.domain)
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
    if args.azure_privileged_roles or run_all:
        print_azure_privileged_roles(G, args.domain)
    if args.azure_app_secrets or run_all:
        print_azure_app_secrets(G, args.domain)
    if args.azure_mfa_bypass or run_all:
        print_azure_mfa_bypass(G, args.domain)
    if args.azure_guest_access or run_all:
        print_azure_guest_access(G, args.domain)
    if args.azure_sp_abuse or run_all:
        print_azure_service_principal_abuse(G, args.domain)
    if args.owned or run_all:
        print_paths_to_owned(G, args.owned, args.domain)
    if (args.path_from or args.path_to) or run_all:
        print_arbitrary_paths(G, args.path_from, args.path_to, args.domain)
    if args.inspect:
        for ident in [x.strip() for x in args.inspect.split(',') if x.strip()]:
            inspect_node(G, ident, args.domain)
    if args.gpo_content_dir or run_all:
        print_gpo_content_analysis(G, args.gpo_content_dir, args.domain)
    print_trust_abuse(G, args.domain)
    print_group_analysis(G, args.domain, deep_analysis=args.deep_analysis)
    print_stats_dashboard(G, args.domain)
    if args.export:
        export_results(G, format_type=args.export, domain_filter=args.domain)
    if args.export_bh:
        export_bloodhound_compatible(G)
    if args.dot:
        export_to_dot(G, args.dot, args.domain)
    print_prioritized_findings()
    elapsed = time.time() - start_time
    console.print(f"\n[italic green]Completed in {elapsed:.2f} seconds[/italic green]")
    if DEBUG:
        console.print(f"[bold blue]DEBUG: Total findings: {len(global_findings)}[/bold blue]")

if __name__ == '__main__':
    main()