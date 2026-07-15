#!/usr/bin/env python3
"""Generate a SharpHound CE-style AD corpus with known ground-truth findings.

Public real SharpHound dumps are scarce and often OPSEC-sensitive. This tool
builds a deterministic multi-scenario lab (CORPLAB.LOCAL) that exercises the
high-entropy paths BloodBash must handle: unexpected DCSync, broad ACLs,
RBCD configure noise, GPO links, LAPS mix, ADCS, sessions, roast, etc.

Usage:
  python3 tools/generate_synthetic_sharphound.py
  python3 tools/generate_synthetic_sharphound.py --out testData/synthetic-corp-lab

Outputs SharpHound CE JSON files + ground_truth.json for assertion tests.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DOMAIN = "CORPLAB.LOCAL"
DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"
DOMAIN_DN = "DC=corplab,DC=local"
TS = 1700000000  # fixed for determinism


def sid(rid: int) -> str:
    return f"{DOMAIN_SID}-{rid}"


def wk(suffix: str) -> str:
    """Domain-prefixed well-known SID (SharpHound CE style)."""
    return f"{DOMAIN}-{suffix}"


def ace(principal: str, ptype: str, right: str, inherited: bool = False) -> dict:
    return {
        "PrincipalSID": principal,
        "PrincipalType": ptype,
        "RightName": right,
        "IsInherited": inherited,
    }


def member(oid: str, otype: str = "User") -> dict:
    return {"ObjectIdentifier": oid, "ObjectType": otype}


def meta(kind: str, count: int) -> dict:
    return {"methods": 0, "type": kind, "count": count, "version": 6}


def user(
    rid: int,
    sam: str,
    *,
    enabled: bool = True,
    highvalue: bool = False,
    hasspn: bool = False,
    spns: Optional[List[str]] = None,
    dontreqpreauth: bool = False,
    pwdneverexpires: bool = False,
    passwordnotreqd: bool = False,
    description: str = "",
    display: str = "",
    primary: int = 513,
    aces: Optional[List[dict]] = None,
    contained_by: Optional[dict] = None,
) -> dict:
    name = f"{sam.upper()}@{DOMAIN}"
    props = {
        "domain": DOMAIN,
        "name": name,
        "distinguishedname": f"CN={sam},{DOMAIN_DN}",
        "domainsid": DOMAIN_SID,
        "samaccountname": sam,
        "displayname": display or sam,
        "description": description,
        "enabled": enabled,
        "highvalue": highvalue,
        "hasspn": hasspn,
        "serviceprincipalnames": spns or ([] if not hasspn else [f"HTTP/{sam.lower()}.corplab.local"]),
        "dontreqpreauth": dontreqpreauth,
        "pwdneverexpires": pwdneverexpires,
        "passwordnotreqd": passwordnotreqd,
        "sensitive": False,
        "unconstraineddelegation": False,
        "trustedtoauth": False,
        "admincount": highvalue,
        "lastlogon": TS,
        "lastlogontimestamp": TS,
        "pwdlastset": TS - 86400 * 100,
        "whencreated": TS - 86400 * 400,
        "sidhistory": [],
        "email": f"{sam.lower()}@corplab.local",
        "isaclprotected": False,
    }
    obj = {
        "ObjectIdentifier": sid(rid),
        "ObjectType": "User",
        "Properties": props,
        "PrimaryGroupSID": sid(primary),
        "Aces": aces or default_user_aces(rid),
        "AllowedToDelegate": [],
        "HasSIDHistory": [],
        "SPNTargets": [],
        "IsDeleted": False,
        "IsACLProtected": False,
    }
    if contained_by:
        obj["ContainedBy"] = contained_by
    return obj


def computer(
    rid: int,
    sam: str,
    *,
    is_dc: bool = False,
    haslaps: bool = False,
    unconstrained: bool = False,
    trusted_to_auth: bool = False,
    allowed_to_act: Optional[List[dict]] = None,
    allowed_to_delegate: Optional[List[str]] = None,
    sessions: Optional[List[dict]] = None,
    local_groups: Optional[List[dict]] = None,
    aces: Optional[List[dict]] = None,
    primary: int = 515,
) -> dict:
    name = f"{sam.upper()}.{DOMAIN}"
    props = {
        "domain": DOMAIN,
        "name": name,
        "distinguishedname": f"CN={sam},{DOMAIN_DN}",
        "domainsid": DOMAIN_SID,
        "samaccountname": f"{sam}$",
        "enabled": True,
        "haslaps": haslaps,
        "unconstraineddelegation": unconstrained,
        "trustedtoauth": trusted_to_auth,
        "isdc": is_dc,
        "operatingsystem": "Windows Server 2019" if is_dc else "Windows 10",
        "lastlogon": TS,
        "lastlogontimestamp": TS,
        "pwdlastset": TS,
        "whencreated": TS - 86400 * 200,
        "serviceprincipalnames": [f"HOST/{sam.upper()}.{DOMAIN}"],
        "isaclprotected": False,
    }
    return {
        "ObjectIdentifier": sid(rid),
        "ObjectType": "Computer",
        "Properties": props,
        "PrimaryGroupSID": sid(primary if not is_dc else 516),
        "AllowedToAct": allowed_to_act or [],
        "AllowedToDelegate": allowed_to_delegate or [],
        "HasSIDHistory": [],
        "Sessions": {
            "Results": sessions or [],
            "Collected": True,
            "FailureReason": None,
        },
        "PrivilegedSessions": {"Results": [], "Collected": True, "FailureReason": None},
        "RegistrySessions": {"Results": [], "Collected": True, "FailureReason": None},
        "LocalGroups": local_groups or [],
        "IsDC": is_dc,
        "DomainSID": DOMAIN_SID,
        "Aces": aces or default_computer_aces(rid),
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def group(
    rid: int,
    sam: str,
    members: Optional[List[dict]] = None,
    *,
    highvalue: bool = False,
    aces: Optional[List[dict]] = None,
) -> dict:
    name = f"{sam.upper()}@{DOMAIN}"
    return {
        "ObjectIdentifier": sid(rid) if rid < 100000 else sid(rid),
        "ObjectType": "Group",
        "Properties": {
            "domain": DOMAIN,
            "name": name,
            "distinguishedname": f"CN={sam},{DOMAIN_DN}",
            "domainsid": DOMAIN_SID,
            "samaccountname": sam,
            "highvalue": highvalue,
            "admincount": highvalue,
            "description": "",
            "whencreated": TS,
            "isaclprotected": False,
        },
        "Members": members or [],
        "Aces": aces or [
            ace(sid(512), "Group", "Owns"),
            ace(sid(512), "Group", "GenericAll"),
        ],
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def well_known_group(oid: str, name: str) -> dict:
    return {
        "ObjectIdentifier": oid,
        "ObjectType": "Group",
        "Properties": {
            "domain": DOMAIN,
            "name": f"{name}@{DOMAIN}",
            "distinguishedname": f"CN={name},{DOMAIN_DN}",
            "domainsid": DOMAIN_SID,
            "samaccountname": name,
            "highvalue": False,
            "whencreated": TS,
            "isaclprotected": False,
        },
        "Members": [],
        "Aces": [],
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def default_user_aces(rid: int) -> List[dict]:
    return [
        ace(sid(512), "Group", "GenericAll"),
        ace(sid(519), "Group", "GenericAll"),
        ace(wk("S-1-5-32-544"), "Group", "GenericAll"),
    ]


def default_computer_aces(rid: int) -> List[dict]:
    return [
        ace(sid(512), "Group", "Owns"),
        ace(sid(512), "Group", "GenericAll"),
        ace(sid(519), "Group", "GenericAll"),
        ace(wk("S-1-5-32-544"), "Group", "GenericAll"),
    ]


def gpo(guid: str, name: str, aces: List[dict]) -> dict:
    return {
        "ObjectIdentifier": guid,
        "ObjectType": "GPO",
        "Properties": {
            "domain": DOMAIN,
            "name": f"{name}@{DOMAIN}",
            "distinguishedname": f"CN={{{guid}}},CN=Policies,CN=System,{DOMAIN_DN}",
            "gpcpath": f"\\\\{DOMAIN}\\SysVol\\{DOMAIN}\\Policies\\{{{guid}}}",
            "highvalue": False,
            "whencreated": TS,
            "isaclprotected": False,
        },
        "Aces": aces,
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def ou(oid: str, name: str, links: Optional[List[dict]] = None) -> dict:
    return {
        "ObjectIdentifier": oid,
        "ObjectType": "OU",
        "Properties": {
            "domain": DOMAIN,
            "name": f"{name}@{DOMAIN}",
            "distinguishedname": f"OU={name},{DOMAIN_DN}",
            "domainsid": DOMAIN_SID,
            "highvalue": "DOMAIN CONTROLLERS" in name.upper(),
            "whencreated": TS,
            "isaclprotected": False,
        },
        "Links": links or [],
        "Aces": [ace(sid(512), "Group", "GenericAll")],
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def domain_obj(links: List[dict], aces: List[dict]) -> dict:
    return {
        "ObjectIdentifier": DOMAIN_SID,
        "ObjectType": "Domain",
        "Properties": {
            "domain": DOMAIN,
            "name": DOMAIN,
            "distinguishedname": DOMAIN_DN,
            "domainsid": DOMAIN_SID,
            "highvalue": True,
            "functionallevel": "2016",
            "whencreated": TS,
            "isaclprotected": False,
        },
        "Links": links,
        "Trusts": [],
        "ChildObjects": [],
        "Aces": aces,
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def cert_template(oid: str, name: str, **flags) -> dict:
    props = {
        "domain": DOMAIN,
        "name": f"{name}@{DOMAIN}",
        "distinguishedname": f"CN={name},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{DOMAIN_DN}",
        "enrolleesuppliessubject": flags.get("enrollee_supplies", False),
        "requiresmanagerapproval": flags.get("manager_approval", False),
        "authenticationenabled": True,
        "schannelauthenticationenabled": True,
        "enrollee_supplies_subject": flags.get("enrollee_supplies", False),
        "pkienrollmentflag": flags.get("enrollment_flag", 0),
        "nopkienrollmentflag": False,
        "effectiveekus": flags.get(
            "ekus",
            ["1.3.6.1.5.5.7.3.2"],  # Client Auth
        ),
        "whencreated": TS,
    }
    aces = flags.get("aces") or [
        ace(sid(513), "Group", "Enroll"),
        ace(sid(512), "Group", "GenericAll"),
    ]
    return {
        "ObjectIdentifier": oid,
        "ObjectType": "Certificate Template",
        "Properties": props,
        "Aces": aces,
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def enterprise_ca(oid: str, name: str) -> dict:
    return {
        "ObjectIdentifier": oid,
        "ObjectType": "Enterprise CA",
        "Properties": {
            "domain": DOMAIN,
            "name": f"{name}@{DOMAIN}",
            "distinguishedname": f"CN={name},CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{DOMAIN_DN}",
            "flags": "SUPPORTS_USER_KEY_ENROLLMENT",
            "caname": name,
            "dnshostname": f"CA01.{DOMAIN}",
            "whencreated": TS,
        },
        "Aces": [
            ace(sid(512), "Group", "ManageCA"),
            ace(sid(512), "Group", "ManageCertificates"),
            ace(sid(513), "Group", "Enroll"),
        ],
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def build_corpus() -> Dict[str, Any]:
    """Build full corpus + ground truth expectations."""
    # --- RID map (stable) ---
    # 512 DA, 513 DU, 514 Guests, 515 Domain Computers, 516 Domain Controllers, 519 EA
    # 544 Builtin Admins well-known domain-prefixed
    # Custom: 1000+ users/computers/groups

    RID = {
        "da": 512,
        "du": 513,
        "dc_group": 516,
        "ea": 519,
        "helpdesk": 2001,
        "sysadmins": 2002,  # SYSTEM ADMINISTRATORS — must NOT match Builtin Admins
        "vpn": 2003,
        "ssrs": 2004,
        "lowpriv": 1100,
        "msol": 1101,  # unexpected DCSync
        "svc_sql": 1102,  # kerberoastable + priv nested
        "asrep": 1103,
        "mrios": 1104,  # Everyone GenericWrite target
        "nested_da": 1105,  # nested into DA — expected DCSync
        "helpdesk_user": 1106,
        "dc01": 1001,
        "ws01": 1002,
        "ws02": 1003,
        "pentestpc": 1004,
        "srv_app": 1005,
        "aws_connector": 2100,  # bulk can-configure RBCD
        "pam_gpo": "A1111111-1111-1111-1111-111111111111",
        "default_gpo": "B2222222-2222-2222-2222-222222222222",
        "ou_workstations": f"OU=Workstations,{DOMAIN_DN}",
        "ou_dc": f"OU=Domain Controllers,{DOMAIN_DN}",
        "ou_pam": f"OU=PAM,{DOMAIN_DN}",
        "esc1_tpl": "C3333333-3333-3333-3333-333333333333",
        "safe_tpl": "D4444444-4444-4444-4444-444444444444",
        "ca": "E5555555-5555-5555-5555-555555555555",
    }

    # Groups
    groups = [
        group(RID["da"], "Domain Admins", [member(sid(RID["nested_da"]))], highvalue=True),
        group(RID["ea"], "Enterprise Admins", [], highvalue=True),
        group(RID["du"], "Domain Users", [member(sid(RID["lowpriv"])), member(sid(RID["helpdesk_user"]))]),
        group(RID["dc_group"], "Domain Controllers", [member(sid(RID["dc01"]), "Computer")], highvalue=True),
        group(
            RID["helpdesk"],
            "CORP Helpdesk",
            [member(sid(RID["helpdesk_user"]))],
        ),
        group(
            RID["sysadmins"],
            "System Administrators",  # false-positive trap for administrators@ needle
            [member(sid(RID["helpdesk"]), "Group")],
        ),
        group(RID["vpn"], "Corp VPN", [member(sid(RID["lowpriv"]))]),
        group(RID["ssrs"], "SSRS-Users", [member(sid(RID["vpn"]), "Group")]),
        group(RID["aws_connector"], "AWS AD Connectors", []),
        well_known_group(wk("S-1-5-32-544"), "Administrators"),
        well_known_group(wk("S-1-5-11"), "Authenticated Users"),
        well_known_group(wk("S-1-1-0"), "Everyone"),
        well_known_group(wk("S-1-5-32-545"), "Users"),
        group(515, "Domain Computers", []),
    ]

    # Users
    users = [
        user(RID["lowpriv"], "alice.low", description="standard user"),
        user(RID["msol"], "MSOL_SYNC", description="Azure AD Connect"),
        user(
            RID["svc_sql"],
            "svc_sql",
            hasspn=True,
            spns=["MSSQLSvc/sql.corplab.local:1433"],
            description="SQL service",
        ),
        user(RID["asrep"], "bob.asrep", dontreqpreauth=True),
        user(
            RID["mrios"],
            "mrios",
            aces=default_user_aces(RID["mrios"])
            + [ace(wk("S-1-1-0"), "Group", "GenericWrite")],
        ),
        user(RID["nested_da"], "carol.admin", highvalue=True),
        user(RID["helpdesk_user"], "dave.help"),
        user(
            1107,
            "eve.pne",
            pwdneverexpires=True,
        ),
        user(
            1108,
            "frank.pnr",
            passwordnotreqd=True,
        ),
        user(
            1109,
            "grace.shadow",
            aces=default_user_aces(1109)
            + [ace(sid(RID["helpdesk_user"]), "User", "AddKeyCredentialLink")],
        ),
    ]
    # Nest svc_sql into Domain Admins for privileged roast
    for g in groups:
        if g["ObjectIdentifier"] == sid(RID["da"]):
            g["Members"].append(member(sid(RID["svc_sql"])))

    # Computers — bulk AWS connector rights + helpdesk + pentest
    computers = []
    computers.append(
        computer(
            RID["dc01"],
            "DC01",
            is_dc=True,
            haslaps=True,
            unconstrained=True,
            primary=516,
            sessions=[{"UserSID": sid(RID["nested_da"])}],
            local_groups=[
                {
                    "ObjectIdentifier": f"{sid(RID['dc01'])}-544",
                    "Name": "ADMINISTRATORS@DC01",
                    "Results": [
                        {"ObjectIdentifier": sid(RID["da"]), "ObjectType": "Group"},
                    ],
                }
            ],
        )
    )
    computers.append(
        computer(
            RID["ws01"],
            "WS01",
            haslaps=True,
            sessions=[{"UserSID": sid(RID["lowpriv"])}],
            local_groups=[
                {
                    "ObjectIdentifier": f"{sid(RID['ws01'])}-544",
                    "Name": "ADMINISTRATORS@WS01",
                    "Results": [
                        {"ObjectIdentifier": sid(RID["helpdesk_user"]), "ObjectType": "User"},
                    ],
                },
                {
                    "ObjectIdentifier": f"{sid(RID['ws01'])}-555",
                    "Name": "REMOTE DESKTOP USERS@WS01",
                    "Results": [
                        {"ObjectIdentifier": sid(RID["lowpriv"]), "ObjectType": "User"},
                    ],
                },
            ],
        )
    )
    computers.append(computer(RID["ws02"], "WS02", haslaps=False))
    computers.append(
        computer(
            RID["pentestpc"],
            "PENTESTPC",
            haslaps=False,
            aces=default_computer_aces(RID["pentestpc"])
            + [
                ace(sid(RID["lowpriv"]), "User", "AllExtendedRights"),
                ace(sid(RID["lowpriv"]), "User", "WriteAccountRestrictions"),
            ],
            allowed_to_act=[member(sid(RID["ws01"]), "Computer")],
        )
    )
    computers.append(
        computer(
            RID["srv_app"],
            "SRVAPP",
            haslaps=True,
            trusted_to_auth=True,
            allowed_to_delegate=["cifs/DC01.CORPLAB.LOCAL"],
        )
    )

    # 40 extra hosts for bulk can-configure RBCD (AWS connector + helpdesk WAR)
    bulk_hosts = []
    for i in range(40):
        rid = 3000 + i
        bulk_hosts.append(rid)
        computers.append(
            computer(
                rid,
                f"HOST{i:02d}",
                haslaps=(i % 3 == 0),
                aces=default_computer_aces(rid)
                + [
                    ace(sid(RID["aws_connector"]), "Group", "WriteAccountRestrictions"),
                    ace(sid(RID["aws_connector"]), "Group", "AddAllowedToAct"),
                    ace(sid(RID["aws_connector"]), "Group", "GenericWrite"),
                    ace(sid(RID["helpdesk"]), "Group", "WriteAccountRestrictions"),
                    ace(sid(RID["helpdesk"]), "Group", "AllExtendedRights"),
                    ace(sid(RID["helpdesk"]), "Group", "Owns"),
                ],
            )
        )

    # GPOs
    gpos = [
        gpo(
            RID["pam_gpo"],
            "PAMAGENTINSTALL",
            [
                ace(sid(RID["da"]), "Group", "Owns"),
                ace(sid(RID["da"]), "Group", "GenericWrite"),
                ace(sid(RID["ea"]), "Group", "GenericWrite"),
                ace(wk("S-1-5-11"), "Group", "GenericWrite"),
                ace(wk("S-1-5-11"), "Group", "WriteDacl"),
                ace(wk("S-1-5-11"), "Group", "WriteOwner"),
            ],
        ),
        gpo(
            RID["default_gpo"],
            "Default Domain Policy",
            [
                ace(sid(RID["da"]), "Group", "GenericAll"),
                ace(sid(RID["ea"]), "Group", "GenericWrite"),
            ],
        ),
    ]

    # OUs with correct GPLink direction (container → GPO)
    ous = [
        ou(
            RID["ou_pam"],
            "PAM",
            links=[{"GUID": RID["pam_gpo"], "IsEnforced": True}],
        ),
        ou(
            RID["ou_workstations"],
            "Workstations",
            links=[{"GUID": RID["default_gpo"], "IsEnforced": False}],
        ),
        ou(
            RID["ou_dc"],
            "Domain Controllers",
            links=[{"GUID": RID["default_gpo"], "IsEnforced": True}],
        ),
    ]

    # Domain ACEs — unexpected MSOL DCSync + expected DA/EA/Admins
    domain_aces = [
        ace(wk("S-1-5-32-544"), "Group", "Owns"),
        ace(wk("S-1-5-32-544"), "Group", "GetChanges"),
        ace(wk("S-1-5-32-544"), "Group", "GetChangesAll"),
        ace(sid(RID["da"]), "Group", "GenericAll"),
        ace(sid(RID["ea"]), "Group", "GenericAll"),
        ace(sid(RID["dc_group"]), "Group", "GetChangesAll"),
        ace(sid(RID["msol"]), "User", "GetChanges"),
        ace(sid(RID["msol"]), "User", "GetChangesAll"),
        ace(sid(RID["nested_da"]), "User", "GetChanges"),
        ace(sid(RID["nested_da"]), "User", "GetChangesAll"),
    ]
    domains = [
        domain_obj(
            links=[
                {"GUID": RID["default_gpo"], "IsEnforced": False},
            ],
            aces=domain_aces,
        )
    ]

    # ADCS
    templates = [
        cert_template(
            RID["esc1_tpl"],
            "ESC1-UserAuth",
            enrollee_supplies=True,
            manager_approval=False,
            aces=[
                ace(sid(RID["lowpriv"]), "User", "Enroll"),
                ace(sid(513), "Group", "Enroll"),
                ace(sid(RID["da"]), "Group", "GenericAll"),
            ],
        ),
        cert_template(
            RID["safe_tpl"],
            "User",
            enrollee_supplies=False,
            manager_approval=True,
        ),
    ]
    cas = [enterprise_ca(RID["ca"], "CORPLAB-CA")]

    files = {
        "users.json": {"meta": meta("users", len(users)), "data": users},
        "computers.json": {"meta": meta("computers", len(computers)), "data": computers},
        "groups.json": {"meta": meta("groups", len(groups)), "data": groups},
        "gpos.json": {"meta": meta("gpos", len(gpos)), "data": gpos},
        "ous.json": {"meta": meta("ous", len(ous)), "data": ous},
        "domains.json": {"meta": meta("domains", len(domains)), "data": domains},
        "certtemplates.json": {
            "meta": meta("certtemplates", len(templates)),
            "data": templates,
        },
        "enterprisecas.json": {
            "meta": meta("enterprisecas", len(cas)),
            "data": cas,
        },
    }

    ground_truth = {
        "domain": DOMAIN,
        "domain_sid": DOMAIN_SID,
        "description": (
            "Synthetic SharpHound CE corpus for BloodBash regression. "
            "Not real engagement data."
        ),
        "generated_by": "tools/generate_synthetic_sharphound.py",
        "scenarios": {
            "unexpected_dcsync": {
                "principal": f"MSOL_SYNC@{DOMAIN}",
                "expect_finding_category": "DCSync",
                "expect_substring": "MSOL_SYNC",
                "expect_unexpected": True,
            },
            "expected_dcsync_nested_da": {
                "principal": f"CAROL.ADMIN@{DOMAIN}",
                "expect_finding_category": "DCSync",
                "must_not_be_critical_only": True,
            },
            "system_administrators_not_default_priv": {
                "principal": f"SYSTEM ADMINISTRATORS@{DOMAIN}",
                "must_not_match_default_high_priv": True,
            },
            "helpdesk_can_configure_rbcd_bulk": {
                "principal": f"CORP HELPDESK@{DOMAIN}",
                "min_computers": 40,
            },
            "aws_connector_can_configure_rbcd_bulk": {
                "principal": f"AWS AD CONNECTORS@{DOMAIN}",
                "min_computers": 40,
            },
            "lowpriv_pentestpc_rbcd_configure": {
                "principal": f"ALICE.LOW@{DOMAIN}",
                "target_contains": "PENTESTPC",
            },
            "rbcd_configured_on_pentestpc": {
                "resource_contains": "PENTESTPC",
            },
            "auth_users_gpo_write": {
                "principal_contains": "AUTHENTICATED USERS",
                "target_contains": "PAMAGENTINSTALL",
            },
            "everyone_user_genericwrite": {
                "principal_contains": "EVERYONE",
                "target_contains": "MRIOS",
            },
            "gpo_linked_not_no_links": {
                "gpo_contains": "PAMAGENTINSTALL",
                "must_not_contain": "No links detected",
            },
            "privileged_kerberoast": {
                "principal_contains": "SVC_SQL",
            },
            "asrep": {
                "principal_contains": "BOB.ASREP",
            },
            "laps_mixed": {
                "expect_enabled_gt": 0,
                "expect_disabled_gt": 0,
            },
            "localadmin_not_genericall": {
                "must_list_principal_contains": "DAVE.HELP",
                "must_not_treat_da_genericall_as_localadmin": True,
            },
            "esc1": {
                "template_contains": "ESC1-UserAuth",
            },
            "password_never_expires": {
                "principal_contains": "EVE.PNE",
            },
            "password_not_required": {
                "principal_contains": "FRANK.PNR",
            },
            "shadow_creds": {
                "principal_contains": "DAVE.HELP",
                "or_target_contains": "GRACE.SHADOW",
            },
            "dossier_alice_impact": {
                "principal": f"ALICE.LOW@{DOMAIN}",
                "min_impact_edges": 1,
            },
        },
        "stats": {
            "users": len(users),
            "computers": len(computers),
            "groups": len(groups),
            "gpos": len(gpos),
            "ous": len(ous),
            "bulk_hosts": len(bulk_hosts),
        },
    }
    return files, ground_truth


def write_corpus(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    files, ground_truth = build_corpus()
    for name, payload in files.items():
        path = out_dir / name
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    gt_path = out_dir / "ground_truth.json"
    gt_path.write_text(json.dumps(ground_truth, indent=2) + "\n", encoding="utf-8")
    readme = out_dir / "README.md"
    readme.write_text(
        "# Synthetic CORPLAB.LOCAL SharpHound CE corpus\n\n"
        "Generated by `tools/generate_synthetic_sharphound.py`.\n"
        "Contains **no real engagement data** — synthetic SIDs and names only.\n\n"
        "See `ground_truth.json` for expected BloodBash findings.\n"
        "Regenerate with:\n\n"
        "```bash\n"
        "python3 tools/generate_synthetic_sharphound.py --out testData/synthetic-corp-lab\n"
        "```\n",
        encoding="utf-8",
    )
    return out_dir


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("testData/synthetic-corp-lab"),
        help="Output directory for SharpHound JSON + ground_truth.json",
    )
    args = ap.parse_args()
    out = write_corpus(args.out.resolve())
    print(f"Wrote synthetic corpus to {out}")
    gt = json.loads((out / "ground_truth.json").read_text(encoding="utf-8"))
    print(f"  users={gt['stats']['users']} computers={gt['stats']['computers']} "
          f"groups={gt['stats']['groups']} bulk_hosts={gt['stats']['bulk_hosts']}")
    print(f"  scenarios={len(gt['scenarios'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
