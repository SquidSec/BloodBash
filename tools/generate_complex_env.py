#!/usr/bin/env python3
"""Build complex, multi-issue SharpHound CE environments (realistic scale + entropy).

Unlike the focused archetype toggles, each profile plants *many concurrent*
misconfigurations the way real domains look: nested groups, bulk computer ACLs,
hybrid sync accounts, weak GPOs, roastables, LAPS gaps, ADCS, sessions, etc.

Used by tools/run_scenario_battery.py.
"""
from __future__ import annotations

import hashlib
import random
from typing import Any, Dict, List, Optional, Tuple

TS = 1_700_000_000

# 10 complex environment profiles (realistic org shapes)
ENV_PROFILES = [
    {
        "id": "healthcare_clinic",
        "domain": "CLINICLAB.LOCAL",
        "description": "Healthcare-like: VPN/WiFi groups, helpdesk bulk WAR, Auth Users GPO, AAD Connect DCSync",
        "users": 80,
        "computers": 120,
        "traits": {
            "msol_dcsync": True,
            "auth_users_gpo": True,
            "everyone_user_gw": True,
            "helpdesk_bulk_rbcd": True,
            "aws_connector_bulk": True,
            "vpn_nesting": True,
            "system_admins_trap": True,
            "esc1": True,
            "privileged_kerb": True,
            "asrep": True,
            "shadow": True,
            "pne_pnr": True,
            "laps_ratio": 0.35,
            "localadmin_helpdesk": True,
            "rbcd_configured": True,
            "sessions": True,
        },
    },
    {
        "id": "financial_services",
        "domain": "FINCORP.LOCAL",
        "description": "Finance: privileged service accounts, shadow creds, constrained del, tight HV paths",
        "users": 100,
        "computers": 90,
        "traits": {
            "msol_dcsync": True,
            "auth_users_gpo": False,
            "everyone_user_gw": False,
            "helpdesk_bulk_rbcd": True,
            "aws_connector_bulk": False,
            "vpn_nesting": True,
            "system_admins_trap": True,
            "esc1": True,
            "privileged_kerb": True,
            "asrep": False,
            "shadow": True,
            "pne_pnr": True,
            "laps_ratio": 0.7,
            "localadmin_helpdesk": True,
            "rbcd_configured": True,
            "sessions": True,
            "constrained_del": True,
        },
    },
    {
        "id": "msp_connector_noise",
        "domain": "MSPCLIENT.LOCAL",
        "description": "MSP-managed: many connector principals with AddAllowedToAct on almost all hosts",
        "users": 60,
        "computers": 150,
        "traits": {
            "msol_dcsync": True,
            "auth_users_gpo": True,
            "everyone_user_gw": False,
            "helpdesk_bulk_rbcd": True,
            "aws_connector_bulk": True,
            "vpn_nesting": False,
            "system_admins_trap": True,
            "esc1": False,
            "privileged_kerb": False,
            "asrep": True,
            "shadow": True,
            "pne_pnr": True,
            "laps_ratio": 0.2,
            "localadmin_helpdesk": True,
            "rbcd_configured": False,
            "sessions": True,
        },
    },
    {
        "id": "manufacturing_legacy",
        "domain": "PLANT.LOCAL",
        "description": "Legacy plant: unconstrained non-DC, AS-REP, PNE, poor LAPS, no ADCS collect",
        "users": 70,
        "computers": 100,
        "traits": {
            "msol_dcsync": False,
            "auth_users_gpo": True,
            "everyone_user_gw": True,
            "helpdesk_bulk_rbcd": True,
            "aws_connector_bulk": False,
            "vpn_nesting": True,
            "system_admins_trap": True,
            "esc1": False,
            "no_adcs": True,
            "privileged_kerb": True,
            "asrep": True,
            "shadow": False,
            "pne_pnr": True,
            "laps_ratio": 0.1,
            "localadmin_helpdesk": True,
            "rbcd_configured": True,
            "sessions": True,
            "unconstrained_workstation": True,
        },
    },
    {
        "id": "edu_campus",
        "domain": "CAMPUS.EDU",
        "description": "Campus: Everyone ACLs, many AS-REP students, weak GPO, light priv roast",
        "users": 150,
        "computers": 80,
        "traits": {
            "msol_dcsync": True,
            "auth_users_gpo": True,
            "everyone_user_gw": True,
            "helpdesk_bulk_rbcd": False,
            "aws_connector_bulk": False,
            "vpn_nesting": True,
            "system_admins_trap": True,
            "esc1": True,
            "privileged_kerb": False,
            "asrep": True,
            "asrep_many": True,
            "shadow": False,
            "pne_pnr": True,
            "laps_ratio": 0.25,
            "localadmin_helpdesk": True,
            "rbcd_configured": False,
            "sessions": True,
        },
    },
    {
        "id": "tech_startup",
        "domain": "STARTUP.LOCAL",
        "description": "Startup: ESC1, shadow creds, configured RBCD, few DAs, lean groups",
        "users": 40,
        "computers": 50,
        "traits": {
            "msol_dcsync": False,
            "auth_users_gpo": True,
            "everyone_user_gw": False,
            "helpdesk_bulk_rbcd": False,
            "aws_connector_bulk": True,
            "vpn_nesting": False,
            "system_admins_trap": False,
            "esc1": True,
            "privileged_kerb": True,
            "asrep": False,
            "shadow": True,
            "pne_pnr": False,
            "laps_ratio": 0.5,
            "localadmin_helpdesk": True,
            "rbcd_configured": True,
            "sessions": True,
        },
    },
    {
        "id": "gov_tiered",
        "domain": "GOVLAB.LOCAL",
        "description": "Tiered admin: nested DA expected DCSync, System Admins trap, limited unexpected",
        "users": 90,
        "computers": 70,
        "traits": {
            "msol_dcsync": False,
            "auth_users_gpo": False,
            "everyone_user_gw": False,
            "helpdesk_bulk_rbcd": True,
            "aws_connector_bulk": False,
            "vpn_nesting": True,
            "system_admins_trap": True,
            "esc1": False,
            "privileged_kerb": True,
            "asrep": False,
            "shadow": True,
            "pne_pnr": True,
            "laps_ratio": 0.85,
            "localadmin_helpdesk": False,
            "rbcd_configured": False,
            "sessions": True,
            "nested_da_dcsync": True,
        },
    },
    {
        "id": "retail_fleet",
        "domain": "RETAIL.LOCAL",
        "description": "Retail fleet: many POS/workstations, sessions, localadmin, bulk helpdesk RBCD",
        "users": 50,
        "computers": 180,
        "traits": {
            "msol_dcsync": True,
            "auth_users_gpo": True,
            "everyone_user_gw": True,
            "helpdesk_bulk_rbcd": True,
            "aws_connector_bulk": True,
            "vpn_nesting": True,
            "system_admins_trap": True,
            "esc1": False,
            "privileged_kerb": False,
            "asrep": True,
            "shadow": False,
            "pne_pnr": True,
            "laps_ratio": 0.15,
            "localadmin_helpdesk": True,
            "rbcd_configured": True,
            "sessions": True,
        },
    },
    {
        "id": "hybrid_azure_connect",
        "domain": "HYBRID.LOCAL",
        "description": "Hybrid: MSOL DCSync + dual admin paths + ESC1 + shadow",
        "users": 110,
        "computers": 95,
        "traits": {
            "msol_dcsync": True,
            "auth_users_gpo": True,
            "everyone_user_gw": False,
            "helpdesk_bulk_rbcd": True,
            "aws_connector_bulk": True,
            "vpn_nesting": True,
            "system_admins_trap": True,
            "esc1": True,
            "privileged_kerb": True,
            "asrep": True,
            "shadow": True,
            "pne_pnr": True,
            "laps_ratio": 0.55,
            "localadmin_helpdesk": True,
            "rbcd_configured": True,
            "sessions": True,
            "nested_da_dcsync": True,
        },
    },
    {
        "id": "enterprise_kitchensink",
        "domain": "ENTCORP.LOCAL",
        "description": "Large enterprise: all high-signal issues concurrent at scale",
        "users": 200,
        "computers": 200,
        "traits": {
            "msol_dcsync": True,
            "auth_users_gpo": True,
            "everyone_user_gw": True,
            "helpdesk_bulk_rbcd": True,
            "aws_connector_bulk": True,
            "vpn_nesting": True,
            "system_admins_trap": True,
            "esc1": True,
            "privileged_kerb": True,
            "asrep": True,
            "asrep_many": True,
            "shadow": True,
            "pne_pnr": True,
            "laps_ratio": 0.4,
            "localadmin_helpdesk": True,
            "rbcd_configured": True,
            "sessions": True,
            "constrained_del": True,
            "nested_da_dcsync": True,
            "unconstrained_workstation": True,
        },
    },
]


def _sid(domain_sid: str, rid: int) -> str:
    return f"{domain_sid}-{rid}"


def _wk(domain: str, suffix: str) -> str:
    return f"{domain}-{suffix}"


def _ace(principal: str, ptype: str, right: str) -> dict:
    return {
        "PrincipalSID": principal,
        "PrincipalType": ptype,
        "RightName": right,
        "IsInherited": False,
    }


def _member(oid: str, otype: str = "User") -> dict:
    return {"ObjectIdentifier": oid, "ObjectType": otype}


def _meta(kind: str, n: int) -> dict:
    return {"methods": 0, "type": kind, "count": n, "version": 6}


def _domain_sid_from_name(domain: str, seed: int) -> str:
    h = hashlib.sha256(f"{domain}:{seed}".encode()).hexdigest()
    a = int(h[0:8], 16) % 2_000_000_000 + 1_000_000_000
    b = int(h[8:16], 16) % 2_000_000_000 + 1_000_000_000
    c = int(h[16:24], 16) % 2_000_000_000 + 1_000_000_000
    return f"S-1-5-21-{a}-{b}-{c}"


def build_environment(profile: dict, seed: int) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Return (files_dict, ground_truth) for a complex environment profile."""
    rng = random.Random(seed)
    domain = profile["domain"]
    domain_sid = _domain_sid_from_name(domain, seed)
    dn = "DC=" + ",DC=".join(domain.lower().replace(".local", "").replace(".edu", "").split("."))
    if domain.upper().endswith(".LOCAL"):
        base = domain[:-6]
        dn = f"DC={base.lower()},DC=local"
    elif domain.upper().endswith(".EDU"):
        base = domain[:-4]
        dn = f"DC={base.lower()},DC=edu"
    traits = dict(profile["traits"])
    n_users = profile["users"] + rng.randint(-5, 15)
    n_computers = profile["computers"] + rng.randint(-10, 20)
    n_users = max(25, n_users)
    n_computers = max(30, n_computers)

    # Fixed RIDs for special principals
    RID = {
        "da": 512,
        "du": 513,
        "dcg": 516,
        "ea": 519,
        "helpdesk": 2001,
        "sysadmins": 2002,
        "vpn": 2003,
        "ssrs": 2004,
        "wifi": 2005,
        "aws": 2100,
        "msol": 1101,
        "svc_sql": 1102,
        "asrep0": 1103,
        "target_user": 1104,
        "nested_da": 1105,
        "helpdesk_user": 1106,
        "alice": 1100,
        "dc01": 1001,
        "ws01": 1002,
        "pentest": 1004,
        "srvapp": 1005,
        "unc_ws": 1006,
    }

    def sid(rid: int) -> str:
        return _sid(domain_sid, rid)

    def wk(sfx: str) -> str:
        return _wk(domain, sfx)

    def uname(sam: str) -> str:
        return f"{sam.upper()}@{domain}"

    def cname(sam: str) -> str:
        return f"{sam.upper()}.{domain}"

    # --- Groups ---
    groups = []
    groups.append(
        {
            "ObjectIdentifier": sid(RID["da"]),
            "ObjectType": "Group",
            "Properties": {
                "domain": domain,
                "name": uname("Domain Admins"),
                "samaccountname": "Domain Admins",
                "highvalue": True,
                "domainsid": domain_sid,
            },
            "Members": [_member(sid(RID["nested_da"]))],
            "Aces": [_ace(sid(RID["da"]), "Group", "GenericAll")],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
    )
    groups.append(
        {
            "ObjectIdentifier": sid(RID["ea"]),
            "ObjectType": "Group",
            "Properties": {
                "domain": domain,
                "name": uname("Enterprise Admins"),
                "samaccountname": "Enterprise Admins",
                "highvalue": True,
                "domainsid": domain_sid,
            },
            "Members": [],
            "Aces": [_ace(sid(RID["da"]), "Group", "GenericAll")],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
    )
    groups.append(
        {
            "ObjectIdentifier": sid(RID["du"]),
            "ObjectType": "Group",
            "Properties": {
                "domain": domain,
                "name": uname("Domain Users"),
                "samaccountname": "Domain Users",
                "domainsid": domain_sid,
            },
            "Members": [],
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
    )
    groups.append(
        {
            "ObjectIdentifier": sid(RID["dcg"]),
            "ObjectType": "Group",
            "Properties": {
                "domain": domain,
                "name": uname("Domain Controllers"),
                "samaccountname": "Domain Controllers",
                "highvalue": True,
                "domainsid": domain_sid,
            },
            "Members": [_member(sid(RID["dc01"]), "Computer")],
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
    )
    groups.append(
        {
            "ObjectIdentifier": sid(RID["helpdesk"]),
            "ObjectType": "Group",
            "Properties": {
                "domain": domain,
                "name": uname("CORP Helpdesk"),
                "samaccountname": "CORP Helpdesk",
                "domainsid": domain_sid,
            },
            "Members": [_member(sid(RID["helpdesk_user"]))],
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
    )
    if traits.get("system_admins_trap"):
        groups.append(
            {
                "ObjectIdentifier": sid(RID["sysadmins"]),
                "ObjectType": "Group",
                "Properties": {
                    "domain": domain,
                    "name": uname("System Administrators"),
                    "samaccountname": "System Administrators",
                    "domainsid": domain_sid,
                },
                "Members": [_member(sid(RID["helpdesk"]), "Group")],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )
    if traits.get("vpn_nesting"):
        groups.append(
            {
                "ObjectIdentifier": sid(RID["vpn"]),
                "ObjectType": "Group",
                "Properties": {
                    "domain": domain,
                    "name": uname("Corp VPN"),
                    "samaccountname": "Corp VPN",
                    "domainsid": domain_sid,
                },
                "Members": [_member(sid(RID["alice"]))],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )
        groups.append(
            {
                "ObjectIdentifier": sid(RID["ssrs"]),
                "ObjectType": "Group",
                "Properties": {
                    "domain": domain,
                    "name": uname("SSRS-Users"),
                    "samaccountname": "SSRS-Users",
                    "domainsid": domain_sid,
                },
                "Members": [_member(sid(RID["vpn"]), "Group")],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )
        groups.append(
            {
                "ObjectIdentifier": sid(RID["wifi"]),
                "ObjectType": "Group",
                "Properties": {
                    "domain": domain,
                    "name": uname("WIFI-Users"),
                    "samaccountname": "WIFI-Users",
                    "domainsid": domain_sid,
                },
                "Members": [_member(sid(RID["alice"]))],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )
    if traits.get("aws_connector_bulk"):
        groups.append(
            {
                "ObjectIdentifier": sid(RID["aws"]),
                "ObjectType": "Group",
                "Properties": {
                    "domain": domain,
                    "name": uname("AWS AD Connectors"),
                    "samaccountname": "AWS AD Connectors",
                    "domainsid": domain_sid,
                },
                "Members": [],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )
    for oid, name in [
        (wk("S-1-5-32-544"), "Administrators"),
        (wk("S-1-5-11"), "Authenticated Users"),
        (wk("S-1-1-0"), "Everyone"),
        (wk("S-1-5-32-545"), "Users"),
    ]:
        groups.append(
            {
                "ObjectIdentifier": oid,
                "ObjectType": "Group",
                "Properties": {
                    "domain": domain,
                    "name": uname(name),
                    "samaccountname": name,
                    "domainsid": domain_sid,
                },
                "Members": [],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )

    # --- Users ---
    users = []

    def add_user(rid: int, sam: str, **props_extra):
        aces = props_extra.pop("aces", None) or [
            _ace(sid(RID["da"]), "Group", "GenericAll"),
            _ace(wk("S-1-5-32-544"), "Group", "GenericAll"),
        ]
        u = {
            "ObjectIdentifier": sid(rid),
            "ObjectType": "User",
            "Properties": {
                "domain": domain,
                "name": uname(sam),
                "samaccountname": sam,
                "domainsid": domain_sid,
                "enabled": True,
                "hasspn": False,
                "serviceprincipalnames": [],
                "dontreqpreauth": False,
                "pwdneverexpires": False,
                "passwordnotreqd": False,
                "sensitive": False,
                "highvalue": False,
                "lastlogon": TS - rng.randint(0, 86400 * 400),
                "lastlogontimestamp": TS - rng.randint(0, 86400 * 400),
                "pwdlastset": TS - rng.randint(86400 * 30, 86400 * 900),
                "whencreated": TS - 86400 * 500,
                "description": "",
                "displayname": sam,
            },
            "PrimaryGroupSID": sid(RID["du"]),
            "Aces": aces,
            "AllowedToDelegate": [],
            "HasSIDHistory": [],
            "SPNTargets": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
        u["Properties"].update(props_extra)
        users.append(u)
        # Domain Users membership
        for g in groups:
            if g["ObjectIdentifier"] == sid(RID["du"]):
                g["Members"].append(_member(sid(rid)))
        return u

    add_user(RID["alice"], "alice.low")
    add_user(RID["nested_da"], "carol.admin", highvalue=True)
    add_user(RID["helpdesk_user"], "dave.help")
    add_user(RID["msol"], "MSOL_SYNC", description="Azure AD Connect sync")
    add_user(
        RID["svc_sql"],
        "svc_sql",
        hasspn=bool(traits.get("privileged_kerb")),
        serviceprincipalnames=(
            [f"MSSQLSvc/sql.{domain.lower()}:1433"] if traits.get("privileged_kerb") else []
        ),
    )
    if traits.get("privileged_kerb"):
        for g in groups:
            if g["ObjectIdentifier"] == sid(RID["da"]):
                g["Members"].append(_member(sid(RID["svc_sql"])))

    asrep_count = 1
    if traits.get("asrep_many"):
        asrep_count = min(12, max(3, n_users // 20))
    if traits.get("asrep"):
        add_user(RID["asrep0"], "bob.asrep", dontreqpreauth=True)
        for i in range(1, asrep_count):
            add_user(1200 + i, f"student{i:02d}", dontreqpreauth=True)

    target_aces = [
        _ace(sid(RID["da"]), "Group", "GenericAll"),
        _ace(wk("S-1-5-32-544"), "Group", "GenericAll"),
    ]
    if traits.get("everyone_user_gw"):
        target_aces.append(_ace(wk("S-1-1-0"), "Group", "GenericWrite"))
    add_user(RID["target_user"], "mrios", aces=target_aces)

    if traits.get("pne_pnr"):
        add_user(1107, "eve.pne", pwdneverexpires=True)
        add_user(1108, "frank.pnr", passwordnotreqd=True)

    if traits.get("shadow"):
        add_user(
            1109,
            "grace.shadow",
            aces=[
                _ace(sid(RID["da"]), "Group", "GenericAll"),
                _ace(sid(RID["helpdesk_user"]), "User", "AddKeyCredentialLink"),
            ],
        )

    # filler users
    next_rid = 5000
    while len(users) < n_users:
        add_user(next_rid, f"user{next_rid}")
        next_rid += 1

    # --- Computers ---
    computers = []
    laps_ratio = float(traits.get("laps_ratio", 0.4))

    def add_computer(rid: int, sam: str, **kw):
        is_dc = kw.get("is_dc", False)
        haslaps = kw.get("haslaps", rng.random() < laps_ratio)
        aces = kw.get("aces") or [
            _ace(sid(RID["da"]), "Group", "Owns"),
            _ace(sid(RID["da"]), "Group", "GenericAll"),
            _ace(sid(RID["ea"]), "Group", "GenericAll"),
            _ace(wk("S-1-5-32-544"), "Group", "GenericAll"),
        ]
        sessions = kw.get("sessions") or []
        local_groups = kw.get("local_groups") or []
        c = {
            "ObjectIdentifier": sid(rid),
            "ObjectType": "Computer",
            "Properties": {
                "domain": domain,
                "name": cname(sam),
                "samaccountname": f"{sam}$",
                "domainsid": domain_sid,
                "enabled": True,
                "haslaps": haslaps,
                "isdc": is_dc,
                "unconstraineddelegation": kw.get("unconstrained", is_dc),
                "trustedtoauth": kw.get("trusted_to_auth", False),
                "operatingsystem": "Windows Server 2019" if is_dc else "Windows 10",
                "lastlogon": TS,
                "pwdlastset": TS,
                "whencreated": TS - 86400 * 200,
                "serviceprincipalnames": [f"HOST/{cname(sam)}"],
            },
            "PrimaryGroupSID": sid(RID["dcg"] if is_dc else 515),
            "AllowedToAct": kw.get("allowed_to_act") or [],
            "AllowedToDelegate": kw.get("allowed_to_delegate") or [],
            "HasSIDHistory": [],
            "Sessions": {"Results": sessions, "Collected": True, "FailureReason": None},
            "PrivilegedSessions": {"Results": [], "Collected": True, "FailureReason": None},
            "RegistrySessions": {"Results": [], "Collected": True, "FailureReason": None},
            "LocalGroups": local_groups,
            "IsDC": is_dc,
            "DomainSID": domain_sid,
            "Aces": aces,
            "IsDeleted": False,
            "IsACLProtected": False,
        }
        computers.append(c)
        return c

    add_computer(
        RID["dc01"],
        "DC01",
        is_dc=True,
        haslaps=True,
        unconstrained=True,
        sessions=[{"UserSID": sid(RID["nested_da"])}] if traits.get("sessions") else [],
        local_groups=[
            {
                "ObjectIdentifier": f"{sid(RID['dc01'])}-544",
                "Name": f"ADMINISTRATORS@DC01",
                "Results": [{"ObjectIdentifier": sid(RID["da"]), "ObjectType": "Group"}],
            }
        ],
    )
    ws_local = []
    if traits.get("localadmin_helpdesk"):
        ws_local.append(
            {
                "ObjectIdentifier": f"{sid(RID['ws01'])}-544",
                "Name": "ADMINISTRATORS@WS01",
                "Results": [
                    {"ObjectIdentifier": sid(RID["helpdesk_user"]), "ObjectType": "User"}
                ],
            }
        )
    ws_local.append(
        {
            "ObjectIdentifier": f"{sid(RID['ws01'])}-555",
            "Name": "REMOTE DESKTOP USERS@WS01",
            "Results": [{"ObjectIdentifier": sid(RID["alice"]), "ObjectType": "User"}],
        }
    )
    add_computer(
        RID["ws01"],
        "WS01",
        haslaps=True,
        sessions=[{"UserSID": sid(RID["alice"])}] if traits.get("sessions") else [],
        local_groups=ws_local,
    )

    pentest_aces = [
        _ace(sid(RID["da"]), "Group", "GenericAll"),
        _ace(wk("S-1-5-32-544"), "Group", "GenericAll"),
    ]
    if traits.get("rbcd_configured") or traits.get("alice_war", True):
        pentest_aces += [
            _ace(sid(RID["alice"]), "User", "AllExtendedRights"),
            _ace(sid(RID["alice"]), "User", "WriteAccountRestrictions"),
        ]
    add_computer(
        RID["pentest"],
        "PENTESTPC",
        haslaps=False,
        aces=pentest_aces,
        allowed_to_act=(
            [_member(sid(RID["ws01"]), "Computer")] if traits.get("rbcd_configured") else []
        ),
    )
    if traits.get("constrained_del"):
        add_computer(
            RID["srvapp"],
            "SRVAPP",
            haslaps=True,
            trusted_to_auth=True,
            allowed_to_delegate=[f"cifs/DC01.{domain}"],
        )
    if traits.get("unconstrained_workstation"):
        add_computer(RID["unc_ws"], "DEVBOX", haslaps=False, unconstrained=True)

    # bulk fleet
    bulk_rids = []
    rid_c = 3000
    while len(computers) < n_computers:
        bulk_rids.append(rid_c)
        aces = [
            _ace(sid(RID["da"]), "Group", "Owns"),
            _ace(sid(RID["da"]), "Group", "GenericAll"),
            _ace(sid(RID["ea"]), "Group", "GenericAll"),
            _ace(wk("S-1-5-32-544"), "Group", "GenericAll"),
        ]
        if traits.get("helpdesk_bulk_rbcd"):
            aces += [
                _ace(sid(RID["helpdesk"]), "Group", "WriteAccountRestrictions"),
                _ace(sid(RID["helpdesk"]), "Group", "AllExtendedRights"),
                _ace(sid(RID["helpdesk"]), "Group", "Owns"),
            ]
        if traits.get("aws_connector_bulk"):
            aces += [
                _ace(sid(RID["aws"]), "Group", "AddAllowedToAct"),
                _ace(sid(RID["aws"]), "Group", "WriteAccountRestrictions"),
                _ace(sid(RID["aws"]), "Group", "GenericWrite"),
            ]
        add_computer(rid_c, f"HOST{rid_c - 3000:03d}", aces=aces)
        rid_c += 1

    # --- GPOs / OUs ---
    pam_guid = "A1111111-1111-1111-1111-111111111111"
    def_guid = "B2222222-2222-2222-2222-222222222222"
    pam_aces = [
        _ace(sid(RID["da"]), "Group", "Owns"),
        _ace(sid(RID["da"]), "Group", "GenericWrite"),
        _ace(sid(RID["ea"]), "Group", "GenericWrite"),
    ]
    if traits.get("auth_users_gpo"):
        pam_aces += [
            _ace(wk("S-1-5-11"), "Group", "GenericWrite"),
            _ace(wk("S-1-5-11"), "Group", "WriteDacl"),
            _ace(wk("S-1-5-11"), "Group", "WriteOwner"),
        ]
    gpos = [
        {
            "ObjectIdentifier": pam_guid,
            "ObjectType": "GPO",
            "Properties": {
                "domain": domain,
                "name": uname("PAMAGENTINSTALL"),
                "domainsid": domain_sid,
            },
            "Aces": pam_aces,
            "IsDeleted": False,
            "IsACLProtected": False,
        },
        {
            "ObjectIdentifier": def_guid,
            "ObjectType": "GPO",
            "Properties": {
                "domain": domain,
                "name": uname("Default Domain Policy"),
                "domainsid": domain_sid,
            },
            "Aces": [
                _ace(sid(RID["da"]), "Group", "GenericAll"),
                _ace(sid(RID["ea"]), "Group", "GenericWrite"),
            ],
            "IsDeleted": False,
            "IsACLProtected": False,
        },
    ]
    ous = [
        {
            "ObjectIdentifier": f"OU=PAM,{dn}",
            "ObjectType": "OU",
            "Properties": {"domain": domain, "name": uname("PAM"), "domainsid": domain_sid},
            "Links": [{"GUID": pam_guid, "IsEnforced": True}],
            "Aces": [_ace(sid(RID["da"]), "Group", "GenericAll")],
            "IsDeleted": False,
            "IsACLProtected": False,
        },
        {
            "ObjectIdentifier": f"OU=Workstations,{dn}",
            "ObjectType": "OU",
            "Properties": {
                "domain": domain,
                "name": uname("Workstations"),
                "domainsid": domain_sid,
            },
            "Links": [{"GUID": def_guid, "IsEnforced": False}],
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        },
        {
            "ObjectIdentifier": f"OU=Domain Controllers,{dn}",
            "ObjectType": "OU",
            "Properties": {
                "domain": domain,
                "name": uname("Domain Controllers"),
                "domainsid": domain_sid,
                "highvalue": True,
            },
            "Links": [{"GUID": def_guid, "IsEnforced": True}],
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        },
    ]

    # Domain ACEs
    domain_aces = [
        _ace(wk("S-1-5-32-544"), "Group", "Owns"),
        _ace(wk("S-1-5-32-544"), "Group", "GetChanges"),
        _ace(wk("S-1-5-32-544"), "Group", "GetChangesAll"),
        _ace(sid(RID["da"]), "Group", "GenericAll"),
        _ace(sid(RID["ea"]), "Group", "GenericAll"),
        _ace(sid(RID["dcg"]), "Group", "GetChangesAll"),
    ]
    if traits.get("msol_dcsync"):
        domain_aces += [
            _ace(sid(RID["msol"]), "User", "GetChanges"),
            _ace(sid(RID["msol"]), "User", "GetChangesAll"),
        ]
    if traits.get("nested_da_dcsync") or traits.get("msol_dcsync"):
        domain_aces += [
            _ace(sid(RID["nested_da"]), "User", "GetChanges"),
            _ace(sid(RID["nested_da"]), "User", "GetChangesAll"),
        ]
    domains = [
        {
            "ObjectIdentifier": domain_sid,
            "ObjectType": "Domain",
            "Properties": {
                "domain": domain,
                "name": domain,
                "domainsid": domain_sid,
                "distinguishedname": dn,
                "highvalue": True,
            },
            "Links": [{"GUID": def_guid, "IsEnforced": False}],
            "Trusts": [],
            "ChildObjects": [],
            "Aces": domain_aces,
            "IsDeleted": False,
            "IsACLProtected": False,
        }
    ]

    # ADCS
    templates = []
    cas = []
    if not traits.get("no_adcs"):
        cas.append(
            {
                "ObjectIdentifier": "E5555555-5555-5555-5555-555555555555",
                "ObjectType": "Enterprise CA",
                "Properties": {
                    "domain": domain,
                    "name": uname(f"{domain.split('.')[0]}-CA"),
                    "caname": f"{domain.split('.')[0]}-CA",
                    "dnshostname": f"CA01.{domain}",
                },
                "Aces": [
                    _ace(sid(RID["da"]), "Group", "ManageCA"),
                    _ace(sid(RID["du"]), "Group", "Enroll"),
                ],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )
        templates.append(
            {
                "ObjectIdentifier": "D4444444-4444-4444-4444-444444444444",
                "ObjectType": "Certificate Template",
                "Properties": {
                    "domain": domain,
                    "name": uname("User"),
                    "enrolleesuppliessubject": False,
                    "requiresmanagerapproval": True,
                    "effectiveekus": ["1.3.6.1.5.5.7.3.2"],
                },
                "Aces": [_ace(sid(RID["du"]), "Group", "Enroll")],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )
        if traits.get("esc1"):
            templates.append(
                {
                    "ObjectIdentifier": "C3333333-3333-3333-3333-333333333333",
                    "ObjectType": "Certificate Template",
                    "Properties": {
                        "domain": domain,
                        "name": uname("ESC1-UserAuth"),
                        "enrolleesuppliessubject": True,
                        "requiresmanagerapproval": False,
                        "effectiveekus": ["1.3.6.1.5.5.7.3.2"],
                    },
                    "Aces": [
                        _ace(sid(RID["alice"]), "User", "Enroll"),
                        _ace(sid(RID["du"]), "Group", "Enroll"),
                        _ace(sid(RID["da"]), "Group", "GenericAll"),
                    ],
                    "IsDeleted": False,
                    "IsACLProtected": False,
                }
            )

    files = {
        "users.json": {"meta": _meta("users", len(users)), "data": users},
        "computers.json": {"meta": _meta("computers", len(computers)), "data": computers},
        "groups.json": {"meta": _meta("groups", len(groups)), "data": groups},
        "gpos.json": {"meta": _meta("gpos", len(gpos)), "data": gpos},
        "ous.json": {"meta": _meta("ous", len(ous)), "data": ous},
        "domains.json": {"meta": _meta("domains", 1), "data": domains},
        "certtemplates.json": {
            "meta": _meta("certtemplates", len(templates)),
            "data": templates,
        },
        "enterprisecas.json": {
            "meta": _meta("enterprisecas", len(cas)),
            "data": cas,
        },
    }

    # Ground-truth checks for this environment
    checks: List[dict] = [
        {
            "id": "system_admins_not_builtin",
            "type": "predicate",
            "predicate": "system_admins_not_default_priv",
            "domain": domain,
        }
    ]
    if traits.get("msol_dcsync"):
        checks.append(
            {
                "id": "msol_unexpected_dcsync",
                "type": "output_contains",
                "detector": "print_dcsync_rights",
                "must_contain": ["MSOL_SYNC", "UNEXPECTED"],
            }
        )
    if traits.get("auth_users_gpo"):
        checks.append(
            {
                "id": "auth_users_gpo",
                "type": "output_contains",
                "detector": "print_gpo_abuse",
                "must_contain": ["PAMAGENTINSTALL", "AUTHENTICATED USERS"],
                "must_not_contain": ["NO LINKS DETECTED"],
            }
        )
        checks.append(
            {
                "id": "broad_auth_gpo",
                "type": "broad_acl",
                "principal_contains": "AUTHENTICATED USERS",
                "target_contains": "PAMAGENTINSTALL",
            }
        )
    if traits.get("everyone_user_gw"):
        checks.append(
            {
                "id": "everyone_mrios",
                "type": "broad_acl",
                "principal_contains": "EVERYONE",
                "target_contains": "MRIOS",
            }
        )
    if traits.get("helpdesk_bulk_rbcd"):
        checks.append(
            {
                "id": "helpdesk_rbcd",
                "type": "rbcd_principal_min",
                "principal_contains": "HELPDESK",
                "min_count": max(10, len(bulk_rids) // 2),
            }
        )
    if traits.get("aws_connector_bulk"):
        checks.append(
            {
                "id": "aws_rbcd",
                "type": "rbcd_principal_min",
                "principal_contains": "AWS AD CONNECTORS",
                "min_count": max(10, len(bulk_rids) // 2),
            }
        )
    if traits.get("rbcd_configured"):
        checks.append(
            {
                "id": "rbcd_configured",
                "type": "output_contains",
                "detector": "print_rbcd",
                "must_contain": ["PENTESTPC", "RBCD CONFIGURED"],
            }
        )
    if traits.get("esc1"):
        checks.append(
            {
                "id": "esc1",
                "type": "output_contains",
                "detector": "print_adcs_vulnerabilities",
                "must_contain": ["ESC1", "ESC1-USERAUTH"],
            }
        )
    if traits.get("no_adcs"):
        checks.append(
            {
                "id": "no_adcs_msg",
                "type": "output_contains",
                "detector": "print_adcs_vulnerabilities",
                "must_contain": ["NO ADCS OBJECTS"],
            }
        )
    if traits.get("privileged_kerb"):
        checks.append(
            {
                "id": "priv_kerb",
                "type": "output_contains",
                "detector": "print_privileged_roast_targets",
                "must_contain": ["SVC_SQL"],
            }
        )
    if traits.get("asrep"):
        checks.append(
            {
                "id": "asrep",
                "type": "output_contains",
                "detector": "print_as_rep_roastable",
                "must_contain": ["ASREP"] if not traits.get("asrep_many") else ["STUDENT"],
            }
        )
        # bob always if asrep
        checks.append(
            {
                "id": "asrep_bob",
                "type": "output_contains",
                "detector": "print_as_rep_roastable",
                "must_contain": ["BOB.ASREP"],
            }
        )
    if traits.get("shadow"):
        checks.append(
            {
                "id": "shadow",
                "type": "output_contains",
                "detector": "print_shadow_credentials",
                "must_contain_any": ["DAVE.HELP", "GRACE.SHADOW", "ADDKEYCREDENTIALLINK"],
            }
        )
    if traits.get("pne_pnr"):
        checks += [
            {
                "id": "pne",
                "type": "output_contains",
                "detector": "print_password_never_expires",
                "must_contain": ["EVE.PNE"],
            },
            {
                "id": "pnr",
                "type": "output_contains",
                "detector": "print_password_not_required",
                "must_contain": ["FRANK.PNR"],
            },
        ]
    if traits.get("localadmin_helpdesk"):
        checks.append(
            {
                "id": "localadmin",
                "type": "output_contains",
                "detector": "print_sessions_localadmin",
                "must_contain": ["DAVE.HELP", "LOCALADMIN"],
                "must_not_contain": ["GENERICALL"],
            }
        )
    checks.append(
        {
            "id": "laps_summary",
            "type": "output_contains",
            "detector": "print_laps_status",
            "must_contain": ["LAPS ENABLED"],
        }
    )
    # Alice impact if she has WAR or ESC1 enroll
    if traits.get("rbcd_configured") or traits.get("esc1") or traits.get("auth_users_gpo"):
        checks.append(
            {
                "id": "dossier_alice",
                "type": "dossier_impact",
                "principal": uname("alice.low"),
                "min_impact": 1,
            }
        )
    # Scale sanity
    checks.append(
        {
            "id": "scale_users",
            "type": "graph_min",
            "node_type": "user",
            "min": max(20, n_users // 2),
        }
    )
    checks.append(
        {
            "id": "scale_computers",
            "type": "graph_min",
            "node_type": "computer",
            "min": max(20, n_computers // 2),
        }
    )

    gt = {
        "profile_id": profile["id"],
        "description": profile["description"],
        "domain": domain,
        "domain_sid": domain_sid,
        "seed": seed,
        "traits": traits,
        "checks": checks,
        "stats": {
            "users": len(users),
            "computers": len(computers),
            "groups": len(groups),
            "gpos": len(gpos),
            "bulk_hosts": len(bulk_rids),
            "templates": len(templates),
        },
    }
    return files, gt
