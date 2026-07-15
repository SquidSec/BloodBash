#!/usr/bin/env python3
"""Twenty realistic multi-hop engagement scenarios as SharpHound CE corpora.

Each scenario plants a composite attack chain (foothold → pivots → DA/DCSync)
drawn from common red-team patterns. Fictional domains only — no customer data.

s01–s10: classic chains (kerberoast DCSync, helpdesk, unconstrained, ESC1, …)
s11–s20: additional common debt (svc in DA, ESC8, LAPS readers, DNSAdmins, …)

Used by tools/run_scenario_battery.py.
"""
from __future__ import annotations

import hashlib
import random
from typing import Any, Dict, List, Optional, Tuple

TS = 1_700_000_000

# ---------------------------------------------------------------------------
# Scenario catalog (course / engagement case studies)
# ---------------------------------------------------------------------------
ENGAGEMENT_SCENARIOS = [
    {
        "id": "s01_kerberoast_dcsync_svc",
        "title": "Kerberoast over-privileged legacy service → DCSync",
        "domain": "MFGPROD.LOCAL",
        "foothold": "jdoe (Domain User)",
        "summary": (
            "svc_erp has SPN + GetChanges/GetChangesAll; standard user can roast and DCSync."
        ),
    },
    {
        "id": "s02_helpdesk_genericall_backup_dcsync",
        "title": "Helpdesk GenericAll → backup service → DCSync",
        "domain": "PROSVC.LOCAL",
        "foothold": "helpdesk_jane",
        "summary": (
            "Helpdesk_Tier1 GenericAll on svc_veeam; reset/shadow then DCSync."
        ),
    },
    {
        "id": "s03_unconstrained_jump_da_session",
        "title": "Unconstrained delegation jump box + DA session",
        "domain": "APPLINE.LOCAL",
        "foothold": "lowpriv with path to app-jump01",
        "summary": (
            "app-jump01 unconstrained (non-DC); DA HasSession → ticket theft path."
        ),
    },
    {
        "id": "s04_adcs_esc1",
        "title": "AD CS ESC1 SAN impersonation",
        "domain": "CORPVPN.LOCAL",
        "foothold": "any Domain User",
        "summary": (
            "ESC1 template enrollable by Domain Users / lowpriv; Client Auth + ESS."
        ),
    },
    {
        "id": "s05_gpo_edit_high_tier",
        "title": "GPO edit rights linked toward servers/DCs",
        "domain": "SERVEROPS.LOCAL",
        "foothold": "server_admins member",
        "summary": (
            "Server Admins can edit GPO linked to servers OU (and weak link near DCs)."
        ),
    },
    {
        "id": "s06_asrep_acl_chain",
        "title": "AS-REP roast + ACL path upward",
        "domain": "LEGACYAPP.LOCAL",
        "foothold": "standard user",
        "summary": (
            "Preauth-disabled account with GenericWrite toward privileged object."
        ),
    },
    {
        "id": "s07_rbcd_machine_quota_path",
        "title": "RBCD after low-priv computer control",
        "domain": "DEVNET.LOCAL",
        "foothold": "standard user / local admin on low box",
        "summary": (
            "Can-configure RBCD on high-value server; optional configured AllowedToAct."
        ),
    },
    {
        "id": "s08_localadmin_cached_da",
        "title": "Local admin workstation + DA interactive session",
        "domain": "TIERFAIL.LOCAL",
        "foothold": "user with LocalAdmin on WS",
        "summary": (
            "DA HasSession on workstation where foothold has LocalAdmin."
        ),
    },
    {
        "id": "s09_nested_acl_multihop",
        "title": "Multi-hop nested groups + ACL chaining",
        "domain": "MERGER.LOCAL",
        "foothold": "contractor in ProjectX",
        "summary": (
            "Contractors → GenericWrite intermediate → path toward backup/DCSync principal."
        ),
    },
    {
        "id": "s10_gpo_svc_delegation_combo",
        "title": "GPO + service account + delegation combination",
        "domain": "APPCHAIN.LOCAL",
        "foothold": "GPO editors group member",
        "summary": (
            "Editable app GPO + Kerberoastable svc + constrained/unconstrained on related host."
        ),
    },
    # ---- Scenarios 11–20 (additional common misconfigs) ----
    {
        "id": "s11_svc_in_domain_admins",
        "title": "Service accounts directly in Domain Admins (Kerberoast → DA)",
        "domain": "LOGISTICS.LOCAL",
        "foothold": "jdoe (Domain User)",
        "summary": (
            "svc_oracle / svc_sharepoint nested in Domain Admins with SPNs; roast → DA."
        ),
    },
    {
        "id": "s12_adcs_esc8_web_enrollment",
        "title": "AD CS ESC8 web enrollment (relay-ready CA surface)",
        "domain": "RELAYLAB.LOCAL",
        "foothold": "any authenticated user (network path assumed)",
        "summary": (
            "Enterprise CA with HasWebEnrollment; graph-visible ESC8 signal for relay chains."
        ),
    },
    {
        "id": "s13_laps_overpermissive_readers",
        "title": "LAPS over-permissive ReadLAPSPassword ACLs",
        "domain": "HELPDESKLAPS.LOCAL",
        "foothold": "helpdesk or Domain User with LAPS read",
        "summary": (
            "Helpdesk/Domain Users can ReadLAPSPassword on workstations → local admin pivot."
        ),
    },
    {
        "id": "s14_dnsadmins_dangerous_rights",
        "title": "DNSAdmins with dangerous rights on DC",
        "domain": "DNSOPS.LOCAL",
        "foothold": "user nested into DNSAdmins",
        "summary": (
            "DNSAdmins member path + GenericAll/Write on DC computer object."
        ),
    },
    {
        "id": "s15_print_operators_path",
        "title": "Print Operators / Server Operators nesting toward privilege",
        "domain": "OPSBUILTINS.LOCAL",
        "foothold": "helpdesk nested into Print Operators",
        "summary": (
            "Built-in operator groups retain members; graph shows membership + HV adjacency."
        ),
    },
    {
        "id": "s16_tiering_fail_wdigest_adjacent",
        "title": "Tiering fail: local admin + DA session (WDigest-adjacent graph)",
        "domain": "WDSURFACE.LOCAL",
        "foothold": "local admin on workstation",
        "summary": (
            "Graph-visible half of WDigest abuse: LocalAdmin + DA HasSession (host registry not in SH)."
        ),
    },
    {
        "id": "s17_domain_nc_krbtgt_acl",
        "title": "Overly permissive ACLs on domain NC / krbtgt",
        "domain": "ACLDEBT.LOCAL",
        "foothold": "IT support group member",
        "summary": (
            "IT_Support has WriteDacl/GenericWrite on domain object and GenericAll on krbtgt."
        ),
    },
    {
        "id": "s18_gpp_cpassword_gpo",
        "title": "GPO Preferences-style embedded credentials (GPO content)",
        "domain": "GPPLAB.LOCAL",
        "foothold": "any Domain User (SYSVOL read)",
        "summary": (
            "GPO props plant cpassword/task markers BloodBash GPO content parser flags."
        ),
    },
    {
        "id": "s19_constrained_protocol_transition",
        "title": "Constrained delegation with protocol transition",
        "domain": "S4ULAB.LOCAL",
        "foothold": "compromise of web tier computer/account",
        "summary": (
            "Computer/user TrustedToAuth + AllowedToDelegate toward high-value SPNs."
        ),
    },
    {
        "id": "s20_entra_connect_overpriv",
        "title": "Entra Connect / MSOL sync account over-privileged on-prem",
        "domain": "HYBRIDSYNC.LOCAL",
        "foothold": "compromise of sync server or MSOL creds",
        "summary": (
            "MSOL_* has unexpected GetChanges+GetChangesAll (and optional EA adjacency)."
        ),
    },
]


def _sid(domain_sid: str, rid: int) -> str:
    return f"{domain_sid}-{rid}"


def _wk(domain: str, sfx: str) -> str:
    return f"{domain}-{sfx}"


def _ace(p: str, pt: str, right: str) -> dict:
    return {
        "PrincipalSID": p,
        "PrincipalType": pt,
        "RightName": right,
        "IsInherited": False,
    }


def _mem(oid: str, otype: str = "User") -> dict:
    return {"ObjectIdentifier": oid, "ObjectType": otype}


def _meta(kind: str, n: int) -> dict:
    return {"methods": 0, "type": kind, "count": n, "version": 6}


def _domain_sid(domain: str, seed: int) -> str:
    h = hashlib.sha256(f"{domain}:{seed}:eng".encode()).hexdigest()
    a = int(h[0:8], 16) % 1_500_000_000 + 1_000_000_000
    b = int(h[8:16], 16) % 1_500_000_000 + 1_000_000_000
    c = int(h[16:24], 16) % 1_500_000_000 + 1_000_000_000
    return f"S-1-5-21-{a}-{b}-{c}"


def _dn(domain: str) -> str:
    d = domain.upper()
    if d.endswith(".LOCAL"):
        return f"DC={domain[:-6].lower()},DC=local"
    if d.endswith(".EDU"):
        return f"DC={domain[:-4].lower()},DC=edu"
    parts = domain.lower().split(".")
    return ",".join(f"DC={p}" for p in parts)


class EnvBuilder:
    """Accumulate SharpHound CE objects for one engagement scenario."""

    def __init__(self, domain: str, seed: int):
        self.domain = domain
        self.seed = seed
        self.rng = random.Random(seed)
        self.domain_sid = _domain_sid(domain, seed)
        self.dn = _dn(domain)
        self.users: List[dict] = []
        self.computers: List[dict] = []
        self.groups: List[dict] = []
        self.gpos: List[dict] = []
        self.ous: List[dict] = []
        self.domains: List[dict] = []
        self.templates: List[dict] = []
        self.cas: List[dict] = []
        self.checks: List[dict] = []
        self.notes: List[str] = []
        # well-known
        self.sid_da = self.sid(512)
        self.sid_du = self.sid(513)
        self.sid_dcg = self.sid(516)
        self.sid_ea = self.sid(519)
        self.sid_admins = self.wk("S-1-5-32-544")
        self.sid_au = self.wk("S-1-5-11")
        self.sid_everyone = self.wk("S-1-1-0")

    def sid(self, rid: int) -> str:
        return _sid(self.domain_sid, rid)

    def wk(self, sfx: str) -> str:
        return _wk(self.domain, sfx)

    def uname(self, sam: str) -> str:
        return f"{sam.upper()}@{self.domain}"

    def cname(self, sam: str) -> str:
        return f"{sam.upper()}.{self.domain}"

    def add_group(
        self,
        rid: int,
        sam: str,
        members: Optional[List[dict]] = None,
        *,
        highvalue: bool = False,
        oid: Optional[str] = None,
    ) -> str:
        oid = oid or self.sid(rid)
        self.groups.append(
            {
                "ObjectIdentifier": oid,
                "ObjectType": "Group",
                "Properties": {
                    "domain": self.domain,
                    "name": self.uname(sam),
                    "samaccountname": sam,
                    "domainsid": self.domain_sid,
                    "highvalue": highvalue,
                    "whencreated": TS,
                },
                "Members": members or [],
                "Aces": [_ace(self.sid_da, "Group", "GenericAll")],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )
        return oid

    def add_user(
        self,
        rid: int,
        sam: str,
        *,
        hasspn: bool = False,
        spns: Optional[List[str]] = None,
        dontreqpreauth: bool = False,
        highvalue: bool = False,
        aces: Optional[List[dict]] = None,
        description: str = "",
        pwdneverexpires: bool = False,
        passwordnotreqd: bool = False,
        admincount: bool = False,
    ) -> str:
        oid = self.sid(rid)
        default_aces = [
            _ace(self.sid_da, "Group", "GenericAll"),
            _ace(self.sid_admins, "Group", "GenericAll"),
        ]
        self.users.append(
            {
                "ObjectIdentifier": oid,
                "ObjectType": "User",
                "Properties": {
                    "domain": self.domain,
                    "name": self.uname(sam),
                    "samaccountname": sam,
                    "domainsid": self.domain_sid,
                    "enabled": True,
                    "hasspn": hasspn,
                    "serviceprincipalnames": spns
                    or ([f"HTTP/{sam.lower()}.{self.domain.lower()}"] if hasspn else []),
                    "dontreqpreauth": dontreqpreauth,
                    "pwdneverexpires": pwdneverexpires,
                    "passwordnotreqd": passwordnotreqd,
                    "highvalue": highvalue,
                    "admincount": admincount or highvalue,
                    "sensitive": False,
                    "description": description,
                    "displayname": sam,
                    "lastlogon": TS - self.rng.randint(0, 86400 * 200),
                    "lastlogontimestamp": TS - self.rng.randint(0, 86400 * 200),
                    "pwdlastset": TS - self.rng.randint(86400 * 100, 86400 * 900),
                    "whencreated": TS - 86400 * 600,
                },
                "PrimaryGroupSID": self.sid_du,
                "Aces": aces or default_aces,
                "AllowedToDelegate": [],
                "HasSIDHistory": [],
                "SPNTargets": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )
        return oid

    def add_computer(
        self,
        rid: int,
        sam: str,
        *,
        is_dc: bool = False,
        unconstrained: bool = False,
        trusted_to_auth: bool = False,
        haslaps: bool = False,
        allowed_to_act: Optional[List[dict]] = None,
        allowed_to_delegate: Optional[List[str]] = None,
        sessions: Optional[List[dict]] = None,
        local_groups: Optional[List[dict]] = None,
        aces: Optional[List[dict]] = None,
    ) -> str:
        oid = self.sid(rid)
        default_aces = [
            _ace(self.sid_da, "Group", "Owns"),
            _ace(self.sid_da, "Group", "GenericAll"),
            _ace(self.sid_ea, "Group", "GenericAll"),
            _ace(self.sid_admins, "Group", "GenericAll"),
        ]
        self.computers.append(
            {
                "ObjectIdentifier": oid,
                "ObjectType": "Computer",
                "Properties": {
                    "domain": self.domain,
                    "name": self.cname(sam),
                    "samaccountname": f"{sam}$",
                    "domainsid": self.domain_sid,
                    "enabled": True,
                    "isdc": is_dc,
                    "haslaps": haslaps,
                    "unconstraineddelegation": unconstrained or is_dc,
                    "trustedtoauth": trusted_to_auth,
                    "operatingsystem": "Windows Server 2019" if is_dc else "Windows 10",
                    "lastlogon": TS,
                    "pwdlastset": TS,
                    "whencreated": TS - 86400 * 300,
                    "serviceprincipalnames": [f"HOST/{self.cname(sam)}"],
                },
                "PrimaryGroupSID": self.sid_dcg if is_dc else self.sid(515),
                "AllowedToAct": allowed_to_act or [],
                "AllowedToDelegate": allowed_to_delegate or [],
                "HasSIDHistory": [],
                "Sessions": {
                    "Results": sessions or [],
                    "Collected": True,
                    "FailureReason": None,
                },
                "PrivilegedSessions": {
                    "Results": [],
                    "Collected": True,
                    "FailureReason": None,
                },
                "RegistrySessions": {
                    "Results": [],
                    "Collected": True,
                    "FailureReason": None,
                },
                "LocalGroups": local_groups or [],
                "IsDC": is_dc,
                "DomainSID": self.domain_sid,
                "Aces": aces or default_aces,
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )
        return oid

    def add_gpo(self, guid: str, name: str, aces: List[dict]) -> str:
        self.gpos.append(
            {
                "ObjectIdentifier": guid,
                "ObjectType": "GPO",
                "Properties": {
                    "domain": self.domain,
                    "name": self.uname(name),
                    "domainsid": self.domain_sid,
                    "whencreated": TS,
                },
                "Aces": aces,
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )
        return guid

    def add_ou(self, name: str, links: Optional[List[dict]] = None, highvalue: bool = False) -> str:
        oid = f"OU={name},{self.dn}"
        self.ous.append(
            {
                "ObjectIdentifier": oid,
                "ObjectType": "OU",
                "Properties": {
                    "domain": self.domain,
                    "name": self.uname(name),
                    "domainsid": self.domain_sid,
                    "highvalue": highvalue,
                },
                "Links": links or [],
                "Aces": [_ace(self.sid_da, "Group", "GenericAll")],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )
        return oid

    def finalize_domain(self, domain_aces: List[dict], gpo_links: Optional[List[dict]] = None):
        self.domains = [
            {
                "ObjectIdentifier": self.domain_sid,
                "ObjectType": "Domain",
                "Properties": {
                    "domain": self.domain,
                    "name": self.domain,
                    "domainsid": self.domain_sid,
                    "distinguishedname": self.dn,
                    "highvalue": True,
                },
                "Links": gpo_links or [],
                "Trusts": [],
                "ChildObjects": [],
                "Aces": domain_aces,
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        ]

    def add_filler(self, n_users: int = 40, n_computers: int = 50):
        """Background population for realism / scale."""
        # Domain Users group if missing
        if not any(g["ObjectIdentifier"] == self.sid_du for g in self.groups):
            self.add_group(513, "Domain Users")
        du = next(g for g in self.groups if g["ObjectIdentifier"] == self.sid_du)
        base_u = 8000
        while len(self.users) < n_users:
            rid = base_u + len(self.users)
            oid = self.add_user(rid, f"user{rid}")
            du["Members"].append(_mem(oid))
        base_c = 9000
        while len(self.computers) < n_computers:
            rid = base_c + len(self.computers)
            self.add_computer(rid, f"WS{rid}", haslaps=self.rng.random() < 0.3)

    def add_baseline_groups(self):
        self.add_group(512, "Domain Admins", highvalue=True)
        self.add_group(519, "Enterprise Admins", highvalue=True)
        self.add_group(513, "Domain Users")
        self.add_group(516, "Domain Controllers", highvalue=True)
        self.add_group(515, "Domain Computers")
        for oid, name in [
            (self.sid_admins, "Administrators"),
            (self.sid_au, "Authenticated Users"),
            (self.sid_everyone, "Everyone"),
            (self.wk("S-1-5-32-545"), "Users"),
        ]:
            self.add_group(0, name, oid=oid)

    def files_and_gt(self, scenario: dict) -> Tuple[dict, dict]:
        files = {
            "users.json": {"meta": _meta("users", len(self.users)), "data": self.users},
            "computers.json": {
                "meta": _meta("computers", len(self.computers)),
                "data": self.computers,
            },
            "groups.json": {"meta": _meta("groups", len(self.groups)), "data": self.groups},
            "gpos.json": {"meta": _meta("gpos", len(self.gpos)), "data": self.gpos},
            "ous.json": {"meta": _meta("ous", len(self.ous)), "data": self.ous},
            "domains.json": {
                "meta": _meta("domains", len(self.domains)),
                "data": self.domains,
            },
            "certtemplates.json": {
                "meta": _meta("certtemplates", len(self.templates)),
                "data": self.templates,
            },
            "enterprisecas.json": {
                "meta": _meta("enterprisecas", len(self.cas)),
                "data": self.cas,
            },
        }
        gt = {
            "scenario_id": scenario["id"],
            "title": scenario["title"],
            "domain": self.domain,
            "foothold": scenario["foothold"],
            "summary": scenario["summary"],
            "notes": self.notes,
            "seed": self.seed,
            "checks": self.checks,
            "stats": {
                "users": len(self.users),
                "computers": len(self.computers),
                "groups": len(self.groups),
                "gpos": len(self.gpos),
            },
        }
        return files, gt


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------


def build_s01(seed: int) -> Tuple[dict, dict]:
    """Kerberoast svc_erp with DCSync."""
    sc = ENGAGEMENT_SCENARIOS[0]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    jdoe = b.add_user(1100, "jdoe", description="phished standard user")
    svc = b.add_user(
        1200,
        "svc_erp",
        hasspn=True,
        spns=[f"MSSQLSvc/erp.{sc['domain'].lower()}:1433"],
        description="Legacy ERP — DCSync granted for agentless backup 2022",
        admincount=True,
        pwdneverexpires=True,
    )
    da_user = b.add_user(1101, "da_admin", highvalue=True)
    # DA membership
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da_user))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(jdoe), _mem(svc)]
        if g["ObjectIdentifier"] == b.sid_dcg:
            pass
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_computer(1002, "ERP01", haslaps=False)
    b.add_filler(45, 55)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "Owns"),
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(b.sid_ea, "Group", "GenericAll"),
            _ace(svc, "User", "GetChanges"),
            _ace(svc, "User", "GetChangesAll"),
        ]
    )
    b.notes = [
        "Foothold jdoe can Kerberoast svc_erp (SPN).",
        "svc_erp has unexpected DCSync → full domain equivalent.",
    ]
    b.checks = [
        {
            "id": "kerb_svc_erp",
            "type": "output_contains",
            "detector": "print_kerberoastable",
            "must_contain": ["SVC_ERP"],
        },
        {
            "id": "dcsync_svc_unexpected",
            "type": "output_contains",
            "detector": "print_dcsync_rights",
            "must_contain": ["SVC_ERP", "UNEXPECTED"],
        },
        {
            "id": "dcsync_finding",
            "type": "finding",
            "category": "DCSync",
            "must_contain": "SVC_ERP",
        },
        {
            "id": "pne_svc",
            "type": "output_contains",
            "detector": "print_password_never_expires",
            "must_contain": ["SVC_ERP"],
        },
    ]
    return b.files_and_gt(sc)


def build_s02(seed: int) -> Tuple[dict, dict]:
    """Helpdesk GenericAll on svc_veeam → DCSync."""
    sc = ENGAGEMENT_SCENARIOS[1]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    jane = b.add_user(1100, "helpdesk_jane")
    hd = b.add_group(2001, "Helpdesk_Tier1", [_mem(jane)])
    veeam = b.add_user(
        1200,
        "svc_veeam",
        description="Backup agent — DCSync for agentless",
        aces=[
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(hd, "Group", "GenericAll"),
            _ace(hd, "Group", "ForceChangePassword"),
            _ace(hd, "Group", "AddKeyCredentialLink"),
        ],
    )
    b.add_user(1101, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(b.sid(1101)))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(jane), _mem(veeam)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(40, 45)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(veeam, "User", "GetChanges"),
            _ace(veeam, "User", "GetChangesAll"),
        ]
    )
    b.notes = [
        "helpdesk_jane in Helpdesk_Tier1 with GenericAll on svc_veeam.",
        "svc_veeam has unexpected DCSync.",
    ]
    b.checks = [
        {
            "id": "dcsync_veeam",
            "type": "output_contains",
            "detector": "print_dcsync_rights",
            "must_contain": ["SVC_VEEAM", "UNEXPECTED"],
        },
        {
            "id": "shadow_or_dangerous",
            "type": "output_contains",
            "detector": "print_shadow_credentials",
            "must_contain_any": ["HELPDESK", "SVC_VEEAM", "ADDKEYCREDENTIALLINK"],
        },
        {
            "id": "dossier_jane_impact",
            "type": "dossier_impact",
            "principal": b.uname("helpdesk_jane"),
            "min_impact": 1,
        },
    ]
    return b.files_and_gt(sc)


def build_s03(seed: int) -> Tuple[dict, dict]:
    """Unconstrained non-DC jump + DA session."""
    sc = ENGAGEMENT_SCENARIOS[2]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    low = b.add_user(1100, "devuser")
    da = b.add_user(1101, "da_ops", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(low), _mem(da)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True, unconstrained=True)
    jump = b.add_computer(
        1002,
        "APP-JUMP01",
        unconstrained=True,  # non-DC unconstrained — abuse
        haslaps=False,
        sessions=[{"UserSID": da}],
        local_groups=[
            {
                "ObjectIdentifier": f"{b.sid(1002)}-544",
                "Name": "ADMINISTRATORS@APP-JUMP01",
                "Results": [{"ObjectIdentifier": low, "ObjectType": "User"}],
            }
        ],
    )
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(35, 40)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ]
    )
    b.notes = [
        "APP-JUMP01 has unconstrained delegation (non-DC).",
        "da_ops HasSession on jump; devuser is LocalAdmin.",
    ]
    b.checks = [
        {
            "id": "unc_non_dc",
            "type": "output_contains",
            "detector": "print_unconstrained_delegation",
            "must_contain": ["APP-JUMP01"],
        },
        {
            "id": "localadmin_dev",
            "type": "output_contains",
            "detector": "print_sessions_localadmin",
            "must_contain": ["DEVUSER", "LOCALADMIN"],
            "must_not_contain": ["GENERICALL"],
        },
    ]
    return b.files_and_gt(sc)


def build_s04(seed: int) -> Tuple[dict, dict]:
    """AD CS ESC1."""
    sc = ENGAGEMENT_SCENARIOS[3]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    user = b.add_user(1100, "jsmith")
    da = b.add_user(1101, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(user), _mem(da)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.cas.append(
        {
            "ObjectIdentifier": "E5555555-5555-5555-5555-555555555555",
            "ObjectType": "Enterprise CA",
            "Properties": {
                "domain": b.domain,
                "name": b.uname("CORPVPN-CA"),
                "caname": "CORPVPN-CA",
                "dnshostname": f"CA01.{b.domain}",
            },
            "Aces": [
                _ace(b.sid_da, "Group", "ManageCA"),
                _ace(b.sid_du, "Group", "Enroll"),
            ],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
    )
    b.templates.append(
        {
            "ObjectIdentifier": "C3333333-3333-3333-3333-333333333333",
            "ObjectType": "Certificate Template",
            "Properties": {
                "domain": b.domain,
                "name": b.uname("CorpUser"),
                "enrolleesuppliessubject": True,
                "requiresmanagerapproval": False,
                "effectiveekus": ["1.3.6.1.5.5.7.3.2"],
            },
            "Aces": [
                _ace(user, "User", "Enroll"),
                _ace(b.sid_du, "Group", "Enroll"),
                _ace(b.sid_da, "Group", "GenericAll"),
            ],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
    )
    b.add_filler(40, 40)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ]
    )
    b.notes = ["ESC1 CorpUser template: ESS + no approval + Domain Users enroll."]
    b.checks = [
        {
            "id": "esc1",
            "type": "output_contains",
            "detector": "print_adcs_vulnerabilities",
            "must_contain": ["ESC1", "CORPUSER"],
        },
        {
            "id": "not_empty",
            "type": "output_not_contains",
            "detector": "print_adcs_vulnerabilities",
            "must_not_contain": ["NO ADCS OBJECTS"],
        },
    ]
    return b.files_and_gt(sc)


def build_s05(seed: int) -> Tuple[dict, dict]:
    """GPO edit rights on policy linked to servers."""
    sc = ENGAGEMENT_SCENARIOS[4]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    sa_user = b.add_user(1100, "srv_ops")
    sa = b.add_group(2001, "Server Admins", [_mem(sa_user)])
    da = b.add_user(1101, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(sa_user), _mem(da)]
    gpo_id = "A1111111-1111-1111-1111-111111111111"
    b.add_gpo(
        gpo_id,
        "Server-Maintenance",
        [
            _ace(b.sid_da, "Group", "Owns"),
            _ace(b.sid_da, "Group", "GenericWrite"),
            _ace(sa, "Group", "GenericWrite"),
            _ace(sa, "Group", "WriteDacl"),
            _ace(sa, "Group", "WriteOwner"),
        ],
    )
    b.add_ou("Servers", links=[{"GUID": gpo_id, "IsEnforced": False}])
    b.add_ou("Domain Controllers", links=[{"GUID": gpo_id, "IsEnforced": False}], highvalue=True)
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    b.add_computer(1002, "APP01", haslaps=False)
    b.add_computer(1003, "APP02", haslaps=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(35, 40)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ],
        gpo_links=[],
    )
    b.notes = [
        "Server Admins can edit Server-Maintenance GPO.",
        "GPO linked to Servers and Domain Controllers OUs.",
    ]
    b.checks = [
        {
            "id": "gpo_weak",
            "type": "output_contains",
            "detector": "print_gpo_abuse",
            "must_contain": ["SERVER-MAINTENANCE", "SERVER ADMINS"],
            "must_not_contain": ["NO LINKS DETECTED"],
        },
        {
            "id": "dossier_ops",
            "type": "dossier_impact",
            "principal": b.uname("srv_ops"),
            "min_impact": 1,
        },
    ]
    return b.files_and_gt(sc)


def build_s06(seed: int) -> Tuple[dict, dict]:
    """AS-REP + ACL toward privileged."""
    sc = ENGAGEMENT_SCENARIOS[5]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    std = b.add_user(1100, "analyst1")
    roast = b.add_user(
        1200,
        "legacy_app",
        dontreqpreauth=True,
        description="Legacy flag for old app",
        aces=[
            _ace(b.sid_da, "Group", "GenericAll"),
            # chain: after roast, account has GenericWrite on svc with DCSync
        ],
    )
    target = b.add_user(
        1201,
        "svc_monitor",
        aces=[
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(roast, "User", "GenericWrite"),
            _ace(roast, "User", "ForceChangePassword"),
        ],
    )
    da = b.add_user(1101, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(std), _mem(roast), _mem(target), _mem(da)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(40, 45)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(target, "User", "GetChanges"),
            _ace(target, "User", "GetChangesAll"),
        ]
    )
    b.notes = [
        "legacy_app is AS-REP roastable.",
        "legacy_app has GenericWrite/ForceChangePassword on svc_monitor.",
        "svc_monitor has unexpected DCSync.",
    ]
    b.checks = [
        {
            "id": "asrep",
            "type": "output_contains",
            "detector": "print_as_rep_roastable",
            "must_contain": ["LEGACY_APP"],
        },
        {
            "id": "dcsync_monitor",
            "type": "output_contains",
            "detector": "print_dcsync_rights",
            "must_contain": ["SVC_MONITOR", "UNEXPECTED"],
        },
    ]
    return b.files_and_gt(sc)


def build_s07(seed: int) -> Tuple[dict, dict]:
    """RBCD configure path to high-value server."""
    sc = ENGAGEMENT_SCENARIOS[6]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    user = b.add_user(1100, "dev_alice")
    da = b.add_user(1101, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(user), _mem(da)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    filesrv = b.add_computer(
        1002,
        "FILE01",
        haslaps=True,
        sessions=[{"UserSID": da}],
        aces=[
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(b.sid_admins, "Group", "GenericAll"),
            _ace(user, "User", "WriteAccountRestrictions"),
            _ace(user, "User", "GenericWrite"),
            _ace(user, "User", "AddAllowedToAct"),
        ],
        allowed_to_act=[],  # not yet configured — attacker will set
    )
    # low box attacker controls
    b.add_computer(
        1003,
        "DEVBOX01",
        haslaps=False,
        local_groups=[
            {
                "ObjectIdentifier": f"{b.sid(1003)}-544",
                "Name": "ADMINISTRATORS@DEVBOX01",
                "Results": [{"ObjectIdentifier": user, "ObjectType": "User"}],
            }
        ],
    )
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    # bulk noise
    for i in range(25):
        b.add_computer(
            3000 + i,
            f"HOST{i:02d}",
            aces=[
                _ace(b.sid_da, "Group", "GenericAll"),
                _ace(user, "User", "WriteAccountRestrictions"),
            ],
        )
    b.add_filler(40, 30)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ]
    )
    b.notes = [
        "dev_alice can configure RBCD on FILE01 (and many hosts).",
        "FILE01 has DA session — RBCD target of choice.",
    ]
    b.checks = [
        {
            "id": "alice_rbcd_file",
            "type": "rbcd_pair",
            "principal_contains": "DEV_ALICE",
            "target_contains": "FILE01",
        },
        {
            "id": "alice_bulk",
            "type": "rbcd_principal_min",
            "principal_contains": "DEV_ALICE",
            "min_count": 20,
        },
        {
            "id": "dossier",
            "type": "dossier_impact",
            "principal": b.uname("dev_alice"),
            "min_impact": 1,
        },
    ]
    return b.files_and_gt(sc)


def build_s08(seed: int) -> Tuple[dict, dict]:
    """LocalAdmin + DA HasSession on same workstation."""
    sc = ENGAGEMENT_SCENARIOS[7]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    user = b.add_user(1100, "wks_user")
    da = b.add_user(1101, "da_breakglass", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(user), _mem(da)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True, unconstrained=True)
    b.add_computer(
        1002,
        "WS-FINANCE07",
        haslaps=False,
        sessions=[{"UserSID": da}],
        local_groups=[
            {
                "ObjectIdentifier": f"{b.sid(1002)}-544",
                "Name": "ADMINISTRATORS@WS-FINANCE07",
                "Results": [{"ObjectIdentifier": user, "ObjectType": "User"}],
            }
        ],
    )
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(35, 40)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ]
    )
    b.notes = [
        "wks_user is LocalAdmin on WS-FINANCE07.",
        "da_breakglass HasSession there (tiering violation).",
    ]
    b.checks = [
        {
            "id": "localadmin",
            "type": "output_contains",
            "detector": "print_sessions_localadmin",
            "must_contain": ["WKS_USER", "LOCALADMIN"],
            "must_not_contain": ["GENERICALL"],
        },
    ]
    return b.files_and_gt(sc)


def build_s09(seed: int) -> Tuple[dict, dict]:
    """Multi-hop: Contractors → GenericWrite IT_Support → GenericAll svc_backup DCSync."""
    sc = ENGAGEMENT_SCENARIOS[8]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    contractor = b.add_user(1100, "contractor_bob")
    it_user = b.add_user(1101, "it_support_ann")
    project = b.add_group(2001, "ProjectX_Contractors", [_mem(contractor)])
    itsup = b.add_group(2002, "IT_Support", [_mem(it_user)])
    # intermediate object owned/writable by contractors
    intermediate = b.add_user(
        1200,
        "svc_mid",
        aces=[
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(project, "Group", "GenericWrite"),
            _ace(project, "Group", "GenericAll"),
        ],
    )
    # hop: IT_Support can control backup svc (and contractor can add to IT via mid — simplified as GenericAll on IT group)
    # Represent chain as: ProjectX GenericWrite on IT_Support group (AddMember)
    for g in b.groups:
        if g["ObjectIdentifier"] == itsup:
            g["Aces"] = [
                _ace(b.sid_da, "Group", "GenericAll"),
                _ace(project, "Group", "AddMember"),
                _ace(project, "Group", "GenericWrite"),
            ]
    backup = b.add_user(
        1201,
        "svc_backup",
        aces=[
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(itsup, "Group", "GenericAll"),
            _ace(itsup, "Group", "ForceChangePassword"),
        ],
    )
    da = b.add_user(1102, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(contractor), _mem(it_user), _mem(intermediate), _mem(backup), _mem(da)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(50, 55)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(backup, "User", "GetChanges"),
            _ace(backup, "User", "GetChangesAll"),
        ]
    )
    b.notes = [
        "contractor_bob in ProjectX_Contractors.",
        "ProjectX can AddMember/GenericWrite IT_Support.",
        "IT_Support GenericAll on svc_backup; svc_backup has unexpected DCSync.",
    ]
    b.checks = [
        {
            "id": "dcsync_backup",
            "type": "output_contains",
            "detector": "print_dcsync_rights",
            "must_contain": ["SVC_BACKUP", "UNEXPECTED"],
        },
        {
            "id": "dossier_contractor",
            "type": "dossier_impact",
            "principal": b.uname("contractor_bob"),
            "min_impact": 1,
        },
        {
            "id": "paths_or_groups",
            "type": "output_contains",
            "detector": "print_dcsync_rights",
            "must_contain": ["UNEXPECTED"],
        },
    ]
    return b.files_and_gt(sc)


def build_s10(seed: int) -> Tuple[dict, dict]:
    """GPO + Kerberoastable svc + unconstrained/constrained host."""
    sc = ENGAGEMENT_SCENARIOS[9]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    editor = b.add_user(1100, "app_deployer")
    editors = b.add_group(2001, "GPO_AppEditors", [_mem(editor)])
    svc = b.add_user(
        1200,
        "svc_apppool",
        hasspn=True,
        spns=[f"HTTP/app.{sc['domain'].lower()}"],
        description="App pool identity",
    )
    da = b.add_user(1101, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(editor), _mem(svc), _mem(da)]
    gpo_id = "B2222222-2222-2222-2222-222222222222"
    b.add_gpo(
        gpo_id,
        "App-Deployment",
        [
            _ace(b.sid_da, "Group", "Owns"),
            _ace(editors, "Group", "GenericWrite"),
            _ace(editors, "Group", "WriteDacl"),
            _ace(b.sid_au, "Group", "GenericWrite"),  # sprawl
        ],
    )
    b.add_ou("ApplicationServers", links=[{"GUID": gpo_id, "IsEnforced": True}])
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    b.add_computer(
        1002,
        "APP-WEB01",
        unconstrained=True,
        haslaps=False,
        sessions=[{"UserSID": da}],
        trusted_to_auth=True,
        allowed_to_delegate=[f"cifs/DC01.{sc['domain']}"],
    )
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(40, 45)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ]
    )
    b.notes = [
        "GPO_AppEditors can edit App-Deployment GPO (Auth Users also GenericWrite).",
        "svc_apppool Kerberoastable; APP-WEB01 unconstrained + constrained flags.",
    ]
    b.checks = [
        {
            "id": "gpo",
            "type": "output_contains",
            "detector": "print_gpo_abuse",
            "must_contain": ["APP-DEPLOYMENT"],
            "must_not_contain": ["NO LINKS DETECTED"],
        },
        {
            "id": "kerb",
            "type": "output_contains",
            "detector": "print_kerberoastable",
            "must_contain": ["SVC_APPPOOL"],
        },
        {
            "id": "unc",
            "type": "output_contains",
            "detector": "print_unconstrained_delegation",
            "must_contain": ["APP-WEB01"],
        },
        {
            "id": "broad_or_gpo",
            "type": "broad_acl",
            "principal_contains": "AUTHENTICATED USERS",
            "target_contains": "APP-DEPLOYMENT",
        },
    ]
    return b.files_and_gt(sc)


# ---------------------------------------------------------------------------
# Scenarios 11–20
# ---------------------------------------------------------------------------


def build_s11(seed: int) -> Tuple[dict, dict]:
    """Service accounts nested directly into Domain Admins + SPN."""
    sc = ENGAGEMENT_SCENARIOS[10]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    jdoe = b.add_user(1100, "jdoe")
    svc_oracle = b.add_user(
        1200,
        "svc_oracle",
        hasspn=True,
        spns=[f"oracle/{sc['domain'].lower()}"],
        description="ERP app pool — still in Domain Admins since 2019 upgrade",
        admincount=True,
        pwdneverexpires=True,
    )
    svc_sp = b.add_user(
        1201,
        "svc_sharepoint",
        hasspn=True,
        spns=[f"HTTP/sp.{sc['domain'].lower()}"],
        admincount=True,
    )
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"] += [_mem(svc_oracle), _mem(svc_sp)]
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(jdoe), _mem(svc_oracle), _mem(svc_sp)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(50, 55)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ]
    )
    b.notes = [
        "svc_oracle and svc_sharepoint are Domain Admins with SPNs.",
        "Any user can Kerberoast → cracked hash is direct DA.",
    ]
    b.checks = [
        {
            "id": "kerb_oracle",
            "type": "output_contains",
            "detector": "print_kerberoastable",
            "must_contain": ["SVC_ORACLE"],
        },
        {
            "id": "priv_kerb",
            "type": "output_contains",
            "detector": "print_privileged_roast_targets",
            "must_contain": ["SVC_ORACLE", "DOMAIN ADMINS"],
        },
        {
            "id": "sharepoint_kerb",
            "type": "output_contains",
            "detector": "print_kerberoastable",
            "must_contain": ["SVC_SHAREPOINT"],
        },
    ]
    return b.files_and_gt(sc)


def build_s12(seed: int) -> Tuple[dict, dict]:
    """ESC8 web enrollment on enterprise CA (+ optional ESC1)."""
    sc = ENGAGEMENT_SCENARIOS[11]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    user = b.add_user(1100, "employee1")
    da = b.add_user(1101, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(user), _mem(da)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.cas.append(
        {
            "ObjectIdentifier": "E6666666-6666-6666-6666-666666666666",
            "ObjectType": "Enterprise CA",
            "Properties": {
                "domain": b.domain,
                "name": b.uname("RELAYLAB-CA"),
                "caname": "RELAYLAB-CA",
                "dnshostname": f"CA01.{b.domain}",
                "HasWebEnrollment": True,
                "haswebenrollment": True,
            },
            "Aces": [
                _ace(b.sid_da, "Group", "ManageCA"),
                _ace(b.sid_du, "Group", "Enroll"),
                _ace(b.sid_au, "Group", "Enroll"),
            ],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
    )
    b.templates.append(
        {
            "ObjectIdentifier": "C7777777-7777-7777-7777-777777777777",
            "ObjectType": "Certificate Template",
            "Properties": {
                "domain": b.domain,
                "name": b.uname("User"),
                "enrolleesuppliessubject": False,
                "requiresmanagerapproval": True,
                "effectiveekus": ["1.3.6.1.5.5.7.3.2"],
            },
            "Aces": [_ace(b.sid_du, "Group", "Enroll")],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
    )
    b.add_filler(35, 40)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ]
    )
    b.notes = [
        "RELAYLAB-CA has HasWebEnrollment (ESC8 graph signal).",
        "LLMNR/NTLM relay itself is network-layer — not in SharpHound.",
    ]
    b.checks = [
        {
            "id": "esc8",
            "type": "output_contains",
            "detector": "print_adcs_vulnerabilities",
            "must_contain": ["ESC8", "RELAYLAB-CA"],
        },
    ]
    return b.files_and_gt(sc)


def build_s13(seed: int) -> Tuple[dict, dict]:
    """LAPS ReadLAPSPassword for helpdesk / domain users."""
    sc = ENGAGEMENT_SCENARIOS[12]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    hd_user = b.add_user(1100, "helpdesk_lee")
    std = b.add_user(1101, "jdoe")
    hd = b.add_group(2001, "Helpdesk_Tier1", [_mem(hd_user)])
    da = b.add_user(1102, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(hd_user), _mem(std), _mem(da)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    # workstations with LAPS + ReadLAPSPassword ACEs
    for i, rid in enumerate([1002, 1003, 1004, 1005, 1006]):
        aces = [
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(b.sid_admins, "Group", "GenericAll"),
            _ace(hd, "Group", "ReadLAPSPassword"),
        ]
        if i < 2:
            aces.append(_ace(b.sid_du, "Group", "ReadLAPSPassword"))
        b.add_computer(rid, f"WS-LAPS{i:02d}", haslaps=True, aces=aces)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(40, 35)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ]
    )
    b.notes = [
        "Helpdesk_Tier1 can ReadLAPSPassword on LAPS-enabled workstations.",
        "Domain Users also has ReadLAPSPassword on some hosts (rollout debt).",
    ]
    b.checks = [
        {
            "id": "laps_readers",
            "type": "output_contains",
            "detector": "print_laps_readers",
            "must_contain": ["HELPDESK", "READLAPSPASSWORD"],
        },
        {
            "id": "laps_enabled_some",
            "type": "output_contains",
            "detector": "print_laps_status",
            "must_contain": ["LAPS ENABLED"],
        },
    ]
    return b.files_and_gt(sc)


def build_s14(seed: int) -> Tuple[dict, dict]:
    """DNSAdmins member + GenericAll on DC."""
    sc = ENGAGEMENT_SCENARIOS[13]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    dns_user = b.add_user(1100, "dns_ops")
    # RID 1102 historically DNSAdmins in some domains; use custom
    dnsadmins = b.add_group(1102, "DnsAdmins", [_mem(dns_user)], highvalue=True)
    da = b.add_user(1101, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(dns_user), _mem(da)]
    dc = b.add_computer(
        1001,
        "DC01",
        is_dc=True,
        haslaps=True,
        aces=[
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(b.sid_admins, "Group", "GenericAll"),
            _ace(dnsadmins, "Group", "GenericAll"),
            _ace(dnsadmins, "Group", "WriteDacl"),
        ],
    )
    # Ensure DC is treated as high-value for dangerous-ACL reporting
    for c in b.computers:
        if c["ObjectIdentifier"] == dc:
            c["Properties"]["highvalue"] = True
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(40, 40)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ]
    )
    b.notes = [
        "dns_ops is DnsAdmins; group has GenericAll on DC01.",
        "Classic DNS service abuse path once on-box rights exist.",
    ]
    b.checks = [
        {
            "id": "dangerous_dc",
            "type": "output_contains",
            "detector": "print_dangerous_permissions",
            "must_contain": ["DNSADMINS"],
        },
        {
            "id": "dossier_dns",
            "type": "dossier_impact",
            "principal": b.uname("dns_ops"),
            "min_impact": 1,
        },
    ]
    return b.files_and_gt(sc)


def build_s15(seed: int) -> Tuple[dict, dict]:
    """Print Operators nesting from helpdesk."""
    sc = ENGAGEMENT_SCENARIOS[14]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    hd = b.add_user(1100, "print_help")
    # Builtin Print Operators often S-1-5-32-550
    po = b.add_group(
        0,
        "Print Operators",
        [_mem(hd)],
        highvalue=True,
        oid=b.wk("S-1-5-32-550"),
    )
    so = b.add_group(
        0,
        "Server Operators",
        [],
        highvalue=True,
        oid=b.wk("S-1-5-32-549"),
    )
    da = b.add_user(1101, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(hd), _mem(da)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(35, 40)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ]
    )
    b.notes = [
        "print_help is a member of Print Operators (built-in).",
        "Server Operators group present (empty) for inventory/HV surface.",
    ]
    b.checks = [
        {
            "id": "priv_inventory",
            "type": "output_contains",
            "detector": "print_privilege_inventory",
            "must_contain_any": ["PRINT OPERATORS", "SERVER OPERATORS"],
        },
        {
            "id": "hv_or_paths",
            "type": "output_contains",
            "detector": "print_shortest_paths",
            "must_contain_any": ["DOMAIN ADMINS", "PRINT OPERATORS", "DA_ADMIN"],
        },
    ]
    return b.files_and_gt(sc)


def build_s16(seed: int) -> Tuple[dict, dict]:
    """WDigest-adjacent: LocalAdmin + DA session (registry not in SH)."""
    sc = ENGAGEMENT_SCENARIOS[15]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    user = b.add_user(1100, "desk_user")
    da = b.add_user(1101, "da_helpdesk_break", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(user), _mem(da)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    b.add_computer(
        1002,
        "WS-HELP01",
        haslaps=False,
        sessions=[{"UserSID": da}],
        local_groups=[
            {
                "ObjectIdentifier": f"{b.sid(1002)}-544",
                "Name": "ADMINISTRATORS@WS-HELP01",
                "Results": [{"ObjectIdentifier": user, "ObjectType": "User"}],
            }
        ],
    )
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(40, 45)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ]
    )
    b.notes = [
        "Graph shows LocalAdmin + DA HasSession (tiering fail).",
        "WDigest UseLogonCredential is host registry — not present in SharpHound JSON.",
    ]
    b.checks = [
        {
            "id": "localadmin",
            "type": "output_contains",
            "detector": "print_sessions_localadmin",
            "must_contain": ["DESK_USER", "LOCALADMIN"],
            "must_not_contain": ["GENERICALL"],
        },
    ]
    return b.files_and_gt(sc)


def build_s17(seed: int) -> Tuple[dict, dict]:
    """WriteDacl on domain + GenericAll on krbtgt from IT group."""
    sc = ENGAGEMENT_SCENARIOS[16]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    it_user = b.add_user(1100, "it_mike")
    itg = b.add_group(2001, "IT_Support", [_mem(it_user)])
    # krbtgt is typically RID 502
    krbtgt = b.add_user(
        502,
        "krbtgt",
        highvalue=True,
        aces=[
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(b.sid_admins, "Group", "GenericAll"),
            _ace(itg, "Group", "GenericAll"),
            _ace(itg, "Group", "WriteDacl"),
        ],
    )
    da = b.add_user(1101, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(it_user), _mem(da), _mem(krbtgt)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(40, 40)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "Owns"),
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(itg, "Group", "WriteDacl"),
            _ace(itg, "Group", "GenericWrite"),
            _ace(itg, "Group", "WriteOwner"),
        ]
    )
    b.notes = [
        "IT_Support has WriteDacl/GenericWrite on the domain NC.",
        "IT_Support has GenericAll on krbtgt.",
    ]
    b.checks = [
        {
            "id": "dangerous_domain",
            "type": "output_contains",
            "detector": "print_dangerous_permissions",
            "must_contain_any": ["IT_SUPPORT", "KRBTGT", "ACLDEBT.LOCAL"],
        },
        {
            "id": "dossier_it",
            "type": "dossier_impact",
            "principal": b.uname("it_mike"),
            "min_impact": 1,
        },
    ]
    return b.files_and_gt(sc)


def build_s18(seed: int) -> Tuple[dict, dict]:
    """GPO content with cpassword / scheduled task markers in props."""
    sc = ENGAGEMENT_SCENARIOS[17]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    user = b.add_user(1100, "employee")
    da = b.add_user(1101, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(user), _mem(da)]
    gpo_id = "D4444444-4444-4444-4444-444444444444"
    b.gpos.append(
        {
            "ObjectIdentifier": gpo_id,
            "ObjectType": "GPO",
            "Properties": {
                "domain": b.domain,
                "name": b.uname("Legacy-LocalAdmin-GPP"),
                "domainsid": b.domain_sid,
                # Graph-visible markers for print_gpo_content_parsing
                "TaskName": "UpdateLocalAdmin",
                "ScriptPath": "\\\\domain\\sysvol\\scripts\\setadmin.bat",
                "cpassword": "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw",
                "ScheduledTask": "GPP_LocalAdmin",
            },
            "Aces": [
                _ace(b.sid_da, "Group", "GenericAll"),
                _ace(b.sid_du, "Group", "GenericWrite"),  # readable/editable sprawl
            ],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
    )
    b.add_ou("Workstations", links=[{"GUID": gpo_id, "IsEnforced": False}])
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(35, 40)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ]
    )
    b.notes = [
        "Legacy GPO plants TaskName/ScriptPath/cpassword props for GPO content parser.",
        "Real GPP lives in SYSVOL XML; SharpHound alone may not collect XML without --gpo-content-dir.",
    ]
    b.checks = [
        {
            "id": "gpo_content",
            "type": "output_contains",
            "detector": "print_gpo_content_parsing",
            "must_contain": ["LEGACY-LOCALADMIN-GPP", "EXPLOITABLE"],
        },
    ]
    return b.files_and_gt(sc)


def build_s19(seed: int) -> Tuple[dict, dict]:
    """Constrained delegation with protocol transition (TrustedToAuth)."""
    sc = ENGAGEMENT_SCENARIOS[18]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    web = b.add_user(1100, "svc_web")
    da = b.add_user(1101, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(web), _mem(da)]
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    b.add_computer(
        1002,
        "WEB01",
        haslaps=True,
        trusted_to_auth=True,
        allowed_to_delegate=[
            f"cifs/DC01.{sc['domain']}",
            f"ldap/DC01.{sc['domain']}",
            f"http/intranet.{sc['domain'].lower()}",
        ],
    )
    # also mark user trustedtoauth for constrained on service account
    for u in b.users:
        if u["ObjectIdentifier"] == web:
            u["Properties"]["trustedtoauth"] = True
            u["AllowedToDelegate"] = [f"http/intranet.{sc['domain'].lower()}"]
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(40, 40)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
        ]
    )
    b.notes = [
        "WEB01 has TrustedToAuth + AllowedToDelegate (protocol transition).",
        "svc_web also has constrained delegation flags.",
    ]
    b.checks = [
        {
            "id": "constrained",
            "type": "output_contains",
            "detector": "print_constrained_delegation",
            "must_contain_any": ["WEB01", "SVC_WEB", "TRUSTED_TO_AUTH", "PROTOCOL"],
        },
    ]
    return b.files_and_gt(sc)


def build_s20(seed: int) -> Tuple[dict, dict]:
    """MSOL / Entra Connect unexpected DCSync."""
    sc = ENGAGEMENT_SCENARIOS[19]
    b = EnvBuilder(sc["domain"], seed)
    b.add_baseline_groups()
    msol = b.add_user(
        1100,
        "MSOL_A1B2C3D4E5F6",
        description="Microsoft Entra Connect sync account",
        pwdneverexpires=True,
    )
    da = b.add_user(1101, "da_admin", highvalue=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_da:
            g["Members"].append(_mem(da))
        if g["ObjectIdentifier"] == b.sid_du:
            g["Members"] += [_mem(msol), _mem(da)]
    # Sync server
    b.add_computer(
        1002,
        "AADCONNECT01",
        haslaps=True,
        sessions=[{"UserSID": msol}],
        local_groups=[
            {
                "ObjectIdentifier": f"{b.sid(1002)}-544",
                "Name": "ADMINISTRATORS@AADCONNECT01",
                "Results": [{"ObjectIdentifier": msol, "ObjectType": "User"}],
            }
        ],
    )
    dc = b.add_computer(1001, "DC01", is_dc=True, haslaps=True)
    for g in b.groups:
        if g["ObjectIdentifier"] == b.sid_dcg:
            g["Members"].append(_mem(dc, "Computer"))
    b.add_filler(45, 50)
    b.finalize_domain(
        [
            _ace(b.sid_admins, "Group", "Owns"),
            _ace(b.sid_admins, "Group", "GetChanges"),
            _ace(b.sid_admins, "Group", "GetChangesAll"),
            _ace(b.sid_da, "Group", "GenericAll"),
            _ace(b.sid_ea, "Group", "GenericAll"),
            _ace(msol, "User", "GetChanges"),
            _ace(msol, "User", "GetChangesAll"),
        ]
    )
    b.notes = [
        "MSOL_* has unexpected GetChanges+GetChangesAll on the domain.",
        "AADCONNECT01 hosts the sync account (session + local admin).",
    ]
    b.checks = [
        {
            "id": "msol_unexpected",
            "type": "output_contains",
            "detector": "print_dcsync_rights",
            "must_contain": ["MSOL_", "UNEXPECTED"],
        },
        {
            "id": "msol_finding",
            "type": "finding",
            "category": "DCSync",
            "must_contain": "MSOL_",
        },
        {
            "id": "da_expected",
            "type": "output_contains",
            "detector": "print_dcsync_rights",
            "must_contain": ["DOMAIN ADMINS", "EXPECTED"],
        },
    ]
    return b.files_and_gt(sc)


BUILDERS = {
    "s01_kerberoast_dcsync_svc": build_s01,
    "s02_helpdesk_genericall_backup_dcsync": build_s02,
    "s03_unconstrained_jump_da_session": build_s03,
    "s04_adcs_esc1": build_s04,
    "s05_gpo_edit_high_tier": build_s05,
    "s06_asrep_acl_chain": build_s06,
    "s07_rbcd_machine_quota_path": build_s07,
    "s08_localadmin_cached_da": build_s08,
    "s09_nested_acl_multihop": build_s09,
    "s10_gpo_svc_delegation_combo": build_s10,
    "s11_svc_in_domain_admins": build_s11,
    "s12_adcs_esc8_web_enrollment": build_s12,
    "s13_laps_overpermissive_readers": build_s13,
    "s14_dnsadmins_dangerous_rights": build_s14,
    "s15_print_operators_path": build_s15,
    "s16_tiering_fail_wdigest_adjacent": build_s16,
    "s17_domain_nc_krbtgt_acl": build_s17,
    "s18_gpp_cpassword_gpo": build_s18,
    "s19_constrained_protocol_transition": build_s19,
    "s20_entra_connect_overpriv": build_s20,
}


def build_engagement_scenario(scenario_id: str, seed: int) -> Tuple[dict, dict]:
    if scenario_id not in BUILDERS:
        raise KeyError(f"Unknown scenario {scenario_id}")
    return BUILDERS[scenario_id](seed)


def list_scenarios() -> List[dict]:
    return list(ENGAGEMENT_SCENARIOS)
