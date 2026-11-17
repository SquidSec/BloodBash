# BloodBash glossary

Terms used across the docs. Definitions describe how BloodBash uses the term.

| Related | Purpose |
|---------|---------|
| [User guide](user-guide.md) | Feature reference |
| [Architecture](architecture.md) | Design |
| [Docs index](README.md) | Catalog |

---

## A

**ACL**: Access Control List. The DACL on an AD object, made of ACEs. BloodBash turns each ACE into an edge from the principal to the object.

**ACE**: Access Control Entry. One grant of a right (`GenericAll`, `WriteDacl`, …) from a principal to an object.

**ADCS**: Active Directory Certificate Services. The CA and template infrastructure whose misconfigurations are ESC1 through ESC13.

**AdminTo**: BloodHound edge meaning a principal has local admin on a computer. BloodBash stores the collector's `LocalAdmin` label and projects it as `AdminTo` for task lists.

**AdminCount**: AD attribute set to 1 on accounts that were once in a protected group. A signal of historical privilege.

**AS-REP roasting**: Requesting an AS-REP for an account with preauthentication disabled, then cracking the encrypted part offline. Requires `DONT_REQ_PREAUTH`.

**Attack path**: A chain of relationships from a principal you control to a high-value target.

**AzureHound**: Entra ID collector. Produces the JSON BloodBash reads for Azure checks.

## B

**BloodHound**: SpecterOps graph tool for AD and Entra. BloodBash reproduces its labels and relationship names without Neo4j.

**Bolt**: Neo4j's binary protocol. BloodBash does not use it; PlumHound does.

## C

**Collection**: One run of a collector, producing a set of JSON files. BloodBash accepts a collection as a directory or zip.

**Collection health**: BloodBash's banner reporting object counts, edge coverage, and a reliability ceiling.

**Compromise dossier**: BloodBash's outbound report for a foothold principal. Built with `--from-user`.

**Constrained delegation**: Kerberos delegation limited to named services. Represented by `allowedtodelegate`.

**CSV pack**: PlumHound-shaped multi-CSV output. Built with `--csv-pack`.

## D

**DCSync**: Replicating directory secrets by holding both `GetChanges` and `GetChangesAll` on a domain. BloodBash requires both rights on the same target.

**DOT**: Graphviz text format. Exported with `--dot`.

**Dossier**: See *compromise dossier*.

## E

**EA**: Enterprise Admins. A forest-level privileged group.

**Edge**: A relationship in the graph.

**Entra ID**: Microsoft's cloud identity service, formerly Azure AD.

**ESC1-ESC13**: Certificate template and CA misconfiguration classes documented by SpecterOps. BloodBash covers ESC1-ESC8, plus ESC9 and ESC13 when the collector supplies the properties.

## F

**Foothold**: A principal you have just compromised. Analyzed with `--from-user`.

**Fingerprint**: Hash of collection paths, sizes, and modification times. Names the graph cache file.

## G

**Golden path**: One path to Domain Admins, printed as plain text. Built with `--golden-path`, exits 1 when there is none.

**GPO**: Group Policy Object. Write access to a linked GPO means code execution across its scope.

**GraphML**: XML graph format for Gephi and yEd. Exported with `--graphml`.

## H

**HasSession**: Edge meaning a user has a logon session on a computer. Indicates credential exposure.

**High-value target (HV)**: A principal whose compromise matters. Includes DA, EA, builtin Administrators, and DC computers.

## I

**Indirect**: Rights or paths reached through group nesting rather than directly. Enabled with `--indirect`.

**Ingest**: Reading collector JSON and building the graph.

## K

**Kerberoasting**: Requesting a service ticket for an account with an SPN, then cracking it offline.

## L

**LAPS**: Local Administrator Password Solution. Randomizes local admin passwords. BloodBash reports coverage and readers.

**LocalAdmin**: Collector edge label for local admin rights. Projected as `AdminTo`.

## M

**MemberOf**: Edge from a principal to a group it belongs to.

## N

**Neo4j**: Graph database BloodHound uses. BloodBash requires none.

**NetworkX**: Python graph library BloodBash uses for the in-memory graph.

## O

**Object ID**: Unique identifier for an AD object, usually a SID or GUID. BloodBash falls back to a stable SHA-256 when a collector omits one.

**Owned**: A principal you already control, supplied with `--owned`. Used for inbound pathfinding.

## P

**Path break**: The set of edges whose removal breaks the most attack paths. Built with `--path-break`.

**Path mode**: Edge weighting for pathfinding: `short`, `abuse`, or `deep`.

**PNE**: Password Never Expires.

**Projection**: Read-only BloodHound-shaped view of the graph, used by task lists. Never mutated.

**Profile**: YAML file bundling flags into a named run mode. Built with `--profile`.

## R

**RBCD**: Resource-based constrained delegation. Configured via `msDS-AllowedToActOnBehalfOfOtherIdentity`.

**Report pack**: Multi-page HTML suite plus per-section CSVs. Built with `--report-pack`.

**Roastable**: Account whose credential can be obtained offline via Kerberoasting or AS-REP roasting.

## S

**SARIF**: Static Analysis Results Interchange Format. Used by GitHub code scanning. Exported with `--export sarif`.

**SharpHound**: SpecterOps AD collector. The primary input format.

**SID history**: Prior SIDs retained on an account. Abusable when trust SID filtering is disabled.

**SID-only node**: A principal referenced by SID in a collection but never fully described. Counted in collection health.

**Snapshot**: Saved findings state for trend comparison. Built with `--snapshot`.

**Suppression**: YAML entry hiding an accepted finding, optionally until an expiry date.

## T

**Task list**: PlumHound-format file of Cypher queries, one per line. Run with `--tasks`.

**Task query subset**: The read-only Cypher subset BloodBash evaluates.

## U

**Unconstrained delegation**: Delegation with no service restriction. A compromised host can capture any authenticating user's TGT.

## W

**Watch mode**: Re-run analysis when collector files change. Enabled with `--watch`.

---

For authorized security testing only.
