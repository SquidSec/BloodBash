##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'open3'
require 'shellwords'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SquidSec BloodBash — SharpHound & AzureHound Offline Analyzer',
      'Description'    => %q{
        This module wraps SquidSec's BloodBash open source tool to analyze SharpHound and
        AzureHound JSON files offline. It detects AD and Azure/Entra ID attack paths,
        misconfigurations (ADCS ESC, DCSync, dangerous ACLs, roastable accounts, shadow
        credentials, GPO abuse, LAPS gaps, privileged Azure roles, etc.), PlumHound-style
        inventory/path remediation, and compromise dossiers for foothold users.
        Results are displayed and can be reported to the Metasploit database.

        BloodBash is created and managed by SquidSec (https://squidoffense.com/).
        Requires BloodBash v1.4.0+ and Python dependencies (NetworkX, Rich, tqdm, PyYAML)
        installed on the system (or a SquidSec-published standalone binary).
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['☣️ Mr. The Plague ☣️', 'DotNetRussell', 'SquidSec'],
      'References'     => [
        ['URL', 'https://squidoffense.com/'],
        ['URL', 'https://github.com/DotNetRussell/BloodBash'],
        ['URL', 'https://github.com/ly4k/BloodHound'],
        ['URL', 'https://github.com/BloodHoundAD/AzureHound'],
      ],

      'Platform'       => 'ruby',
      'Arch'           => ARCH_RUBY,
      'DisclosureDate' => '2026-06-27'
    ))

    register_options([
      # ── Input / runtime ──────────────────────────────────────────────
      OptString.new('BLOODBASH_PATH', [true, 'Path to BloodBash.py or standalone binary', File.expand_path('~/BloodBash/BloodBash.py')]),
      OptString.new('JSON_DIR', [true, 'Directory or zip archive containing SharpHound/AzureHound JSON files', File.expand_path('~/BloodBash/SampleSharphoundADData')]),
      OptString.new('PYTHON', [false, 'Python interpreter (ignored when BLOODBASH_PATH is a non-.py binary)', 'python3']),
      OptBool.new('ALL_CHECKS', [false, 'Run all analyses (equivalent to --all)', false]),
      OptString.new('PROFILE', [false, 'YAML analysis profile path or built-in name (quick, adcs-heavy, hygiene)', nil]),
      OptBool.new('VERBOSE', [false, 'Enable verbose summary', false]),
      OptBool.new('FAST', [false, 'Enable fast mode (limit heavy pathfinding)', false]),
      OptBool.new('DEBUG', [false, 'Enable verbose debug output', false]),
      OptBool.new('ALL_FINDINGS', [false, 'Print complete findings table at end of run (not top-20 only)', false]),
      OptString.new('LOG_FILE', [false, 'Write a run audit log (empty string → bloodbash.log)', nil]),

      # ── AD privilege & abuse ─────────────────────────────────────────
      OptBool.new('SHORTEST_PATHS', [false, 'Compute shortest paths to high-value targets', false]),
      OptBool.new('DANGEROUS_PERMISSIONS', [false, 'Check dangerous permissions', false]),
      OptBool.new('ADCS', [false, 'Check ADCS ESC vulnerabilities', false]),
      OptBool.new('GPO_ABUSE', [false, 'Check GPO abuse risks', false]),
      OptBool.new('DCSYNC', [false, 'Check DCSync rights', false]),
      OptBool.new('RBCD', [false, 'Check RBCD configurations', false]),
      OptBool.new('SESSIONS', [false, 'Check session/local admin summaries', false]),
      OptBool.new('SID_HISTORY', [false, 'Check SID history abuse', false]),
      OptBool.new('UNCONSTRAINED_DELEGATION', [false, 'Check unconstrained delegation', false]),
      OptBool.new('CONSTRAINED_DELEGATION', [false, 'Check constrained delegation', false]),
      OptBool.new('SHADOW_CREDENTIALS', [false, 'Check Shadow Credentials (KeyCredentialLink)', false]),
      OptBool.new('LAPS', [false, 'Check LAPS enabled/disabled status', false]),
      OptBool.new('GPO_PARSING', [false, 'Basic GPO content parsing', false]),
      OptString.new('GPO_CONTENT_DIR', [false, 'Directory containing GPO XML reports for full content analysis', nil]),

      # ── AD credentials ───────────────────────────────────────────────
      OptBool.new('KERBEROASTABLE', [false, 'Check Kerberoastable accounts (hasspn or SPN list)', false]),
      OptBool.new('AS_REP_ROASTABLE', [false, 'Check AS-REP roastable accounts', false]),
      OptBool.new('PASSWORD_DESCRIPTIONS', [false, 'Check passwords stored in user descriptions', false]),
      OptBool.new('PASSWORD_NEVER_EXPIRES', [false, 'Check PasswordNeverExpires / pwdneverexpires users', false]),
      OptBool.new('PASSWORD_NOT_REQUIRED', [false, 'Check PasswordNotRequired / passwordnotreqd users', false]),

      # ── Azure / Entra ────────────────────────────────────────────────
      OptBool.new('AZURE_PRIVILEGED_ROLES', [false, 'Check Azure privileged roles', false]),
      OptBool.new('AZURE_APP_SECRETS', [false, 'Check Azure app secrets/certificates', false]),
      OptBool.new('AZURE_MFA_BYPASS', [false, 'Check Azure MFA bypass risks', false]),
      OptBool.new('AZURE_GUEST_ACCESS', [false, 'Check Azure guest user risks', false]),
      OptBool.new('AZURE_SP_ABUSE', [false, 'Check Azure service principal abuse', false]),

      # ── Paths & remediation ──────────────────────────────────────────
      OptBool.new('INDIRECT', [false, 'Include indirect paths/permissions', false]),
      OptBool.new('DEEP_ANALYSIS', [false, 'Enable slow group nesting depth + cycle detection', false]),
      OptString.new('BUSIEST_PATHS', [false, 'Rank principals on most HV paths (short|all; empty → short)', nil, ['short', 'all']]),
      OptInt.new('BUSIEST_PATHS_TOP', [false, 'Top N busiest principals (default 5)', 5]),
      OptBool.new('PATH_BREAK', [false, 'Recommend edges to remove to break the most attack paths', false]),
      OptInt.new('PATH_BREAK_TOP', [false, 'Top N path-break edges (default 15)', 15]),
      OptString.new('OWNED', [false, 'Comma-separated owned principals — find paths *to* them (inbound)', nil]),
      OptString.new('FROM_USER', [false, 'Compromise dossier for USER (outbound foothold analysis); comma-separated OK', nil]),
      OptString.new('FROM_USER_EXPORT', [false, 'Export dossier lists to DIR (empty string → compromise-<user>/)', nil]),
      OptString.new('PATH_FROM', [false, 'Comma-separated source principals for arbitrary paths', nil]),
      OptString.new('PATH_TO', [false, 'Comma-separated target principals for arbitrary paths', nil]),
      OptString.new('INSPECT', [false, 'Comma-separated nodes to inspect (props + edges)', nil]),

      # ── Inventory ────────────────────────────────────────────────────
      OptBool.new('INVENTORY', [false, 'Structural + password-age + stale + privilege inventories', false]),
      OptBool.new('PASSWORD_AGE', [false, 'Password age inventory ladders', false]),
      OptBool.new('STALE_ACCOUNTS', [false, 'Inactive / never-active account inventory', false]),
      OptBool.new('PRIVILEGE_INVENTORY', [false, 'Privileged group membership inventory', false]),
      OptBool.new('OWNED_INVENTORY', [false, 'AdminTo/MemberOf inventory for --owned principals', false]),

      # ── Export & deliverables ────────────────────────────────────────
      OptBool.new('EXPORT_BH', [false, 'Export full graph as BloodHound-compatible JSON', false]),
      OptString.new('EXPORT', [false, 'Export format (md, json, html, csv, yaml)', nil, ['md', 'json', 'html', 'csv', 'yaml']]),
      OptString.new('DOT', [false, 'Export key subgraph to Graphviz DOT file (optional filename)', nil]),
      OptString.new('REPORT_PACK', [false, 'Write multi-page HTML report suite + CSVs + index.html to DIR', nil]),
      OptString.new('EXPORT_ZIP', [false, 'Zip the report pack (empty string → bloodbash-reports.zip)', nil]),
      OptString.new('DB', [false, 'SQLite DB path for graph persistence (save/load)', nil]),

      # ── Filters ──────────────────────────────────────────────────────
      OptString.new('DOMAIN', [false, 'Filter by AD domain or Azure tenantId (case-insensitive)', nil]),
      OptString.new('RHOSTS', [false, 'Target hosts (dummy for offline tool; used for report_vuln host)', '127.0.0.1'])
    ])
  end

  def run
    bloodbash_path = File.expand_path(datastore['BLOODBASH_PATH'])
    json_dir = File.expand_path(datastore['JSON_DIR'])

    unless File.exist?(bloodbash_path)
      print_error("BloodBash script/binary not found at #{bloodbash_path}")
      return
    end

    unless File.exist?(json_dir) || (datastore['DB'] && File.exist?(File.expand_path(datastore['DB'])))
      print_error("JSON directory/archive not found at #{json_dir} (and no existing DB to load)")
      return
    end

    cmd = build_command(bloodbash_path, json_dir)
    print_status("Executing BloodBash: #{Shellwords.shelljoin(cmd)}")

    stdout, stderr, status = Open3.capture3(*cmd)
    output = [stdout, stderr].join

    unless status.success?
      print_error("BloodBash execution failed with exit code #{status.exitstatus}")
      print_error("Output: #{output}") unless output.strip.empty?
      return
    end

    print_status('BloodBash analysis completed. Output:')
    print_line(output)

    report_findings(output)
  end

  def build_command(bloodbash_path, json_dir)
    cmd = bloodbash_invocation(bloodbash_path)
    cmd << json_dir

    # Boolean store_true flags (option key → CLI flag)
    flag_map = {
      'ALL_CHECKS' => '--all',
      'ALL_FINDINGS' => '--all-findings',
      'SHORTEST_PATHS' => '--shortest-paths',
      'DANGEROUS_PERMISSIONS' => '--dangerous-permissions',
      'ADCS' => '--adcs',
      'GPO_ABUSE' => '--gpo-abuse',
      'DCSYNC' => '--dcsync',
      'RBCD' => '--rbcd',
      'SESSIONS' => '--sessions',
      'KERBEROASTABLE' => '--kerberoastable',
      'AS_REP_ROASTABLE' => '--as-rep-roastable',
      'SID_HISTORY' => '--sid-history',
      'UNCONSTRAINED_DELEGATION' => '--unconstrained-delegation',
      'PASSWORD_DESCRIPTIONS' => '--password-descriptions',
      'PASSWORD_NEVER_EXPIRES' => '--password-never-expires',
      'PASSWORD_NOT_REQUIRED' => '--password-not-required',
      'SHADOW_CREDENTIALS' => '--shadow-credentials',
      'GPO_PARSING' => '--gpo-parsing',
      'CONSTRAINED_DELEGATION' => '--constrained-delegation',
      'LAPS' => '--laps',
      'AZURE_PRIVILEGED_ROLES' => '--azure-privileged-roles',
      'AZURE_APP_SECRETS' => '--azure-app-secrets',
      'AZURE_MFA_BYPASS' => '--azure-mfa-bypass',
      'AZURE_GUEST_ACCESS' => '--azure-guest-access',
      'AZURE_SP_ABUSE' => '--azure-sp-abuse',
      'VERBOSE' => '--verbose',
      'FAST' => '--fast',
      'INDIRECT' => '--indirect',
      'DEEP_ANALYSIS' => '--deep-analysis',
      'EXPORT_BH' => '--export-bh',
      'DEBUG' => '--debug',
      'PATH_BREAK' => '--path-break',
      'PASSWORD_AGE' => '--password-age',
      'STALE_ACCOUNTS' => '--stale-accounts',
      'PRIVILEGE_INVENTORY' => '--privilege-inventory',
      'OWNED_INVENTORY' => '--owned-inventory',
      'INVENTORY' => '--inventory'
    }

    flag_map.each do |option, flag|
      cmd << flag if datastore[option]
    end

    # String options with values
    add_string_option(cmd, '--domain', datastore['DOMAIN'])
    add_string_option(cmd, '--owned', datastore['OWNED'])
    add_string_option(cmd, '--from-user', datastore['FROM_USER'])
    add_string_option(cmd, '--path-from', datastore['PATH_FROM'])
    add_string_option(cmd, '--path-to', datastore['PATH_TO'])
    add_string_option(cmd, '--inspect', datastore['INSPECT'])
    add_string_option(cmd, '--gpo-content-dir', datastore['GPO_CONTENT_DIR'])
    add_string_option(cmd, '--db', datastore['DB'])
    add_string_option(cmd, '--profile', datastore['PROFILE'])
    add_string_option(cmd, '--report-pack', datastore['REPORT_PACK'])

    # Optional-value flags (CLI nargs='?'): present with or without a path/mode
    add_optional_value_flag(cmd, '--from-user-export', datastore['FROM_USER_EXPORT'])
    add_optional_value_flag(cmd, '--log-file', datastore['LOG_FILE'])
    add_optional_value_flag(cmd, '--export-zip', datastore['EXPORT_ZIP'])
    add_optional_value_flag(cmd, '--dot', datastore['DOT'])

    # busiest-paths: mode short|all (empty string → flag only; CLI defaults to short)
    unless datastore['BUSIEST_PATHS'].nil?
      mode = datastore['BUSIEST_PATHS'].to_s.strip
      cmd << '--busiest-paths'
      cmd << mode unless mode.empty?
      cmd << '--busiest-paths-top'
      cmd << datastore['BUSIEST_PATHS_TOP'].to_s
    end

    if datastore['PATH_BREAK']
      cmd << '--path-break-top'
      cmd << datastore['PATH_BREAK_TOP'].to_s
    end

    if datastore['EXPORT']
      cmd << '--export'
      cmd << datastore['EXPORT']
    end

    cmd
  end

  # Prefer standalone binary when path is not a .py script.
  def bloodbash_invocation(bloodbash_path)
    if bloodbash_path.downcase.end_with?('.py')
      [datastore['PYTHON'].to_s.empty? ? 'python3' : datastore['PYTHON'], bloodbash_path]
    else
      [bloodbash_path]
    end
  end

  def add_string_option(cmd, flag, value)
    return if value.nil?

    str = value.to_s
    return if str.strip.empty?

    cmd << flag
    cmd << str
  end

  # For CLI flags with nargs='?': set to "" (empty) means flag-only; non-empty passes value.
  # Unset (nil) means omit the flag entirely.
  def add_optional_value_flag(cmd, flag, value)
    return if value.nil?

    cmd << flag
    str = value.to_s
    cmd << str unless str.empty?
  end

  def report_findings(output)
    clean = normalize_table_text(strip_ansi(output))
    findings = []

    clean.each_line do |line|
      next if line.strip.empty?

      # BloodBash findings tables (Rich, after normalize_table_text):
      #   | # | Severity Score | Category | Details |
      # Also accept legacy 3-col rows without the index column.
      if (match = line.match(/^\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*([^|]+)\|\s*(.+?)\s*\|?\s*$/))
        # 4-col: #, score, category, details
        score = match[2].to_i
        category = match[3].strip
        details = match[4].strip
        next if category.casecmp('category').zero? || details.casecmp('details').zero?
        next if category == '(none)'

        findings << { score: score, category: category, details: details }
        next
      end

      if (match = line.match(/^\|\s*(\d+)\s*\|\s*([^|]+)\|\s*(.+?)\s*\|?\s*$/))
        # 3-col legacy: score, category, details (no index)
        score = match[1].to_i
        category = match[2].strip
        details = match[3].strip
        next if category.casecmp('category').zero? || details.casecmp('details').zero?
        next if category.casecmp('severity score').zero?
        next if category == '(none)'
        # Skip header-ish rows and pure index-only misparses
        next if score.zero? && category =~ /^\d+$/

        findings << { score: score, category: category, details: details }
        next
      end

      HIGH_SEVERITY_PATTERNS.each do |pattern, category|
        if line =~ pattern
          findings << {
            score: 8,
            category: category,
            details: line.strip
          }
          break
        end
      end
    end

    findings.uniq! { |f| "#{f[:category]}:#{f[:details]}" }

    findings.each do |finding|
      report_vuln(
        host: datastore['RHOSTS'],
        name: "BloodBash: #{finding[:category]}",
        info: "Severity #{finding[:score]}: #{finding[:details]}",
        refs: ['BloodHound', 'SharpHound', 'AzureHound', 'BloodBash', 'SquidSec']
      )
    end

    if findings.empty?
      print_status('No prioritized or high-severity findings were parsed from BloodBash output.')
    else
      print_good("Reported #{findings.size} findings to Metasploit database.")
    end
  end

  def strip_ansi(text)
    text.gsub(/\e\[[0-9;]*m/, '')
  end

  # Rich tables use Unicode box-drawing (│ ┃ etc.); normalize to ASCII '|' for parsing.
  def normalize_table_text(text)
    text.gsub(/[│┃┊┋╎╏]/, '|')
  end

  HIGH_SEVERITY_PATTERNS = [
    [/DCSync/i, 'DCSync'],
    [/ESC[1-9]|ESC1[0-3]/i, 'ADCS'],
    [/RBCD/i, 'RBCD'],
    [/GenericAll|WriteDacl|ResetPassword|WriteOwner|AddKeyCredentialLink/i, 'Dangerous Permissions'],
    [/Kerberoastable|has SPN/i, 'Kerberoastable'],
    [/AS-REP roastable|DONT_REQ_PREAUTH/i, 'AS-REP Roastable'],
    [/Shadow Credential/i, 'Shadow Credentials'],
    [/Password Never Expires/i, 'Password Never Expires'],
    [/Password Not Required/i, 'Password Not Required'],
    [/password in description/i, 'Password in Description'],
    [/Unconstrained delegation/i, 'Unconstrained Delegation'],
    [/Constrained Delegation/i, 'Constrained Delegation'],
    [/LAPS not enabled/i, 'LAPS'],
    [/GPO Abuse|Weak GPO|cPassword/i, 'GPO Abuse'],
    [/SID History/i, 'SID History Abuse'],
    [/path break|Busiest path/i, 'Path Remediation'],
    [/Compromise dossier|FROM_USER/i, 'Compromise Dossier'],
    [/Global Administrator|Privileged Role Admin/i, 'Azure Privileged Roles'],
    [/MFA bypass|without MFA/i, 'Azure MFA Bypass'],
    [/Service Principal abuse/i, 'Azure Service Principal Abuse'],
    [/guest user/i, 'Azure Guest Access'],
    [/app secret|certificate control/i, 'Azure App Secrets']
  ].freeze
end
