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
        misconfigurations (e.g., ADCS ESC vulnerabilities, dangerous permissions,
        privileged Azure roles), and other vulnerabilities. Results are displayed and
        can be reported to the Metasploit database.

        BloodBash is created and managed by SquidSec (https://squidoffense.com/).
        Requires BloodBash v1.3.1+ and Python dependencies (NetworkX, Rich, tqdm, PyYAML)
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
      OptString.new('BLOODBASH_PATH', [true, 'Path to BloodBash.py script', File.expand_path('~/BloodBash/BloodBash.py')]),
      OptString.new('JSON_DIR', [true, 'Directory or zip archive containing SharpHound/AzureHound JSON files', File.expand_path('~/BloodBash/SampleSharphoundADData')]),
      OptString.new('PYTHON', [false, 'Python interpreter to use', 'python3']),
      OptBool.new('ALL_CHECKS', [false, 'Run all analyses (equivalent to --all)', false]),
      OptBool.new('SHORTEST_PATHS', [false, 'Compute shortest paths to high-value targets', false]),
      OptBool.new('DANGEROUS_PERMISSIONS', [false, 'Check dangerous permissions', false]),
      OptBool.new('ADCS', [false, 'Check ADCS ESC vulnerabilities', false]),
      OptBool.new('GPO_ABUSE', [false, 'Check GPO abuse risks', false]),
      OptBool.new('DCSYNC', [false, 'Check DCSync rights', false]),
      OptBool.new('RBCD', [false, 'Check RBCD configurations', false]),
      OptBool.new('SESSIONS', [false, 'Check session/local admin summaries', false]),
      OptBool.new('KERBEROASTABLE', [false, 'Check Kerberoastable accounts', false]),
      OptBool.new('AS_REP_ROASTABLE', [false, 'Check AS-REP roastable accounts', false]),
      OptBool.new('SID_HISTORY', [false, 'Check SID history abuse', false]),
      OptBool.new('UNCONSTRAINED_DELEGATION', [false, 'Check unconstrained delegation', false]),
      OptBool.new('PASSWORD_DESCRIPTIONS', [false, 'Check passwords stored in user descriptions', false]),
      OptBool.new('PASSWORD_NEVER_EXPIRES', [false, 'Check PasswordNeverExpires users', false]),
      OptBool.new('PASSWORD_NOT_REQUIRED', [false, 'Check PasswordNotRequired users', false]),
      OptBool.new('SHADOW_CREDENTIALS', [false, 'Check Shadow Credentials (KeyCredentialLink)', false]),
      OptBool.new('GPO_PARSING', [false, 'Basic GPO content parsing', false]),
      OptString.new('GPO_CONTENT_DIR', [false, 'Directory containing GPO XML reports for full content analysis', nil]),
      OptBool.new('CONSTRAINED_DELEGATION', [false, 'Check constrained delegation', false]),
      OptBool.new('LAPS', [false, 'Check LAPS enabled/disabled status', false]),
      OptBool.new('AZURE_PRIVILEGED_ROLES', [false, 'Check Azure privileged roles', false]),
      OptBool.new('AZURE_APP_SECRETS', [false, 'Check Azure app secrets/certificates', false]),
      OptBool.new('AZURE_MFA_BYPASS', [false, 'Check Azure MFA bypass risks', false]),
      OptBool.new('AZURE_GUEST_ACCESS', [false, 'Check Azure guest user risks', false]),
      OptBool.new('AZURE_SP_ABUSE', [false, 'Check Azure service principal abuse', false]),
      OptBool.new('VERBOSE', [false, 'Enable verbose summary', false]),
      OptBool.new('FAST', [false, 'Enable fast mode (skip heavy pathfinding)', false]),
      OptBool.new('INDIRECT', [false, 'Include indirect paths/permissions', false]),
      OptBool.new('DEEP_ANALYSIS', [false, 'Enable slow group nesting depth + cycle detection', false]),
      OptBool.new('EXPORT_BH', [false, 'Export full graph as BloodHound-compatible JSON', false]),
      OptBool.new('DEBUG', [false, 'Enable verbose debug output', false]),
      OptString.new('DOMAIN', [false, 'Filter by AD domain or Azure tenantId', nil]),
      OptString.new('OWNED', [false, 'Comma-separated owned principals (find paths to them)', nil]),
      OptString.new('PATH_FROM', [false, 'Comma-separated source principals for arbitrary paths', nil]),
      OptString.new('PATH_TO', [false, 'Comma-separated target principals for arbitrary paths', nil]),
      OptString.new('INSPECT', [false, 'Comma-separated nodes to inspect', nil]),
      OptString.new('EXPORT', [false, 'Export format (md, json, html, csv, yaml)', nil, ['md', 'json', 'html', 'csv', 'yaml']]),
      OptString.new('DOT', [false, 'Export key subgraph to Graphviz DOT file (optional filename)', nil]),
      OptString.new('DB', [false, 'SQLite DB path for graph persistence (save/load)', nil]),
      OptString.new('RHOSTS', [false, 'Target hosts (dummy for offline tool)', '127.0.0.1'])
    ])
  end

  def run
    bloodbash_path = File.expand_path(datastore['BLOODBASH_PATH'])
    json_dir = File.expand_path(datastore['JSON_DIR'])

    unless File.exist?(bloodbash_path)
      print_error("BloodBash script not found at #{bloodbash_path}")
      return
    end

    unless File.exist?(json_dir)
      print_error("JSON directory or archive not found at #{json_dir}")
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
    cmd = [datastore['PYTHON'], bloodbash_path, json_dir]

    flag_map = {
      'ALL_CHECKS' => '--all',
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
      'DEBUG' => '--debug'
    }

    flag_map.each do |option, flag|
      cmd << flag if datastore[option]
    end

    add_string_option(cmd, '--domain', datastore['DOMAIN'])
    add_string_option(cmd, '--owned', datastore['OWNED'])
    add_string_option(cmd, '--path-from', datastore['PATH_FROM'])
    add_string_option(cmd, '--path-to', datastore['PATH_TO'])
    add_string_option(cmd, '--inspect', datastore['INSPECT'])
    add_string_option(cmd, '--gpo-content-dir', datastore['GPO_CONTENT_DIR'])
    add_string_option(cmd, '--db', datastore['DB'])

    if datastore['EXPORT']
      cmd << '--export'
      cmd << datastore['EXPORT']
    end

    if datastore['DOT']
      cmd << '--dot'
      cmd << datastore['DOT']
    end

    cmd
  end

  def add_string_option(cmd, flag, value)
    return if value.nil? || value.strip.empty?

    cmd << flag
    cmd << value
  end

  def report_findings(output)
    clean = strip_ansi(output)
    findings = []

    clean.each_line do |line|
      next if line.strip.empty?

      if (match = line.match(/^\|\s*(\d+)\s*\|\s*([^|]+)\|\s*(.+?)\s*\|/))
        score = match[1].to_i
        category = match[2].strip
        details = match[3].strip
        next if category == 'Category' || details == 'Details'

        findings << {
          score: score,
          category: category,
          details: details
        }
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
        refs: ['BloodHound', 'SharpHound', 'AzureHound', 'BloodBash']
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

  HIGH_SEVERITY_PATTERNS = [
    [/DCSync/i, 'DCSync'],
    [/ESC[1-8]/i, 'ADCS'],
    [/RBCD/i, 'RBCD'],
    [/GenericAll|WriteDacl|ResetPassword|WriteOwner/i, 'Dangerous Permissions'],
    [/Kerberoastable/i, 'Kerberoastable'],
    [/AS-REP roastable/i, 'AS-REP Roastable'],
    [/Shadow Credential/i, 'Shadow Credentials'],
    [/Global Administrator|Privileged Role Admin/i, 'Azure Privileged Roles'],
    [/MFA bypass/i, 'Azure MFA Bypass'],
    [/Service Principal abuse/i, 'Azure Service Principal Abuse']
  ].freeze
end