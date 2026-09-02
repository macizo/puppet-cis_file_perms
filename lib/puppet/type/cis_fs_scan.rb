# frozen_string_literal: true

Puppet::Type.newtype(:cis_fs_scan) do
  @doc = <<-DOC
    Scans one or more directory trees for CIS filesystem controls and
    remediates where safe to do so — all in a single provider walk.

    Covers three CIS controls in one catalog resource:
      - Unexpected SUID/SGID binaries (CIS 6.1.9-6.1.12): reported and
        stripped unless listed in suid_whitelist.
      - World-writable files (CIS 6.1.x): reported and permission stripped.
      - Unowned files — no valid uid/gid (CIS 6.1.x): reported only,
        manual remediation required.
      - Local interactive-user dotfiles: ownership and permissions are
        checked, restricted files receive their tighter mode, and legacy
        trust files are reported or removed according to dotfile_enforce.

    Uses one shared Find walk for the filesystem checks, then inspects only
    the top level of applicable home directories for dotfile controls.
    Attach a weekly Puppet schedule to avoid scanning on every agent run.

    Runs in `--noop` mode as a pure audit: offenders are reported in the
    Puppet run report without being touched.

    @example Weekly scan of standard paths
      cis_fs_scan { 'weekly':
        paths          => ['/usr', '/bin', '/sbin', '/home', '/opt', '/var'],
        suid_whitelist => ['/usr/bin/sudo', '/usr/bin/su', '/usr/bin/passwd'],
        exclude        => ['/var/run', '/usr/local/games'],  # prune subtrees within the scanned paths
      }
  DOC

  newparam(:name, namevar: true) do
    desc 'Unique name for this scan (e.g. "weekly", "production").'
  end

  newparam(:paths) do
    desc 'Directory trees to scan. Defaults cover standard Linux paths.'
    defaultto ['/usr', '/bin', '/sbin', '/home', '/opt', '/var']

    validate do |value|
      Array(value).each do |v|
        raise ArgumentError, "path must be absolute, got '#{v}'" unless v.is_a?(String) && v.start_with?('/')
      end
    end

    munge do |value|
      Array(value).map { |v| v == '/' ? v : v.chomp('/') }
    end
  end

  newparam(:suid_whitelist) do
    desc 'Binaries permitted to carry SUID or SGID bits. ' \
         'Any SUID/SGID file not in this list is an offender.'
    defaultto []

    validate do |value|
      Array(value).each do |v|
        raise ArgumentError, "suid_whitelist entries must be absolute paths, got '#{v}'" unless v.is_a?(String) && v.start_with?('/')
      end
    end

    munge do |value|
      Array(value).map { |v| v.chomp('/') }
    end
  end

  newparam(:world_writable) do
    desc 'When true, report and strip world-writable bits from files found in paths.'
    newvalues(:true, :false)
    defaultto :true
  end

  newparam(:unowned) do
    desc 'When true, report files whose uid or gid has no matching passwd/group entry.'
    newvalues(:true, :false)
    defaultto :true
  end

  newparam(:dotfiles_enabled) do
    desc 'When true, inspect top-level dotfiles in local interactive-user home directories.'
    newvalues(:true, :false)
    defaultto :true
  end

  newparam(:dotfile_enforce) do
    desc 'When true, remediate dotfile ownership/mode and remove prohibited dotfiles. ' \
         'When false, findings are written to the status report and warned about only.'
    newvalues(:true, :false)
    defaultto :false
  end

  newparam(:home_min_uid) do
    desc 'Minimum UID considered a local interactive user. Root is controlled separately by include_root.'
    defaultto 1000

    munge { |value| Integer(value) }

    validate do |value|
      int = Integer(value)
      raise ArgumentError, 'home_min_uid must be non-negative' if int.negative?
    rescue TypeError, ArgumentError
      raise ArgumentError, "home_min_uid must be a non-negative integer, got '#{value}'"
    end
  end

  newparam(:include_root) do
    desc 'Whether to include root and /root in the local-user dotfile control.'
    newvalues(:true, :false)
    defaultto :true
  end

  newparam(:home_exclude_users) do
    desc 'Local usernames excluded from the home/dotfile control.'
    defaultto []

    munge { |value| Array(value) }

    validate do |value|
      Array(value).each do |user|
        raise ArgumentError, 'home_exclude_users entries must be non-empty strings' unless user.is_a?(String) && !user.empty?
      end
    end
  end

  newparam(:dotfile_forbidden_mask) do
    desc 'Octal permission bits forbidden on ordinary dotfiles. 0022 forbids group/other write.'
    defaultto '0022'

    validate do |value|
      raise ArgumentError, "dotfile_forbidden_mask must be an octal mode, got '#{value}'" unless value.to_s.match?(%r{\A0?[0-7]{3,4}\z})
    end

    munge { |value| value.to_s }
  end

  newparam(:restricted_dotfiles) do
    desc 'Dotfile name to maximum permitted octal mode, for example .netrc => 0600.'
    defaultto({ '.netrc' => '0600' })

    validate do |value|
      raise ArgumentError, 'restricted_dotfiles must be a hash' unless value.is_a?(Hash)
      value.each do |name, mode|
        unless name.is_a?(String) && name.start_with?('.') && !name.include?('/')
          raise ArgumentError, "restricted_dotfiles key must be a top-level dotfile name, got '#{name}'"
        end
        raise ArgumentError, "restricted_dotfiles mode must be octal, got '#{mode}'" unless mode.to_s.match?(%r{\A0?[0-7]{3,4}\z})
      end
    end
  end

  newparam(:prohibited_dotfiles) do
    desc 'Top-level legacy trust files that must not exist in applicable home directories.'
    defaultto ['.forward', '.rhosts']

    munge { |value| Array(value) }

    validate do |value|
      Array(value).each do |name|
        unless name.is_a?(String) && name.start_with?('.') && !name.include?('/')
          raise ArgumentError, "prohibited_dotfiles entries must be top-level dotfile names, got '#{name}'"
        end
      end
    end
  end

  newparam(:exclude) do
    desc 'Subtrees to prune within the scanned paths. Use this to skip specific ' \
         'directories nested inside a path you are already scanning — for example, ' \
         'exclude /var/run when scanning /var, or /usr/local/games when scanning /usr. ' \
         'There is no need to list paths that are not under any entry in `paths`. ' \
         'For pattern-based exclusion (e.g. rotated log filenames), use exclude_glob instead.'
    defaultto []

    validate do |value|
      Array(value).each do |v|
        raise ArgumentError, "exclude entries must be absolute paths, got '#{v}'" unless v.is_a?(String) && v.start_with?('/')
      end
    end

    munge do |value|
      Array(value).map { |v| v == '/' ? v : v.chomp('/') }
    end
  end

  newparam(:exclude_glob) do
    desc 'Absolute shell-glob patterns to skip (e.g. "/var/log/wtmp*"). ' \
         'Matched with File.fnmatch? against the full path -- "*" does not cross "/". ' \
         'Kept separate from `exclude` so plain paths are never silently glob-matched.'
    defaultto []

    validate do |value|
      Array(value).each do |v|
        raise ArgumentError, "exclude_glob entries must be absolute paths, got '#{v}'" unless v.is_a?(String) && v.start_with?('/')
      end
    end
  end

  newparam(:max_depth) do
    desc 'Maximum directory depth to descend. Root of each path is depth 0.'
    defaultto 32

    munge { |value| Integer(value) }

    validate do |value|
      begin
        int = Integer(value)
      rescue TypeError, ArgumentError
        raise ArgumentError, "max_depth must be an integer, got '#{value}'"
      end
      raise ArgumentError, 'max_depth must be a non-negative integer' if int.negative?
    end
  end

  # --- properties -------------------------------------------------------
  # Each property's getter returns the offender list from the provider scan.
  # insync? returns true when the list is empty (nothing to fix).
  # Setters remediate where safe; unowned_files is report-only.

  newproperty(:suid_sgid) do
    desc 'Files carrying unexpected SUID or SGID bits (not in suid_whitelist). ' \
         'Puppet strips the bits from offenders.'
    defaultto :enforce

    def insync?(is)
      Array(is).empty?
    end

    def is_to_s(is)
      list = Array(is)
      return 'compliant — no unexpected SUID/SGID files' if list.empty?
      suffix = list.length > 5 ? " (#{list.length} total)" : ''
      "#{list.length} file(s) with unexpected SUID/SGID#{suffix}: #{list.first(5).join(', ')}"
    end

    def should_to_s(_should)
      'no unexpected SUID/SGID files'
    end

    def change_to_s(is, _should)
      "stripped SUID/SGID bits from #{Array(is).length} file(s)"
    end
  end

  newproperty(:world_writable_files) do
    desc 'Files with world-writable (o+w) permission. ' \
         'Puppet strips the world-write bit from offenders.'
    defaultto :enforce

    def insync?(is)
      Array(is).empty?
    end

    def is_to_s(is)
      list = Array(is)
      return 'compliant — no world-writable files' if list.empty?
      suffix = list.length > 5 ? " (#{list.length} total)" : ''
      "#{list.length} world-writable file(s)#{suffix}: #{list.first(5).join(', ')}"
    end

    def should_to_s(_should)
      'no world-writable files'
    end

    def change_to_s(is, _should)
      "stripped world-write bit from #{Array(is).length} file(s)"
    end
  end

  newproperty(:unowned_files) do
    desc 'Files whose uid or gid has no matching entry in passwd/group. ' \
         'Reported only — Puppet does not auto-remediate ownership.'
    defaultto :enforce

    def insync?(is)
      Array(is).empty?
    end

    def is_to_s(is)
      list = Array(is)
      return 'compliant — no unowned files' if list.empty?
      suffix = list.length > 5 ? " (#{list.length} total)" : ''
      "#{list.length} unowned file(s)#{suffix}: #{list.first(5).join(', ')}"
    end

    def should_to_s(_should)
      'no unowned files'
    end

    def change_to_s(is, _should)
      "reported #{Array(is).length} unowned file(s) — manual remediation required"
    end
  end

  newproperty(:dotfiles_wrong_owner) do
    desc 'Dotfiles not owned by the owner of the corresponding passwd home entry.'
    defaultto :enforce

    def insync?(is)
      resource[:dotfile_enforce] == :false || Array(is).empty?
    end

    def is_to_s(is)
      "#{Array(is).length} dotfile(s) with wrong ownership: #{Array(is).first(5).join(', ')}"
    end

    def should_to_s(_should)
      'all dotfiles owned by their local user'
    end

    def change_to_s(is, _should)
      "corrected ownership on #{Array(is).length} dotfile(s)"
    end
  end

  newproperty(:dotfiles_unsafe_mode) do
    desc 'Ordinary dotfiles carrying permission bits forbidden by dotfile_forbidden_mask.'
    defaultto :enforce

    def insync?(is)
      resource[:dotfile_enforce] == :false || Array(is).empty?
    end

    def is_to_s(is)
      "#{Array(is).length} dotfile(s) with unsafe permissions: #{Array(is).first(5).join(', ')}"
    end

    def should_to_s(_should)
      'no forbidden permission bits on local-user dotfiles'
    end

    def change_to_s(is, _should)
      "removed forbidden permission bits from #{Array(is).length} dotfile(s)"
    end
  end

  newproperty(:restricted_dotfiles_unsafe_mode) do
    desc 'Restricted dotfiles, such as .netrc, with permissions broader than their configured maximum.'
    defaultto :enforce

    def insync?(is)
      resource[:dotfile_enforce] == :false || Array(is).empty?
    end

    def is_to_s(is)
      "#{Array(is).length} restricted dotfile(s) with unsafe permissions: #{Array(is).first(5).join(', ')}"
    end

    def should_to_s(_should)
      'restricted dotfiles at or below their configured maximum mode'
    end

    def change_to_s(is, _should)
      "restricted permissions on #{Array(is).length} dotfile(s)"
    end
  end

  newproperty(:prohibited_dotfiles_found) do
    desc 'Legacy trust files that must not exist. Removed only when dotfile_enforce is true.'
    defaultto :enforce

    def insync?(is)
      resource[:dotfile_enforce] == :false || Array(is).empty?
    end

    def is_to_s(is)
      "#{Array(is).length} prohibited dotfile(s): #{Array(is).first(5).join(', ')}"
    end

    def should_to_s(_should)
      'no prohibited legacy trust dotfiles'
    end

    def change_to_s(is, _should)
      "removed #{Array(is).length} prohibited dotfile(s)"
    end
  end
end
