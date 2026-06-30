# frozen_string_literal: true

Puppet::Type.newtype(:dir_perms) do
  @doc = <<-DOC
    Enforces permission constraints across a directory tree as a single
    catalog resource.

    Unlike `file` with `recurse => true`, which materialises one resource
    per file found (tens of thousands of resources on a system binary
    directory), this type walks the tree once inside the provider and
    reports/remediates only the offending entries.

    Designed for CIS-style hardening controls (e.g. CIS Debian 6.1.x:
    no group/other write on system binary directories).

    Runs in `--noop` mode as a pure audit: offenders are reported in the
    puppet run report without being touched.

    @example Strip group/other write from system binary dirs
      dir_perms { ['/bin', '/usr/bin', '/sbin', '/usr/sbin']:
        strip_mode => 'go-w',
      }

    @example Enforce ownership and exclude a path
      dir_perms { '/var/log':
        strip_mode => 'o-rwx',
        owner      => 'root',
        exclude    => ['/var/log/journal'],
      }
  DOC

  newparam(:path, namevar: true) do
    desc 'Absolute path of the directory tree to enforce.'

    munge do |value|
      value == '/' ? value : value.chomp('/')
    end

    validate do |value|
      unless value.is_a?(String) && value.start_with?('/')
        raise ArgumentError, "path must be an absolute path, got '#{value}'"
      end
    end
  end

  newproperty(:strip_mode) do
    desc <<-DOC
      Permission bits that must NOT be set anywhere in the tree, in
      symbolic notation limited to removal, e.g. 'go-w', 'o-rwx' or
      comma-separated combinations like 'g-w,o-rwx'.
    DOC

    validate do |value|
      value.split(',').each do |seg|
        unless seg =~ %r{\A[ugoa]+-[rwx]+\z}
          raise ArgumentError,
                "invalid strip_mode segment '#{seg}' (expected e.g. 'go-w', 'g-w,o-rwx')"
        end
      end
    end

    # The provider's getter returns the list of offending paths;
    # the tree is in sync when that list is empty.
    def insync?(is)
      Array(is).empty?
    end

    def is_to_s(is)
      list = Array(is)
      return 'compliant' if list.empty?
      sample = list.first(5).join(', ')
      suffix = list.length > 5 ? ", ... (#{list.length} total)" : ''
      "#{list.length} entr#{list.length == 1 ? 'y' : 'ies'} with forbidden bits: #{sample}#{suffix}"
    end

    def should_to_s(should)
      "no '#{should}' bits in tree"
    end

    def change_to_s(is, _should)
      "removed forbidden permission bits from #{Array(is).length} entr#{Array(is).length == 1 ? 'y' : 'ies'}"
    end
  end

  newproperty(:owner) do
    desc 'User (name or uid) every entry in the tree must be owned by.'

    validate do |value|
      unless value.is_a?(String) && !value.empty?
        raise ArgumentError, 'owner must be a non-empty string (username or uid)'
      end
    end

    def insync?(is)
      Array(is).empty?
    end

    def is_to_s(is)
      list = Array(is)
      return 'compliant' if list.empty?
      sample = list.first(5).join(', ')
      suffix = list.length > 5 ? ", ... (#{list.length} total)" : ''
      "#{list.length} entr#{list.length == 1 ? 'y' : 'ies'} with wrong owner: #{sample}#{suffix}"
    end

    def should_to_s(should)
      "all entries owned by '#{should}'"
    end

    def change_to_s(is, should)
      "chowned #{Array(is).length} entr#{Array(is).length == 1 ? 'y' : 'ies'} to '#{should}'"
    end
  end

  newproperty(:group) do
    desc 'Group (name or gid) every entry in the tree must belong to.'

    validate do |value|
      unless value.is_a?(String) && !value.empty?
        raise ArgumentError, 'group must be a non-empty string (groupname or gid)'
      end
    end

    def insync?(is)
      Array(is).empty?
    end

    def is_to_s(is)
      list = Array(is)
      return 'compliant' if list.empty?
      sample = list.first(5).join(', ')
      suffix = list.length > 5 ? ", ... (#{list.length} total)" : ''
      "#{list.length} entr#{list.length == 1 ? 'y' : 'ies'} with wrong group: #{sample}#{suffix}"
    end

    def should_to_s(should)
      "all entries in group '#{should}'"
    end

    def change_to_s(is, should)
      "chgrped #{Array(is).length} entr#{Array(is).length == 1 ? 'y' : 'ies'} to '#{should}'"
    end
  end

  newparam(:exclude) do
    desc 'Absolute paths to skip. A directory entry excludes its whole subtree. ' \
         'For pattern-based exclusion (e.g. rotated log filenames), use exclude_glob instead.'

    munge do |value|
      Array(value).map { |p| p == '/' ? p : p.chomp('/') }
    end

    validate do |value|
      Array(value).each do |p|
        unless p.is_a?(String) && p.start_with?('/')
          raise ArgumentError, "exclude entries must be absolute paths, got '#{p}'"
        end
      end
    end

    defaultto []
  end

  newparam(:exclude_glob) do
    desc 'Absolute shell-glob patterns to skip (e.g. "/var/log/wtmp*"). ' \
         'Matched with File.fnmatch? against the full path -- "*" does not cross "/". ' \
         'Kept separate from `exclude` so plain paths are never silently glob-matched.'

    validate do |value|
      Array(value).each do |p|
        unless p.is_a?(String) && p.start_with?('/')
          raise ArgumentError, "exclude_glob entries must be absolute paths, got '#{p}'"
        end
      end
    end

    defaultto []
  end

  newparam(:max_depth) do
    desc 'Maximum directory depth to descend (root itself is depth 0).'

    munge { |value| Integer(value) }

    validate do |value|
      begin
        int = Integer(value)
      rescue TypeError, ArgumentError
        raise ArgumentError, "max_depth must be an integer, got '#{value}'"
      end
      raise ArgumentError, 'max_depth must be a non-negative integer' if int.negative?
    end

    defaultto 32
  end

  validate do
    if self[:strip_mode].nil? && self[:owner].nil? && self[:group].nil?
      raise Puppet::Error,
            'dir_perms requires at least one of strip_mode, owner or group'
    end
  end
end
