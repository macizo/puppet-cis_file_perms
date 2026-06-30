# frozen_string_literal: true

require 'find'
require 'etc'

Puppet::Type.type(:dir_perms).provide(:posix) do
  desc <<-DOC
    POSIX implementation. Walks the tree once per resource (memoized for
    the run), collecting offenders for every property in a single pass.
    Setters touch only the offending entries, so compliant files keep
    their mtimes and a second run reports zero changes.
  DOC

  confine feature: :posix
  defaultfor feature: :posix

  # ---- strip_mode parsing ----------------------------------------------

  PERM_BITS  = { 'r' => 4, 'w' => 2, 'x' => 1 }.freeze
  CLASS_SHIFT = { 'u' => 6, 'g' => 3, 'o' => 0 }.freeze

  # 'go-w' -> 0o022, 'g-w,o-rwx' -> 0o027, 'a-rwx' -> 0o777
  def self.parse_strip_mode(spec)
    mask = 0
    spec.split(',').each do |seg|
      m = seg.match(%r{\A([ugoa]+)-([rwx]+)\z})
      raise Puppet::Error, "invalid strip_mode segment '#{seg}'" unless m

      classes = m[1].chars.flat_map { |c| c == 'a' ? %w[u g o] : [c] }.uniq
      perm = m[2].chars.uniq.sum { |p| PERM_BITS[p] }
      classes.each { |c| mask |= perm << CLASS_SHIFT[c] }
    end
    mask
  end

  # ---- property getters (offender lists) -------------------------------

  def strip_mode
    scan[:mode]
  end

  def owner
    scan[:owner]
  end

  def group
    scan[:group]
  end

  # ---- property setters (remediate offenders only) ---------------------

  def strip_mode=(_value)
    scan[:mode].each do |path|
      st = File.lstat(path)
      next if st.symlink?
      File.chmod(st.mode & 0o7777 & ~mask, path)
    end
  end

  def owner=(_value)
    uid = desired_uid
    scan[:owner].each { |path| File.chown(uid, nil, path) }
  end

  def group=(_value)
    gid = desired_gid
    scan[:group].each { |path| File.chown(nil, gid, path) }
  end

  # ---- the single walk --------------------------------------------------

  def scan
    @scan ||= begin
      root = resource[:path]
      offenders = { mode: [], owner: [], group: [] }

      if File.directory?(root)
        check_mode  = !resource[:strip_mode].nil?
        check_owner = !resource[:owner].nil?
        check_group = !resource[:group].nil?
        want_uid = check_owner ? desired_uid : nil
        want_gid = check_group ? desired_gid : nil

        Find.find(root) do |path|
          next if path == root # never flag the scan root itself -- matches the standard find -mindepth 1 idiom this is meant to mirror; stripping execute from the root container (not its contents) breaks traversal for /home, /var/log, etc.
          Find.prune if excluded?(path)
          Find.prune if depth_of(path, root) > resource[:max_depth]

          begin
            st = File.lstat(path)
          rescue Errno::ENOENT, Errno::EACCES
            next
          end
          next if st.symlink?

          offenders[:mode]  << path if check_mode && (st.mode & mask) != 0
          offenders[:owner] << path if check_owner && st.uid != want_uid
          offenders[:group] << path if check_group && st.gid != want_gid
        end
      end

      write_status(offenders)
      offenders
    end
  end

  private

  # Full offender lists, not just the 5-sample summary Puppet's own
  # notice/report machinery shows. One file per resource (path-derived
  # name) under /var/lib/cis_file_perms/dir_perms/, so "what exact files
  # would this change" is answerable by reading a file on the node,
  # independent of whether report processing is even working.
  def write_status(offenders)
    require 'json'
    require 'fileutils'
    dir = '/var/log/cis-reports/dir_perms'
    FileUtils.mkdir_p(dir)
    safe_name = resource[:path].gsub(%r{[^a-zA-Z0-9_-]+}, '_').sub(%r{\A_}, '')
    status = {
      'timestamp' => Time.now.to_i,
      'noop'      => Puppet[:noop],
      'path'      => resource[:path],
      'mode'      => { 'count' => offenders[:mode].length, 'paths' => offenders[:mode] },
      'owner'     => { 'count' => offenders[:owner].length, 'paths' => offenders[:owner] },
      'group'     => { 'count' => offenders[:group].length, 'paths' => offenders[:group] },
    }
    File.write("#{dir}/#{safe_name}.json", JSON.generate(status))
  rescue => e
    Puppet.warning("dir_perms #{resource[:path]}: could not write status file: #{e}")
  end

  def mask
    @mask ||= self.class.parse_strip_mode(resource[:strip_mode])
  end

  def excluded?(path)
    resource[:exclude].any? { |ex| path == ex || path.start_with?("#{ex}/") } ||
      resource[:exclude_glob].any? { |pattern| File.fnmatch?(pattern, path, File::FNM_PATHNAME) }
  end

  def depth_of(path, root)
    return 0 if path == root

    rel = path[(root == '/' ? 1 : root.length + 1)..-1]
    rel.count('/') + 1
  end

  def desired_uid
    @desired_uid ||= begin
      o = resource[:owner]
      o =~ %r{\A\d+\z} ? o.to_i : Etc.getpwnam(o).uid
    rescue ArgumentError
      raise Puppet::Error, "dir_perms #{resource[:path]}: unknown user '#{o}'"
    end
  end

  def desired_gid
    @desired_gid ||= begin
      g = resource[:group]
      g =~ %r{\A\d+\z} ? g.to_i : Etc.getgrnam(g).gid
    rescue ArgumentError
      raise Puppet::Error, "dir_perms #{resource[:path]}: unknown group '#{g}'"
    end
  end
end
