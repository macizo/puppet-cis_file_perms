# frozen_string_literal: true

require 'find'
require 'etc'
require 'set'

Puppet::Type.type(:cis_fs_scan).provide(:posix) do
  desc <<-DOC
    POSIX implementation. Walks each path tree once (memoized for the run),
    collecting offenders for all three CIS checks in a single pass.
    Setters remediate suid_sgid and world_writable_files in-place;
    unowned_files is report-only.
  DOC

  confine feature: :posix
  defaultfor feature: :posix

  # ---- property getters ------------------------------------------------
  # Each getter returns its offender list from the memoized scan.
  def suid_sgid
    scan[:suid_sgid]
  end

  def world_writable_files
    scan[:world_writable_files]
  end

  def unowned_files
    scan[:unowned_files]
  end

  # ---- property setters ------------------------------------------------
  # suid_sgid=    : strip bits 04000/02000 from each offender
  def suid_sgid=(_value)
    scan[:suid_sgid].each do |path|
      st = File.lstat(path)
      next if st.symlink?
      File.chmod(st.mode & 0o7777 & ~0o6000, path)
    end
  end
  # world_writable_files= : strip bit 0o002 from each offender
  def world_writable_files=(_value)
    scan[:world_writable_files].each do |path|
      st = File.lstat(path)
      next if st.symlink?
      File.chmod(st.mode & 0o7777 & ~0o002, path)
    end
  end

  # unowned_files=        : no-op — report only, manual remediation required
  def unowned_files=(_value)
  # report only — manual remediation required
  end


  # ---- single memoized walk --------------------------------------------
  # Walk all resource[:paths], pruning excluded subtrees and respecting
  # max_depth. Cache valid UIDs/GIDs in Sets for O(1) lookup.
  # Collect three offender arrays:
  #   :suid_sgid           — mode & 0o6000 != 0 and not in whitelist
  #   :world_writable_files — mode & 0o002 != 0
  #   :unowned_files        — uid or gid not found in passwd/group
   # ---- the single walk --------------------------------------------------

  def scan
    @scan ||= begin
      offenders = { suid_sgid: [], world_writable_files: [], unowned_files: [] }

      whitelist = Set.new(resource[:suid_whitelist])
      valid_uids = Set.new
      Etc.passwd { |e| valid_uids << e.uid }
      valid_gids = Set.new
      Etc.group  { |e| valid_gids << e.gid }

      resource[:paths].each do |root|
        next unless File.directory?(root)
        Find.find(root) do |path|
          Find.prune if excluded?(path)
          Find.prune if depth_of(path, root) > resource[:max_depth]
          begin
            st = File.lstat(path)
          rescue Errno::ENOENT, Errno::EACCES
            next
          end
          next if st.symlink?

          offenders[:suid_sgid] << path if (st.mode & 0o6000) != 0 && !whitelist.include?(path)
          offenders[:world_writable_files] << path if (st.mode & 0o002) != 0
          offenders[:unowned_files] << path unless valid_uids.include?(st.uid) && valid_gids.include?(st.gid)
        end
      end
      write_status(offenders)
      offenders
    end
  end

  def write_status(offenders)
    require 'json'
    require 'fileutils'
    dir = '/var/log/cis-reports'
    FileUtils.mkdir_p(dir)
    status = {
      'timestamp'      => Time.now.to_i,
      'noop'           => Puppet[:noop],
      # Written to /var/log/cis-reports/ (common dir alongside
      # dir_perms's own reports) so any monitoring agent -- Wazuh log
      # collector/FIM, a Lynis custom check, etc. -- can pick these up
      # without depending on a specific tool. 'samples' (first 5) is a
      # quick glance; 'paths' is the full offender list -- independent
      # of whether Puppet's own report processing is even working.
      'suid_sgid'      => { 'count' => offenders[:suid_sgid].length,            'samples' => offenders[:suid_sgid].first(5),            'paths' => offenders[:suid_sgid] },
      'world_writable' => { 'count' => offenders[:world_writable_files].length, 'samples' => offenders[:world_writable_files].first(5), 'paths' => offenders[:world_writable_files] },
      'unowned'        => { 'count' => offenders[:unowned_files].length,        'samples' => offenders[:unowned_files].first(5),        'paths' => offenders[:unowned_files] },
    }
    File.write("#{dir}/fs_scan.json", JSON.generate(status))
  rescue => e
    Puppet.warning("cis_fs_scan: could not write status file: #{e}")
  end

  private

  # excluded?(path) — true if path matches any entry in resource[:exclude]
  def excluded?(path)
    resource[:exclude].any? { |ex| path == ex || path.start_with?("#{ex}/") } ||
      resource[:exclude_glob].any? { |pattern| File.fnmatch?(pattern, path, File::FNM_PATHNAME) }
  end

  # depth_of(path, root) — counts '/' separators relative to root
  def depth_of(path, root)
    return 0 if path == root
    rel = path[(root == '/' ? 1 : root.length + 1)..-1]
    rel.count('/') + 1
  end

end
