# frozen_string_literal: true

require 'find'
require 'etc'
require 'set'

Puppet::Type.type(:cis_fs_scan).provide(:posix) do
  desc <<-DOC
    POSIX implementation. Walks each path tree once (memoized for the run),
    collecting offenders for the filesystem checks in a single pass and
    inspecting applicable home-directory dotfiles without recursive walks.
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

  def dotfiles_wrong_owner
    scan[:dotfiles_wrong_owner]
  end

  def dotfiles_unsafe_mode
    scan[:dotfiles_unsafe_mode]
  end

  def restricted_dotfiles_unsafe_mode
    scan[:restricted_dotfiles_unsafe_mode]
  end

  def prohibited_dotfiles_found
    scan[:prohibited_dotfiles_found]
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

  def dotfiles_wrong_owner=(_value)
    return unless resource[:dotfile_enforce] == :true

    scan[:dotfiles_wrong_owner].each do |path|
      File.chown(scan[:dotfile_owner_uids][path], nil, path)
    rescue Errno::ENOENT, Errno::EACCES => e
      Puppet.warning("cis_fs_scan: could not correct owner on #{path}: #{e}")
    end
  end

  def dotfiles_unsafe_mode=(_value)
    return unless resource[:dotfile_enforce] == :true

    forbidden_mask = Integer(resource[:dotfile_forbidden_mask], 8)
    scan[:dotfiles_unsafe_mode].each do |path|
      st = File.lstat(path)
      next if st.symlink?
      File.chmod(st.mode & 0o7777 & ~forbidden_mask, path)
    rescue Errno::ENOENT, Errno::EACCES => e
      Puppet.warning("cis_fs_scan: could not restrict mode on #{path}: #{e}")
    end
  end

  def restricted_dotfiles_unsafe_mode=(_value)
    return unless resource[:dotfile_enforce] == :true

    scan[:restricted_dotfiles_unsafe_mode].each do |path|
      st = File.lstat(path)
      next if st.symlink?
      File.chmod(st.mode & scan[:restricted_dotfile_modes][path], path)
    rescue Errno::ENOENT, Errno::EACCES => e
      Puppet.warning("cis_fs_scan: could not restrict mode on #{path}: #{e}")
    end
  end

  def prohibited_dotfiles_found=(_value)
    return unless resource[:dotfile_enforce] == :true

    scan[:prohibited_dotfiles_found].each do |path|
      st = File.lstat(path)
      if st.directory? && !st.symlink?
        Puppet.warning("cis_fs_scan: refusing to remove prohibited dotfile directory #{path}")
      else
        File.unlink(path)
      end
    rescue Errno::ENOENT
      next
    rescue Errno::EACCES => e
      Puppet.warning("cis_fs_scan: could not remove prohibited dotfile #{path}: #{e}")
    end
  end


  # ---- single memoized walk --------------------------------------------
  # Walk all resource[:paths], pruning excluded subtrees and respecting
  # max_depth. Cache valid UIDs/GIDs in Sets for O(1) lookup.
  # Collect the filesystem and home-dotfile offender arrays:
  #   :suid_sgid           — mode & 0o6000 != 0 and not in whitelist
  #   :world_writable_files — mode & 0o002 != 0
  #   :unowned_files        — uid or gid not found in passwd/group
   # ---- the single walk --------------------------------------------------

  def scan
    @scan ||= begin
      offenders = {
        suid_sgid: [],
        world_writable_files: [],
        unowned_files: [],
        dotfiles_wrong_owner: [],
        dotfiles_unsafe_mode: [],
        restricted_dotfiles_unsafe_mode: [],
        prohibited_dotfiles_found: [],
        dotfile_owner_uids: {},
        restricted_dotfile_modes: {},
      }

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

          if st.file?
            offenders[:suid_sgid] << path if (st.mode & 0o6000) != 0 && !whitelist.include?(path)
            offenders[:world_writable_files] << path if (st.mode & 0o002) != 0
          end
          offenders[:unowned_files] << path unless valid_uids.include?(st.uid) && valid_gids.include?(st.gid)
        end
      end
      scan_dotfiles(offenders) if resource[:dotfiles_enabled] == :true
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
      'dotfiles'       => {
        'enforce'          => resource[:dotfile_enforce] == :true,
        'wrong_owner'      => { 'count' => offenders[:dotfiles_wrong_owner].length, 'paths' => offenders[:dotfiles_wrong_owner] },
        'unsafe_mode'      => { 'count' => offenders[:dotfiles_unsafe_mode].length, 'paths' => offenders[:dotfiles_unsafe_mode] },
        'restricted_mode'  => { 'count' => offenders[:restricted_dotfiles_unsafe_mode].length, 'paths' => offenders[:restricted_dotfiles_unsafe_mode] },
        'prohibited_found' => { 'count' => offenders[:prohibited_dotfiles_found].length, 'paths' => offenders[:prohibited_dotfiles_found] },
      },
    }
    File.write("#{dir}/fs_scan.json", JSON.generate(status))
  rescue => e
    Puppet.warning("cis_fs_scan: could not write status file: #{e}")
  end

  private

  def scan_dotfiles(offenders)
    excluded_users = Set.new(resource[:home_exclude_users])
    prohibited = Set.new(resource[:prohibited_dotfiles])
    restricted = resource[:restricted_dotfiles].transform_values { |mode| Integer(mode.to_s, 8) }
    forbidden_mask = Integer(resource[:dotfile_forbidden_mask], 8)
    nonlogin_shells = Set.new(['/usr/sbin/nologin', '/sbin/nologin', '/bin/false', '/usr/bin/false', ''])

    Etc.passwd do |entry|
      include_user = entry.uid >= resource[:home_min_uid] || (resource[:include_root] == :true && entry.uid.zero? && entry.name == 'root')
      next unless include_user
      next if excluded_users.include?(entry.name) || nonlogin_shells.include?(entry.shell)
      next unless entry.dir && File.directory?(entry.dir)

      Dir.children(entry.dir).select { |name| name.start_with?('.') }.each do |name|
        path = File.join(entry.dir, name)
        begin
          st = File.lstat(path)
        rescue Errno::ENOENT, Errno::EACCES
          next
        end

        if prohibited.include?(name)
          offenders[:prohibited_dotfiles_found] << path
          next
        end

        next if st.symlink?

        if st.uid != entry.uid
          offenders[:dotfiles_wrong_owner] << path
          offenders[:dotfile_owner_uids][path] = entry.uid
        end

        if restricted.key?(name)
          desired_mode = restricted[name]
          if (st.mode & 0o7777 & ~desired_mode) != 0
            offenders[:restricted_dotfiles_unsafe_mode] << path
            offenders[:restricted_dotfile_modes][path] = desired_mode
          end
        elsif (st.mode & forbidden_mask) != 0
          offenders[:dotfiles_unsafe_mode] << path
        end
      end
    end

    findings = offenders.values_at(:dotfiles_wrong_owner, :dotfiles_unsafe_mode, :restricted_dotfiles_unsafe_mode, :prohibited_dotfiles_found).flatten
    if resource[:dotfile_enforce] == :false && !findings.empty?
      Puppet.warning("cis_fs_scan: dotfile audit found #{findings.length} offender(s); see /var/log/cis-reports/fs_scan.json")
    end
  end

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
