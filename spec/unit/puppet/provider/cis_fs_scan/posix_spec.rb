require 'spec_helper'
require 'tmpdir'
require 'fileutils'
require File.expand_path('../../../../../lib/puppet/type/cis_fs_scan', __dir__)
require File.expand_path('../../../../../lib/puppet/provider/cis_fs_scan/posix', __dir__)

describe Puppet::Type.type(:cis_fs_scan).provider(:posix) do
  around(:each) do |example|
    Dir.mktmpdir('cis_fs_scan_spec') do |dir|
      @root = dir
      example.run
    end
  end

  def build_resource(**overrides)
    Puppet::Type.type(:cis_fs_scan).new(
      { name: 'test', paths: [@root], suid_whitelist: [], dotfiles_enabled: false }.merge(overrides),
    )
  end
  
  def provider_for(resource)
    described_class.new(resource)
  end

  before(:each) do
    FileUtils.mkdir_p(File.join(@root, 'sub'))
      # for suid_sgid tests
    File.write(File.join(@root, 'clean'),      'x'); File.chmod(0o755,  File.join(@root, 'clean'))
    File.write(File.join(@root, 'suid_file'),  'x'); File.chmod(0o4755, File.join(@root, 'suid_file'))
    File.write(File.join(@root, 'sgid_file'),  'x'); File.chmod(0o2755, File.join(@root, 'sgid_file'))

      # for world_writable_files tests
    File.write(File.join(@root, 'ww_file'),    'x'); File.chmod(0o666,  File.join(@root, 'ww_file'))
    File.write(File.join(@root, 'sub', 'ww_sub'), 'x'); File.chmod(0o777, File.join(@root, 'sub', 'ww_sub'))

    FileUtils.mkdir_p(File.join(@root, 'sgid_dir'))
    File.chmod(0o2775, File.join(@root, 'sgid_dir'))
    FileUtils.mkdir_p(File.join(@root, 'ww_dir'))
    File.chmod(0o0777, File.join(@root, 'ww_dir'))

    File.chmod(0o755, File.join(@root, 'sub'))
    File.chmod(0o755, @root)
    File.write(File.join(@root, 'sub', 'sub_suid'), 'x')
    File.chmod(0o4755, File.join(@root, 'sub', 'sub_suid'))
  end

  describe 'suid_sgid detection' do
    it 'finds exactly the suid/sgid offenders' do
        provider = provider_for(build_resource)
        expect(provider.suid_sgid).to contain_exactly(
          File.join(@root, 'suid_file'),
          File.join(@root, 'sgid_file'),
          File.join(@root, 'sub', 'sub_suid'),
        )
    end
  
    it 'ignores symlinks' do
      link = File.join(@root, 'link_to_suid')
      File.symlink(File.join(@root, 'suid_file'), link)
      expect(provider_for(build_resource).suid_sgid).not_to include(link)
    end

    it 'respects exclude (prunes subtree)' do
      provider = provider_for(build_resource(exclude: [File.join(@root, 'sub')]))
      expect(provider.suid_sgid).not_to include(File.join(@root, 'sub', 'ww_sub'))
    end
  end

  describe 'world_writable_files detection' do
    it 'finds exactly the world-writable offenders' do
      provider = provider_for(build_resource)
      expect(provider.world_writable_files).to contain_exactly(
        File.join(@root, 'ww_file'),
        File.join(@root, 'sub', 'ww_sub'),
      )
    end

    it 'respects exclude' do
      provider = provider_for(build_resource(exclude: [File.join(@root, 'sub')]))
      expect(provider.world_writable_files).to contain_exactly(File.join(@root, 'ww_file'))
    end

    it 'does not classify SGID or world-writable directories as files' do
      provider = provider_for(build_resource)

      expect(provider.suid_sgid).not_to include(File.join(@root, 'sgid_dir'))
      expect(provider.world_writable_files).not_to include(File.join(@root, 'ww_dir'))
    end

    it 'respects exclude_glob' do
      File.write(File.join(@root, 'wtmp'), 'x')
      File.chmod(0o666, File.join(@root, 'wtmp'))
      File.write(File.join(@root, 'wtmp-20260601.gz'), 'x')
      File.chmod(0o666, File.join(@root, 'wtmp-20260601.gz'))

      provider = provider_for(build_resource(exclude_glob: [File.join(@root, 'wtmp*')]))
      offenders = provider.world_writable_files
      expect(offenders).not_to include(File.join(@root, 'wtmp'))
      expect(offenders).not_to include(File.join(@root, 'wtmp-20260601.gz'))
      expect(offenders).to include(File.join(@root, 'ww_file'))
    end

    it 'respects max_depth' do
      provider = provider_for(build_resource(max_depth: 1))
      expect(provider.world_writable_files).to contain_exactly(File.join(@root, 'ww_file'))
    end
  end

  describe 'single-walk memoization' do
    it 'walks once for all three properties' do
      resource = build_resource
      provider = provider_for(resource)
      expect(Find).to receive(:find).once.and_call_original
      provider.suid_sgid
      provider.world_writable_files
      provider.unowned_files
    end
  end
  
  describe 'unowned_files detection' do
  # files in tmpdir belong to Process.uid/Process.gid
  # stub Etc to control what the provider considers "valid"

    it 'reports nothing when all files have valid uid and gid' do
      allow(Etc).to receive(:passwd).and_yield(double(uid: Process.uid))
      allow(Etc).to receive(:group).and_yield(double(gid: Process.gid))

      expect(provider_for(build_resource).unowned_files).to be_empty
    end

    it 'flags files whose uid is not in passwd' do
      # tell the provider no valid uids exist — everything looks unowned
      allow(Etc).to receive(:passwd).and_yield(double(uid: Process.uid + 9999))
      allow(Etc).to receive(:group).and_yield(double(gid: Process.gid))

      offenders = provider_for(build_resource).unowned_files
      expect(offenders).to include(File.join(@root, 'clean'))
    end

    it 'flags files whose gid is not in group' do
      allow(Etc).to receive(:passwd).and_yield(double(uid: Process.uid))
      allow(Etc).to receive(:group).and_yield(double(gid: Process.gid + 9999))

      offenders = provider_for(build_resource).unowned_files
      expect(offenders).to include(File.join(@root, 'clean'))
    end

    it 'unowned_files= is a no-op' do
      allow(Etc).to receive(:passwd).and_yield(double(uid: Process.uid + 9999))
      allow(Etc).to receive(:group).and_yield(double(gid: Process.gid))

      provider = provider_for(build_resource)
      expect { provider.unowned_files = [] }.not_to raise_error
      # mode unchanged
      expect(File.stat(File.join(@root, 'clean')).mode & 0o777).to eq(0o755)
    end
  end

  describe 'suid_sgid remediation' do
    it 'strips suid bit, leaves other bits alone' do
      f = File.join(@root, 'suid_file')
      provider = provider_for(build_resource)
      provider.suid_sgid = []
      expect(File.stat(f).mode & 0o6000).to eq(0)
      expect(File.stat(f).mode & 0o0755).to eq(0o0755)
    end

    it 'is idempotent: fresh scan after remediation finds nothing' do
      provider = provider_for(build_resource)
      provider.suid_sgid = []
      expect(provider_for(build_resource).suid_sgid).not_to include(File.join(@root, 'suid_file'))
    end
  end

  describe 'world_writable_files remediation' do
    it 'strips world-write bit, leaves other bits alone' do
      f = File.join(@root, 'ww_file')
      provider = provider_for(build_resource)
      provider.world_writable_files = []
      expect(File.stat(f).mode & 0o002).to eq(0)
      expect(File.stat(f).mode & 0o664).to eq(0o664)
    end

    it 'does not change SGID or world-writable directory modes' do
      provider = provider_for(build_resource)
      provider.suid_sgid = []
      provider.world_writable_files = []

      expect(File.stat(File.join(@root, 'sgid_dir')).mode & 0o7777).to eq(0o2775)
      expect(File.stat(File.join(@root, 'ww_dir')).mode & 0o7777).to eq(0o0777)
    end
  end

  describe 'local-user dotfile controls' do
    let(:passwd_entry) do
      double(
        name: 'testuser',
        uid: Process.uid,
        gid: Process.gid,
        dir: @root,
        shell: '/bin/bash',
      )
    end

    before(:each) do
      allow(Etc).to receive(:passwd).and_yield(passwd_entry)
      allow(Etc).to receive(:group).and_yield(double(gid: Process.gid))
    end

    def dotfile_resource(**overrides)
      build_resource(
        dotfiles_enabled: true,
        dotfile_enforce: false,
        home_min_uid: 0,
        include_root: false,
        **overrides,
      )
    end

    it 'detects unsafe ordinary, restricted, and prohibited dotfiles' do
      bashrc = File.join(@root, '.bashrc')
      netrc = File.join(@root, '.netrc')
      forward = File.join(@root, '.forward')
      File.write(bashrc, 'x'); File.chmod(0o666, bashrc)
      File.write(netrc, 'x'); File.chmod(0o640, netrc)
      File.write(forward, 'x'); File.chmod(0o600, forward)

      provider = provider_for(dotfile_resource)
      expect(provider.dotfiles_unsafe_mode).to contain_exactly(bashrc)
      expect(provider.restricted_dotfiles_unsafe_mode).to contain_exactly(netrc)
      expect(provider.prohibited_dotfiles_found).to contain_exactly(forward)
    end

    it 'ignores ordinary symlinks without following them' do
      link = File.join(@root, '.linked')
      File.symlink(File.join(@root, 'ww_file'), link)

      provider = provider_for(dotfile_resource)
      expect(provider.dotfiles_unsafe_mode).not_to include(link)
      expect(provider.dotfiles_wrong_owner).not_to include(link)
    end

    it 'remediates modes and removes prohibited files only when enforcement is enabled' do
      bashrc = File.join(@root, '.bashrc')
      netrc = File.join(@root, '.netrc')
      rhosts = File.join(@root, '.rhosts')
      File.write(bashrc, 'x'); File.chmod(0o666, bashrc)
      File.write(netrc, 'x'); File.chmod(0o664, netrc)
      File.write(rhosts, 'x'); File.chmod(0o600, rhosts)

      provider = provider_for(dotfile_resource(dotfile_enforce: true))
      provider.dotfiles_unsafe_mode = []
      provider.restricted_dotfiles_unsafe_mode = []
      provider.prohibited_dotfiles_found = []

      expect(File.stat(bashrc).mode & 0o022).to eq(0)
      expect(File.stat(netrc).mode & 0o077).to eq(0)
      expect(File.exist?(rhosts)).to be(false)
    end

    it 'does not remediate while dotfile enforcement is disabled' do
      forward = File.join(@root, '.forward')
      File.write(forward, 'x')

      provider = provider_for(dotfile_resource)
      provider.prohibited_dotfiles_found = []

      expect(File.exist?(forward)).to be(true)
    end
  end

  describe 'edge cases' do
    it 'returns empty when root does not exist' do
      resource = build_resource(paths: ['/nonexistent/path/xyz'])
      expect(provider_for(resource).suid_sgid).to be_empty
    end
  end
end
