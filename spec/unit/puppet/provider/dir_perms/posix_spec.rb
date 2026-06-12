# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe Puppet::Type.type(:dir_perms).provider(:posix) do
  describe '.parse_strip_mode' do
    {
      'go-w'      => 0o022,
      'o-rwx'     => 0o007,
      'a-rwx'     => 0o777,
      'g-w,o-rwx' => 0o027,
      'u-x'       => 0o100,
      'ug-wx'     => 0o330,
    }.each do |spec, expected|
      it "parses '#{spec}' to #{format('0o%03o', expected)}" do
        expect(described_class.parse_strip_mode(spec)).to eq(expected)
      end
    end

    it 'raises on garbage' do
      expect {
        described_class.parse_strip_mode('go+w')
      }.to raise_error(Puppet::Error, %r{invalid})
    end
  end

  context 'against a real directory tree' do
    around(:each) do |example|
      Dir.mktmpdir('dir_perms_spec') do |dir|
        @root = dir
        example.run
      end
    end

    def build_resource(**overrides)
      Puppet::Type.type(:dir_perms).new(
        { name: @root, strip_mode: 'go-w' }.merge(overrides),
      )
    end

    def provider_for(resource)
      described_class.new(resource)
    end

    before(:each) do
      FileUtils.mkdir_p(File.join(@root, 'sub', 'deeper'))
      File.write(File.join(@root, 'good'), 'x')
      File.write(File.join(@root, 'bad'), 'x')
      File.write(File.join(@root, 'sub', 'also_bad'), 'x')
      File.write(File.join(@root, 'sub', 'deeper', 'deep_bad'), 'x')
      File.chmod(0o755, File.join(@root, 'good'))
      File.chmod(0o775, File.join(@root, 'bad'))            # g+w
      File.chmod(0o757, File.join(@root, 'sub', 'also_bad')) # o+w
      File.chmod(0o777, File.join(@root, 'sub', 'deeper', 'deep_bad'))
      File.chmod(0o755, File.join(@root, 'sub'))
      File.chmod(0o755, File.join(@root, 'sub', 'deeper'))
      File.chmod(0o755, @root)
    end

    describe 'detection (property getter)' do
      it 'finds exactly the offenders' do
        provider = provider_for(build_resource)
        expect(provider.strip_mode).to contain_exactly(
          File.join(@root, 'bad'),
          File.join(@root, 'sub', 'also_bad'),
          File.join(@root, 'sub', 'deeper', 'deep_bad'),
        )
      end

      it 'returns empty on a compliant tree' do
        File.chmod(0o755, File.join(@root, 'bad'))
        File.chmod(0o755, File.join(@root, 'sub', 'also_bad'))
        File.chmod(0o755, File.join(@root, 'sub', 'deeper', 'deep_bad'))
        expect(provider_for(build_resource).strip_mode).to be_empty
      end

      it 'flags world-writable directories too' do
        File.chmod(0o777, File.join(@root, 'sub'))
        offenders = provider_for(build_resource).strip_mode
        expect(offenders).to include(File.join(@root, 'sub'))
      end

      it 'ignores symlinks' do
        File.symlink(File.join(@root, 'bad'), File.join(@root, 'link'))
        offenders = provider_for(build_resource).strip_mode
        expect(offenders).not_to include(File.join(@root, 'link'))
      end

      it 'respects exclude (whole subtree)' do
        provider = provider_for(
          build_resource(exclude: [File.join(@root, 'sub')]),
        )
        expect(provider.strip_mode).to contain_exactly(File.join(@root, 'bad'))
      end

      it 'respects max_depth' do
        provider = provider_for(build_resource(max_depth: 1))
        expect(provider.strip_mode).to contain_exactly(File.join(@root, 'bad'))
      end

      it 'returns empty when the root does not exist' do
        resource = Puppet::Type.type(:dir_perms).new(
          name: File.join(@root, 'nope'), strip_mode: 'go-w',
        )
        expect(provider_for(resource).strip_mode).to be_empty
      end
    end

    describe 'remediation (property setter)' do
      it 'fixes only the offenders' do
        good = File.join(@root, 'good')
        bad = File.join(@root, 'bad')
        good_mtime_before = File.stat(good).mtime

        provider = provider_for(build_resource)
        provider.strip_mode = 'go-w'

        expect(File.stat(bad).mode & 0o022).to eq(0)
        expect(File.stat(bad).mode & 0o7777).to eq(0o755)
        expect(File.stat(good).mode & 0o7777).to eq(0o755)
        expect(File.stat(good).mtime).to eq(good_mtime_before)
      end

      it 'is idempotent: a fresh scan after remediation finds nothing' do
        provider = provider_for(build_resource)
        provider.strip_mode = 'go-w'

        expect(provider_for(build_resource).strip_mode).to be_empty
      end

      it 'leaves bits outside the mask alone' do
        special = File.join(@root, 'special')
        File.write(special, 'x')
        File.chmod(0o4775, special) # setuid + g+w

        provider = provider_for(build_resource)
        provider.strip_mode = 'go-w'

        # g+w stripped, setuid untouched (suid handling is the suid_sgid type's job)
        expect(File.stat(special).mode & 0o7777).to eq(0o4755)
      end
    end

    describe 'owner/group resolution' do
      it 'accepts numeric ids without lookup' do
        uid = Process.uid
        resource = Puppet::Type.type(:dir_perms).new(
          name: @root, owner: uid.to_s,
        )
        # Everything in the tmpdir belongs to us: no offenders.
        expect(provider_for(resource).owner).to be_empty
      end

      it 'flags entries not owned by the desired uid' do
        other_uid = Process.uid + 1
        resource = Puppet::Type.type(:dir_perms).new(
          name: @root, owner: other_uid.to_s,
        )
        offenders = provider_for(resource).owner
        expect(offenders).to include(File.join(@root, 'good'))
      end

      it 'raises a useful error for unknown users' do
        resource = Puppet::Type.type(:dir_perms).new(
          name: @root, owner: 'no_such_user_xyz',
        )
        expect {
          provider_for(resource).owner
        }.to raise_error(Puppet::Error, %r{unknown user})
      end
    end

    describe 'single-walk memoization' do
      it 'walks once for multiple properties' do
        resource = Puppet::Type.type(:dir_perms).new(
          name: @root, strip_mode: 'go-w', owner: Process.uid.to_s,
        )
        provider = provider_for(resource)
        expect(Find).to receive(:find).once.and_call_original
        provider.strip_mode
        provider.owner
      end
    end
  end
end
