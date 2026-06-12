# frozen_string_literal: true

require 'spec_helper'

describe Puppet::Type.type(:dir_perms) do
  let(:valid_params) { { name: '/usr/bin', strip_mode: 'go-w' } }

  describe 'path (namevar)' do
    it 'accepts an absolute path' do
      expect { described_class.new(**valid_params) }.not_to raise_error
    end

    it 'rejects a relative path' do
      expect {
        described_class.new(name: 'usr/bin', strip_mode: 'go-w')
      }.to raise_error(Puppet::Error, %r{absolute})
    end

    it 'strips a trailing slash' do
      res = described_class.new(name: '/usr/bin/', strip_mode: 'go-w')
      expect(res[:path]).to eq('/usr/bin')
    end

    it 'leaves / untouched' do
      res = described_class.new(name: '/', strip_mode: 'go-w')
      expect(res[:path]).to eq('/')
    end
  end

  describe 'strip_mode' do
    %w[go-w o-rwx a-rwx g-w,o-rwx u-x].each do |spec|
      it "accepts '#{spec}'" do
        expect {
          described_class.new(name: '/x', strip_mode: spec)
        }.not_to raise_error
      end
    end

    %w[go+w 777 g-s w-go go- -w go-w; x-w].each do |spec|
      it "rejects '#{spec}'" do
        expect {
          described_class.new(name: '/x', strip_mode: spec)
        }.to raise_error(Puppet::Error, %r{invalid strip_mode})
      end
    end

    describe 'insync?' do
      let(:prop) { described_class.new(**valid_params).property(:strip_mode) }

      it 'is in sync when the offender list is empty' do
        expect(prop.insync?([])).to be true
      end

      it 'is out of sync when offenders exist' do
        expect(prop.insync?(['/usr/bin/evil'])).to be false
      end
    end

    describe 'reporting' do
      let(:prop) { described_class.new(**valid_params).property(:strip_mode) }

      it 'caps the offender sample at 5 and shows the total' do
        offenders = (1..12).map { |i| "/usr/bin/f#{i}" }
        msg = prop.is_to_s(offenders)
        expect(msg).to include('12 entries')
        expect(msg).to include('(12 total)')
        expect(msg.scan(%r{/usr/bin/f\d+}).length).to eq(5)
      end
    end
  end

  describe 'exclude' do
    it 'accepts absolute paths and normalises trailing slashes' do
      res = described_class.new(name: '/x', strip_mode: 'go-w',
                                exclude: ['/x/skip/', '/x/other'])
      expect(res[:exclude]).to eq(['/x/skip', '/x/other'])
    end

    it 'rejects relative paths' do
      expect {
        described_class.new(name: '/x', strip_mode: 'go-w', exclude: ['skip'])
      }.to raise_error(Puppet::Error, %r{absolute})
    end

    it 'defaults to empty' do
      expect(described_class.new(**valid_params)[:exclude]).to eq([])
    end
  end

  describe 'max_depth' do
    it 'defaults to 32' do
      expect(described_class.new(**valid_params)[:max_depth]).to eq(32)
    end

    it 'rejects negative values' do
      expect {
        described_class.new(name: '/x', strip_mode: 'go-w', max_depth: -1)
      }.to raise_error(Puppet::Error, %r{non-negative})
    end

    it 'rejects non-integers' do
      expect {
        described_class.new(name: '/x', strip_mode: 'go-w', max_depth: 'deep')
      }.to raise_error(Puppet::Error, %r{integer})
    end
  end

  describe 'resource-level validation' do
    it 'requires at least one property' do
      expect {
        described_class.new(name: '/x')
      }.to raise_error(Puppet::Error, %r{at least one})
    end

    it 'is satisfied by owner alone' do
      expect {
        described_class.new(name: '/x', owner: 'root')
      }.not_to raise_error
    end
  end
end
