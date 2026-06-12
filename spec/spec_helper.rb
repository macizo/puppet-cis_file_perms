# frozen_string_literal: true

begin
  require 'puppetlabs_spec_helper/module_spec_helper'
rescue LoadError
  # Unit tests for types/providers only need the puppet gem.
  require 'puppet'
  require 'rspec'
end
