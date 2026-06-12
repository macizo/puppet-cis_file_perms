# frozen_string_literal: true

begin
  require 'puppetlabs_spec_helper/rake_tasks'
rescue LoadError
  require 'rspec/core/rake_task'
  RSpec::Core::RakeTask.new(:spec)
  task default: :spec
end
