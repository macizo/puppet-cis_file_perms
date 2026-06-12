# frozen_string_literal: true

source 'https://rubygems.org'

puppet_version = ENV['PUPPET_GEM_VERSION'] || ['>= 7.24', '< 9']

gem 'puppet', *Array(puppet_version)

group :development, :test do
  gem 'puppetlabs_spec_helper', '~> 7.0', require: false
  gem 'puppet-lint', '~> 4.0', require: false
  gem 'rspec', '~> 3.0', require: false
  gem 'rubocop', '~> 1.50', require: false
  gem 'rubocop-rspec', '~> 2.19', require: false
end
