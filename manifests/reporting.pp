# @summary Write CIS scan/audit results to a shared, tool-agnostic location.
#
# Drops the cis_audit Facter fact to JSON alongside the fs_scan
# provider's own status file (cis_fs_scan writes fs_scan.json into the
# same directory independently of this class). Both land in one place
# under a stable schema so any monitoring agent -- Wazuh, Nagios/Icinga
# via NRPE, a Lynis custom check, a Prometheus textfile-collector
# script, whatever the site already runs -- can read them without this
# module knowing about that tool.
#
# @param report_dir Directory both this class and the cis_fs_scan
#   provider write status JSON into.
class cis_file_perms::reporting (
  Stdlib::Absolutepath $report_dir = '/var/log/cis-reports',
) {
  file { $report_dir:
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  if $facts['cis_audit'] {
    $cis_audit_data = $facts['cis_audit']
    file { "${report_dir}/audit.json":
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      require => File[$report_dir],
      content => inline_template('<%= require "json"; JSON.generate(@cis_audit_data) + "\n" %>'),
    }
  }
}
