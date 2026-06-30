class cis_file_perms::checkmk {
  $status_dir = '/var/lib/check_mk/cis'

  file { $status_dir:
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  # Write cis_audit Facter fact to JSON so the local check can read it
  # without needing to invoke facter at check time.
  if $facts['cis_audit'] {
    $cis_audit_data = $facts['cis_audit']
    file { "${status_dir}/audit.json":
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      require => File[$status_dir],
      content => inline_template('<%= require "json"; JSON.generate(@cis_audit_data) + "\n" %>'),
    }
  }

  # Local check script — reads both status files and outputs one
  # CIS_* service line per control so they group together in CheckMK.
  file { '/usr/lib/check_mk_agent/local/cis_compliance':
    ensure => file,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
    source => 'puppet:///modules/cis_file_perms/cis_compliance',
  }
}
