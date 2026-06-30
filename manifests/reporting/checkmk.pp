# @summary Optional CheckMK adapter for cis_file_perms::reporting.
#
# Installs a CheckMK local check that reads the generic JSON status
# files written by cis_file_perms::reporting and cis_fs_scan, and
# turns them into CIS_* services. Include this only on nodes actually
# monitored by CheckMK; cis_file_perms::reporting itself stays
# tool-agnostic so other monitoring stacks can read the same files
# without this class.
class cis_file_perms::reporting::checkmk {
  include cis_file_perms::reporting

  file { '/usr/lib/check_mk_agent/local/cis_compliance':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    source  => 'puppet:///modules/cis_file_perms/cis_compliance',
    require => Class['cis_file_perms::reporting'],
  }
}
