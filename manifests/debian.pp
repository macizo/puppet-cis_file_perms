# @summary CIS Debian defaults: strip group/other write from system
#   binary directories (CIS Debian Benchmark 6.1.x).
#
# Drop-in replacement for the recursive part of
# os_hardening::minimize_access, without the per-file catalog bloat.
#
# @param bin_dirs   Directories to enforce 'go-w' on.
# @param exclude    Paths to skip entirely.
# @param noop_mode  Audit-only mode; report offenders, change nothing.
class cis_file_perms::debian (
  Array[String[1]] $bin_dirs  = [
    '/bin',
    '/sbin',
    '/usr/bin',
    '/usr/sbin',
    '/usr/local/bin',
    '/usr/local/sbin',
    '/usr/local/games',
  ],
  Array[String[1]] $exclude   = [],
  Boolean          $noop_mode = false,
) {
  $rules = $bin_dirs.reduce({}) |Hash $memo, String $dir| {
    $memo + { $dir => { 'strip_mode' => 'go-w', 'exclude' => $exclude } }
  }

  class { 'cis_file_perms':
    rules     => $rules,
    noop_mode => $noop_mode,
  }
}
