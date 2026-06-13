# @summary Enforces CIS controls for system binary directory permissions.
#   Strips group/other write bits from standard system binary directories.
#   Applies to all Linux systems — control numbers vary by benchmark and
#   distro version but the requirement is identical everywhere (~6.1.x).
#
# Drop-in replacement for the recursive part of
# os_hardening::minimize_access, without the per-file catalog bloat.
#
# @param bin_dirs   Directories to enforce 'go-w' on.
# @param exclude    Paths to skip entirely.
# @param noop_mode  Audit-only mode; report offenders, change nothing.
# @param force_run  Force a run to test the module

class cis_file_perms::system_binaries (
  Array[String[1]] $bin_dirs  = [],
  Array[String[1]] $exclude   = [],
  Boolean          $noop_mode = false,
  Boolean          $force_run = false,
) {
  $rules = $bin_dirs.reduce({}) |Hash $memo, String $dir| {
    $memo + { $dir => { 'strip_mode' => 'go-w', 'exclude' => $exclude } }
  }

  class { 'cis_file_perms':
    rules     => $rules,
    noop_mode => $noop_mode,
    force_run => $force_run,
  }
}
