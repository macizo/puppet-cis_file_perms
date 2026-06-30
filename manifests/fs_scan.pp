# @summary Declare a cis_fs_scan resource from hiera, optionally inside a
#   schedule window so the filesystem walk doesn't run on every agent run.
#
# @param paths
#   Directory trees to scan.
#
# @param suid_whitelist
#   Paths permitted to carry SUID/SGID bits.
#
# @param exclude
#   Subtrees to prune within the scanned paths.
#
# @param manage_schedule
#   When true, creates a schedule and attaches it to the scan so the walk
#   only runs within the configured window. Set false or use force_run to
#   run on every agent run.
#
# @param schedule_period
#   Puppet schedule period: daily or weekly.
#
# @param schedule_range
#   Time range within which the scan may run, e.g. '22:00 - 6:00'.
#
# @param schedule_weekday
#   Day(s) the scan may run. Comma-separated numbers (0=Sun ... 6=Sat),
#   or undef to allow any day.
#
# @param noop_mode
#   When true, offenders are reported but never remediated.
#   Recommended for first rollout in any environment.
#
# @param force_run
#   When true, disables the schedule gate so the scan runs on every
#   agent run. Use temporarily to verify remediation, then reset to false.
class cis_file_perms::fs_scan (
  Array[String]    $paths,
  Array[String]    $suid_whitelist,
  Array[String]    $exclude,
  Boolean          $manage_schedule,
  String           $schedule_period,
  String           $schedule_range,
  Optional[String] $schedule_weekday,
  Boolean          $noop_mode,
  Boolean          $force_run,
) {
  if $manage_schedule and !$force_run {
    schedule { 'cis_fs_scan_window':
      period  => $schedule_period,
      range   => $schedule_range,
      weekday => $schedule_weekday,
      repeat  => 1,
    }

    $schedule_attr = { 'schedule' => 'cis_fs_scan_window' }
  } else {
    $schedule_attr = {}
  }

  cis_fs_scan { 'scan':
    paths          => $paths,
    suid_whitelist => $suid_whitelist,
    exclude        => $exclude,
    noop           => $noop_mode,
    *              => $schedule_attr,
  }
}
