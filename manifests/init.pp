# @summary Declare dir_perms rules from hiera, optionally inside a
#   randomized daily schedule window so the tree walks don't run on
#   every agent run.
#
# @param rules
#   Hash of path => dir_perms attributes, e.g.
#     cis_file_perms::rules:
#       '/usr/bin':
#         strip_mode: 'go-w'
#
# @param manage_schedule
#   When true, creates a daily puppet schedule with an fqdn_rand-based
#   window and attaches it to every rule, so each host sweeps once a day
#   at a host-specific hour instead of on every run.
#
# @param schedule_start_range
#   Earliest hour of the random window (window is one hour long,
#   chosen deterministically per host within [start, start + spread]).
#
# @param schedule_spread_hours
#   Number of hours over which host windows are spread.
#
# @param noop_mode
#   When true, rules audit and report but never change anything.
#   Recommended for initial rollout.
#
# @param force_run
#   When true, disables the schedule gate so the walk runs on every
#   puppet agent run. Use temporarily to verify remediation works,
#   then set back to false.
class cis_file_perms (
  Hash                  $rules                 = {},
  Boolean               $manage_schedule       = true,
  Integer[0, 22]        $schedule_start_range  = 1,
  Integer[1, 23]        $schedule_spread_hours = 5,
  Boolean               $noop_mode             = false,
  Boolean               $force_run             = false,
) {
  if $manage_schedule and !$force_run {
    $window_start = $schedule_start_range + fqdn_rand($schedule_spread_hours, 'cis_file_perms')
    $schedule_name = 'cis_file_perms_window'

    schedule { $schedule_name:
      period => daily,
      range  => sprintf('%d:00 - %d:59', $window_start, $window_start),
      repeat => 1,
    }

    $schedule_attr = { 'schedule' => $schedule_name }
  } else {
    $schedule_attr = {}
  }

  $rules.each |String $path, Hash $attrs| {
    dir_perms { $path:
      noop => $noop_mode,
      *    => $schedule_attr + $attrs,
    }
  }
}
