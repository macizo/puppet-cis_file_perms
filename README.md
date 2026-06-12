# cis_file_perms

CIS file-permission hardening for Puppet **without catalog bloat**.

## The problem

The usual way to enforce CIS controls like *"no group/other write on
system binary directories"* (CIS Debian Benchmark 6.1.x) is a `file`
resource with `recurse => true`:

```puppet
file { '/usr/bin':
  mode         => 'go-w',
  recurse      => true,
  recurselimit => 5,
}
```

This materialises **one catalog resource per file found**. On a typical
Debian server that's 10,000–25,000 extra resources per run: minutes of
catalog application time every 30 minutes, bloated reports, PuppetDB
storage pressure, and permanent fighting with the package manager.
This is exactly what `dev-sec/puppet-os-hardening`'s `minimize_access`
does, and why it is widely disabled in practice.

The `exec`-with-`find` workaround avoids the bloat but loses everything
that makes Puppet worth using: no per-file change reporting, no real
idempotence, and `--noop` tells you nothing.

## The solution

A custom type + provider. One catalog resource per directory tree; the
provider does a single Ruby `Find` walk, reports only the offending
entries, and remediates only those:

```puppet
dir_perms { ['/bin', '/usr/bin', '/sbin', '/usr/sbin']:
  strip_mode => 'go-w',
}
```

* **One resource, one walk** — catalog size and PuppetDB stay sane.
* **Real change reporting** — `removed forbidden permission bits from
  3 entries` lands in the run report, with offender paths (sample
  capped at 5).
* **`--noop` is a free audit mode** — offenders are reported, nothing
  is touched. Roll out with `noop => true`, watch reports, then flip.
* **Compliant files are never touched** — mtimes preserved, second run
  reports zero changes.
* **Scheduling support** — gate the walk with Puppet's native
  `schedule` metaparameter so it runs once a day per host instead of
  on every agent run.

## Usage

### Resource type

```puppet
dir_perms { '/var/log':
  strip_mode => 'g-w,o-rwx',          # bits that must not be set
  owner      => 'root',               # optional ownership enforcement
  exclude    => ['/var/log/journal'], # subtrees to skip
  max_depth  => 5,                    # default 32
}
```

`strip_mode` takes symbolic removal notation: `go-w`, `o-rwx`,
`a-rwx`, or comma-separated combinations (`g-w,o-rwx`).

### Class with hiera-driven rules and a daily randomized window

```puppet
include cis_file_perms
```

```yaml
cis_file_perms::rules:
  '/usr/bin':
    strip_mode: 'go-w'
  '/var/log':
    strip_mode: 'o-rwx'
    owner: 'root'
cis_file_perms::noop_mode: true   # audit-only rollout
```

With `manage_schedule => true` (the default) each host gets a
deterministic one-hour window (via `fqdn_rand`) between 01:00 and
06:59 in which the sweep runs once daily. Outside the window the
resource is skipped entirely — no filesystem walk.

### CIS Debian defaults

```puppet
class { 'cis_file_perms::debian':
  noop_mode => true,   # start in audit mode
}
```

Enforces `go-w` on `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`,
`/usr/local/bin`, `/usr/local/sbin`, `/usr/local/games`
(CIS Debian 6.1.x).

## Migrating from dev-sec os_hardening

```puppet
class { 'os_hardening':
  # ... your existing params ...
  folders_to_restrict => [],   # disables the 25k-resource recursion
}

class { 'cis_file_perms::debian':
  noop_mode => true,           # audit first, enforce later
}
```

The cheap parts of `minimize_access` (shadow perms, `/bin/su`,
system-user shells) are single resources and unaffected — keep them.

## Who changes the permissions?

The puppet agent itself (root), inside the normal transaction, through
the provider's property setters. No external scripts, no cron jobs, no
second enforcement actor. Detection happens in the property getter
(read-only walk); remediation in the setter, only on the offender list,
and only when puppet is applying (never in `--noop`). Every change is
in the puppet report and PuppetDB — full audit trail.

## Roadmap

* `suid_sgid` type: whitelist-based SUID/SGID enforcement
  (CIS 6.1.9–6.1.12)
* Status fact (last sweep time, offender count) for monitoring
  integration
* Litmus acceptance tests

## Development

```bash
bundle install
bundle exec rspec spec/unit
```

## License

Apache-2.0
