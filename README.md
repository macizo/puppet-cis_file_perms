# cis_file_perms

CIS file-permission hardening for Puppet **without catalog bloat**.

## The problem

The usual way to enforce CIS controls like *"no group/other write on
system binary directories"* is a `file` resource with `recurse => true`:

This control appears in every major Linux CIS benchmark — the number
varies by distro and version but the requirement is identical everywhere:

| Benchmark | Control numbers |
|---|---|
| CIS Debian/Ubuntu | ~6.1.1–6.1.4 |
| CIS RHEL/CentOS/Rocky | ~6.1.1–6.1.4 |
| CIS SUSE | ~6.1.1–6.1.4 |

The requirement: no group-write or other-write bits on system binary
directories (`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`,
`/usr/local/sbin`, `/usr/local/games`).

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

All three parameters (`strip_mode`, `owner`, `group`) are optional and
independent. The provider only checks what you declare — if you omit
`owner`, no uid comparison is done anywhere in the walk, so there is
no unnecessary overhead:

```puppet
# only fix permissions, don't touch ownership
dir_perms { '/opt/myapp':
  strip_mode => 'o-rwx',
}

# only enforce owner, leave mode and group alone
dir_perms { '/opt/myapp':
  owner => 'root',
}

# all three at once
dir_perms { '/opt/myapp':
  strip_mode => 'go-w',
  owner      => 'root',
  group      => 'root',
}
```

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

### System binary defaults

```puppet
class { 'cis_file_perms::system_binaries':
  noop_mode => true,   # start in audit mode
}
```

Enforces `go-w` on `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`,
`/usr/local/bin`, `/usr/local/sbin`, `/usr/local/games`
(CIS ~6.1.x on all Linux benchmarks).

## Using with dev-sec os_hardening

`os_hardening` is a comprehensive hardening module — most of what it does
(shadow perms, `/bin/su`, system-user shells) is single-resource and has no
performance impact. The one exception is `minimize_access`, which uses
`file` with `recurse => true` and generates one catalog resource per file
found (typically 10,000–25,000 extra per run).

Disable just that part and let this module handle it instead:

```puppet
class { 'os_hardening':
  # ... your existing params ...
  folders_to_restrict => [],   # disables the recursive file walk only
}

class { 'cis_file_perms::system_binaries':
  noop_mode => true,           # audit first, enforce later
}
```

Everything else in `os_hardening` keeps running as normal.

## Who changes the permissions?

The puppet agent itself (root), inside the normal transaction, through
the provider's property setters. No external scripts, no cron jobs, no
second enforcement actor. Detection happens in the property getter
(read-only walk); remediation in the setter, only on the offender list,
and only when puppet is applying (never in `--noop`). Every change is
in the puppet report and PuppetDB — full audit trail.

## `cis_fs_scan` — SUID/SGID and world-writable enforcement

Scans one or more directory trees and strips illegitimate SUID/SGID bits
and world-writable permissions.

```puppet
class { 'cis_file_perms::fs_scan':
  noop_mode => true,   # always start here
}
```

> [!CAUTION]
> ### ALWAYS build a whitelist before enabling enforcement
>
> SUID and SGID bits exist for a reason. Many system binaries — `sudo`,
> `passwd`, `login`, `unix_chkpwd`, `postdrop`, `ssh-agent` — depend on
> them to function. Stripping these bits without a whitelist **will break
> your servers**:
>
> - `sudo` stops working — you lose privilege escalation
> - `login` / `unix_chkpwd` lose SUID — PAM authentication fails, locking
>   you out of console login and `su`
> - `postdrop` / `postqueue` lose SGID — mail delivery breaks
> - Docker/containerd overlay2 layers contain copies of system binaries
>   with SUID — they appear as violations but must be excluded, not stripped
>
> **The correct rollout sequence:**
>
> 1. Deploy with `noop_mode: true` and `force_run: true` on non-prod
> 2. Review the noop report — identify every flagged path
> 3. For each path: is it a legitimate system binary? Add to `suid_whitelist`.
>    Is it a container layer or app data dir? Add to `exclude`.
> 4. Repeat until the noop report contains only real violations
> 5. Only then set `noop_mode: false`
>
> If you skip steps 1–4 and go straight to enforce mode, every Puppet run
> will strip bits off system binaries. Package manager reinstalls will
> restore them, causing a permanent ping-pong that also masks real violations.
>
> **If you break your servers like the author did — who took down 17 test servers before building the whitelist — you're on your own.**

**Recovery** if you break a server: boot to GRUB recovery mode (no PAM
needed), or if SSH key auth still works:

```bash
apt-get install --reinstall -y sudo passwd login coreutils mount \
  openssh-client postfix policykit-1 dbus && systemctl restart postfix
```

### Hiera configuration

```yaml
cis_file_perms::fs_scan::noop_mode: true      # audit-only until whitelist is validated
cis_file_perms::fs_scan::suid_whitelist:
  - '/usr/bin/sudo'
  - '/usr/bin/passwd'
  - '/usr/bin/mount'
  - '/usr/sbin/unix_chkpwd'
  - '/usr/sbin/postdrop'
  - '/usr/sbin/postqueue'
  # ... see data/common.yaml for the full default list

cis_file_perms::fs_scan::exclude:
  - '/var/lib/docker'        # container image layers
  - '/var/lib/containerd'    # container image layers
  - '/var/spool/postfix/dev'
  - '/var/spool/postfix/private'
```

## Roadmap

* `suid_sgid` type: whitelist-based SUID/SGID enforcement
  (CIS 6.1.9–6.1.12)
* Status fact (last sweep time, offender count) for monitoring
  integration
* Litmus acceptance tests

## Testing

```bash
bundle install
bundle exec rspec spec/unit
```

## License

Apache-2.0
