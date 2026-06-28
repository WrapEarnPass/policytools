# policytools
SELinux policy generator

## Why is this?
SELinux policy management tends to only have three advisements:
- setenforce 0
  - DON'T DO THAT
- audit2allow -a -M module && semodule -i module.pp
  - DON'T DO THAT
- audit2allow -lar and manually edit everything that is generated.
 
Two of those are horrifically unsafe (turning off SELinux, or shoving all avc denies into allows), 
and the last is tedious.

## What is this?
This seperates the output of audit2allow into source-type modules that provide .te files. This allows review 
of generated policies without having to trying to find a working copy of a2dismod (not everyone ships that).

It has a disallow system so that any previously generated policies will automatically be 
renewed when a new disallow is added.

It has an override system so that harmful policies can be generally disallowed, but exceptions made for source-types
that really require an otherwise harmful policy.

## How to do this?
Add any generally disallowed policies to ```./disallows```, following grep -E regex.
```
#cve-2026-31677
user_t.*alg_socket
user_t.*execmod
user_t.*staff_
user_t.*sysadm_
var_log_t.*write
#don't allow regular files to get execute.
xdg_cache_t:file.*execute
xdg_downloads_t:file.*execute
xdg_music.*execute
#xguest should be disabled on this system
xguest_t
#disallow debugfs_t to user_t
user_t.*debugfs_t
```
```./disallows``` must not have any blank lines. Comments are ok though.

If a source-type has a known exception that is in ```disallows``` it can be overridden by
```./source_t.allow``` containing a ```allow source_t target_t:class { permission };```

Run as any user, it generates policies in ```.generated/``` from ```audit2allow -a``` and ```journalctl```

Generated policies are named ```machinename_sourcetype``` (without the _t) to prevent them from overriding
any default source-type policy.

Each time it runs, it will add any new findings to existing policies, creating a running log,
and updating policy versioning using the ```./.run``` file as a timekeeper.

Each time it runs, it will skip attempting to update policies if the ```audit2allow``` log
only has previously requested changes. This limits the number of times that policy has to be reloaded.

If executed as root:
- policytools will try to autoload ```.generated/``` policies.
- policytools will try to truncate ```audit.log```.
- policytools can load the policies with ```semodule -D``` if ```./disable_dontaudit``` exists.

## Dependencies:
This is implemented as a collection of bash-5 scripts, using what should be widely available system tools:
hostname, which, whoami, grep (one that supports -E and -P), checkmodule, semodule_package, cmp, audit2allow, journalctl

semodule, if running as root.

## Tested against:

debian 6.12.94+deb13-amd64

selinux-policy-default 2:2.20250213-10

## Licensing:
See LICENSE
