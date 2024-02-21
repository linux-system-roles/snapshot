Changelog
=========

[1.3.1] - 2024-02-21
--------------------

### Bug Fixes

- fix: better error handling for all platforms and ansible versions (#47)

[1.3.0] - 2024-02-20
--------------------

### New Features

- feat: add support for snapshot_lvm_vg_include (#39)

### Bug Fixes

- fix: ostree test failures - use /var/mnt (#37)
- fix: ensure role is idempotent and supports check mode (#41)

### Other Changes

- refactor: use iterator function for listing vgs, lvs (#36)
- refactor: centralize test setup/cleanup - add cleanup debugging (#38)

[1.2.0] - 2024-02-13
--------------------

### New Features

- feat: add support to extending existing snapshots to required percentage (#22)
- feat: add support for the "list" command (#31)
- feat: add support mounting/unmounting snapshots and origins (#34)

### Bug Fixes

- fix: rename the clean command to remove (#24)

### Other Changes

- ci: Bump codecov/codecov-action from 3 to 4 (#25)
- ci: fix python unit test - copy pytest config to tests/unit (#26)
- refactor: fix linter issues (#27)
- docs: remove template badge (#28)

[1.1.0] - 2024-01-26
--------------------

### New Features

- feat: add support for reverting LV back to state of snapshot  (#15)

[1.0.0] - 2024-01-24
--------------------

### New Features

- feat: New Role - snapshot - support for LVM snapshots
