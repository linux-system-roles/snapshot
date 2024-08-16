Changelog
=========

[1.4.1] - 2024-08-16
--------------------

### Other Changes

- ci: Add tft plan and workflow (#68)
- ci: Update fmf plan to add a separate job to prepare managed nodes (#70)
- ci: Bump sclorg/testing-farm-as-github-action from 2 to 3 (#71)
- ci: Add workflow for ci_test bad, use remote fmf plan (#72)
- ci: Fix missing slash in ARTIFACTS_URL (#73)
- test: should only operate on test_ vgs (#75)

[1.4.0] - 2024-07-15
--------------------

### New Features

- feat: rewrite snapshot.py as an Ansible module / add support for thin origins (#58)

### Bug Fixes

- fix: add support for EL10 (#66)

### Other Changes

- ci: use tox-lsr 3.3.0 which uses ansible-test 2.17 (#60)
- ci: tox-lsr 3.4.0 - fix py27 tests; move other checks to py310 (#62)
- ci: Add supported_ansible_also to .ansible-lint (#63)
- ci: ansible-lint action now requires absolute directory (#64)

[1.3.3] - 2024-05-21
--------------------

### Other Changes

- refactor: translate command line arguments into JSON format and use common functions  (#55)

[1.3.2] - 2024-04-04
--------------------

### Other Changes

- test: use storage_udevadm_trigger, gather debug when fail (#49)
- ci: Bump ansible/ansible-lint from 6 to 24 (#50)
- ci: Bump mathieudutour/github-tag-action from 6.1 to 6.2 (#53)

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
