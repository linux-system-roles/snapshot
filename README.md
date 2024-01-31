# snapshot

[![ansible-lint.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/ansible-lint.yml) [![ansible-test.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/ansible-test.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/ansible-test.yml) [![codeql.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/codeql.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/codeql.yml) [![integration.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/integration.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/integration.yml) [![markdownlint.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/markdownlint.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/markdownlint.yml) [![python-unit-test.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/python-unit-test.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/python-unit-test.yml) [![shellcheck.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/shellcheck.yml) [![woke.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/woke.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/woke.yml) [![Coverage Status](https://coveralls.io/repos/github/linux-system-roles/snapshot/badge.svg)](https://coveralls.io/github/linux-system-roles/snapshot) [![Code Style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black) [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/linux-system-roles/snapshot.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/linux-system-roles/snapshot/context:python)

![template](https://github.com/linux-system-roles/snapshot/workflows/tox/badge.svg)

The `snapshot` role enables users to add/remove snapshots on target machines.
This role can be used to configure snapshots via:

- LVM

## Requirements

See below

### Collection requirements

If you want to manage `rpm-ostree` systems with this role, you will need to
install additional collections.  Please run the following command line to
install them:

```bash
ansible-galaxy collection install -vv -r meta/collection-requirements.yml
```

## Role Variables

### snapshot_lvm_action

This variable is required. It supports one of the following values:

- `snapshot`: Take snapshots of the specified VGs/LVs

- `check`: Validate that snapshot names don't have conflicts and there is sufficient space to take the snapshots

- `clean`: Remove snapshots that conform to the specified prefix and pattern

- `revert`: Revert to snapshots that are specifed by either the pattern or set.  If either the source LV or
            snapshot are open, the merge is deferred until the next time the server reboots and the
            source logical volume is activated.

- `extend`: Extend snapshot to have at least snapshot_lvm_percent_space_required space allocated to the
            snapshot.  Allocations are rounded up to the next multiple of the volume group extent size.

### snapshot_lvm_set

The snapshot role supports sets of volumes.  Sets may contain any number of volumes.
Sets are defined in the following format:

```text
    snapshot_lvm_set:
      name: snapset1
      volumes:
        - name: snapshot VG1 LV1
          vg: test_vg1
          lv: lv1
          percent_space_required: 20
        - name: snapshot VG1 LV1
          vg: test_vg2
          lv: lv1
          percent_space_required: 25
        - name: snapshot VG2 LV3
          vg: test_vg2
          lv: lv3
          percent_space_required: 15
        - name: snapshot VG3 LV7
          vg: test_vg3
          lv: lv7
          percent_space_required: 15
```

If before running the role, with :

### snapshot_lvm_prefix

This variable is required if not using sets. snapshot_lvm_prefix is a string that will be
prepended to the name of the LV when the snapshot is created.

### snapshot_lvm_suffix

This variable is required if not using sets. snapshot_lvm_prefix is a string that will be
appended to the name of the LV when the snapshot is created.

If before running the role, the following LVs exist:

```text
LV      VG   Attr       LSize   Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
home    rhel -wi-ao----   1.00g
root    rhel -wi-ao----  35.00g
swap    rhel -wi-ao----  <3.88g
lv1_vg1 vg1  -wi-a-----   1.00g
lv2_vg1 vg1  -wi-a-----  40.00m
lv1_vg2 vg2  -wi-a-----   1.00g
lv2_vg2 vg2  -wi-a-----  80.00m
lv1_vg3 vg3  -wi-a-----   1.00g
lv3_vg3 vg3  -wi-a----- 120.00m
```

If the prefix is set to "a_" and the suffix is set to "_z", running the role will result
in the following:

```text
LV          VG   Attr       LSize   Pool Origin  Data%  Meta%  Move Log Cpy%Sync Convert
a_home_z    rhel swi-a-s--- 104.00m      home    0.00
a_root_z    rhel swi-a-s---   3.50g      root    0.01
a_swap_z    rhel swi-a-s--- 400.00m      swap    0.00
home        rhel owi-aos---   1.00g
root        rhel owi-aos---  35.00g
swap        rhel owi-aos---  <3.88g
a_lv1_vg1_z vg1  swi-a-s--- 104.00m      lv1_vg1 0.00
a_lv2_vg1_z vg1  swi-a-s---   8.00m      lv2_vg1 0.00
lv1_vg1     vg1  owi-a-s---   1.00g
lv2_vg1     vg1  owi-a-s---  40.00m
a_lv1_vg2_z vg2  swi-a-s--- 104.00m      lv1_vg2 0.00
a_lv2_vg2_z vg2  swi-a-s---  12.00m      lv2_vg2 0.00
lv1_vg2     vg2  owi-a-s---   1.00g
lv2_vg2     vg2  owi-a-s---  80.00m
a_lv1_vg3_z vg3  swi-a-s--- 104.00m      lv1_vg3 0.00
a_lv3_vg3_z vg3  swi-a-s---  16.00m      lv3_vg3 0.00
lv1_vg3     vg3  owi-a-s---   1.00g
lv3_vg3     vg3  owi-a-s--- 120.00m
```

### snapshot_lvm_percent_space_required

This is required for check and snapshot actions if not using sets.

See the LVM man page for lvcreate with the -s (snapshot) and -L (size) options.
The snapshot role will ensure that there is at least snapshot_lvm_percent_space_required
space available in the VG.

Note: LVM will round up size to full physical extent

### snapshot_lvm_all_vgs

This is a boolean value with default false.  If true the role will snapshot
all VGs on the target system.  If false, the snapshot_lvm_vg must be set.

### snapshot_lvm_vg

If set, the role will create snapshots for all the logical volumes in the volume group.
If snapshot_lvm_lv is also set, a snapshot will be created for only that logical volume
in the volume group. If neither snapshot_lvm_all_vgs or snapshot_lvm_set are set,
snapshot_lvm_vg is required.

### snapshot_lvm_lv

If set, the role will create snapshots for the single logical volume in the volume group
specified by snapshot_lvm_vg.  The parameter requires snapshot_lvm_vg is set to a valid
volume group.

### snapshot_lvm_verify_only

If true, the check and clean commands verify that the system is in the correct state.
For the clean command, the target system will be searched for any snapshots that would
be removed by the clean command without snapshot_lvm_verify_only.

snapshot_lvm_verify_only is intended to be used to double check that the snapshot or
clean command have completed the operation correctly.

## rpm-ostree

See README-ostree.md

## License

MIT
