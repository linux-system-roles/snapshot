# snapshot

[![ansible-lint.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/ansible-lint.yml) [![ansible-test.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/ansible-test.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/ansible-test.yml) [![codeql.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/codeql.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/codeql.yml) [![markdownlint.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/markdownlint.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/markdownlint.yml) [![python-unit-test.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/python-unit-test.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/python-unit-test.yml) [![shellcheck.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/shellcheck.yml) [![woke.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/woke.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/woke.yml)

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

- `remove`: Remove snapshots that conform to the specified prefix and pattern

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

### snapshot_lvm_snapset_name

This variable is required. snapshot_lvm_snapset_name is a string that will be
appended to the name of the LV when the snapshot set is created.  It will be used
to identify members of the set.  It must be at least one character long and contain
valid characters for use in an LVM volume name. A to Z, a to z, 0 to 9, underscore (_),
hyphen (-), dot (.), and plus (+) are valid characters.

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

If snapshot_lvm_snapset_name is set to "_snapset1", running the role will result
in the following:

```text
LV               VG   Attr       LSize   Pool Origin  Data%  Meta%  Move Log Cpy%Sync Convert
home_snapset1    rhel swi-a-s--- 104.00m      home    0.00
root_snapset1    rhel swi-a-s---   3.50g      root    0.01
swap_snapset1    rhel swi-a-s--- 400.00m      swap    0.00
home             rhel owi-aos---   1.00g
root             rhel owi-aos---  35.00g
swap             rhel owi-aos---  <3.88g
lv1_vg1_snapset1 vg1  swi-a-s--- 104.00m      lv1_vg1 0.00
lv2_vg1_snapset1 vg1  swi-a-s---   8.00m      lv2_vg1 0.00
lv1_vg1          vg1  owi-a-s---   1.00g
lv2_vg1          vg1  owi-a-s---  40.00m
lv1_vg2_snapset1 vg2  swi-a-s--- 104.00m      lv1_vg2 0.00
lv2_vg2_snapset1 vg2  swi-a-s---  12.00m      lv2_vg2 0.00
lv1_vg2          vg2  owi-a-s---   1.00g
lv2_vg2          vg2  owi-a-s---  80.00m
lv1_vg3_snapset1 vg3  swi-a-s--- 104.00m      lv1_vg3 0.00
lv3_vg3_snapset1 vg3  swi-a-s---  16.00m      lv3_vg3 0.00
lv1_vg3          vg3  owi-a-s---   1.00g
lv3_vg3          vg3  owi-a-s--- 120.00m
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

If true, the check and remove commands verify that the system is in the correct state.
For the remove command, the target system will be searched for any snapshots that would
be removed by the remove command without snapshot_lvm_verify_only.

snapshot_lvm_verify_only is intended to be used to double check that the snapshot or
remove command have completed the operation correctly.

### Variables Exported by the Role

#### snapshot_facts

Contains volume and mount point information for a given snapset.

For example:

```json
{
    "volumes": {
        "vg3": [
            {
                "lv_uuid": "VY7oRQ-zB1q-DzsP-1y7G-J3gL-ci1e-nQXwAy",
                "lv_name": "lv1_vg3",
                "lv_full_name": "vg3/lv1_vg3",
                "lv_path": "/dev/vg3/lv1_vg3",
                "lv_size": "1073741824",
                "origin": "",
                "origin_size": "1073741824",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "owi-a-s---",
                "vg_name": "vg3",
                "data_percent": "",
                "metadata_percent": ""
            },
            {
                "lv_uuid": "Yhn7RG-k7pM-ylf9-NNt8-xuGI-WwrF-i0Pf6T",
                "lv_name": "lv1_vg3_snapset2",
                "lv_full_name": "vg3/lv1_vg3_snapset2",
                "lv_path": "/dev/vg3/lv1_vg3_snapset2",
                "lv_size": "322961408",
                "origin": "lv1_vg3",
                "origin_size": "1073741824",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "swi-a-s---",
                "vg_name": "vg3",
                "data_percent": "0.00",
                "metadata_percent": ""
            },
            {
                "lv_uuid": "NlwbxX-NhwK-IHTj-sV9k-ldZY-Twvj-2SiCVe",
                "lv_name": "lv2_vg3",
                "lv_full_name": "vg3/lv2_vg3",
                "lv_path": "/dev/vg3/lv2_vg3",
                "lv_size": "1073741824",
                "origin": "",
                "origin_size": "1073741824",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "owi-a-s---",
                "vg_name": "vg3",
                "data_percent": "",
                "metadata_percent": ""
            },
            {
                "lv_uuid": "j0RCzX-OVaA-MGDw-ejHO-Eu35-f4yG-VJL2Kr",
                "lv_name": "lv2_vg3_snapset2",
                "lv_full_name": "vg3/lv2_vg3_snapset2",
                "lv_path": "/dev/vg3/lv2_vg3_snapset2",
                "lv_size": "322961408",
                "origin": "lv2_vg3",
                "origin_size": "1073741824",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "swi-aos---",
                "vg_name": "vg3",
                "data_percent": "0.66",
                "metadata_percent": ""
            },
            {
                "lv_uuid": "8kfTDY-22SL-4tC7-vTsR-1R63-zVzq-55qEL3",
                "lv_name": "lv3_vg3",
                "lv_full_name": "vg3/lv3_vg3",
                "lv_path": "/dev/vg3/lv3_vg3",
                "lv_size": "125829120",
                "origin": "",
                "origin_size": "125829120",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "owi-a-s---",
                "vg_name": "vg3",
                "data_percent": "",
                "metadata_percent": ""
            },
            {
                "lv_uuid": "babChm-IzEN-Pf8q-1dxk-BJ9R-3kZb-u91utS",
                "lv_name": "lv3_vg3_snapset2",
                "lv_full_name": "vg3/lv3_vg3_snapset2",
                "lv_path": "/dev/vg3/lv3_vg3_snapset2",
                "lv_size": "41943040",
                "origin": "lv3_vg3",
                "origin_size": "125829120",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "swi-a-s---",
                "vg_name": "vg3",
                "data_percent": "0.00",
                "metadata_percent": ""
            }
        ],
        "vg2": [
            {
                "lv_uuid": "8uMuRW-1KCV-8FTJ-frhX-X39o-V15B-1uEC98",
                "lv_name": "lv1_vg2",
                "lv_full_name": "vg2/lv1_vg2",
                "lv_path": "/dev/vg2/lv1_vg2",
                "lv_size": "1073741824",
                "origin": "",
                "origin_size": "1073741824",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "owi-a-s---",
                "vg_name": "vg2",
                "data_percent": "",
                "metadata_percent": ""
            },
            {
                "lv_uuid": "GGssIK-SHYI-to1m-MhVL-2BDk-PJ8X-dBnL7G",
                "lv_name": "lv1_vg2_snapset2",
                "lv_full_name": "vg2/lv1_vg2_snapset2",
                "lv_path": "/dev/vg2/lv1_vg2_snapset2",
                "lv_size": "322961408",
                "origin": "lv1_vg2",
                "origin_size": "1073741824",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "swi-aos---",
                "vg_name": "vg2",
                "data_percent": "20.97",
                "metadata_percent": ""
            },
            {
                "lv_uuid": "83A9VM-kVEy-sc60-kF14-gKGb-5Ryj-7yDyEG",
                "lv_name": "lv2_vg2",
                "lv_full_name": "vg2/lv2_vg2",
                "lv_path": "/dev/vg2/lv2_vg2",
                "lv_size": "83886080",
                "origin": "",
                "origin_size": "83886080",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "owi-a-s---",
                "vg_name": "vg2",
                "data_percent": "",
                "metadata_percent": ""
            },
            {
                "lv_uuid": "6tVL8A-U1x1-qqUt-WFVG-POsG-msFs-ZbbPq1",
                "lv_name": "lv2_vg2_snapset2",
                "lv_full_name": "vg2/lv2_vg2_snapset2",
                "lv_path": "/dev/vg2/lv2_vg2_snapset2",
                "lv_size": "29360128",
                "origin": "lv2_vg2",
                "origin_size": "83886080",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "swi-a-s---",
                "vg_name": "vg2",
                "data_percent": "0.00",
                "metadata_percent": ""
            }
        ],
        "vg1": [
            {
                "lv_uuid": "UnN0s0-TauJ-csnN-BgC1-3ocI-p8bE-jz0Hd8",
                "lv_name": "lv1_vg1",
                "lv_full_name": "vg1/lv1_vg1",
                "lv_path": "/dev/vg1/lv1_vg1",
                "lv_size": "1073741824",
                "origin": "",
                "origin_size": "1073741824",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "owi-aos---",
                "vg_name": "vg1",
                "data_percent": "",
                "metadata_percent": ""
            },
            {
                "lv_uuid": "5Np7N9-H15x-Go96-fIwL-E0GR-4fVB-clLDW2",
                "lv_name": "lv1_vg1_snapset2",
                "lv_full_name": "vg1/lv1_vg1_snapset2",
                "lv_path": "/dev/vg1/lv1_vg1_snapset2",
                "lv_size": "322961408",
                "origin": "lv1_vg1",
                "origin_size": "1073741824",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "swi-a-s---",
                "vg_name": "vg1",
                "data_percent": "20.97",
                "metadata_percent": ""
            },
            {
                "lv_uuid": "P0LPUQ-CljS-hOEm-U749-yyr9-USE7-1qDc2N",
                "lv_name": "lv2_vg1",
                "lv_full_name": "vg1/lv2_vg1",
                "lv_path": "/dev/vg1/lv2_vg1",
                "lv_size": "41943040",
                "origin": "",
                "origin_size": "41943040",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "owi-a-s---",
                "vg_name": "vg1",
                "data_percent": "",
                "metadata_percent": ""
            },
            {
                "lv_uuid": "FYIBRe-FDiW-PDUE-3l1y-mLzN-bLEg-qF12cz",
                "lv_name": "lv2_vg1_snapset2",
                "lv_full_name": "vg1/lv2_vg1_snapset2",
                "lv_path": "/dev/vg1/lv2_vg1_snapset2",
                "lv_size": "16777216",
                "origin": "lv2_vg1",
                "origin_size": "41943040",
                "pool_lv": "",
                "lv_tags": "",
                "lv_attr": "swi-a-s---",
                "vg_name": "vg1",
                "data_percent": "0.00",
                "metadata_percent": ""
            }
        ]
    },
    "mounts": {
        "/dev/vg3/lv1_vg3": null,
        "/dev/vg3/lv1_vg3_snapset2": [
            {
                "TARGET": "/mnt/database",
                "SOURCE": "/dev/mapper/vg3-lv1_vg3_snapset2",
                "FSTYPE": "xfs",
                "OPTIONS": "rw,relatime,seclabel,attr2,inode64,logbufs=8,logbsize=32k,noquota"
            }
        ],
        "/dev/vg3/lv2_vg3": null,
        "/dev/vg3/lv2_vg3_snapset2": null,
        "/dev/vg3/lv3_vg3": null,
        "/dev/vg3/lv3_vg3_snapset2": null,
        "/dev/vg2/lv1_vg2": null,
        "/dev/vg2/lv1_vg2_snapset2": [
            {
                "TARGET": "/mnt/production_mnt",
                "SOURCE": "/dev/mapper/vg2-lv1_vg2_snapset2",
                "FSTYPE": "xfs",
                "OPTIONS": "rw,relatime,seclabel,attr2,inode64,logbufs=8,logbsize=32k,noquota"
            }
        ],
        "/dev/vg2/lv2_vg2": null,
        "/dev/vg2/lv2_vg2_snapset2": null,
        "/dev/vg1/lv1_vg1": null,
        "/dev/vg1/lv1_vg1_snapset2": [
            {
                "TARGET": "/mnt/new_mountpoint",
                "SOURCE": "/dev/mapper/vg1-lv1_vg1_snapset2",
                "FSTYPE": "xfs",
                "OPTIONS": "rw,relatime,seclabel,attr2,inode64,logbufs=8,logbsize=32k,noquota"
            },
            {
                "TARGET": "/mnt/other_mp",
                "SOURCE": "/dev/mapper/vg1-lv1_vg1_snapset2",
                "FSTYPE": "xfs",
                "OPTIONS": "rw,relatime,seclabel,attr2,inode64,logbufs=8,logbsize=32k,noquota"
            }
        ],
        "/dev/vg1/lv2_vg1": null,
        "/dev/vg1/lv2_vg1_snapset2": null
    }
}
```

## rpm-ostree

See README-ostree.md

## License

MIT
