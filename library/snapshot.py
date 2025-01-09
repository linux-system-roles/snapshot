#!/usr/bin/python

# Copyright: (c) 2024, Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: snapshot

short_description: Module for snapshots

version_added: "2.13.0"

description:
    - "WARNING: Do not use this module directly! It is only for role internal use."
    - Manage LVM snapshots.

options:
    ansible_check_mode:
        description: running in check mode
        type: bool
    snapshot_lvm_fstype:
        description: file system type
        type: str
    snapshot_lvm_snapset_name:
        description: snapset name
        type: str
    snapshot_lvm_action:
        description: action to perform
        type: str
    snapshot_lvm_percent_space_required:
        description: See the LVM man page for lvcreate with the -s (snapshot) and -L (size) options.
            The snapshot role will ensure that there is at least snapshot_lvm_percent_space_required
            space available in the VG. When used inside of a snapset definition, use
            percent_space_required parameter.
        type: str
    snapshot_lvm_all_vgs:
        description: This is a boolean value with default false.  If true the role will snapshot
            all VGs on the target system.  If false, the snapshot_lvm_vg or snapshot_lvm_set
            must be set.
        type: bool
    snapshot_lvm_vg:
        description: If set, the role will create snapshots for all the logical volumes in the volume group.
            If snapshot_lvm_lv is also set, a snapshot will be created for only that logical volume
            in the volume group. If neither snapshot_lvm_all_vgs or snapshot_lvm_set are set,
            snapshot_lvm_vg is required. When used inside of a snapset definition, use
            vg parameter.
        type: str
    snapshot_lvm_lv:
        description: If set, the role will create snapshots for the single logical volume in the volume group
            specified by snapshot_lvm_vg.  The parameter requires snapshot_lvm_vg is set to a valid
            volume group. When used inside of a snapset definition, use lv parameter.
        type: str
    snapshot_lvm_verify_only:
        description: If true, the check and remove commands verify that the system is in the correct state.
            For the remove command, the target system will be searched for any snapshots that would
            be removed by the remove command without snapshot_lvm_verify_only.
        type: bool
    snapshot_lvm_mountpoint_create:
        description: If the mount point specified doesn't currently exist, create the mount point and any
            parent directories necessary for the mount point. When used inside of a snapset definition,
            use mountpoint_create parameter.
        type: bool
    snapshot_lvm_mountpoint:
        description: The mount target for the block device. When used inside of a snapset definition,
            use mountpoint parameter.
        type: str
    snapshot_lvm_mount_origin:
        description: If set to true, mount the origin of the snapshot rather than the snapshot.
            When used inside of a snapset definition, use mount_origin parameter.
        type: bool
    snapshot_lvm_mount_options:
        description: Options to pass to the mount command for the filesystem.  The argument is
            a comma separated list.  See the man page for mount for details.
            Note that XFS by default will not allow multiple filesystems with the
            same UUID to be mounted at the same time.  Using the "nouuid" will
            bypass the duplicate UUID check and allow a snapshot to be mounted
            at the same time as the snapshot source.
        type: str
    snapshot_lvm_unmount_all:
        description: If set to true, unmount all mountpoint for the resulting blockdevice.
            Linux allows filesystems to be mounted in multiple locations.  Setting
            this flag will unmount all locations.
        type: bool
    snapshot_lvm_vg_include:
        description: When using `snapshot_lvm_all_vgs`, there may be some
            subset of all volume groups that you want to use.  Set `snapshot_lvm_vg_include`
            to a regex pattern that matches the names of the volume groups you want to use and
            the rest will be excluded
        type: str
    snapshot_lvm_set:
        description: set of volumes
        type: dict
        suboptions:
            name:
                description: name of set
                type: str
            volumes:
                description: list of volumes
                type: list
                elements: dict
                default: []
                suboptions:
                    name:
                        description: name of volume
                        type: str
                    vg:
                        description: name of volume group
                        type: str
                    lv:
                        description: name of logical volume
                        type: str
                    percent_space_required:
                        description: percent of space required for volume
                        type: str
                    mountpoint:
                        description: path where to mount the snapshot
                        type: str
                    mountpoint_create:
                        description: create mountpoint and parent dirs
                        type: bool
                    mount_origin:
                        description: whether to mount the origin of the snapshot
                        type: bool
                    fstype:
                        description: file system type
                        type: str
                    options:
                        description: mount options
                        type: str
                    all_targets:
                        description: apply operation to all matching targets
                        type: bool
                    thin_pool:
                        description: name of thin pool
                        type: str

author:
    - Todd Gill (@trgill)
"""


EXAMPLES = r"""
# Create Snapshots of all VGs
---
- name: Extend all snapshots
  snapshot:
    snapshot_lvm_percent_space_required: 40
    snapshot_lvm_all_vgs: true
    snapshot_lvm_action: extend
    snapshot_lvm_set:
      name: snapshot
      volumes:
        - name: data1 snapshot
          vg: data_vg
          lv: data1
        - name: data2 snapshot
          vg: data_vg
          lv: data2
"""

RETURN = r"""
# Examples of possible return values.
msg:
    description: On success an empty string.  On failure a message to
        indicate the type of failure.
    type: str
    returned: success
data:
    description: json with an entry for each snapshot. data is included
        for the list command only.
    type: str
    returned: success
return_code:
    description: 0 is returned for success. On failure a return code from
        the SnapshotStatus class.
    type: int
    returned: success
changed:
    description: an indicator set to true if any action was taken, otherwise
        set to false.
    type: bool
    returned: success
"""

import logging
import os
import re

from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils.snapshot_lsr.consts import SnapshotStatus, SnapshotCommand
from ansible.module_utils.snapshot_lsr.utils import set_up_logging, get_command_const
from ansible.module_utils.snapshot_lsr.lvm import (
    snapshot_cmd,
    check_cmd,
    remove_cmd,
    revert_cmd,
    extend_cmd,
    list_cmd,
    mount_cmd,
    umount_cmd,
)
from ansible.module_utils.snapshot_lsr.snapmgr import (
    use_snapshot_manager,
    mgr_snapshot_cmd,
    mgr_check_cmd,
    mgr_remove_cmd,
    mgr_extend_cmd,
    mgr_revert_cmd,
    mgr_mount_cmd,
    mgr_umount_cmd,
)
from ansible.module_utils.snapshot_lsr.validate import (
    validate_snapset_args,
    validate_snapset_json,
)

logger = logging.getLogger("snapshot-role")

use_snapm = use_snapshot_manager()


__metaclass__ = type


def snapshot_cmd_execute(cmd, module, module_args, snapset_dict, vg_include):
    cmd_result = None

    if use_snapm:
        if cmd == SnapshotCommand.SNAPSHOT:
            cmd_result = mgr_snapshot_cmd(module, module_args, snapset_dict)
        elif cmd == SnapshotCommand.CHECK:
            cmd_result = mgr_check_cmd(module, module_args, snapset_dict)
        elif cmd == SnapshotCommand.REMOVE:
            cmd_result = mgr_remove_cmd(module_args, snapset_dict)
        elif cmd == SnapshotCommand.REVERT:
            cmd_result = mgr_revert_cmd(module_args, snapset_dict)
        elif cmd == SnapshotCommand.EXTEND:
            cmd_result = mgr_extend_cmd(module, module_args, snapset_dict)
        elif cmd == SnapshotCommand.LIST:
            cmd_result = list_cmd(module, module_args, vg_include)
        elif cmd == SnapshotCommand.MOUNT:
            cmd_result = mgr_mount_cmd(module, module_args, snapset_dict)
        elif cmd == SnapshotCommand.UMOUNT:
            cmd_result = mgr_umount_cmd(module, module_args, snapset_dict)
    else:
        if cmd == SnapshotCommand.SNAPSHOT:
            cmd_result = snapshot_cmd(module, module_args, snapset_dict)
        elif cmd == SnapshotCommand.CHECK:
            cmd_result = check_cmd(module, module_args, snapset_dict)
        elif cmd == SnapshotCommand.REMOVE:
            cmd_result = remove_cmd(module, module_args, snapset_dict)
        elif cmd == SnapshotCommand.REVERT:
            cmd_result = revert_cmd(module, module_args, snapset_dict)
        elif cmd == SnapshotCommand.EXTEND:
            cmd_result = extend_cmd(module, module_args, snapset_dict)
        elif cmd == SnapshotCommand.LIST:
            cmd_result = list_cmd(module, module_args, vg_include)
        elif cmd == SnapshotCommand.MOUNT:
            cmd_result = mount_cmd(module, module_args, snapset_dict)
        elif cmd == SnapshotCommand.UMOUNT:
            cmd_result = umount_cmd(module, module_args, snapset_dict)

    return cmd_result


def run_module():
    logger.info("run_module()")
    vg_include = None
    # define available arguments/parameters a user can pass to the module
    # available arguments/parameters that a user can pass
    module_args = dict(
        ansible_check_mode=dict(type="bool"),
        snapshot_lvm_action=dict(type="str"),
        snapshot_lvm_all_vgs=dict(type="bool"),
        snapshot_lvm_verify_only=dict(type="bool"),
        snapshot_lvm_mount_origin=dict(type="bool"),
        snapshot_lvm_mountpoint_create=dict(type="bool"),
        snapshot_lvm_unmount_all=dict(type="bool"),
        snapshot_lvm_percent_space_required=dict(type="str"),
        snapshot_lvm_vg=dict(type="str"),
        snapshot_lvm_lv=dict(type="str"),
        snapshot_lvm_snapset_name=dict(type="str"),
        snapshot_lvm_mount_options=dict(type="str"),
        snapshot_lvm_mountpoint=dict(type="str"),
        snapshot_lvm_fstype=dict(type="str"),
        snapshot_lvm_vg_include=dict(type="str"),
        snapshot_lvm_set=dict(
            type="dict",
            options=dict(
                name=dict(type="str"),
                volumes=dict(
                    type="list",
                    elements="dict",
                    default=[],
                    options=dict(
                        name=dict(type="str"),
                        vg=dict(type="str"),
                        lv=dict(type="str"),
                        percent_space_required=dict(type="str"),
                        mountpoint=dict(type="str"),
                        mount_origin=dict(type="bool"),
                        fstype=dict(type="str"),
                        options=dict(type="str"),
                        all_targets=dict(type="bool"),
                        mountpoint_create=dict(type="bool"),
                        thin_pool=dict(type="str"),
                    ),
                ),
            ),
        ),
    )

    result = dict(changed=False, return_code="", message="")

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    logger.info("module params: %s", module.params)

    cmd = get_command_const(module.params["snapshot_lvm_action"])

    if cmd == SnapshotCommand.INVALID:
        result["message"] = "Invalid command: " + module.params["snapshot_lvm_action"]
        module.exit_json(**result)

    if module.params["snapshot_lvm_vg_include"]:
        vg_include = re.compile(module.params["snapshot_lvm_vg_include"])

    if len(module.params["snapshot_lvm_set"].get("volumes")) > 0:
        cmd_result, snapset_dict = validate_snapset_json(
            cmd,
            module.params["snapshot_lvm_set"],
            False,
        )
    else:
        cmd_result, snapset_dict = validate_snapset_args(
            module, cmd, module.params, vg_include
        )

    if cmd_result["return_code"] == SnapshotStatus.SNAPSHOT_OK:
        cmd_result = snapshot_cmd_execute(
            cmd, module, module.params, snapset_dict, vg_include
        )

    logger.info("cmd_result: %s", cmd_result)

    result["errors"] = cmd_result["errors"]
    result["msg"] = cmd_result["errors"]
    result["return_code"] = cmd_result["return_code"]
    result["changed"] = cmd_result["changed"]
    if "data" in cmd_result:
        result["data"] = cmd_result["data"]

    logger.info("result: %s", result)

    if result["return_code"] == SnapshotStatus.SNAPSHOT_OK:
        module.exit_json(**result)
    else:
        module.fail_json(**result)


def main():
    set_up_logging()
    # Ensure that we get consistent output for parsing stdout/stderr and that we
    # are using the lvmdbusd profile.
    os.environ["LC_ALL"] = "C"
    run_module()


if __name__ == "__main__":
    main()
