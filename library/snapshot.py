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


import argparse
import json
import logging
import math
import os
import re
import stat
import sys
from os.path import join as path_join

from ansible.module_utils.basic import AnsibleModule

__metaclass__ = type

logger = logging.getLogger("snapshot-role")

LVM_NOTFOUND_RC = 5
MAX_LVM_NAME = 127
CHUNK_SIZE = 65536
DEV_PREFIX = "/dev"

# Minimum LVM snapshot size (512MiB)
LVM_MIN_SNAPSHOT_SIZE = 512 * 1024**2


class LvmBug(RuntimeError):
    """
    Things that are clearly a bug with lvm itself.
    """

    def __init__(self, msg):
        super().__init__(msg)

    def __str__(self):
        return "lvm bug encountered: %s" % " ".join(self.args)


class LVSpaceState:
    lv_size = 0  # The size of the logical volume
    chunk_size = CHUNK_SIZE  # Unit size in a snapshot volume


class VGSpaceState:
    vg_extent_size = 0  # The size of the physical extents in the volume group
    vg_size = 0  # The size of the volume group
    vg_free = 0  # Size of the free space remaining in the volume group
    lvs = dict()


class SnapshotCommand:
    SNAPSHOT = "snapshot"
    CHECK = "check"
    REMOVE = "remove"
    REVERT = "revert"
    EXTEND = "extend"
    LIST = "list"
    MOUNT = "mount"
    UMOUNT = "umount"
    INVALID = "invalid"


class SnapshotStatus:
    SNAPSHOT_OK = 0
    ERROR_INSUFFICIENT_SPACE = 1
    ERROR_ALREADY_DONE = 2
    ERROR_SNAPSHOT_FAILED = 3
    ERROR_REMOVE_FAILED = 4
    ERROR_REMOVE_FAILED_NOT_SNAPSHOT = 5
    ERROR_REMOVE_FAILED_INUSE = 6
    ERROR_REMOVE_FAILED_NOT_FOUND = 7
    ERROR_LVS_FAILED = 8
    ERROR_NAME_TOO_LONG = 9
    ERROR_ALREADY_EXISTS = 10
    ERROR_NAME_CONFLICT = 11
    ERROR_VG_NOTFOUND = 12
    ERROR_LV_NOTFOUND = 13
    ERROR_VERIFY_NOTSNAPSHOT = 14
    ERROR_VERIFY_COMMAND_FAILED = 15
    ERROR_VERIFY_NOT_FOUND = 16
    ERROR_CMD_INVALID = 17
    ERROR_VERIFY_REMOVE_FAILED = 18
    ERROR_VERIFY_REMOVE_SOURCE_SNAPSHOT = 19
    ERROR_SNAPSET_SOURCE_DOES_NOT_EXIST = 20
    ERROR_SNAPSET_CHECK_STATUS_FAILED = 21
    ERROR_SNAPSET_INSUFFICIENT_SPACE = 22
    ERROR_JSON_PARSER_ERROR = 23
    ERROR_INVALID_PERCENT_REQUESTED = 24
    ERROR_UNKNOWN_FAILURE = 25
    ERROR_REVERT_FAILED = 26
    ERROR_EXTEND_NOT_SNAPSHOT = 27
    ERROR_EXTEND_NOT_FOUND = 28
    ERROR_EXTEND_FAILED = 29
    ERROR_EXTEND_VERIFY_FAILED = 29
    ERROR_UMOUNT_FAILED = 30
    ERROR_MOUNT_FAILED = 31
    ERROR_MOUNT_POINT_NOT_EXISTING = 32
    ERROR_MOUNT_NOT_BLOCKDEV = 33
    ERROR_MOUNT_INVALID_PARAMS = 34
    ERROR_MOUNT_POINT_ALREADY_MOUNTED = 35
    ERROR_MOUNT_VERIFY_FAILED = 36
    ERROR_UMOUNT_VERIFY_FAILED = 37
    ERROR_UMOUNT_NOT_MOUNTED = 38


def get_command_const(command):
    if command == SnapshotCommand.SNAPSHOT:
        return SnapshotCommand.SNAPSHOT
    elif command == SnapshotCommand.CHECK:
        return SnapshotCommand.CHECK
    elif command == SnapshotCommand.REMOVE:
        return SnapshotCommand.REMOVE
    elif command == SnapshotCommand.REVERT:
        return SnapshotCommand.REVERT
    elif command == SnapshotCommand.EXTEND:
        return SnapshotCommand.EXTEND
    elif command == SnapshotCommand.LIST:
        return SnapshotCommand.LIST
    elif command == SnapshotCommand.MOUNT:
        return SnapshotCommand.MOUNT
    elif command == SnapshotCommand.UMOUNT:
        return SnapshotCommand.UMOUNT
    else:
        return SnapshotCommand.INVALID


def makedirs(path):
    if not os.path.isdir(path):
        os.makedirs(path, 0o755)


def get_mounted_device(mount_target):
    """If mount_target is mounted, return the device that is mounted.
    If mount_target is not mounted, return None."""
    with open("/proc/mounts") as pm:
        for line in pm:
            params = line.split(" ")
            if mount_target == params[1]:
                return params[0]
    return None


def to_bool(to_convert):
    if isinstance(to_convert, bool):
        return to_convert

    return to_convert.lower() in ["true", "1", "t", "y"]


def mount(
    module,
    blockdev,
    mountpoint,
    fstype=None,
    options=None,
    mountpoint_create=False,
    check_mode=False,
):
    mount_command = []
    mountpoint = os.path.normpath(mountpoint)
    if options is None:
        options = "defaults"

    mounted_dev = get_mounted_device(mountpoint)
    if mounted_dev:
        try:
            if os.path.samefile(blockdev, mounted_dev):
                return (
                    SnapshotStatus.ERROR_MOUNT_POINT_ALREADY_MOUNTED,
                    mountpoint + " is already mounted at " + blockdev,
                )
            else:
                return (
                    SnapshotStatus.ERROR_MOUNT_FAILED,
                    mountpoint
                    + " is already mounted at different device "
                    + mounted_dev,
                )
        except Exception as exc:
            return (
                SnapshotStatus.ERROR_MOUNT_FAILED,
                "could not verify mountpoint "
                + mountpoint
                + " at "
                + blockdev
                + ": "
                + str(exc),
            )

    if not os.path.isdir(mountpoint):
        if not mountpoint_create:
            return (
                SnapshotStatus.ERROR_MOUNT_POINT_NOT_EXISTING,
                "mount point does not exist",
            )
        makedirs(mountpoint)

    mountpoint = os.path.normpath(mountpoint)
    mount_command.append("mount")

    if fstype:
        mount_command.append("-t")
        mount_command.append(fstype)

    if options:
        mount_command.append("-o")
        mount_command.append(options)

    mount_command.append(blockdev)
    mount_command.append(mountpoint)

    if check_mode:
        return SnapshotStatus.SNAPSHOT_OK, "Would run command " + " ".join(
            mount_command
        )

    rc, _output, stderr = module.run_command(mount_command)

    if rc != 0:
        logger.error("failed to mount: ".join(mount_command))
        logger.error(stderr)
        return SnapshotStatus.ERROR_MOUNT_FAILED, stderr

    return SnapshotStatus.SNAPSHOT_OK, ""


def umount(module, umount_target, all_targets, check_mode):
    mounted_dev = get_mounted_device(umount_target)
    if not mounted_dev:
        return (
            SnapshotStatus.ERROR_UMOUNT_NOT_MOUNTED,
            "not mounted " + umount_target,
        )
    else:
        logger.info("umount target %s from device %s", umount_target, mounted_dev)

    umount_command = []

    umount_command.append("umount")
    umount_command.append(umount_target)
    if all_targets:
        umount_command.append("-A")

    if check_mode:
        return SnapshotStatus.SNAPSHOT_OK, "Would run command " + " ".join(
            umount_command
        )

    rc, output, stderr = module.run_command(umount_command)

    if rc != 0:
        logger.error("failed to unmount %s: %s: %s", umount_target, output, stderr)
        return SnapshotStatus.ERROR_UMOUNT_FAILED, stderr
    return SnapshotStatus.SNAPSHOT_OK, ""


# what percentage is part of whole
def percentage(part, whole):
    return 100 * float(part) / float(whole)


# what is number is percent of whole
def percentof(percent, whole):
    return float(whole) / 100 * float(percent)


def get_snapshot_size_required(lv_size, required_percent, extent_size):
    return round_up(math.ceil(percentof(required_percent, lv_size)), extent_size)


def set_up_logging(log_dir="/tmp", log_prefix="snapshot_role"):
    logger.setLevel(logging.DEBUG)

    def make_handler(path, prefix, level):
        log_file = "%s/%s.log" % (path, prefix)
        log_file = os.path.realpath(log_file)
        handler = logging.FileHandler(log_file)
        handler.setLevel(level)
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s/%(threadName)s: %(message)s"
        )
        handler.setFormatter(formatter)
        return handler

    handler = make_handler(log_dir, log_prefix, logging.DEBUG)

    # Ansible ansible.builtin.script feature doesn't seperate stdout
    # and stderr when the text is returned to the calling .yaml. Logging
    # to stdout will cause problems with ansible checking the return
    # strings from the python script.

    # stdout_handler = logging.StreamHandler(stream=sys.stdout)

    logger.addHandler(handler)
    # logger.addHandler(stdout_handler)


def check_positive(value):
    try:
        value = int(value)
        if value <= 0:
            raise argparse.ArgumentTypeError(
                "{0:d} is not a positive integer".format(value)
            )
    except ValueError:
        raise Exception(
            "{0:04x} is not an integer, it is type {1}".format(value, value.__class__)
        )
    return value


def round_up(value, multiple):
    return value + (multiple - (value % multiple))


def lvm_full_report_json(module):
    report_command = [
        "lvm",
        "fullreport",
        "--units",
        "B",
        "--nosuffix",
        "--configreport",
        "vg",
        "-o",
        "vg_name,vg_uuid,vg_size,vg_free,vg_extent_size",
        "--configreport",
        "lv",
        "-o",
        "lv_uuid,lv_name,lv_full_name,lv_path,lv_size,origin,origin_size,pool_lv,lv_tags,lv_attr,vg_name,data_percent,metadata_percent,pool_lv",
        "--configreport",
        "pv",
        "-o",
        "pv_name",
        "--reportformat",
        "json",
    ]

    rc, output, stderr = module.run_command(report_command)

    if rc:
        logger.info("'fullreport' exited with code : {rc}", rc=rc)
        raise LvmBug("'fullreport' exited with code : %d: %s" % (rc, stderr))
    try:
        lvm_json = json.loads(output)
    except ValueError as error:
        logger.info(error)
        raise LvmBug("'fullreport' decode failed : %s" % error.args[0])

    return lvm_json


def lvm_get_fs_mount_points(module, block_path):
    find_mnt_command = [
        "findmnt",
        block_path,
        "-P",
    ]
    mount_list = list()

    rc, output, stderr = module.run_command(find_mnt_command)
    if rc:
        logger.error("'lvm_get_fs_mount_points' exited with code : %d: %s", rc, stderr)
        return None

    output = output.replace('"', "")

    for line in output.split("\n"):
        if len(line):
            mount_list.append(dict(arg.split("=", 1) for arg in line.split(" ") if arg))

    return mount_list


def vgs_lvs_iterator(module, vg_name, lv_name, vg_include, omit_empty_lvs=False):
    """Return an iterator which returns tuples.
    The first element in the tuple is the vg object matching given vg_name,
    or all vgs if vg_name is None.  The second element is a list of
    corresponding lv items where the lv name matches the given
    lv_name, or all lvs if lv_name is None.  By default the lv list
    will be returned even if empty.  Use omit_empty_lvs if you want
    only the vgs that have lvs."""
    lvm_json = lvm_full_report_json(module)
    for list_item in lvm_json["report"]:
        vg = list_item.get("vg", [{}])[0]
        # pylint: disable-msg=E0601
        if (
            vg
            and vg["vg_name"]
            and (not vg_name or vg_name == vg["vg_name"])
            and (not vg_include or vg_include.search(vg["vg_name"]))
        ):
            lvs = [
                lv
                for lv in list_item["lv"]
                if (not lv_name or lv_name == lv["lv_name"])
            ]
            if lvs or not omit_empty_lvs:
                yield (vg, lvs)


def vgs_lvs_dict(module, vg_name, lv_name, vg_include):
    """Return a dict using vgs_lvs_iterator.  Key is
    vg name, value is list of lvs corresponding to vg.
    The returned dict will not have vgs that have no lvs."""
    return dict(
        [
            (vg["vg_name"], lvs)
            for vg, lvs in vgs_lvs_iterator(module, vg_name, lv_name, vg_include, True)
        ]
    )


def lvm_list_json(module, vg_name, lv_name, vg_include):
    vg_dict = vgs_lvs_dict(module, vg_name, lv_name, vg_include)
    fs_dict = dict()
    top_level = dict()
    for lv_list in vg_dict.values():
        for lv_item in lv_list:
            block_path = lv_item["lv_path"]
            fs_mount_points = lvm_get_fs_mount_points(module, block_path)
            fs_dict[block_path] = fs_mount_points

    top_level["volumes"] = vg_dict
    top_level["mounts"] = fs_dict
    return SnapshotStatus.SNAPSHOT_OK, top_level


def get_snapshot_name(lv_name, suffix):
    if suffix:
        suffix_str = suffix
    else:
        suffix_str = ""

    return lv_name + "_" + suffix_str


def lvm_get_attr(module, vg_name, lv_name):
    lvs_command = ["lvs", "--reportformat", "json", vg_name + "/" + lv_name]

    rc, output, stderr = module.run_command(lvs_command)

    if rc == LVM_NOTFOUND_RC:
        return SnapshotStatus.SNAPSHOT_OK, False

    if rc:
        return SnapshotStatus.ERROR_LVS_FAILED, stderr

    try:
        lvs_json = json.loads(output)
    except ValueError as error:
        logger.info(error)
        message = "lvm_is_snapshot: json decode failed : %s" % error.args[0]
        return SnapshotStatus.ERROR_JSON_PARSER_ERROR, message

    lv_list = lvs_json["report"]

    if len(lv_list) > 1 or len(lv_list[0]["lv"]) > 1:
        raise LvmBug("'lvs' returned more than 1 lv '%d'" % rc)

    lv = lv_list[0]["lv"][0]

    lv_attr = lv["lv_attr"]

    if len(lv_attr) == 0:
        raise LvmBug("'lvs' zero length attr : '%d'" % rc)

    return SnapshotStatus.SNAPSHOT_OK, lv_attr


def lvm_is_thinpool(module, vg_name, lv_name):
    rc, lv_attr = lvm_get_attr(module, vg_name, lv_name)

    if rc == LVM_NOTFOUND_RC:
        return SnapshotStatus.SNAPSHOT_OK, False

    if rc:
        return SnapshotStatus.ERROR_LVS_FAILED, None

    if lv_attr[0] == "t":
        return SnapshotStatus.SNAPSHOT_OK, True
    else:
        return SnapshotStatus.SNAPSHOT_OK, False


def lvm_lv_exists(module, vg_name, lv_name):
    vg_exists = False
    lv_exists = False

    if not vg_name:
        return SnapshotStatus.SNAPSHOT_OK, vg_exists, lv_exists
    # check for VG
    lvs_command = ["lvs", vg_name]

    rc, _output, _stderr = module.run_command(lvs_command)
    if rc == 0:
        vg_exists = True

    if not lv_name:
        return SnapshotStatus.SNAPSHOT_OK, vg_exists, lv_exists

    lvs_command = ["lvs", vg_name + "/" + lv_name]
    rc, _output, _stderr = module.run_command(lvs_command)
    if rc == 0:
        lv_exists = True

    return SnapshotStatus.SNAPSHOT_OK, vg_exists, lv_exists


def lvm_is_owned(lv_name, suffix):
    if suffix:
        suffix_str = suffix
    else:
        suffix_str = ""

    if not lv_name.endswith(suffix_str):
        return False

    return True


def lvm_is_inuse(module, vg_name, lv_name):
    lvs_command = ["lvs", "--reportformat", "json", vg_name + "/" + lv_name]

    rc, output, stderr = module.run_command(lvs_command)

    if rc == LVM_NOTFOUND_RC:
        return SnapshotStatus.SNAPSHOT_OK, False

    if rc:
        return SnapshotStatus.ERROR_LVS_FAILED, stderr

    try:
        lvs_json = json.loads(output)
    except ValueError as error:
        logger.info(error)
        message = "lvm_is_inuse: json decode failed : %s" % error.args[0]
        return SnapshotStatus.ERROR_JSON_PARSER_ERROR, message

    lv_list = lvs_json["report"]

    if len(lv_list) > 1 or len(lv_list[0]["lv"]) > 1:
        raise LvmBug("'lvs' returned more than 1 lv '%d'" % rc)

    lv = lv_list[0]["lv"][0]

    lv_attr = lv["lv_attr"]

    if len(lv_attr) == 0:
        raise LvmBug("'lvs' zero length attr : '%d'" % rc)

    # check if the device is open
    if lv_attr[5] == "o":
        return SnapshotStatus.SNAPSHOT_OK, True

    return SnapshotStatus.SNAPSHOT_OK, False


def lvm_is_snapshot(module, vg_name, lv_name):
    rc, lv_attr = lvm_get_attr(module, vg_name, lv_name)

    if rc == LVM_NOTFOUND_RC:
        return SnapshotStatus.SNAPSHOT_OK, False

    if rc:
        return SnapshotStatus.ERROR_LVS_FAILED, None

    if lv_attr[0] == "s":
        return SnapshotStatus.SNAPSHOT_OK, True
    else:
        return SnapshotStatus.SNAPSHOT_OK, False


def lvm_snapshot_remove(module, vg_name, snapshot_name, check_mode):
    rc, is_snapshot = lvm_is_snapshot(module, vg_name, snapshot_name)

    if rc != SnapshotStatus.SNAPSHOT_OK:
        raise LvmBug("'lvs' failed '%d'" % rc)

    if not is_snapshot:
        return (
            SnapshotStatus.ERROR_REMOVE_FAILED_NOT_SNAPSHOT,
            snapshot_name + " is not a snapshot",
        )

    remove_command = ["lvremove", "-y", vg_name + "/" + snapshot_name]

    if check_mode:
        return rc, "Would run command " + " ".join(remove_command)

    rc, _output, stderr = module.run_command(remove_command)

    if rc:
        return SnapshotStatus.ERROR_REMOVE_FAILED, stderr

    return SnapshotStatus.SNAPSHOT_OK, ""


def revert_lv(module, vg_name, snapshot_name, check_mode):
    rc, _vg_exists, lv_exists = lvm_lv_exists(module, vg_name, snapshot_name)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        raise LvmBug("'lvs' failed '%d'" % rc)

    if lv_exists:
        rc, is_snapshot = lvm_is_snapshot(module, vg_name, snapshot_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (
                SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                "revert_lv: command failed for LV lvm_is_snapshot()",
            )
        if not is_snapshot:
            return (
                SnapshotStatus.ERROR_REVERT_FAILED,
                "LV with name: " + vg_name + "/" + snapshot_name + " is not a snapshot",
            )
    else:
        return (
            SnapshotStatus.ERROR_LV_NOTFOUND,
            "snapshot not found with name: " + vg_name + "/" + snapshot_name,
        )

    revert_command = ["lvconvert", "--merge", vg_name + "/" + snapshot_name]

    if check_mode:
        return rc, "Would run command " + " ".join(revert_command)

    rc, output, stderr = module.run_command(revert_command)

    if rc:
        return SnapshotStatus.ERROR_REVERT_FAILED, stderr

    return SnapshotStatus.SNAPSHOT_OK, output


def extend_lv_snapshot(
    module, vg_name, lv_name, suffix, percent_space_required, check_mode
):
    snapshot_name = get_snapshot_name(lv_name, suffix)

    rc, _vg_exists, lv_exists = lvm_lv_exists(module, vg_name, snapshot_name)

    changed = False
    if lv_exists:
        rc, is_snapshot = lvm_is_snapshot(module, vg_name, snapshot_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (
                SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                "extend_lv_snapshot: command failed for LV lvm_is_snapshot()",
                changed,
            )
        if not is_snapshot:
            return (
                SnapshotStatus.ERROR_EXTEND_NOT_SNAPSHOT,
                "LV with name: " + vg_name + "/" + snapshot_name + " is not a snapshot",
                changed,
            )
    else:
        return (
            SnapshotStatus.ERROR_EXTEND_NOT_FOUND,
            "snapshot not found with name: " + vg_name + "/" + snapshot_name,
            changed,
        )
    rc, _message, current_space_dict = get_current_space_state(module)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, "extend_lv get_space_state failure", changed

    current_size = current_space_dict[vg_name].lvs[snapshot_name].lv_size
    required_size = get_space_needed(
        vg_name, lv_name, percent_space_required, current_space_dict
    )

    if current_size >= required_size:
        # rare case of OK return and no change
        return SnapshotStatus.SNAPSHOT_OK, "", changed

    extend_command = [
        "lvextend",
        "-L",
        str(required_size) + "B",
        vg_name + "/" + snapshot_name,
    ]

    if check_mode:
        return rc, "Would run command " + " ".join(extend_command), changed

    rc, output, stderr = module.run_command(extend_command)

    if rc != SnapshotStatus.SNAPSHOT_OK:
        return SnapshotStatus.ERROR_EXTEND_FAILED, stderr, changed

    return SnapshotStatus.SNAPSHOT_OK, output, True  # changed


def extend_check_size(module, vg_name, lv_name, snapshot_name, percent_space_required):
    rc, _message, current_space_dict = get_current_space_state(module)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, "extend_lv get_space_state failure", None

    current_size = current_space_dict[vg_name].lvs[snapshot_name].lv_size
    required_size = get_space_needed(
        vg_name, lv_name, percent_space_required, current_space_dict
    )

    if current_size >= required_size:
        return SnapshotStatus.SNAPSHOT_OK, True, ""
    logger.info(
        "extend_check_size : %s %s/%s current size : %d required size : %d",
        snapshot_name,
        vg_name,
        lv_name,
        current_size,
        required_size,
    )
    return SnapshotStatus.SNAPSHOT_OK, False, "current size too small"


def extend_snapshot_set(module, snapset_json, check_mode):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("extend snapsset : %s", snapset_name)

    changed = False
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]
        percent_space_required = list_item["percent_space_required"]

        rc, message, cmd_changed = extend_lv_snapshot(
            module, vg, lv, snapset_name, percent_space_required, check_mode
        )

        if cmd_changed:
            changed = True

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, changed

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def extend_verify_snapshot_set(module, snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]

    logger.info("extend verify snapsset : %s", snapset_name)

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]
        percent_space_required = list_item["percent_space_required"]

        snapshot_name = get_snapshot_name(lv, snapset_name)

        rc, _vg_exists, lv_exists = lvm_lv_exists(module, vg, snapshot_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (
                rc,
                "failure to get status for: " + vg + "/" + snapshot_name,
            )

        if not lv_exists:
            return (
                SnapshotStatus.ERROR_EXTEND_VERIFY_FAILED,
                "extend verify snapshot not found for source LV: "
                + vg
                + "/"
                + snapshot_name,
            )

        rc, size_ok, message = extend_check_size(
            module, vg, lv, snapshot_name, percent_space_required
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

        if not size_ok:
            return (
                SnapshotStatus.ERROR_EXTEND_VERIFY_FAILED,
                "verify failed due to insufficient space for: " + vg + "/" + lv,
            )

    return SnapshotStatus.SNAPSHOT_OK, ""


def snapshot_lv(module, vg_name, lv_name, suffix, snap_size, check_mode):
    snapshot_name = get_snapshot_name(lv_name, suffix)

    rc, _vg_exists, lv_exists = lvm_lv_exists(module, vg_name, snapshot_name)

    if lv_exists:
        rc, is_snapshot = lvm_is_snapshot(module, vg_name, snapshot_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (
                SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                "snapshot_lv: command failed for LV lvm_is_snapshot()",
            )
        if is_snapshot:
            return (
                SnapshotStatus.ERROR_ALREADY_EXISTS,
                "Snapshot of :" + vg_name + "/" + lv_name + " already exists",
            )
        else:
            return (
                SnapshotStatus.ERROR_NAME_CONFLICT,
                "LV with name :" + snapshot_name + " already exits",
            )

    snapshot_command = [
        "lvcreate",
        "-s",
        "-n",
        snapshot_name,
        "-L",
        str(snap_size) + "B",
        vg_name + "/" + lv_name,
    ]

    if check_mode:
        return rc, "Would run command " + " ".join(snapshot_command)

    rc, output, stderr = module.run_command(snapshot_command)

    if rc:
        return SnapshotStatus.ERROR_SNAPSHOT_FAILED, stderr

    return SnapshotStatus.SNAPSHOT_OK, output


def check_space_for_snapshots(vg, lvs, lv_name, required_percent):
    vg_free = int(vg["vg_free"])
    total_lv_used = 0

    logger.info("VG: %s free %s", vg["vg_name"], vg["vg_free"])
    for lv in lvs:
        if lv_name and lv["lv_name"] != lv_name:
            continue
        logger.info("\tLV: %s size : %s", lv["lv_name"], lv["lv_size"])
        total_lv_used += int(lv["lv_size"])

    logger.info("\tLV: total %d", total_lv_used)

    space_needed = percentof(required_percent, total_lv_used)

    logger.info(
        "space needed: %.2f space available: %d sufficient space: %d",
        space_needed,
        vg_free,
        vg_free >= space_needed,
    )

    if vg_free >= space_needed:
        return SnapshotStatus.SNAPSHOT_OK

    return SnapshotStatus.ERROR_INSUFFICIENT_SPACE


def check_name_for_snapshot(lv_name, suffix):
    if suffix:
        suffix_len = len(suffix)
    else:
        suffix_len = 0

    if len(lv_name) + suffix_len > MAX_LVM_NAME:
        return (
            SnapshotStatus.ERROR_NAME_TOO_LONG,
            "resulting snapshot name would exceed LVM maximum: " + lv_name + suffix,
        )
    else:
        return SnapshotStatus.SNAPSHOT_OK, ""


# Verify that the set has been created
def check_verify_lvs_set(module, snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("check snapsset : %s", snapset_name)

    # Check to make sure all the source vgs/lvs exist
    rc, message = verify_snapset_source_lvs_exist(module, snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message

    # Check to make sure that target snapshots/volumes don't already exist
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        snapshot_name = get_snapshot_name(lv, snapset_name)

        rc, _vg_exists, lv_exists = lvm_lv_exists(module, vg, snapshot_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (
                SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                "check verify: command failed for LV snapshot exists",
            )

        if not lv_exists:
            return (
                SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                "check verify: snapshot not found for: " + vg + "/" + lv,
            )

        if lv_exists:
            rc, is_snapshot = lvm_is_snapshot(module, vg, snapshot_name)
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                    "check verify: command failed for LV lvm_is_snapshot()",
                )

            if not is_snapshot:
                return (
                    SnapshotStatus.ERROR_VERIFY_NOTSNAPSHOT,
                    "check verify: target logical volume exits, but it is not a snapshot",
                )

    return SnapshotStatus.SNAPSHOT_OK, ""


def check_verify_lvs_completed(
    module, snapshot_all, vg_name, lv_name, vg_include, suffix
):
    vg_found = False
    lv_found = False

    for vg, lv_list in vgs_lvs_iterator(module, vg_name, lv_name, vg_include):
        vg_found = True
        verify_vg_name = vg["vg_name"]

        for lvs in lv_list:
            lv_found = True
            # Only verify that a snapshot exits for non-snapshot LVs
            rc, is_snapshot = lvm_is_snapshot(module, verify_vg_name, lvs["lv_name"])
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                    "check verify: command failed for LV lvm_is_snapshot()",
                )

            if is_snapshot:
                continue

            snapshot_name = get_snapshot_name(lvs["lv_name"], suffix)

            rc, _vg_exists, lv_exists = lvm_lv_exists(
                module, verify_vg_name, snapshot_name
            )
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                    "check verify: command failed for LV exists",
                )

            if lv_exists:
                rc, is_snapshot = lvm_is_snapshot(module, verify_vg_name, snapshot_name)
                if rc != SnapshotStatus.SNAPSHOT_OK:
                    return (
                        SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                        "check verify: command failed for LV lvm_is_snapshot()",
                    )

                if not is_snapshot:
                    return (
                        SnapshotStatus.ERROR_VERIFY_NOTSNAPSHOT,
                        "target logical volume exits, but it is not a snapshot",
                    )
            else:
                return (
                    SnapshotStatus.ERROR_VERIFY_NOTSNAPSHOT,
                    "target logical volume snapshot does not exist",
                )

    if not snapshot_all:
        if vg_name and not vg_found:
            return (
                SnapshotStatus.ERROR_VG_NOTFOUND,
                "source volume group does not exist: " + vg_name,
            )
        if lv_name and not lv_found:
            return (
                SnapshotStatus.ERROR_LV_NOTFOUND,
                "source logical volume does not exist: " + vg_name + "/" + lv_name,
            )

    return SnapshotStatus.SNAPSHOT_OK, ""


def revert_snapshot_set(module, snapset_json, check_mode):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("revert snapsset : %s", snapset_name)

    changed = False
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        rc, message = revert_lv(
            module, vg, get_snapshot_name(lv, snapset_name), check_mode
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            if rc == SnapshotStatus.ERROR_LV_NOTFOUND:
                rc = SnapshotStatus.SNAPSHOT_OK  # already removed or reverted
            return rc, message, changed

        # if we got here at least 1 snapshot was reverted
        changed = True

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def umount_verify(module, mountpoint, vg_name, lv_to_check):
    blockdev = path_join(DEV_PREFIX, vg_name, lv_to_check)

    mount_list = lvm_get_fs_mount_points(module, mountpoint)

    if mount_list:
        for mount_point_json in mount_list:
            if mount_point_json["SOURCE"] == blockdev:
                return (
                    SnapshotStatus.ERROR_MOUNT_VERIFY_FAILED,
                    "device is mounted on mountpoint: " + blockdev,
                )

            if mount_point_json["TARGET"] == mountpoint:
                return (
                    SnapshotStatus.ERROR_MOUNT_VERIFY_FAILED,
                    "device is mounted on mountpoint: " + mountpoint,
                )

    return SnapshotStatus.SNAPSHOT_OK, ""


def umount_lv(module, umount_target, vg_name, lv_name, all_targets, check_mode):
    logger.info("umount_lv : %s", umount_target)

    changed = False
    if vg_name and lv_name:
        # Check to make sure all the source vgs/lvs exist
        rc, message = verify_source_lvs_exist(module, vg_name, lv_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, changed

    rc, message = umount(module, umount_target, all_targets, check_mode)
    changed = rc == SnapshotStatus.SNAPSHOT_OK
    if rc == SnapshotStatus.ERROR_UMOUNT_NOT_MOUNTED:
        rc = SnapshotStatus.SNAPSHOT_OK  # already unmounted - not an error
    return rc, message, changed


def umount_snapshot_set(module, snapset_json, verify_only, check_mode):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]

    logger.info("mount verify snapsset : %s", snapset_name)

    changed = False
    for list_item in volume_list:
        logger.info("umount_snapshot_set: list_item %s", str(list_item))
        vg_name = list_item["vg"]
        lv_name = list_item["lv"]
        mountpoint = list_item["mountpoint"]

        if list_item.get("all_targets") is not None:
            all_targets = to_bool(list_item["all_targets"])
        else:
            all_targets = False

        if list_item.get("mount_origin") is not None:
            origin = to_bool(list_item["mount_origin"])
        else:
            origin = False

        if origin:
            lv_to_check = lv_name
        else:
            if lv_name and snapset_name:
                lv_to_check = get_snapshot_name(lv_name, snapset_name)
            else:
                lv_to_check = None

        if verify_only:
            rc, message = umount_verify(module, mountpoint, vg_name, lv_to_check)
        else:
            rc, message, cmd_changed = umount_lv(
                module, mountpoint, vg_name, lv_to_check, all_targets, check_mode
            )
            if cmd_changed:
                changed = True

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, changed

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def mount_snapshot_set(
    module, snapset_json, verify_only, cmdline_mountpoint_create, check_mode
):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]

    logger.info("mount verify snapsset : %s", snapset_name)

    changed = False
    for list_item in volume_list:
        vg_name = list_item["vg"]
        lv_name = list_item["lv"]

        if not cmdline_mountpoint_create:
            if list_item["mountpoint_create"] is not None:
                mountpoint_create = to_bool(list_item["mountpoint_create"])
            else:
                mountpoint_create = False
        else:
            mountpoint_create = to_bool(cmdline_mountpoint_create)

        if list_item.get("mount_origin") is not None:
            origin = to_bool(list_item["mount_origin"])
        else:
            origin = False

        fstype = list_item.get("fstype")
        options = list_item.get("options")
        mountpoint = list_item.get("mountpoint")
        if mountpoint is None:
            return (
                SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
                "set item must provide a mountpoint for : " + vg_name + "/" + lv_name,
                changed,
            )

        if origin:
            lv_to_check = lv_name
        else:
            lv_to_check = get_snapshot_name(lv_name, snapset_name)

        blockdev = path_join(DEV_PREFIX, vg_name, lv_to_check)

        if verify_only:
            rc, message = mount_verify(
                module, origin, mountpoint, blockdev, vg_name, lv_name, snapset_name
            )
        else:
            rc, message, cmd_changed = mount_lv(
                module,
                mountpoint_create,
                origin,
                mountpoint,
                fstype,
                blockdev,
                options,
                vg_name,
                lv_name,
                snapset_name,
                check_mode,
            )
            if cmd_changed:
                changed = True

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, changed

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def mount_verify(module, origin, mountpoint, blockdev, vg_name, lv_name, snapset_name):
    logger.info(
        "mount_verify_lv : %d %s %s %s %s",
        origin,
        mountpoint,
        vg_name,
        lv_name,
        snapset_name,
    )

    if not mountpoint:
        return (
            SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
            "must provide mountpoint",
        )

    if not vg_name or not lv_name:
        return (
            SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
            "must provide blockdev or vg/lv for mount source",
        )

    if vg_name and lv_name:
        if origin:
            lv_to_check = lv_name
        else:
            lv_to_check = get_snapshot_name(lv_name, snapset_name)

        # Check to make sure all the source vgs/lvs exist
        rc, message = verify_source_lvs_exist(module, vg_name, lv_to_check)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

        blockdev = path_join(DEV_PREFIX, vg_name, lv_to_check)
    else:
        mode = os.stat(blockdev).st_mode
        if not stat.S_ISBLK(mode):
            return (
                SnapshotStatus.ERROR_MOUNT_NOT_BLOCKDEV,
                "blockdev parameter is not a block device",
            )

    if not blockdev:
        return (
            SnapshotStatus.ERROR_MOUNT_NOT_BLOCKDEV,
            "blockdev or vg/lv is a required",
        )

    mount_list = lvm_get_fs_mount_points(module, blockdev)

    if not mount_list:
        return (
            SnapshotStatus.ERROR_MOUNT_VERIFY_FAILED,
            "blockdev not mounted on any mountpoint: " + blockdev,
        )

    for mount_point_json in mount_list:
        if mount_point_json["TARGET"] == mountpoint:
            return SnapshotStatus.SNAPSHOT_OK, ""

    return (
        SnapshotStatus.ERROR_MOUNT_VERIFY_FAILED,
        "blockdev not mounted on specified mountpoint: " + blockdev + " " + mountpoint,
    )


def mount_lv(
    module,
    create,
    origin,
    mountpoint,
    fstype,
    blockdev,
    options,
    vg_name,
    lv_name,
    snapset_name,
    check_mode,
):
    logger.info("mount_lv : %s", mountpoint)

    changed = False
    if not blockdev and (not vg_name or not lv_name):
        return (
            SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
            "must provide blockdev or vg/lv for mount source",
            changed,
        )

    if vg_name and lv_name:
        if origin:
            lv_to_mount = lv_name
        else:
            lv_to_mount = get_snapshot_name(lv_name, snapset_name)

        # Check to make sure all the source vgs/lvs exist
        rc, message = verify_source_lvs_exist(module, vg_name, lv_to_mount)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, changed

        blockdev = path_join(DEV_PREFIX, vg_name, lv_to_mount)
    else:
        mode = os.stat(blockdev).st_mode
        if not stat.S_ISBLK(mode):
            return (
                SnapshotStatus.ERROR_MOUNT_NOT_BLOCKDEV,
                "blockdev parameter is not a block device",
                changed,
            )

    if not blockdev:
        return (
            SnapshotStatus.ERROR_MOUNT_NOT_BLOCKDEV,
            "blockdev or vg/lv is a required",
            changed,
        )

    rc, message = mount(
        module, blockdev, mountpoint, fstype, options, create, check_mode
    )
    changed = rc == SnapshotStatus.SNAPSHOT_OK
    if rc == SnapshotStatus.ERROR_MOUNT_POINT_ALREADY_MOUNTED:
        rc = SnapshotStatus.SNAPSHOT_OK  # this is ok

    return rc, message, changed


def remove_snapshot_set(module, snapset_json, check_mode):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("remove snapsset : %s", snapset_name)

    # check to make sure the set is removable before attempting to remove
    changed = False
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]
        snapshot_name = get_snapshot_name(lv, snapset_name)

        rc, vg_exists, lv_exists = lvm_lv_exists(module, vg, snapshot_name)

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, "failed to get LV status", changed

        # if there is no snapshot, continue (idempotent)
        if not vg_exists or not lv_exists:
            continue

        rc, in_use = lvm_is_inuse(module, vg, snapshot_name)

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, "failed to lvm_is_inuse status", changed

        if in_use:
            return (
                SnapshotStatus.ERROR_REMOVE_FAILED_INUSE,
                "volume is in use: " + vg + "/" + snapshot_name,
                changed,
            )

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        snapshot_name = get_snapshot_name(lv, snapset_name)

        rc, vg_exists, lv_exists = lvm_lv_exists(module, vg, snapshot_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, "failed to get LV status", changed

        # if there is no snapshot, continue (idempotent)
        if not vg_exists or not lv_exists:
            continue

        rc, message = lvm_snapshot_remove(module, vg, snapshot_name, check_mode)

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, changed

        # if we got here, at least 1 snapshot was removed
        changed = True

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def remove_verify_snapshot_set(module, snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]

    logger.info("remove verify snapsset : %s", snapset_name)

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        snapshot_name = get_snapshot_name(lv, snapset_name)

        rc, _vg_exists, lv_exists = lvm_lv_exists(module, vg, snapshot_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (
                rc,
                "volume exists that matches the pattern: " + vg + "/" + snapshot_name,
            )

        if lv_exists:
            return (
                SnapshotStatus.ERROR_VERIFY_REMOVE_FAILED,
                "volume exists that matches the pattern: " + vg + "/" + snapshot_name,
            )

    return SnapshotStatus.SNAPSHOT_OK, ""


def remove_verify_snapshots(module, vg_name, lv_name, vg_include, suffix):
    # if the vg_name and lv_name are supplied, make sure the source is not a snapshot
    if vg_name and lv_name:
        rc, is_snapshot = lvm_is_snapshot(module, vg_name, lv_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (
                SnapshotStatus.ERROR_VERIFY_REMOVE_FAILED,
                "command failed for LV lvm_is_snapshot() failed to get status on source",
            )
        if is_snapshot:
            return (
                SnapshotStatus.ERROR_VERIFY_REMOVE_SOURCE_SNAPSHOT,
                "source is a snapshot:" + vg_name + "/" + lv_name,
            )

    for vg, lv_list in vgs_lvs_iterator(module, vg_name, lv_name, vg_include):
        verify_vg_name = vg["vg_name"]

        for lvs in lv_list:
            rc, is_snapshot = lvm_is_snapshot(module, verify_vg_name, lvs["lv_name"])
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_VERIFY_REMOVE_FAILED,
                    "command failed for LV lvm_is_snapshot() failed to get status",
                )

            # Only verify for non-snapshot LVs
            if is_snapshot:
                continue

            snapshot_name = get_snapshot_name(lvs["lv_name"], suffix)

            rc, _vg_exists, lv_exists = lvm_lv_exists(
                module, verify_vg_name, snapshot_name
            )

            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                    "remove verify: command failed for LV exists",
                )

            if lv_exists:
                return (
                    SnapshotStatus.ERROR_VERIFY_REMOVE_FAILED,
                    "volume exists that matches the pattern: "
                    + verify_vg_name
                    + "/"
                    + snapshot_name,
                )

    return SnapshotStatus.SNAPSHOT_OK, ""


def get_current_space_state(module):
    vg_size_dict = dict()
    for volume_group, lv_list in vgs_lvs_iterator(module, None, None, None):
        vg_name = volume_group["vg_name"]
        vg_space = VGSpaceState()

        vg_size_dict[vg_name] = vg_space
        vg_space.vg_free = int(volume_group["vg_free"])
        vg_space.vg_size = int(volume_group["vg_size"])
        vg_space.vg_extent_size = int(volume_group["vg_extent_size"])
        logger.info(
            "get_current_space_state: %s \n \
                \tvg_size : %d \n \
                \tvg_free : %d  \
                \tvg_extent_size : %d ",
            vg_name,
            vg_space.vg_size,
            vg_space.vg_free,
            vg_space.vg_extent_size,
        )

        for lv in lv_list:
            lv_name = lv["lv_name"]
            lv_space = LVSpaceState()

            vg_space.lvs[lv_name] = lv_space
            lv_space.lv_size = int(lv["lv_size"])
            # TODO get chunk size in case it isn't default?
            logger.info(
                "\t\tlv: %s \n \
                \t\tlv_size : %s \n \
                \t\tchunk_size : %s \n ",
                lv_name,
                lv_space.lv_size,
                lv_space.chunk_size,
            )

    return SnapshotStatus.SNAPSHOT_OK, "", vg_size_dict


def verify_source_lvs_exist(module, vg_name, lv_name):
    rc, vg_exists, lv_exists = lvm_lv_exists(module, vg_name, lv_name)

    if rc != SnapshotStatus.SNAPSHOT_OK:
        return (
            SnapshotStatus.ERROR_SNAPSET_CHECK_STATUS_FAILED,
            "command failed for LV verify_source_lvs_exist() failed to get status",
        )

    if vg_name and not vg_exists:
        return (
            SnapshotStatus.ERROR_SNAPSET_SOURCE_DOES_NOT_EXIST,
            "source volume group does not exist: " + vg_name,
        )

    if lv_name and not lv_exists:
        return (
            SnapshotStatus.ERROR_SNAPSET_SOURCE_DOES_NOT_EXIST,
            "source logical volume does not exist: " + vg_name + "/" + lv_name,
        )

    return SnapshotStatus.SNAPSHOT_OK, ""


def verify_snapset_target_no_existing(module, snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("verify snapsset : %s", snapset_name)

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        snapshot_name = get_snapshot_name(lv, snapset_name)

        rc, _vg_exists, lv_exists = lvm_lv_exists(module, vg, snapshot_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (
                rc,
                "could not determine if snapshot exists: " + vg + "/" + snapshot_name,
            )

        if lv_exists:
            rc, exists = lvm_is_snapshot(module, vg, snapshot_name)
            if rc == SnapshotStatus.SNAPSHOT_OK and exists:
                return (
                    SnapshotStatus.ERROR_ALREADY_EXISTS,
                    "snapshot already exists: " + vg + "/" + snapshot_name,
                )
            else:
                return (
                    SnapshotStatus.ERROR_SNAPSET_CHECK_STATUS_FAILED,
                    "volume exists that matches the pattern: "
                    + vg
                    + "/"
                    + snapshot_name,
                )

    return SnapshotStatus.SNAPSHOT_OK, ""


def verify_snapset_source_lvs_exist(module, snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("verify snapsset : %s", snapset_name)
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        rc, vg_exists, lv_exists = lvm_lv_exists(module, vg, lv)

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (
                SnapshotStatus.ERROR_SNAPSET_CHECK_STATUS_FAILED,
                "command failed for LV lvm_is_snapshot() failed to get status",
            )
        if not vg_exists:
            return (
                SnapshotStatus.ERROR_SNAPSET_SOURCE_DOES_NOT_EXIST,
                "source volume group does not exist: " + vg,
            )
        if not lv_exists:
            return (
                SnapshotStatus.ERROR_SNAPSET_SOURCE_DOES_NOT_EXIST,
                "source logical volume does not exist: " + vg + "/" + lv,
            )

    logger.info("snapsset ok: %s", snapset_name)
    return SnapshotStatus.SNAPSHOT_OK, ""


def verify_snapset_names(snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("verify snapsset : %s", snapset_name)
    for list_item in volume_list:
        lv = list_item["lv"]

        rc, message = check_name_for_snapshot(lv, snapset_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

    logger.info("snapsset names ok: %s", snapset_name)

    return SnapshotStatus.SNAPSHOT_OK, ""


def get_space_needed(vg, lv, percent_space_required, current_space_dict):
    lv_size = current_space_dict[vg].lvs[lv].lv_size
    extent_size = current_space_dict[vg].vg_extent_size

    return get_snapshot_size_required(lv_size, percent_space_required, extent_size)


# precheck the set to make sure there is sufficient space for the snapshots
def snapshot_precheck_lv_set_space(module, snapset_json):
    total_space_requested = dict()
    volume_list = snapset_json["volumes"]

    # Calculate total space needed for each VG
    rc, _message, current_space_dict = get_current_space_state(module)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, "get_space_state failure in snapshot_precheck_lv_set_space", None

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        percent_space_required = list_item["percent_space_required"]

        required_size = get_space_needed(
            vg, lv, percent_space_required, current_space_dict
        )
        if vg in total_space_requested:
            total_space_requested[vg] += required_size
        else:
            total_space_requested[vg] = required_size

    # Check to make sure there is enough total space
    for list_item in volume_list:
        vg = list_item["vg"]

        if total_space_requested[vg] > current_space_dict[vg].vg_free:
            return (
                SnapshotStatus.ERROR_SNAPSET_INSUFFICIENT_SPACE,
                "insufficient space for snapshots in: " + vg,
                None,
            )
    return SnapshotStatus.SNAPSHOT_OK, "", current_space_dict


# precheck the set to make sure it will work and create snapshots for
# the source LVs in the set
def snapshot_precheck_lv_set(module, snapset_json):
    rc, message = verify_snapset_source_lvs_exist(module, snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message, None

    rc, message = verify_snapset_target_no_existing(module, snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message, None

    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("verify snapsset : %s", snapset_name)

    # Verify the names for the snapshots are ok
    rc, message = verify_snapset_names(snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message, None

    # check to make sure there are no naming conflicts
    for list_item in volume_list:
        lv = list_item["lv"]

        rc, message = check_name_for_snapshot(lv, snapset_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, "resulting snapshot name would exceed LVM maximum", None

    rc, message, current_space_dict = snapshot_precheck_lv_set_space(
        module, snapset_json
    )
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message, None

    return SnapshotStatus.SNAPSHOT_OK, "", current_space_dict


def snapshot_create_set(module, snapset_json, check_mode):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    changed = False

    rc, message, current_space_dict = snapshot_precheck_lv_set(module, snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        if rc == SnapshotStatus.ERROR_ALREADY_EXISTS:
            rc = SnapshotStatus.SNAPSHOT_OK
        return rc, message, changed

    # Take snapshots
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        percent_space_required = list_item["percent_space_required"]

        required_size = get_space_needed(
            vg, lv, percent_space_required, current_space_dict
        )

        rc, message = snapshot_lv(
            module, vg, lv, snapset_name, required_size, check_mode
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, changed

        # if we got here, at least 1 snapshot was created
        changed = True

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def snapshot_set(module, snapset_json, check_mode):
    changed = False
    rc, message = verify_snapset_source_lvs_exist(module, snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message, changed

    rc, message, changed = snapshot_create_set(module, snapset_json, check_mode)

    return rc, message, changed


def check_required_space(required_space_str):
    try:
        percent_space_required = int(required_space_str)

        if percent_space_required <= 1:
            return (
                SnapshotStatus.ERROR_INVALID_PERCENT_REQUESTED,
                "percent_space_required must be greater than 1: "
                + str(percent_space_required),
            )
    except ValueError:
        return (
            SnapshotStatus.ERROR_INVALID_PERCENT_REQUESTED,
            "percent_space_required must be a positive integer: " + required_space_str,
        )

    return SnapshotStatus.SNAPSHOT_OK, ""


def validate_general_args(module_args):
    rc = SnapshotStatus.ERROR_CMD_INVALID
    message = ""

    if module_args["snapshot_lvm_all_vgs"] and module_args["snapshot_lvm_vg"]:
        return (
            rc,
            "--all and --volume_group are mutually exclusive for operation "
            + module_args["snapshot_lvm_action"],
        )

    if (
        not module_args["snapshot_lvm_all_vgs"]
        and module_args["snapshot_lvm_vg"] is None
        and module_args["snapshot_lvm_snapset_name"] is None
    ):
        return (
            rc,
            "must specify either --all, --volume_group or --snapset for operation "
            + module_args["snapshot_lvm_action"],
        )

    if (
        not module_args["snapshot_lvm_all_vgs"]
        and module_args["snapshot_lvm_vg"] is None
        and module_args["snapshot_lvm_lv"]
    ):
        return (
            rc,
            "--logical_volume requires --volume_group parameter for operation "
            + module_args["snapshot_lvm_action"],
        )

    if not module_args["snapshot_lvm_snapset_name"]:
        return (
            rc,
            "--snapset is required for operation " + module_args["snapshot_lvm_action"],
        )

    if len(module_args["snapshot_lvm_snapset_name"]) == 0:
        return (
            rc,
            "Snapset name must be provided for operation "
            + module_args["snapshot_lvm_action"],
        )

    # not all commands include snapshot_lvm_percent_space_required
    if module_args["snapshot_lvm_percent_space_required"]:
        rc, message = check_required_space(
            module_args["snapshot_lvm_percent_space_required"]
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

    return SnapshotStatus.SNAPSHOT_OK, message


def validate_snapshot_args(module_args):
    if not module_args["snapshot_lvm_percent_space_required"]:
        return (
            SnapshotStatus.ERROR_JSON_PARSER_ERROR,
            "snapset snapshot_lvm_percent_space_required entry not found",
        )

    rc, message = check_required_space(
        module_args["snapshot_lvm_percent_space_required"]
    )

    if rc != SnapshotStatus.SNAPSHOT_OK:
        return {"return_code": rc, "errors": message, "changed": False}

    return SnapshotStatus.SNAPSHOT_OK, ""


def validate_mount_args(module_args):
    if not module_args["snapshot_lvm_vg"] or not module_args["snapshot_lvm_lv"]:
        return (
            SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
            "must provide vg/lv for mount source",
        )

    if not module_args["snapshot_lvm_mountpoint"]:
        return SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS, "mountpoint is required"

    return SnapshotStatus.SNAPSHOT_OK, ""


def validate_umount_args(module_args):

    if not module_args["snapshot_lvm_vg"] or not module_args["snapshot_lvm_lv"]:
        return (
            SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
            "must provide vg/lv for umount source",
        )

    if not module_args["snapshot_lvm_mountpoint"]:
        return (
            SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
            "--mountpoint is required",
        )

    return SnapshotStatus.SNAPSHOT_OK, ""


def validate_snapset_args(module, cmd, module_args, vg_include):

    rc, message = validate_general_args(module_args)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return {"return_code": rc, "errors": message, "changed": False}, None

    if cmd == SnapshotCommand.SNAPSHOT:
        rc, message = validate_snapshot_args(module_args)
    #
    # Currently check, remove, revert, extend and list don't need extra validation
    #
    elif cmd == SnapshotCommand.MOUNT:
        rc, message = validate_mount_args(module_args)
    elif cmd == SnapshotCommand.UMOUNT:
        rc, message = validate_umount_args(module_args)

    if rc != SnapshotStatus.SNAPSHOT_OK:
        return {"return_code": rc, "errors": message, "changed": False}, None

    rc, message, snapset_dict = get_json_from_args(module, module_args, vg_include)
    logger.info("validate_snapset_args: END snapset_dict is %s", str(snapset_dict))
    return {"return_code": rc, "errors": message, "changed": False}, snapset_dict


def print_result(result):
    json.dump(result, sys.stdout, indent=4)
    logger.info("exit code: %d: %s", result["return_code"], str(result["errors"]))


def validate_json_request(snapset_json, check_percent_space_required):

    if "name" not in snapset_json:
        return (SnapshotStatus.ERROR_JSON_PARSER_ERROR, "snapset must include a name")

    if "volumes" not in snapset_json:
        return (
            SnapshotStatus.ERROR_JSON_PARSER_ERROR,
            "snapset must include a volumes list",
        )

    for list_item in snapset_json["volumes"]:
        if "vg" not in list_item:

            return (
                SnapshotStatus.ERROR_JSON_PARSER_ERROR,
                "snapset vg entry not found",
            )
        if "lv" not in list_item:
            return (
                SnapshotStatus.ERROR_JSON_PARSER_ERROR,
                "snapset lv entry not found",
            )

        if check_percent_space_required:

            if not list_item.get("percent_space_required"):
                return (
                    SnapshotStatus.ERROR_JSON_PARSER_ERROR,
                    "snapset percent_space_required entry not found",
                )
            rc, message = check_required_space(list_item["percent_space_required"])
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return rc, message

    return SnapshotStatus.SNAPSHOT_OK, ""


def validate_json_mount(snapset_dict):
    volume_list = snapset_dict["volumes"]
    for list_item in volume_list:

        if "blockdev" not in list_item and (
            "vg" not in list_item or "lv" not in list_item
        ):
            return (
                SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
                "must provide vg/lv or blockdev for mount source",
            )

        if "mountpoint" not in list_item:
            return (
                SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
                "must provide mountpoint",
            )

    return SnapshotStatus.SNAPSHOT_OK, ""


def validate_json_umount(snapset_dict):
    volume_list = snapset_dict["volumes"]
    for list_item in volume_list:
        try:
            vg = list_item["vg"]
            lv = list_item["lv"]
        except KeyError:
            vg = None
            lv = None

        if "mountpoint" not in list_item:
            return (
                SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
                "must provide mountpoint for umount",
            )
        if not vg or not lv:
            return (
                SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
                "must provide vg/lv for mount source",
            )

    return SnapshotStatus.SNAPSHOT_OK, ""


def validate_snapset_json(cmd, snapset_dict, verify_only):

    if cmd == SnapshotCommand.SNAPSHOT:
        rc, message = validate_json_request(snapset_dict, True)
    elif cmd == SnapshotCommand.CHECK and not verify_only:
        rc, message = validate_json_request(snapset_dict, True)
    elif cmd == SnapshotCommand.CHECK and verify_only:
        rc, message = validate_json_request(snapset_dict, not verify_only)
    elif cmd == SnapshotCommand.REMOVE:
        rc, message = validate_json_request(snapset_dict, False)
    elif cmd == SnapshotCommand.LIST:
        rc, message = validate_json_request(snapset_dict, False)
    elif cmd == SnapshotCommand.REVERT:
        rc, message = validate_json_request(snapset_dict, False)
    elif cmd == SnapshotCommand.EXTEND:
        rc, message = validate_json_request(snapset_dict, True)
    elif cmd == SnapshotCommand.MOUNT:
        rc, message = validate_json_mount(snapset_dict)
    elif cmd == SnapshotCommand.UMOUNT:
        rc, message = validate_json_umount(snapset_dict)
    else:
        rc = SnapshotStatus.ERROR_UNKNOWN_FAILURE
        message = "validate_snapset_json for command " + cmd

    logger.info("snapset %s", snapset_dict)
    return {"return_code": rc, "errors": message, "changed": False}, snapset_dict


def get_json_from_args(module, module_args, vg_include):
    volume_list = []
    args_dict = {}
    cmd = get_command_const(module_args["snapshot_lvm_action"])

    logger.info("get_json_from_args: BEGIN")
    if not module_args["snapshot_lvm_all_vgs"] and cmd != SnapshotCommand.UMOUNT:
        rc, message = verify_source_lvs_exist(
            module, module_args["snapshot_lvm_vg"], module_args["snapshot_lvm_lv"]
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (rc, message, "")

    if module_args["snapshot_lvm_snapset_name"]:
        args_dict["name"] = module_args["snapshot_lvm_snapset_name"]

    for vg, lv_list in vgs_lvs_iterator(
        module,
        module_args["snapshot_lvm_vg"],
        module_args["snapshot_lvm_lv"],
        vg_include,
    ):
        logger.info("get_json_from_args: vg %s lv_list %s", str(vg), str(lv_list))
        vg_str = vg["vg_name"]
        for lv in lv_list:

            if lv["lv_name"].endswith(module_args["snapshot_lvm_snapset_name"]):
                logger.info(
                    "get_json_from_args: already a snapshot for %s", lv["lv_name"]
                )
                continue

            rc, is_snapshot = lvm_is_snapshot(module, vg_str, lv["lv_name"])
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                    "get_json_from_args: command failed for LV lvm_is_snapshot()",
                    None,
                )

            if is_snapshot:
                logger.info(
                    "get_json_from_args: lv %s is a snapshot - skipping", lv["lv_name"]
                )
                continue

            rc, is_thinpool = lvm_is_thinpool(module, vg_str, lv["lv_name"])
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                    "get_json_from_args: command failed for LV lvm_is_thinpool()",
                    None,
                )
            if is_thinpool:
                logger.info(
                    "get_json_from_args: lv %s is a thinpool - skipping", lv["lv_name"]
                )
                continue
            volume = {}
            volume["name"] = ("snapshot : " + vg_str + "/" + lv["lv_name"],)
            volume["vg"] = vg_str
            volume["lv"] = lv["lv_name"]

            volume["percent_space_required"] = module_args[
                "snapshot_lvm_percent_space_required"
            ]

            if cmd == SnapshotCommand.MOUNT:
                volume["mountpoint_create"] = module_args[
                    "snapshot_lvm_mountpoint_create"
                ]
                volume["mountpoint"] = module_args["snapshot_lvm_mountpoint"]
                volume["mount_origin"] = module_args["snapshot_lvm_mount_origin"]
                volume["fstype"] = module_args["snapshot_lvm_fstype"]
                volume["options"] = module_args["snapshot_lvm_mount_options"]

            if cmd == SnapshotCommand.UMOUNT:
                volume["mountpoint"] = module_args["snapshot_lvm_mountpoint"]
                volume["all_targets"] = module_args["snapshot_lvm_unmount_all"]

            volume_list.append(volume)
            logger.info("get_json_from_args: adding volume %s", str(volume))

    args_dict["volumes"] = volume_list

    return SnapshotStatus.SNAPSHOT_OK, "", args_dict


def snapshot_cmd(module, module_args, snapset_dict):
    logger.info("snapshot_cmd: %s ", snapset_dict)

    rc, message, changed = snapshot_set(
        module, snapset_dict, module_args["ansible_check_mode"]
    )

    return {"return_code": rc, "errors": message, "changed": changed}


def check_cmd(module, module_args, snapset_dict):
    logger.info("check_cmd: %s", snapset_dict)

    if module_args["snapshot_lvm_verify_only"]:
        rc, message = check_verify_lvs_set(module, snapset_dict)
    else:
        rc, message, _current_space_dict = snapshot_precheck_lv_set(
            module, snapset_dict
        )

    return {"return_code": rc, "errors": message, "changed": False}


def remove_cmd(module, module_args, snapset_dict):
    logger.info("remove_cmd: %s ", snapset_dict)

    changed = False

    if module_args["snapshot_lvm_verify_only"]:
        rc, message = remove_verify_snapshot_set(module, snapset_dict)
    else:
        rc, message, changed = remove_snapshot_set(
            module, snapset_dict, module_args["ansible_check_mode"]
        )

    return {"return_code": rc, "errors": message, "changed": changed}


def revert_cmd(module, module_args, snapset_dict):
    logger.info(
        "revert_cmd: %s %d", snapset_dict, module_args["snapshot_lvm_verify_only"]
    )

    changed = False

    if module_args["snapshot_lvm_verify_only"]:
        # revert re-uses the remove verify since both commands should
        # cause the snapshot to no longer exist
        rc, message = remove_verify_snapshot_set(module, snapset_dict)
    else:
        rc, message, changed = revert_snapshot_set(
            module, snapset_dict, module_args["ansible_check_mode"]
        )

    return {"return_code": rc, "errors": message, "changed": changed}


def extend_cmd(module, module_args, snapset_dict):
    logger.info(
        "extend_cmd: %s %d", snapset_dict, module_args["snapshot_lvm_verify_only"]
    )

    changed = False

    if module_args["snapshot_lvm_verify_only"]:
        rc, message = extend_verify_snapshot_set(module, snapset_dict)
    else:
        rc, message, changed = extend_snapshot_set(
            module, snapset_dict, module_args["ansible_check_mode"]
        )

    return {"return_code": rc, "errors": message, "changed": changed}


def list_cmd(module, module_args, vg_include):
    logger.info(
        "list_cmd: %s %s",
        module_args["snapshot_lvm_vg"],
        module_args["snapshot_lvm_lv"],
    )

    rc, data = lvm_list_json(
        module,
        module_args["snapshot_lvm_vg"],
        module_args["snapshot_lvm_lv"],
        vg_include,
    )

    return {"return_code": rc, "errors": "", "data": data, "changed": False}


def mount_cmd(module, module_args, snapset_dict):
    logger.info(
        "mount_cmd: %d %d %d %s ",
        module_args["snapshot_lvm_verify_only"],
        module_args["snapshot_lvm_mountpoint_create"],
        module_args["ansible_check_mode"],
        snapset_dict,
    )

    rc, message, changed = mount_snapshot_set(
        module,
        snapset_dict,
        module_args["snapshot_lvm_verify_only"],
        module_args["snapshot_lvm_mountpoint_create"],
        module_args["ansible_check_mode"],
    )

    return {"return_code": rc, "errors": message, "changed": changed}


def umount_cmd(module, module_args, snapset_dict):
    logger.info(
        "umount_cmd: %d %s %s",
        module_args["ansible_check_mode"],
        module_args["snapshot_lvm_mountpoint"],
        snapset_dict,
    )

    rc, message, changed = umount_snapshot_set(
        module,
        snapset_dict,
        module_args["snapshot_lvm_verify_only"],
        module_args["ansible_check_mode"],
    )

    return {"return_code": rc, "errors": message, "changed": changed}


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
        if cmd == SnapshotCommand.SNAPSHOT:
            cmd_result = snapshot_cmd(module, module.params, snapset_dict)
        elif cmd == SnapshotCommand.CHECK:
            cmd_result = check_cmd(module, module.params, snapset_dict)
        elif cmd == SnapshotCommand.REMOVE:
            cmd_result = remove_cmd(module, module.params, snapset_dict)
        elif cmd == SnapshotCommand.REVERT:
            cmd_result = revert_cmd(module, module.params, snapset_dict)
        elif cmd == SnapshotCommand.EXTEND:
            cmd_result = extend_cmd(module, module.params, snapset_dict)
        elif cmd == SnapshotCommand.LIST:
            cmd_result = list_cmd(module, module.params, vg_include)
        elif cmd == SnapshotCommand.MOUNT:
            cmd_result = mount_cmd(module, module.params, snapset_dict)
        elif cmd == SnapshotCommand.UMOUNT:
            cmd_result = umount_cmd(module, module.params, snapset_dict)

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
    os.environ["LVM_COMMAND_PROFILE"] = "lvmdbusd"
    run_module()


if __name__ == "__main__":
    main()
