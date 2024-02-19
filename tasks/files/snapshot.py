from __future__ import print_function

import argparse
import json
import logging
import math
import os
import re
import stat
import subprocess
import sys
from os.path import join as path_join

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


def mount(
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

    rc, output = run_command(mount_command)

    if rc != 0:
        logger.error("failed to mount: ".join(mount_command))
        logger.error(output)
        return SnapshotStatus.ERROR_MOUNT_FAILED, output

    return SnapshotStatus.SNAPSHOT_OK, ""


def umount(umount_target, all_targets, check_mode):
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

    rc, output = run_command(umount_command)

    if rc != 0:
        logger.error("failed to unmount %s: %s", umount_target, output)
        return SnapshotStatus.ERROR_UMOUNT_FAILED, output
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


def run_command(argv, stdin=None):
    logger.info("Running... %s", " ".join(argv))
    try:
        proc = subprocess.Popen(
            argv,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )

        out, err = proc.communicate()
        if err:
            logger.info(err.decode().strip())
            out = err.decode("utf-8")
        else:
            out = out.decode("utf-8")
    except OSError as e:
        logger.info("Error running %s: %s", argv[0], e.strerror)
        raise

    logger.info("Return code: %d", proc.returncode)
    for line in out.splitlines():
        logger.info("%s", line)

    return (proc.returncode, out)


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


def lvm_full_report_json():
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

    rc, output = run_command(report_command)

    if rc:
        logger.info("'fullreport' exited with code : {rc}", rc=rc)
        raise LvmBug("'fullreport' exited with code : %d" % rc)
    try:
        lvm_json = json.loads(output)
    except ValueError as error:
        logger.info(error)
        raise LvmBug("'fullreport' decode failed : %s" % error.args[0])

    return lvm_json


def lvm_get_fs_mount_points(block_path):
    find_mnt_command = [
        "findmnt",
        block_path,
        "-P",
    ]
    mount_list = list()

    rc, output = run_command(find_mnt_command)
    if rc:
        return None

    output = output.replace('"', "")

    for line in output.split("\n"):
        if len(line):
            mount_list.append(dict(arg.split("=", 1) for arg in line.split(" ") if arg))

    return mount_list


def vgs_lvs_iterator(vg_name, lv_name, omit_empty_lvs=False):
    """Return an iterator which returns tuples.
    The first element in the tuple is the vg object matching given vg_name,
    or all vgs if vg_name is None.  The second element is a list of
    corresponding lv items where the lv name matches the given
    lv_name, or all lvs if lv_name is None.  By default the lv list
    will be returned even if empty.  Use omit_empty_lvs if you want
    only the vgs that have lvs."""
    lvm_json = lvm_full_report_json()
    for list_item in lvm_json["report"]:
        vg = list_item.get("vg", [{}])[0]
        # pylint: disable-msg=E0601
        if (
            vg
            and vg["vg_name"]
            and (not vg_name or vg_name == vg["vg_name"])
            and (not VG_INCLUDE or VG_INCLUDE.search(vg["vg_name"]))
        ):
            lvs = [
                lv
                for lv in list_item["lv"]
                if (not lv_name or lv_name == lv["lv_name"])
            ]
            if lvs or not omit_empty_lvs:
                yield (vg, lvs)


def vgs_lvs_dict(vg_name, lv_name):
    """Return a dict using vgs_lvs_iterator.  Key is
    vg name, value is list of lvs corresponding to vg.
    The returned dict will not have vgs that have no lvs."""
    return dict(
        [(vg["vg_name"], lvs) for vg, lvs in vgs_lvs_iterator(vg_name, lv_name, True)]
    )


def lvm_list_json(vg_name, lv_name):
    vg_dict = vgs_lvs_dict(vg_name, lv_name)
    fs_dict = dict()
    top_level = dict()
    for lv_list in vg_dict.values():
        for lv_item in lv_list:
            block_path = lv_item["lv_path"]
            fs_mount_points = lvm_get_fs_mount_points(block_path)
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


def lvm_lv_exists(vg_name, lv_name):
    vg_exists = False
    lv_exists = False

    if not vg_name:
        return SnapshotStatus.SNAPSHOT_OK, vg_exists, lv_exists
    # check for VG
    lvs_command = ["lvs", vg_name]

    rc, _output = run_command(lvs_command)
    if rc == 0:
        vg_exists = True

    if not lv_name:
        return SnapshotStatus.SNAPSHOT_OK, vg_exists, lv_exists

    lvs_command = ["lvs", vg_name + "/" + lv_name]
    rc, _output = run_command(lvs_command)
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


def lvm_is_inuse(vg_name, lv_name):
    lvs_command = ["lvs", "--reportformat", "json", vg_name + "/" + lv_name]

    rc, output = run_command(lvs_command)

    if rc == LVM_NOTFOUND_RC:
        return SnapshotStatus.SNAPSHOT_OK, False

    if rc:
        return SnapshotStatus.ERROR_LVS_FAILED, None

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


def lvm_is_snapshot(vg_name, snapshot_name):
    lvs_command = ["lvs", "--reportformat", "json", vg_name + "/" + snapshot_name]

    rc, output = run_command(lvs_command)

    if rc == LVM_NOTFOUND_RC:
        return SnapshotStatus.SNAPSHOT_OK, False

    if rc:
        return SnapshotStatus.ERROR_LVS_FAILED, None

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

    if lv_attr[0] == "s":
        return SnapshotStatus.SNAPSHOT_OK, True
    else:
        return SnapshotStatus.SNAPSHOT_OK, False


def lvm_snapshot_remove(vg_name, snapshot_name, check_mode):
    rc, is_snapshot = lvm_is_snapshot(vg_name, snapshot_name)

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

    rc, output = run_command(remove_command)

    if rc:
        return SnapshotStatus.ERROR_REMOVE_FAILED, output

    return SnapshotStatus.SNAPSHOT_OK, ""


def revert_lv(vg_name, snapshot_name, check_mode):
    rc, _vg_exists, lv_exists = lvm_lv_exists(vg_name, snapshot_name)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        raise LvmBug("'lvs' failed '%d'" % rc)

    if lv_exists:
        if not lvm_is_snapshot(vg_name, snapshot_name):
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

    rc, output = run_command(revert_command)

    if rc:
        return SnapshotStatus.ERROR_REVERT_FAILED, output

    return SnapshotStatus.SNAPSHOT_OK, output


def revert_lvs(vg_name, lv_name, suffix, check_mode):
    # Revert snapshots
    changed = False
    for vg, lv_list in vgs_lvs_iterator(vg_name, lv_name):
        for lv in lv_list:
            lv_item_name = lv["lv_name"]

            # Make sure the source LV isn't a snapshot.
            rc, is_snapshot = lvm_is_snapshot(vg["vg_name"], lv_item_name)

            if rc != SnapshotStatus.SNAPSHOT_OK:
                raise LvmBug("'lvs' failed '%d'" % rc)

            if not is_snapshot:
                continue
            if not lv_item_name.endswith(suffix):
                continue

            rc, message = revert_lv(vg["vg_name"], lv_item_name, check_mode)

            if rc != SnapshotStatus.SNAPSHOT_OK:
                if rc == SnapshotStatus.ERROR_LV_NOTFOUND:
                    rc = SnapshotStatus.SNAPSHOT_OK  # already removed or reverted
                return rc, message, changed

            # if we got here at least 1 snapshot was reverted
            changed = True

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def extend_lv_snapshot(vg_name, lv_name, suffix, percent_space_required, check_mode):
    snapshot_name = get_snapshot_name(lv_name, suffix)

    rc, _vg_exists, lv_exists = lvm_lv_exists(vg_name, snapshot_name)

    changed = False
    if lv_exists:
        if not lvm_is_snapshot(vg_name, snapshot_name):
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
    rc, _message, current_space_dict = get_current_space_state()
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

    rc, output = run_command(extend_command)

    if rc != SnapshotStatus.SNAPSHOT_OK:
        return SnapshotStatus.ERROR_EXTEND_FAILED, output, changed

    return SnapshotStatus.SNAPSHOT_OK, output, True  # changed


def extend_check_size(vg_name, lv_name, snapshot_name, percent_space_required):
    rc, _message, current_space_dict = get_current_space_state()
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


def extend_snapshot_set(snapset_json, check_mode):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("extend snapsset : %s", snapset_name)

    changed = False
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]
        percent_space_required = list_item["percent_space_required"]

        rc, message, cmd_changed = extend_lv_snapshot(
            vg, lv, snapset_name, percent_space_required, check_mode
        )

        if cmd_changed:
            changed = True

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, changed

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def extend_verify_snapshot_set(snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]

    logger.info("extend verify snapsset : %s", snapset_name)

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]
        percent_space_required = list_item["percent_space_required"]

        snapshot_name = get_snapshot_name(lv, snapset_name)

        rc, _vg_exists, lv_exists = lvm_lv_exists(vg, snapshot_name)
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
            vg, lv, snapshot_name, percent_space_required
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

        if not size_ok:
            return (
                SnapshotStatus.ERROR_EXTEND_VERIFY_FAILED,
                "verify failed due to insufficient space for: " + vg + "/" + lv,
            )

    return SnapshotStatus.SNAPSHOT_OK, ""


def extend_verify_snapshots(vg_name, lv_name, suffix, percent_space_required):
    # if the vg_name and lv_name are supplied, make sure the source is not a snapshot
    if vg_name and lv_name:
        rc, is_snapshot = lvm_is_snapshot(vg_name, lv_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (
                SnapshotStatus.ERROR_VERIFY_REMOVE_FAILED,
                "command failed for LV lvm_is_snapshot() failed to get status on source",
            )
        if is_snapshot:
            return (
                SnapshotStatus.ERROR_EXTEND_VERIFY_FAILED,
                "source is a snapshot:" + vg_name + "/" + lv_name,
            )

    for vg, lv_list in vgs_lvs_iterator(vg_name, lv_name):
        for lv in lv_list:
            rc, is_snapshot = lvm_is_snapshot(vg["vg_name"], lv["lv_name"])
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_EXTEND_VERIFY_FAILED,
                    "command failed for LV lvm_is_snapshot() failed to get status",
                )

            # Only verify non snapshot LVs
            if is_snapshot:
                continue

            snapshot_name = get_snapshot_name(lv["lv_name"], suffix)

            # Make sure the snapshot exists
            rc, vg_exists, lv_exists = lvm_lv_exists(vg["vg_name"], snapshot_name)

            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_EXTEND_VERIFY_FAILED,
                    "extend verify lvm_lv_exists failed "
                    + vg["vg_name"]
                    + "/"
                    + snapshot_name,
                )

            if not vg_exists or not lv_exists:
                return (
                    SnapshotStatus.ERROR_EXTEND_VERIFY_FAILED,
                    "extend verify snapshot not found: "
                    + vg["vg_name"]
                    + "/"
                    + snapshot_name,
                )
            rc, is_snapshot = lvm_is_snapshot(vg["vg_name"], snapshot_name)

            if not is_snapshot:
                return (
                    SnapshotStatus.ERROR_VERIFY_NOTSNAPSHOT,
                    "extend verify target is not snapshot",
                )

            rc, size_ok, message = extend_check_size(
                vg["vg_name"], lv["lv_name"], snapshot_name, percent_space_required
            )

            if rc != SnapshotStatus.SNAPSHOT_OK:
                return rc, message

            if not size_ok:
                return (
                    SnapshotStatus.ERROR_EXTEND_VERIFY_FAILED,
                    "verify failed due to insufficient space for: "
                    + vg["vg_name"]
                    + "/"
                    + snapshot_name,
                )
    return SnapshotStatus.SNAPSHOT_OK, ""


def extend_lvs(vg_name, lv_name, suffix, required_space, check_mode):
    # Extend snapshots
    changed = False
    for vg, lv_list in vgs_lvs_iterator(vg_name, lv_name):
        for lv in lv_list:
            lv = lv["lv_name"]

            # Make sure the source LV isn't a snapshot.
            rc, is_snapshot = lvm_is_snapshot(vg["vg_name"], lv)

            if rc != SnapshotStatus.SNAPSHOT_OK:
                raise LvmBug("'lvs' failed '%d'" % rc)

            if is_snapshot:
                continue

            rc, message, cmd_changed = extend_lv_snapshot(
                vg["vg_name"], lv, suffix, required_space, check_mode
            )

            if cmd_changed:
                changed = True

            if rc != SnapshotStatus.SNAPSHOT_OK:
                return rc, message, changed

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def snapshot_lv(vg_name, lv_name, suffix, snap_size, check_mode):
    snapshot_name = get_snapshot_name(lv_name, suffix)

    rc, _vg_exists, lv_exists = lvm_lv_exists(vg_name, snapshot_name)

    if lv_exists:
        if lvm_is_snapshot(vg_name, snapshot_name):
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

    rc, output = run_command(snapshot_command)

    if rc:
        return SnapshotStatus.ERROR_SNAPSHOT_FAILED, output

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


def check_lvs(required_space, vg_name, lv_name, suffix):
    # Check to make sure all the source vgs/lvs exist
    rc, message = verify_source_lvs_exist(vg_name, lv_name)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message

    for vg, lv_list in vgs_lvs_iterator(vg_name, lv_name):
        for lv in lv_list:
            rc, message = check_name_for_snapshot(lv["lv_name"], suffix)
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return rc, message

        if check_space_for_snapshots(vg, lv_list, lv_name, required_space):
            return (
                SnapshotStatus.ERROR_INSUFFICIENT_SPACE,
                "insufficient space for snapshots",
            )

    return SnapshotStatus.SNAPSHOT_OK, ""


# Verify that the set has been created
def check_verify_lvs_set(snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("check snapsset : %s", snapset_name)

    # Check to make sure all the source vgs/lvs exist
    rc, message = verify_snapset_source_lvs_exist(snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message

    # Check to make sure that target snapshots/volumes don't already exist
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        snapshot_name = get_snapshot_name(lv, snapset_name)

        rc, _vg_exists, lv_exists = lvm_lv_exists(vg, snapshot_name)
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
            rc, is_snapshot = lvm_is_snapshot(vg, snapshot_name)
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


def check_verify_lvs_completed(snapshot_all, vg_name, lv_name, suffix):
    vg_found = False
    lv_found = False

    for vg, lv_list in vgs_lvs_iterator(vg_name, lv_name):
        vg_found = True
        verify_vg_name = vg["vg_name"]

        for lvs in lv_list:
            lv_found = True
            # Only verify that a snapshot exits for non-snapshot LVs
            rc, is_snapshot = lvm_is_snapshot(verify_vg_name, lvs["lv_name"])
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                    "check verify: command failed for LV lvm_is_snapshot()",
                )

            if is_snapshot:
                continue

            snapshot_name = get_snapshot_name(lvs["lv_name"], suffix)

            rc, _vg_exists, lv_exists = lvm_lv_exists(verify_vg_name, snapshot_name)
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                    "check verify: command failed for LV exists",
                )

            if lv_exists:
                rc, is_snapshot = lvm_is_snapshot(verify_vg_name, snapshot_name)
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


def revert_snapshot_set(snapset_json, check_mode):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("revert snapsset : %s", snapset_name)

    changed = False
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        rc, message = revert_lv(vg, get_snapshot_name(lv, snapset_name), check_mode)

        if rc != SnapshotStatus.SNAPSHOT_OK:
            if rc == SnapshotStatus.ERROR_LV_NOTFOUND:
                rc = SnapshotStatus.SNAPSHOT_OK  # already removed or reverted
            return rc, message, changed

        # if we got here at least 1 snapshot was reverted
        changed = True

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def umount_verify(mountpoint, vg_name, lv_to_check):
    blockdev = path_join(DEV_PREFIX, vg_name, lv_to_check)

    mount_list = lvm_get_fs_mount_points(mountpoint)

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


def umount_lv(umount_target, vg_name, lv_name, all_targets, check_mode):
    logger.info("umount_lv : %s", umount_target)

    changed = False
    if vg_name and lv_name:
        # Check to make sure all the source vgs/lvs exist
        rc, message = verify_source_lvs_exist(vg_name, lv_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, changed

    rc, message = umount(umount_target, all_targets, check_mode)
    changed = rc == SnapshotStatus.SNAPSHOT_OK
    if rc == SnapshotStatus.ERROR_UMOUNT_NOT_MOUNTED:
        rc = SnapshotStatus.SNAPSHOT_OK  # already unmounted - not an error
    return rc, message, changed


def umount_snapshot_set(snapset_json, verify_only, check_mode):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]

    logger.info("mount verify snapsset : %s", snapset_name)

    changed = False
    for list_item in volume_list:
        vg_name = list_item["vg"]
        lv_name = list_item["lv"]
        if "mountpoint" in list_item:
            mountpoint = list_item["mountpoint"]
        else:
            return (
                SnapshotStatus.ERROR_UMOUNT_VERIFY_FAILED,
                "set item must provide a mountpoint for : " + vg_name + "/" + lv_name,
                changed,
            )

        if "all_targets" in list_item:
            all_targets = bool(list_item["all_targets"])
        else:
            all_targets = False

        if "mount_origin" in list_item:
            origin = bool(list_item["mount_origin"])

        else:
            origin = False

        if origin:
            lv_to_check = lv_name
        else:
            lv_to_check = get_snapshot_name(lv_name, snapset_name)

        if verify_only:
            rc, message = umount_verify(mountpoint, vg_name, lv_to_check)
        else:
            rc, message, cmd_changed = umount_lv(
                mountpoint, vg_name, lv_to_check, all_targets, check_mode
            )
            if cmd_changed:
                changed = True

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, changed

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def mount_snapshot_set(
    snapset_json, verify_only, cmdline_mountpoint_create, check_mode
):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]

    logger.info("mount verify snapsset : %s", snapset_name)

    changed = False
    for list_item in volume_list:
        vg_name = list_item["vg"]
        lv_name = list_item["lv"]

        if not cmdline_mountpoint_create:
            if "mountpoint_create" in list_item:
                mountpoint_create = bool(list_item["mountpoint_create"])
            else:
                mountpoint_create = False
        else:
            mountpoint_create = bool(cmdline_mountpoint_create)

        if "mount_origin" in list_item:
            origin = bool(list_item["mount_origin"])
        else:
            origin = False

        if "fstype" in list_item:
            fstype = list_item["fstype"]
        else:
            fstype = None

        if "options" in list_item:
            options = list_item["options"]
        else:
            options = None

        if "mountpoint" in list_item:
            mountpoint = list_item["mountpoint"]
        else:
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
                origin, mountpoint, blockdev, vg_name, lv_name, snapset_name
            )
        else:
            rc, message, cmd_changed = mount_lv(
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


def mount_verify(origin, mountpoint, blockdev, vg_name, lv_name, snapset_name):
    logger.info(
        "mount_verify_lv : %d %s %s %s %s %s",
        origin,
        mountpoint,
        blockdev,
        vg_name,
        lv_name,
        snapset_name,
    )

    if not mountpoint:
        return (
            SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
            "must provide mountpoint",
        )

    if not blockdev and (not vg_name or not lv_name):
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
        rc, message = verify_source_lvs_exist(vg_name, lv_to_check)
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

    mount_list = lvm_get_fs_mount_points(blockdev)

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
        rc, message = verify_source_lvs_exist(vg_name, lv_to_mount)
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

    rc, message = mount(blockdev, mountpoint, fstype, options, create, check_mode)
    changed = rc == SnapshotStatus.SNAPSHOT_OK
    if rc == SnapshotStatus.ERROR_MOUNT_POINT_ALREADY_MOUNTED:
        rc = SnapshotStatus.SNAPSHOT_OK  # this is ok

    return rc, message, changed


def remove_snapshot_set(snapset_json, check_mode):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("remove snapsset : %s", snapset_name)

    # check to make sure the set is removable before attempting to remove
    changed = False
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]
        snapshot_name = get_snapshot_name(lv, snapset_name)

        rc, vg_exists, lv_exists = lvm_lv_exists(vg, snapshot_name)

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, "failed to get LV status", changed

        # if there is no snapshot, continue (idempotent)
        if not vg_exists or not lv_exists:
            continue

        rc, in_use = lvm_is_inuse(vg, snapshot_name)

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

        rc, vg_exists, lv_exists = lvm_lv_exists(vg, snapshot_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, "failed to get LV status", changed

        # if there is no snapshot, continue (idempotent)
        if not vg_exists or not lv_exists:
            continue

        rc, message = lvm_snapshot_remove(vg, snapshot_name, check_mode)

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, changed

        # if we got here, at least 1 snapshot was removed
        changed = True

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def remove_verify_snapshot_set(snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]

    logger.info("remove verify snapsset : %s", snapset_name)

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        snapshot_name = get_snapshot_name(lv, snapset_name)

        rc, _vg_exists, lv_exists = lvm_lv_exists(vg, snapshot_name)
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


def remove_snapshots(volume_group, logical_volume, suffix, check_mode):
    rc = SnapshotStatus.SNAPSHOT_OK
    message = ""

    if logical_volume:
        search_lv_name = get_snapshot_name(logical_volume, suffix)
    else:
        search_lv_name = None

    changed = False
    for vg, lv_list in vgs_lvs_iterator(volume_group, search_lv_name):
        vg_name = vg["vg_name"]

        for lvs in lv_list:
            lv_name = lvs["lv_name"]

            if not lvm_is_owned(lv_name, suffix):
                continue

            rc, message = lvm_snapshot_remove(vg_name, lv_name, check_mode)

            if rc != SnapshotStatus.SNAPSHOT_OK:
                break

            # if we got here, at least 1 snapshot was removed
            changed = True

        if volume_group:
            break

    return rc, message, changed


def remove_verify_snapshots(vg_name, lv_name, suffix):
    # if the vg_name and lv_name are supplied, make sure the source is not a snapshot
    if vg_name and lv_name:
        rc, is_snapshot = lvm_is_snapshot(vg_name, lv_name)
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

    for vg, lv_list in vgs_lvs_iterator(vg_name, lv_name):
        verify_vg_name = vg["vg_name"]

        for lvs in lv_list:
            rc, is_snapshot = lvm_is_snapshot(verify_vg_name, lvs["lv_name"])
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_VERIFY_REMOVE_FAILED,
                    "command failed for LV lvm_is_snapshot() failed to get status",
                )

            # Only verify for non-snapshot LVs
            if is_snapshot:
                continue

            snapshot_name = get_snapshot_name(lvs["lv_name"], suffix)

            rc, _vg_exists, lv_exists = lvm_lv_exists(verify_vg_name, snapshot_name)

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


def get_current_space_state():
    vg_size_dict = dict()
    for volume_group, lv_list in vgs_lvs_iterator(None, None):
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


def verify_source_lvs_exist(vg_name, lv_name):
    rc, vg_exists, lv_exists = lvm_lv_exists(vg_name, lv_name)

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


def verify_snapset_target_no_existing(snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("verify snapsset : %s", snapset_name)

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        snapshot_name = get_snapshot_name(lv, snapset_name)

        rc, _vg_exists, lv_exists = lvm_lv_exists(vg, snapshot_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (
                rc,
                "could not determine if snapshot exists: " + vg + "/" + snapshot_name,
            )

        if lv_exists:
            rc, exists = lvm_is_snapshot(vg, snapshot_name)
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


def verify_snapset_source_lvs_exist(snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("verify snapsset : %s", snapset_name)
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        rc, vg_exists, lv_exists = lvm_lv_exists(vg, lv)

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (
                SnapshotStatus.ERROR_SNAPSET_CHECK_STATUS_FAILED,
                "command failed for LV lvm_is_snapshot() failed to get status",
            )
        if not vg_exists:
            return (
                SnapshotStatus.ERROR_SNAPSET_SOURCE_DOES_NOT_EXIST,
                "source volume group in snapset does not exist: " + vg,
            )
        if not lv_exists:
            return (
                SnapshotStatus.ERROR_SNAPSET_SOURCE_DOES_NOT_EXIST,
                "source logical volume in snapset does not exist: " + vg + "/" + lv,
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
def snapshot_precheck_lv_set_space(snapset_json):
    total_space_requested = dict()
    volume_list = snapset_json["volumes"]

    # Calculate total space needed for each VG
    rc, _message, current_space_dict = get_current_space_state()
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
def snapshot_precheck_lv_set(snapset_json):
    rc, message = verify_snapset_source_lvs_exist(snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message, None

    rc, message = verify_snapset_target_no_existing(snapset_json)
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

    rc, message, current_space_dict = snapshot_precheck_lv_set_space(snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message, None

    return SnapshotStatus.SNAPSHOT_OK, "", current_space_dict


def snapshot_create_set(snapset_json, check_mode):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    changed = False

    rc, message, current_space_dict = snapshot_precheck_lv_set(snapset_json)
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

        rc, message = snapshot_lv(vg, lv, snapset_name, required_size, check_mode)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, changed

        # if we got here, at least 1 snapshot was created
        changed = True

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def snapshot_set(snapset_json, check_mode):
    changed = False
    rc, message = verify_snapset_source_lvs_exist(snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message, changed

    rc, message, changed = snapshot_create_set(snapset_json, check_mode)

    return rc, message, changed


def snapshot_lvs(required_space, snapshot_all, vg_name, lv_name, suffix, check_mode):
    # check to make sure there is space and no name conflicts
    changed = False
    rc, message = check_lvs(required_space, vg_name, lv_name, suffix)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message, changed

    vg_found = False
    lv_found = False

    # Take Snapshots
    for vg, lv_list in vgs_lvs_iterator(vg_name, lv_name):
        vg_found = True
        for lv in lv_list:
            lv_found = True
            # Make sure the source LV isn't a snapshot.
            rc, is_snapshot = lvm_is_snapshot(vg["vg_name"], lv["lv_name"])

            if rc != SnapshotStatus.SNAPSHOT_OK:
                raise LvmBug("'lvs' failed '%d'" % rc)

            if is_snapshot:
                continue

            lv_size = int(lv["lv_size"])
            snap_size = round_up(
                math.ceil(percentof(required_space, lv_size)), CHUNK_SIZE
            )

            rc, message = snapshot_lv(
                vg["vg_name"], lv["lv_name"], suffix, snap_size, check_mode
            )

            # TODO: Should the existing snapshot be removed and be updated?
            # richm - IMO no - Ansible idempotence requires that the task should
            # report "changed": false for this snapshot - user can use `list`
            # to get list of existing snapshots, and use `remove` if they
            # want to remove and recreate
            if rc == SnapshotStatus.ERROR_ALREADY_EXISTS:
                continue

            if rc != SnapshotStatus.SNAPSHOT_OK:
                return rc, message, changed

            # if we got here, then at least 1 snapshot was created
            changed = True

    if not snapshot_all:
        if vg_name and not vg_found:
            return (
                SnapshotStatus.ERROR_VG_NOTFOUND,
                "volume group does not exist: " + vg_name,
                changed,
            )
        if lv_name and not lv_found:
            return (
                SnapshotStatus.ERROR_LV_NOTFOUND,
                "logical volume does not exist: " + lv_name,
                changed,
            )

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def validate_args(args):
    rc = SnapshotStatus.ERROR_CMD_INVALID
    if args.all and args.volume_group:
        return (
            rc,
            "--all and --volume_group are mutually exclusive for operation "
            + args.operation,
        )

    if not args.all and args.volume_group is None and args.suffix is None:
        return (
            rc,
            "must specify either --all, --volume_group or --snapset for operation "
            + args.operation,
        )

    if not args.all and args.volume_group is None and args.logical_volume:
        return (
            rc,
            "--logical_volume requires --volume_group parameter for operation "
            + args.operation,
        )

    if not args.suffix:
        return rc, "--snapset is required for operation " + args.operation

    if len(args.suffix) == 0:
        return rc, "Snapset name must be provided for operation " + args.operation

    # not all commands include required_space
    if hasattr(args, "required_space"):
        rc, message, _required_space = get_required_space(args.required_space)

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

    return SnapshotStatus.SNAPSHOT_OK, ""


def validate_umount_args(args):
    if not args.mountpoint and not args.blockdev:
        return (
            SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
            "--mountpoint or --blockdev is required",
        )

    return SnapshotStatus.SNAPSHOT_OK, ""


def validate_mount_args(args):
    if not args.blockdev and (not args.volume_group or not args.logical_volume):
        return (
            SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS,
            "must provide blockdev or vg/lv for mount source",
        )

    if not args.mountpoint:
        return SnapshotStatus.ERROR_MOUNT_INVALID_PARAMS, "mountpoint is required"

    return SnapshotStatus.SNAPSHOT_OK, ""


def get_required_space(required_space_str):
    try:
        percent_space_required = int(required_space_str)

        if percent_space_required <= 1:
            return (
                SnapshotStatus.ERROR_INVALID_PERCENT_REQUESTED,
                "percent_space_required must be greater than 1: "
                + str(required_space_str),
                0,
            )
    except ValueError:
        return (
            SnapshotStatus.ERROR_INVALID_PERCENT_REQUESTED,
            "percent_space_required must be a positive integer: " + required_space_str,
            0,
        )

    return SnapshotStatus.SNAPSHOT_OK, "", percent_space_required


def print_result(result):
    json.dump(result, sys.stdout, indent=4)
    logger.info("exit code: %d: %s", result["return_code"], str(result["errors"]))


def validate_json_request(snapset_json, check_percent_space_required):
    try:
        snapset_name = snapset_json["name"]
    except KeyError:
        return (SnapshotStatus.ERROR_JSON_PARSER_ERROR, "snapset must include a name")

    try:
        volume_list = snapset_json["volumes"]
    except KeyError:
        return (
            SnapshotStatus.ERROR_JSON_PARSER_ERROR,
            "snapset must include a volumes list",
        )

    for list_item in volume_list:
        try:
            vg = list_item["vg"]
        except KeyError:
            return (
                SnapshotStatus.ERROR_JSON_PARSER_ERROR,
                "snapset vg not found for :" + snapset_name,
            )
        try:
            list_item["lv"]
        except KeyError:
            return (
                SnapshotStatus.ERROR_JSON_PARSER_ERROR,
                "snapset lv entry not found for vg:" + snapset_name + " " + vg,
            )
        if check_percent_space_required:
            try:
                rc, message, _value = get_required_space(
                    list_item["percent_space_required"]
                )
                if rc != SnapshotStatus.SNAPSHOT_OK:
                    return rc, message
            except KeyError:
                return (
                    SnapshotStatus.ERROR_JSON_PARSER_ERROR,
                    "snapset percent_space_required entry not found for: "
                    + snapset_name
                    + " "
                    + vg,
                )

    return SnapshotStatus.SNAPSHOT_OK, ""


def validate_json_mount_request(snapset_json):
    return SnapshotStatus.SNAPSHOT_OK, ""


def validate_json_umount_request(snapset_json):
    return SnapshotStatus.SNAPSHOT_OK, ""


def validate_snapset_json(cmd, snapset, verify_only):
    try:
        snapset_json = json.loads(snapset)
    except ValueError as error:
        logger.info(error)
        message = "validate_snapset_json: json decode failed : %s" % error.args[0]
        return SnapshotStatus.ERROR_JSON_PARSER_ERROR, message, None

    if cmd == SnapshotCommand.SNAPSHOT:
        rc, message = validate_json_request(snapset_json, True)
    elif cmd == SnapshotCommand.CHECK and not verify_only:
        rc, message = validate_json_request(snapset_json, True)
    elif cmd == SnapshotCommand.CHECK and verify_only:
        rc, message = validate_json_request(snapset_json, not verify_only)
    elif cmd == SnapshotCommand.REMOVE:
        rc, message = validate_json_request(snapset_json, False)
    elif cmd == SnapshotCommand.LIST:
        rc, message = validate_json_request(snapset_json, False)
    elif cmd == SnapshotCommand.MOUNT:
        rc, message = validate_json_mount_request(snapset_json)
    elif cmd == SnapshotCommand.UMOUNT:
        rc, message = validate_json_umount_request(snapset_json)
    else:
        rc = SnapshotStatus.ERROR_UNKNOWN_FAILURE
        message = "validate_snapset_json for command " + cmd

    logger.info("snapset %s", snapset_json)
    return rc, message, snapset_json


def snapshot_cmd(args):
    logger.info(
        "snapshot_cmd: %s %s %s %s %s %s %s",
        args.operation,
        args.required_space,
        args.volume_group,
        args.logical_volume,
        args.suffix,
        args.set_json,
        args.check_mode,
    )

    if args.set_json is None:
        rc, message = validate_args(args)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": False}

        rc, message, required_space = get_required_space(args.required_space)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": False}

        rc, message, changed = snapshot_lvs(
            required_space,
            args.all,
            args.volume_group,
            args.logical_volume,
            args.suffix,
            args.check_mode,
        )
    else:
        rc, message, snapset_json = validate_snapset_json(
            SnapshotCommand.SNAPSHOT, args.set_json, False
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": False}
        rc, message, changed = snapshot_set(snapset_json, args.check_mode)

    return {"return_code": rc, "errors": [message], "changed": changed}


def check_cmd(args):
    logger.info(
        "check_cmd: %s %s %s %s %s %d %s",
        args.operation,
        args.required_space,
        args.volume_group,
        args.logical_volume,
        args.suffix,
        args.verify,
        args.set_json,
    )

    if args.set_json is None:
        rc, message = validate_args(args)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": False}

        if args.verify:
            rc, message = check_verify_lvs_completed(
                args.all,
                args.volume_group,
                args.logical_volume,
                args.suffix,
            )
        else:
            rc, message = check_lvs(
                args.required_space,
                args.volume_group,
                args.logical_volume,
                args.suffix,
            )
    else:
        rc, message, snapset_json = validate_snapset_json(
            SnapshotCommand.CHECK, args.set_json, args.verify
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": False}

        if args.verify:
            rc, message = check_verify_lvs_set(snapset_json)
        else:
            rc, message, _current_space_dict = snapshot_precheck_lv_set(snapset_json)

    return {"return_code": rc, "errors": [message], "changed": False}


def remove_cmd(args):
    logger.info(
        "remove_cmd: %s %s %s %s %d %s",
        args.operation,
        args.volume_group,
        args.logical_volume,
        args.suffix,
        args.verify,
        args.set_json,
    )

    changed = False
    if args.set_json is None:
        rc, message = validate_args(args)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": changed}

        if args.all and args.volume_group:
            return {
                "return_code": SnapshotStatus.ERROR_CMD_INVALID,
                "errors": [
                    "--all and --volume_group are mutually exclusive for operation "
                    + args.operation
                ],
                "changed": changed,
            }

        if args.verify:
            rc, message = remove_verify_snapshots(
                args.volume_group, args.logical_volume, args.suffix
            )
        else:
            rc, message, changed = remove_snapshots(
                args.volume_group, args.logical_volume, args.suffix, args.check_mode
            )
    else:
        rc, message, snapset_json = validate_snapset_json(
            SnapshotCommand.REMOVE, args.set_json, args.verify
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": changed}

        if args.verify:
            rc, message = remove_verify_snapshot_set(snapset_json)
        else:
            rc, message, changed = remove_snapshot_set(snapset_json, args.check_mode)

    return {"return_code": rc, "errors": [message], "changed": changed}


def revert_cmd(args):
    logger.info(
        "revert_cmd: %s %s %s %s %d %s",
        args.operation,
        args.volume_group,
        args.logical_volume,
        args.suffix,
        args.verify,
        args.set_json,
    )

    changed = False
    if args.set_json is None:
        rc, message = validate_args(args)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": changed}

        if args.verify:
            rc, message = remove_verify_snapshots(
                args.volume_group,
                args.logical_volume,
                args.suffix,
            )
        else:
            rc, message, changed = revert_lvs(
                args.volume_group, args.logical_volume, args.suffix, args.check_mode
            )
    else:
        rc, message, snapset_json = validate_snapset_json(
            SnapshotCommand.CHECK, args.set_json, args.verify
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": changed}

        if args.verify:
            # revert re-uses the remove verify since both commands should
            # cause the snapshot to no longer exist
            rc, message = remove_verify_snapshot_set(snapset_json)
        else:
            rc, message, changed = revert_snapshot_set(snapset_json, args.check_mode)

    return {"return_code": rc, "errors": [message], "changed": changed}


def extend_cmd(args):
    logger.info(
        "extend_cmd: %s %s %s %s %d %s",
        args.operation,
        args.volume_group,
        args.logical_volume,
        args.suffix,
        args.verify,
        args.set_json,
    )

    changed = False
    if args.set_json is None:
        rc, message = validate_args(args)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": changed}

        if args.verify:
            rc, message = extend_verify_snapshots(
                args.volume_group,
                args.logical_volume,
                args.suffix,
                args.required_space,
            )
        else:
            rc, message, changed = extend_lvs(
                args.volume_group,
                args.logical_volume,
                args.suffix,
                args.required_space,
                args.check_mode,
            )
    else:
        rc, message, snapset_json = validate_snapset_json(
            SnapshotCommand.CHECK, args.set_json, args.verify
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": changed}

        if args.verify:
            rc, message = extend_verify_snapshot_set(snapset_json)
        else:
            rc, message, changed = extend_snapshot_set(snapset_json, args.check_mode)

    return {"return_code": rc, "errors": [message], "changed": changed}


def list_cmd(args):
    logger.info(
        "list_cmd: %d %s %s %s %s %s",
        args.all,
        args.operation,
        args.volume_group,
        args.logical_volume,
        args.suffix,
        args.set_json,
    )

    if args.set_json is None:
        rc, message = validate_args(args)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": False}

        rc, data = lvm_list_json(
            args.volume_group,
            args.logical_volume,
        )
    else:
        # TODO filter the set based on the JSON
        rc, data = lvm_list_json(None, None)

    return {"return_code": rc, "errors": [], "data": data, "changed": False}


def mount_cmd(args):
    logger.info(
        "mount_cmd: %d %d %d %s %s %s %s %s %s %s %s",
        args.create,
        args.origin,
        args.verify,
        args.mountpoint,
        args.fstype,
        args.blockdev,
        args.options,
        args.suffix,
        args.logical_volume,
        args.volume_group,
        args.set_json,
    )

    changed = False
    if args.set_json is None:
        rc, message = validate_mount_args(args)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": changed}

        if args.verify:
            rc, message = mount_verify(
                args.origin,
                args.mountpoint,
                args.blockdev,
                args.volume_group,
                args.logical_volume,
                args.suffix,
            )
        else:
            rc, message, changed = mount_lv(
                args.create,
                args.origin,
                args.mountpoint,
                args.fstype,
                args.blockdev,
                args.options,
                args.volume_group,
                args.logical_volume,
                args.suffix,
                args.check_mode,
            )
    else:
        rc, message, snapset_json = validate_snapset_json(
            SnapshotCommand.MOUNT, args.set_json, args.verify
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": changed}

        rc, message, changed = mount_snapshot_set(
            snapset_json, args.verify, args.create, args.check_mode
        )

    return {"return_code": rc, "errors": [message], "changed": changed}


def umount_cmd(args):
    logger.info(
        "umount_cmd: %d %s %s %s %s",
        args.all_targets,
        args.mountpoint,
        args.logical_volume,
        args.volume_group,
        args.set_json,
    )
    changed = False
    if args.set_json is None:
        rc, message = validate_umount_args(args)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return {"return_code": rc, "errors": [message], "changed": changed}

        if args.verify:
            rc, message = umount_verify(
                args.mountpoint,
                args.volume_group,
                args.logical_volume,
            )
        else:
            if args.mountpoint:
                umount_target = args.mountpoint
            else:
                umount_target = args.blockdev
            rc, message, changed = umount_lv(
                umount_target,
                args.volume_group,
                args.logical_volume,
                args.all_targets,
                args.check_mode,
            )
    else:
        rc, message, snapset_json = validate_snapset_json(
            SnapshotCommand.UMOUNT, args.set_json, False
        )
        rc, message, changed = umount_snapshot_set(
            snapset_json, args.verify, args.check_mode
        )

    return {"return_code": rc, "errors": [message], "changed": changed}


if __name__ == "__main__":
    set_up_logging()

    # Ensure that we get consistent output for parsing stdout/stderr and that we
    # are using the lvmdbusd profile.
    os.environ["LC_ALL"] = "C"
    os.environ["LVM_COMMAND_PROFILE"] = "lvmdbusd"

    common_parser = argparse.ArgumentParser(add_help=False)
    # arguments common to most operations
    common_parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        default=False,
        dest="all",
        help="snapshot all VGs and LVs",
    )
    common_parser.add_argument(
        "-s",
        "--snapset",
        dest="suffix",
        type=str,
        help="name for snapshot set",
    )
    common_parser.add_argument(
        "-p",
        "--prefix",
        dest="prefix",
        type=str,
        help="prefix to add to volume name for snapshot",
    )
    common_parser.add_argument(
        "--vg-include",
        dest="vg_include",
        type=str,
        help=(
            "Used with --all - only include vgs whose names match the given"
            "pattern.  Uses python re.search to match."
        ),
    )
    common_parser.add_argument(
        "--check-mode",
        action="store_true",
        default=False,
        dest="check_mode",
        help="Are we running in Ansible check-mode?",
    )

    # Group parser
    group_parser = argparse.ArgumentParser(add_help=False)
    group_parser.add_argument(
        "-g",
        "--group",
        nargs="?",
        action="store",
        required=False,
        default=None,
        dest="set_json",
    )

    # LVM VG/LV parser
    lvm_parser = argparse.ArgumentParser(add_help=False)
    lvm_parser.add_argument(
        "-vg",
        "--volumegroup",
        nargs="?",
        action="store",
        default=None,
        dest="volume_group",
        help="volume group to snapshot",
    )
    lvm_parser.add_argument(
        "-lv",
        "--logicalvolume",
        nargs="?",
        action="store",
        default=None,
        dest="logical_volume",
        help="logical volume to snapshot",
    )

    # arguments for operations that do verify
    verify_parser = argparse.ArgumentParser(add_help=False)
    verify_parser.add_argument(
        "-v",
        "--verify",
        action="store_true",
        default=False,
        dest="verify",
        help="verify VGs and LVs have snapshots",
    )

    # arguments for operations that deal with required space
    req_space_parser = argparse.ArgumentParser(add_help=False)
    # TODO: range check required space - setting choices to a range makes the help ugly.
    req_space_parser.add_argument(
        "-r",
        "--requiredspace",
        dest="required_space",
        required=False,
        type=int,  # choices=range(10,100)
        default=20,
        help="percent of required space in the volume group to be reserved for snapshot",
    )

    # arguments for operations that deal with mount of filesytems
    mountpoint_parser = argparse.ArgumentParser(add_help=False)
    mountpoint_parser.add_argument(
        "-m",
        "--mountpoint",
        dest="mountpoint",
        required=False,
        type=str,
        help="mount point for block device",
    )

    # arguments for operations that deal with mount of filesytems
    mount_parser = argparse.ArgumentParser(add_help=False)
    mount_parser.add_argument(
        "-b",
        "--blockdev",
        dest="blockdev",
        required=False,
        type=str,
        help="mount point for block device",
    )
    mount_parser.add_argument(
        "-t",
        "--type",
        dest="fstype",
        required=False,
        default="",
        type=str,
        help="filesystem type",
    )
    mount_parser.add_argument(
        "-o",
        "--options",
        dest="options",
        required=False,
        type=str,
        help="mount options",
    )
    mount_parser.add_argument(
        "-c",
        "--create",
        action="store_true",
        default=False,
        dest="create",
        help="create the directory for the mount point if it doesn't already exist",
    )
    mount_parser.add_argument(
        "-O",
        "--origin",
        action="store_true",
        default=False,
        dest="origin",
        help="mount the origin",
    )
    parser = argparse.ArgumentParser(description="Snapshot Operations")

    # sub-parsers
    subparsers = parser.add_subparsers(dest="operation", help="Available operations")

    # sub-parser for 'snapshot'
    snapshot_parser = subparsers.add_parser(
        SnapshotCommand.SNAPSHOT,
        help="Snapshot given VG/LVs",
        parents=[common_parser, lvm_parser, group_parser, req_space_parser],
    )
    snapshot_parser.set_defaults(func=snapshot_cmd)

    # sub-parser for 'check'
    check_parser = subparsers.add_parser(
        SnapshotCommand.CHECK,
        help="Check space for given VG/LV",
        parents=[
            common_parser,
            lvm_parser,
            group_parser,
            req_space_parser,
            verify_parser,
        ],
    )
    check_parser.set_defaults(func=check_cmd)

    # sub-parser for 'remove'
    remove_parser = subparsers.add_parser(
        SnapshotCommand.REMOVE,
        help="Remove snapshots",
        parents=[common_parser, group_parser, lvm_parser, verify_parser],
    )
    remove_parser.set_defaults(func=remove_cmd)

    # sub-parser for 'revert'
    revert_parser = subparsers.add_parser(
        SnapshotCommand.REVERT,
        help="Revert to snapshots",
        parents=[common_parser, group_parser, lvm_parser, verify_parser],
    )
    revert_parser.set_defaults(func=revert_cmd)

    # sub-parser for 'extend'
    extend_parser = subparsers.add_parser(
        SnapshotCommand.EXTEND,
        help="Extend given LVs",
        parents=[
            common_parser,
            group_parser,
            lvm_parser,
            verify_parser,
            req_space_parser,
        ],
    )
    extend_parser.set_defaults(func=extend_cmd)

    # sub-parser for 'list'
    list_parser = subparsers.add_parser(
        SnapshotCommand.LIST,
        help="List snapshots",
        parents=[common_parser, group_parser, lvm_parser],
    )
    list_parser.set_defaults(func=list_cmd)

    # sub-parser for 'mount'
    mount_parser = subparsers.add_parser(
        SnapshotCommand.MOUNT,
        help="mount filesystems",
        parents=[
            common_parser,
            mountpoint_parser,
            mount_parser,
            group_parser,
            lvm_parser,
            verify_parser,
        ],
    )
    mount_parser.set_defaults(func=mount_cmd)

    # sub-parser for 'umount'
    umount_parser = subparsers.add_parser(
        SnapshotCommand.UMOUNT,
        help="umount filesystems",
        parents=[
            common_parser,
            mountpoint_parser,
            group_parser,
            lvm_parser,
            verify_parser,
        ],
    )
    umount_parser.add_argument(
        "-A",
        "--all-targets",
        action="store_true",
        default=True,
        dest="all_targets",
        help="unmount all mountpoints for the given device",
    )
    umount_parser.set_defaults(func=umount_cmd)

    args = parser.parse_args()
    if args.vg_include:
        VG_INCLUDE = re.compile(args.vg_include)
    else:
        VG_INCLUDE = None
    result = args.func(args)
    print_result(result)

    sys.exit(result["return_code"])
