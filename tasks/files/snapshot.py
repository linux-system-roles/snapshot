from __future__ import print_function

import argparse
import json
import logging
import math
import os
import subprocess
import sys

logger = logging.getLogger("snapshot-role")

LVM_NOTFOUND_RC = 5
MAX_LVM_NAME = 127
CHUNK_SIZE = 65536


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
            argv, stdin=stdin, stdout=subprocess.PIPE, close_fds=True
        )

        out, err = proc.communicate()

        if err is not None:
            logger.info("Error running %s: %s", argv[0], err)

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


def get_snapshot_name(lv_name, prefix, suffix):
    if prefix:
        prefix_str = prefix
    else:
        prefix_str = ""

    if suffix:
        suffix_str = suffix
    else:
        suffix_str = ""

    return prefix_str + lv_name + suffix_str


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


def lvm_is_owned(lv_name, prefix, suffix):
    if prefix:
        prefix_str = prefix
    else:
        prefix_str = ""

    if suffix:
        suffix_str = suffix
    else:
        suffix_str = ""

    if not lv_name.startswith(prefix_str) or not lv_name.endswith(suffix_str):
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


def lvm_snapshot_remove(vg_name, snapshot_name):
    rc, is_snapshot = lvm_is_snapshot(vg_name, snapshot_name)

    if rc != SnapshotStatus.SNAPSHOT_OK:
        raise LvmBug("'lvs' failed '%d'" % rc)

    if not is_snapshot:
        return (
            SnapshotStatus.ERROR_REMOVE_FAILED_NOT_SNAPSHOT,
            snapshot_name + " is not a snapshot",
        )

    remove_command = ["lvremove", "-y", vg_name + "/" + snapshot_name]

    rc, output = run_command(remove_command)

    if rc:
        return SnapshotStatus.ERROR_REMOVE_FAILED, output

    return SnapshotStatus.SNAPSHOT_OK, ""


def revert_lv(vg_name, lv_name, prefix, suffix):
    snapshot_name = get_snapshot_name(lv_name, prefix, suffix)

    rc, _vg_exists, lv_exists = lvm_lv_exists(vg_name, snapshot_name)

    if lv_exists:
        if not lvm_is_snapshot(vg_name, snapshot_name):
            return (
                SnapshotStatus.ERROR_REVERT_FAILED,
                "LV with name: " + vg_name + "/" + snapshot_name + " is not a snapshot",
            )
    else:
        return (
            SnapshotStatus.ERROR_REVERT_FAILED,
            "snapshot not found with name: " + vg_name + "/" + snapshot_name,
        )

    revert_command = ["lvconvert", "--merge", vg_name + "/" + snapshot_name]

    rc, output = run_command(revert_command)

    if rc:
        return SnapshotStatus.ERROR_REVERT_FAILED, output

    return SnapshotStatus.SNAPSHOT_OK, output


def revert_lvs(vg_name, lv_name, prefix, suffix):
    lvm_json = lvm_full_report_json()
    report = lvm_json["report"]

    # Revert snapshots
    for list_item in report:
        # The list contains items that are not VGs
        try:
            list_item["vg"]
        except KeyError:
            continue
        vg = list_item["vg"][0]["vg_name"]
        if vg_name and vg != vg_name:
            continue

        for lv in list_item["lv"]:
            lv = lv["lv_name"]
            if lv_name and lv != lv_name:
                continue

            # Make sure the source LV isn't a snapshot.
            rc, is_snapshot = lvm_is_snapshot(vg, lv)

            if rc != SnapshotStatus.SNAPSHOT_OK:
                raise LvmBug("'lvs' failed '%d'" % rc)

            if is_snapshot:
                continue

            rc, message = revert_lv(
                vg,
                lv,
                prefix,
                suffix,
            )

            if rc != SnapshotStatus.SNAPSHOT_OK:
                return rc, message

    return SnapshotStatus.SNAPSHOT_OK, ""


def extend_lv_snapshot(
    vg_name, lv_name, prefix, suffix, percent_space_required, _size=None
):
    snapshot_name = get_snapshot_name(lv_name, prefix, suffix)

    rc, _vg_exists, lv_exists = lvm_lv_exists(vg_name, snapshot_name)

    if lv_exists:
        if not lvm_is_snapshot(vg_name, snapshot_name):
            return (
                SnapshotStatus.ERROR_EXTEND_NOT_SNAPSHOT,
                "LV with name: " + vg_name + "/" + snapshot_name + " is not a snapshot",
            )
    else:
        return (
            SnapshotStatus.ERROR_EXTEND_NOT_FOUND,
            "snapshot not found with name: " + vg_name + "/" + snapshot_name,
        )
    rc, _message, current_space_dict = get_current_space_state()
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, "extend_lv get_space_state failure"

    current_size = current_space_dict[vg_name].lvs[snapshot_name].lv_size
    required_size = get_space_needed(
        vg_name, lv_name, percent_space_required, current_space_dict
    )

    if current_size >= required_size:
        return SnapshotStatus.SNAPSHOT_OK, ""

    extend_command = [
        "lvextend",
        "-L",
        str(required_size) + "B",
        vg_name + "/" + snapshot_name,
    ]

    rc, output = run_command(extend_command)

    if rc != SnapshotStatus.SNAPSHOT_OK:
        return SnapshotStatus.ERROR_EXTEND_FAILED, output

    return SnapshotStatus.SNAPSHOT_OK, output


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

    return SnapshotStatus.SNAPSHOT_OK, False, "current size too small"


def extend_snapshot_set(snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("extend snapsset : %s", snapset_name)

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]
        percent_space_required = list_item["percent_space_required"]

        rc, message = extend_lv_snapshot(
            vg, lv, None, get_snapset_suffix(snapset_name), percent_space_required
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

    return SnapshotStatus.SNAPSHOT_OK, ""


def extend_verify_snapshot_set(snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]

    logger.info("extend verify snapsset : %s", snapset_name)

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]
        percent_space_required = list_item["percent_space_required"]

        snapshot_name = get_snapshot_name(lv, None, get_snapset_suffix(snapset_name))

        rc, _vg_exists, lv_exists = lvm_lv_exists(vg, snapshot_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return (
                rc,
                "failure to get status for: " + vg + "/" + snapshot_name,
            )

        if not lv_exists:
            return (
                SnapshotStatus.ERROR_VERIFY_REMOVE_FAILED,
                "snapshot not found for source LV: " + vg + "/" + snapshot_name,
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


def extend_verify_snapshots(vg_name, lv_name, prefix, suffix, percent_space_required):
    lvm_json = lvm_full_report_json()
    report = lvm_json["report"]

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

    for list_item in report:
        # The list contains items that are not VGs
        try:
            list_item["vg"]
        except KeyError:
            continue

        if vg_name and list_item["vg"][0]["vg_name"] != vg_name:
            continue

        verify_vg_name = list_item["vg"][0]["vg_name"]

        for lvs in list_item["lv"]:
            if lv_name and lvs["lv_name"] != lv_name:
                continue

            rc, is_snapshot = lvm_is_snapshot(verify_vg_name, lvs["lv_name"])
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_EXTEND_VERIFY_FAILED,
                    "command failed for LV lvm_is_snapshot() failed to get status",
                )

            # Only verify non snapshot LVs
            if is_snapshot:
                continue

            snapshot_name = get_snapshot_name(lvs["lv_name"], prefix, suffix)

            # Make sure the snapshot exists
            rc, vg_exists, lv_exists = lvm_lv_exists(verify_vg_name, snapshot_name)

            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_EXTEND_VERIFY_FAILED,
                    "extend verify lvm_lv_exists failed "
                    + verify_vg_name
                    + "/"
                    + snapshot_name,
                )

            if not vg_exists or not lv_exists:
                return (
                    SnapshotStatus.ERROR_EXTEND_VERIFY_FAILED,
                    "extend verify snapshot not found: "
                    + verify_vg_name
                    + "/"
                    + snapshot_name,
                )
            rc, is_snapshot = lvm_is_snapshot(verify_vg_name, snapshot_name)

            if not is_snapshot:
                return (
                    SnapshotStatus.ERROR_VERIFY_NOTSNAPSHOT,
                    "extend verify target is not snapshot",
                )

            rc, size_ok, message = extend_check_size(
                verify_vg_name, lvs["lv_name"], snapshot_name, percent_space_required
            )

            if rc != SnapshotStatus.SNAPSHOT_OK:
                return rc, message

            if not size_ok:
                return (
                    SnapshotStatus.ERROR_EXTEND_VERIFY_FAILED,
                    "verify failed due to insufficient space for: "
                    + verify_vg_name
                    + "/"
                    + snapshot_name,
                )
    return SnapshotStatus.SNAPSHOT_OK, ""


def extend_lvs(vg_name, lv_name, prefix, suffix, required_space):
    lvm_json = lvm_full_report_json()
    report = lvm_json["report"]

    # Extend snapshots
    for list_item in report:
        # The list contains items that are not VGs
        try:
            list_item["vg"]
        except KeyError:
            continue
        vg = list_item["vg"][0]["vg_name"]
        if vg_name and vg != vg_name:
            continue

        for lv in list_item["lv"]:
            lv = lv["lv_name"]
            if lv_name and lv != lv_name:
                continue

            # Make sure the source LV isn't a snapshot.
            rc, is_snapshot = lvm_is_snapshot(vg, lv)

            if rc != SnapshotStatus.SNAPSHOT_OK:
                raise LvmBug("'lvs' failed '%d'" % rc)

            if is_snapshot:
                continue

            rc, message = extend_lv_snapshot(vg, lv, prefix, suffix, required_space)

            if rc != SnapshotStatus.SNAPSHOT_OK:
                return rc, message

    return SnapshotStatus.SNAPSHOT_OK, ""


def snapshot_lv(vg_name, lv_name, prefix, suffix, snap_size):
    snapshot_name = get_snapshot_name(lv_name, prefix, suffix)

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


def check_name_for_snapshot(lv_name, prefix, suffix):
    if prefix:
        prefix_len = len(prefix)
    else:
        prefix_len = 0

    if suffix:
        suffix_len = len(suffix)
    else:
        suffix_len = 0

    if len(lv_name) + prefix_len + suffix_len > MAX_LVM_NAME:
        return (
            SnapshotStatus.ERROR_NAME_TOO_LONG,
            "resulting snapshot name would exceed LVM maximum: "
            + prefix_len
            + lv_name
            + suffix,
        )
    else:
        return SnapshotStatus.SNAPSHOT_OK, ""


def check_lvs(required_space, vg_name, lv_name, prefix, suffix):
    # Check to make sure all the source vgs/lvs exist
    rc, message = verify_source_lvs_exist(vg_name, lv_name)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message

    lvm_json = lvm_full_report_json()
    report = lvm_json["report"]

    for list_item in report:
        # The list contains items that are not VGs
        try:
            list_item["vg"]
        except KeyError:
            continue

        if vg_name and list_item["vg"][0]["vg_name"] != vg_name:
            continue

        for lvs in list_item["lv"]:
            if lv_name and lvs["lv_name"] != lv_name:
                continue

            rc, message = check_name_for_snapshot(lvs["lv_name"], prefix, suffix)
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return rc, message

        lvs = list_item["lv"]
        volume_group = list_item["vg"][0]

        if check_space_for_snapshots(volume_group, lvs, lv_name, required_space):
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

        snapshot_name = get_snapshot_name(lv, None, get_snapset_suffix(snapset_name))

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


def check_verify_lvs_completed(snapshot_all, vg_name, lv_name, prefix, suffix):
    lvm_json = lvm_full_report_json()
    report = lvm_json["report"]
    vg_found = False
    lv_found = False

    for list_item in report:
        # The list contains items that are not VGs
        try:
            list_item["vg"]
        except KeyError:
            continue

        if vg_name and list_item["vg"][0]["vg_name"] != vg_name:
            continue
        vg_found = True
        verify_vg_name = list_item["vg"][0]["vg_name"]

        for lvs in list_item["lv"]:
            if lv_name and lvs["lv_name"] != lv_name:
                continue

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

            snapshot_name = get_snapshot_name(lvs["lv_name"], prefix, suffix)

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


def revert_snapshot_set(snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("revert snapsset : %s", snapset_name)

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        rc, message = revert_lv(vg, lv, None, get_snapset_suffix(snapset_name))

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

    return SnapshotStatus.SNAPSHOT_OK, ""


def remove_snapshot_set(snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("remove snapsset : %s", snapset_name)

    # check to make sure the set is removable before attempting to remove
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]
        snapshot_name = get_snapshot_name(lv, None, get_snapset_suffix(snapset_name))

        rc, vg_exists, lv_exists = lvm_lv_exists(vg, snapshot_name)

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, "failed to get LV status"

        # if there is no snapshot, continue (idempotent)
        if not vg_exists or not lv_exists:
            continue

        rc, in_use = lvm_is_inuse(vg, snapshot_name)

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, "failed to lvm_is_inuse status"

        if in_use:
            return (rc, "volume is in use: " + vg + "/" + snapshot_name)

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        snapshot_name = get_snapshot_name(lv, None, get_snapset_suffix(snapset_name))

        rc, vg_exists, lv_exists = lvm_lv_exists(vg, snapshot_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

        # if there is no snapshot, continue (idempotent)
        if not vg_exists or not lv_exists:
            continue

        rc, message = lvm_snapshot_remove(vg, snapshot_name)

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

    return SnapshotStatus.SNAPSHOT_OK, ""


def remove_verify_snapshot_set(snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]

    logger.info("remove verify snapsset : %s", snapset_name)

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        snapshot_name = get_snapshot_name(lv, None, get_snapset_suffix(snapset_name))

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


def remove_snapshots(volume_group, logical_volume, prefix, suffix):
    rc = SnapshotStatus.SNAPSHOT_OK
    message = ""
    lvm_json = lvm_full_report_json()
    report = lvm_json["report"]

    for list_item in report:
        # The list contains items that are not VGs
        try:
            list_item["vg"]
        except KeyError:
            continue

        vg_name = list_item["vg"][0]["vg_name"]

        if volume_group and volume_group != vg_name:
            continue

        if logical_volume:
            search_lv_name = get_snapshot_name(logical_volume, prefix, suffix)

        for lvs in list_item["lv"]:
            lv_name = lvs["lv_name"]

            if logical_volume and lv_name != search_lv_name:
                continue

            if not lvm_is_owned(lv_name, prefix, suffix):
                continue

            rc, message = lvm_snapshot_remove(vg_name, lvs["lv_name"])

            if rc != SnapshotStatus.SNAPSHOT_OK:
                break

        if volume_group:
            break

    return rc, message


def remove_verify_snapshots(vg_name, lv_name, prefix, suffix):
    lvm_json = lvm_full_report_json()
    report = lvm_json["report"]

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

    for list_item in report:
        # The list contains items that are not VGs
        try:
            list_item["vg"]
        except KeyError:
            continue

        if vg_name and list_item["vg"][0]["vg_name"] != vg_name:
            continue

        verify_vg_name = list_item["vg"][0]["vg_name"]

        for lvs in list_item["lv"]:
            if lv_name and lvs["lv_name"] != lv_name:
                continue

            rc, is_snapshot = lvm_is_snapshot(verify_vg_name, lvs["lv_name"])
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_VERIFY_REMOVE_FAILED,
                    "command failed for LV lvm_is_snapshot() failed to get status",
                )

            # Only verify for non-snapshot LVs
            if is_snapshot:
                continue

            snapshot_name = get_snapshot_name(lvs["lv_name"], prefix, suffix)

            rc, _vg_exists, lv_exists = lvm_lv_exists(verify_vg_name, snapshot_name)

            if rc != SnapshotStatus.SNAPSHOT_OK:
                return (
                    SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
                    "extend verify: command failed for LV exists",
                )

            rc, _vg_exists, lv_exists = lvm_lv_exists(verify_vg_name, snapshot_name)

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
    lvm_json = lvm_full_report_json()
    report = lvm_json["report"]
    for list_item in report:
        # The list contains items that are not VGs
        try:
            list_item["vg"]
        except KeyError:
            continue
        volume_group = list_item["vg"][0]

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

        for lv in list_item["lv"]:
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

        snapshot_name = get_snapshot_name(lv, None, get_snapset_suffix(snapset_name))

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


def get_snapset_suffix(snapset_name):
    return "_" + snapset_name


def verify_snapset_names(snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("verify snapsset : %s", snapset_name)
    for list_item in volume_list:
        lv = list_item["lv"]

        rc, message = check_name_for_snapshot(
            lv, None, get_snapset_suffix(snapset_name)
        )
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

        rc, message = check_name_for_snapshot(lv, None, snapset_name)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, "resulting snapshot name would exceed LVM maximum", None

    rc, message, current_space_dict = snapshot_precheck_lv_set_space(snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message, None

    return SnapshotStatus.SNAPSHOT_OK, "", current_space_dict


def snapshot_create_set(snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]

    rc, message, current_space_dict = snapshot_precheck_lv_set(snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message

    # Take snapshots
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        percent_space_required = list_item["percent_space_required"]

        required_size = get_space_needed(
            vg, lv, percent_space_required, current_space_dict
        )

        rc, message = snapshot_lv(
            vg, lv, None, get_snapset_suffix(snapset_name), required_size
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

    return SnapshotStatus.SNAPSHOT_OK, ""


def snapshot_set(snapset_json):
    rc, message = verify_snapset_source_lvs_exist(snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message

    rc, message = snapshot_create_set(snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message

    return SnapshotStatus.SNAPSHOT_OK, ""


def snapshot_lvs(required_space, snapshot_all, vg_name, lv_name, prefix, suffix):
    lvm_json = lvm_full_report_json()
    report = lvm_json["report"]
    vg_found = False
    lv_found = False

    # check to make sure there is space and no name conflicts
    rc, message = check_lvs(required_space, vg_name, lv_name, prefix, suffix)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message

    # Take Snapshots
    for list_item in report:
        # The list contains items that are not VGs
        try:
            list_item["vg"]
        except KeyError:
            continue

        if vg_name and list_item["vg"][0]["vg_name"] != vg_name:
            continue
        vg_found = True
        for lv in list_item["lv"]:
            if lv_name and lv["lv_name"] != lv_name:
                continue
            lv_found = True
            # Make sure the source LV isn't a snapshot.
            rc, is_snapshot = lvm_is_snapshot(
                list_item["vg"][0]["vg_name"], lv["lv_name"]
            )

            if rc != SnapshotStatus.SNAPSHOT_OK:
                raise LvmBug("'lvs' failed '%d'" % rc)

            if is_snapshot:
                continue

            lv_size = int(lv["lv_size"])
            snap_size = round_up(
                math.ceil(percentof(required_space, lv_size)), CHUNK_SIZE
            )

            rc, message = snapshot_lv(
                list_item["vg"][0]["vg_name"],
                lv["lv_name"],
                prefix,
                suffix,
                snap_size,
            )

            # TODO: Should the exiting snapshot be removed and be updated?
            if rc == SnapshotStatus.ERROR_ALREADY_EXISTS:
                continue

            if rc != SnapshotStatus.SNAPSHOT_OK:
                return rc, message

    if not snapshot_all:
        if vg_name and not vg_found:
            return SnapshotStatus.ERROR_VG_NOTFOUND, "volume group does not exist"
        if lv_name and not lv_found:
            return SnapshotStatus.ERROR_LV_NOTFOUND, "logical volume does not exist"

    return SnapshotStatus.SNAPSHOT_OK, ""


def validate_snapset_args(args):
    if args.set_json is None:
        print("%s snapset command requires -group parameter", args.operation)
        sys.exit(SnapshotStatus.ERROR_CMD_INVALID)


def validate_args(args):
    if args.all and args.volume_group:
        print("-all and --volume_group are mutually exclusive: ", args.operation)
        sys.exit(SnapshotStatus.ERROR_CMD_INVALID)

    if not args.all and args.volume_group is None:
        print("must specify either --all or a volume group: ", args.operation)
        sys.exit(SnapshotStatus.ERROR_CMD_INVALID)

    if not args.all and args.volume_group is None and args.logical_volume:
        print("--logical_volume requires --volume_group parameter : ", args.operation)
        sys.exit(SnapshotStatus.ERROR_CMD_INVALID)

    if not args.prefix and not args.suffix:
        print("One of --prefix or --suffix is required : ", args.operation)
        sys.exit(SnapshotStatus.ERROR_CMD_INVALID)

    # not all commands include required_space
    if hasattr(args, "required_space"):
        rc, message, _required_space = get_required_space(args.required_space)

        if rc != SnapshotStatus.SNAPSHOT_OK:
            print(message)
            sys.exit(SnapshotStatus.ERROR_CMD_INVALID)

    return True


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


def print_result(rc, message):
    if rc != SnapshotStatus.SNAPSHOT_OK:
        print(message, file=sys.stderr)
        logger.info("exit code: %d: %s", rc, message)


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
        rc, message = validate_json_request(snapset_json, False)
    elif cmd == SnapshotCommand.REMOVE:
        rc, message = validate_json_request(snapset_json, False)
    else:
        rc = SnapshotStatus.ERROR_UNKNOWN_FAILURE
        message = "validate_snapset_json"

    logger.info("snapset %s", snapset_json)
    return rc, message, snapset_json


def snapshot_cmd(args):
    logger.info(
        "snapshot_cmd: %s %s %s %s %s %s %s",
        args.operation,
        args.required_space,
        args.volume_group,
        args.logical_volume,
        args.prefix,
        args.suffix,
        args.set_json,
    )

    if args.set_json is None:
        rc, message, required_space = get_required_space(args.required_space)
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

        rc, message = snapshot_lvs(
            required_space,
            args.all,
            args.volume_group,
            args.logical_volume,
            args.prefix,
            args.suffix,
        )
    else:
        rc, message, snapset_json = validate_snapset_json(
            SnapshotCommand.SNAPSHOT, args.set_json, False
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message
        rc, message = snapshot_set(snapset_json)

    return rc, message


def check_cmd(args):
    logger.info(
        "check_cmd: %s %s %s %s %s %s %d %s",
        args.operation,
        args.required_space,
        args.volume_group,
        args.logical_volume,
        args.prefix,
        args.suffix,
        args.verify,
        args.set_json,
    )

    if args.set_json is None:
        validate_args(args)

        if args.verify:
            rc, message = check_verify_lvs_completed(
                args.all,
                args.volume_group,
                args.logical_volume,
                args.prefix,
                args.suffix,
            )
        else:
            rc, message = check_lvs(
                args.required_space,
                args.volume_group,
                args.logical_volume,
                args.prefix,
                args.suffix,
            )
    else:
        rc, message, snapset_json = validate_snapset_json(
            SnapshotCommand.CHECK, args.set_json, args.verify
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

        if args.verify:
            rc, message = check_verify_lvs_set(snapset_json)
        else:
            rc, message, _current_space_dict = snapshot_precheck_lv_set(snapset_json)

    return rc, message


def remove_cmd(args):
    logger.info(
        "remove_cmd: %s %s %s %s %s %d %s",
        args.operation,
        args.volume_group,
        args.logical_volume,
        args.suffix,
        args.prefix,
        args.verify,
        args.set_json,
    )

    if args.set_json is None:
        if args.all and args.volume_group:
            print("-all and --volume_group are mutually exclusive: ", args.operation)
            sys.exit(1)

        if args.verify:
            return remove_verify_snapshots(
                args.volume_group, args.logical_volume, args.prefix, args.suffix
            )
        else:
            return remove_snapshots(
                args.volume_group, args.logical_volume, args.prefix, args.suffix
            )
    else:
        rc, message, snapset_json = validate_snapset_json(
            SnapshotCommand.REMOVE, args.set_json, args.verify
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

        if args.verify:
            rc, message = remove_verify_snapshot_set(snapset_json)
        else:
            rc, message = remove_snapshot_set(snapset_json)
    return rc, message


def revert_cmd(args):
    logger.info(
        "revert_cmd: %s %s %s %s %s %d %s",
        args.operation,
        args.volume_group,
        args.logical_volume,
        args.suffix,
        args.prefix,
        args.verify,
        args.set_json,
    )

    if args.set_json is None:
        validate_args(args)

        if args.verify:
            rc, message = remove_verify_snapshots(
                args.volume_group,
                args.logical_volume,
                args.prefix,
                args.suffix,
            )
        else:
            rc, message = revert_lvs(
                args.volume_group,
                args.logical_volume,
                args.prefix,
                args.suffix,
            )
    else:
        rc, message, snapset_json = validate_snapset_json(
            SnapshotCommand.CHECK, args.set_json, args.verify
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

        if args.verify:
            # revert re-uses the remove verify since both commands should
            # cause the snapshot to no longer exist
            rc, message = remove_verify_snapshot_set(snapset_json)
        else:
            rc, message = revert_snapshot_set(snapset_json)

    return rc, message


def extend_cmd(args):
    logger.info(
        "extend_cmd: %s %s %s %s %s %d %s",
        args.operation,
        args.volume_group,
        args.logical_volume,
        args.suffix,
        args.prefix,
        args.verify,
        args.set_json,
    )

    if args.set_json is None:
        validate_args(args)

        if args.verify:
            rc, message = extend_verify_snapshots(
                args.volume_group,
                args.logical_volume,
                args.prefix,
                args.suffix,
                args.required_space,
            )
        else:
            rc, message = extend_lvs(
                args.volume_group,
                args.logical_volume,
                args.prefix,
                args.suffix,
                args.required_space,
            )
    else:
        rc, message, snapset_json = validate_snapset_json(
            SnapshotCommand.CHECK, args.set_json, args.verify
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message

        if args.verify:
            rc, message = extend_verify_snapshot_set(snapset_json)
        else:
            rc, message = extend_snapshot_set(snapset_json)

    return rc, message


if __name__ == "__main__":
    set_up_logging()

    # Ensure that we get consistent output for parsing stdout/stderr and that we
    # are using the lvmdbusd profile.
    os.environ["LC_ALL"] = "C"
    os.environ["LVM_COMMAND_PROFILE"] = "lvmdbusd"

    # arguments common to all operations
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "-g",
        "--group",
        nargs="?",
        action="store",
        required=False,
        default=None,
        dest="set_json",
    )
    common_parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        default=False,
        dest="all",
        help="snapshot all VGs and LVs",
    )
    common_parser.add_argument(
        "-vg",
        "--volumegroup",
        nargs="?",
        action="store",
        default=None,
        dest="volume_group",
        help="volume group to snapshot",
    )
    common_parser.add_argument(
        "-lv",
        "--logicalvolume",
        nargs="?",
        action="store",
        default=None,
        dest="logical_volume",
        help="logical volume to snapshot",
    )
    common_parser.add_argument(
        "-s",
        "--suffix",
        dest="suffix",
        type=str,
        help="suffix to add to volume name for snapshot",
    )
    common_parser.add_argument(
        "-p",
        "--prefix",
        dest="prefix",
        type=str,
        help="prefix to add to volume name for snapshot",
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

    parser = argparse.ArgumentParser(description="Snapshot Operations")

    # sub-parsers
    subparsers = parser.add_subparsers(dest="operation", help="Available operations")

    # sub-parser for 'snapshot'
    snapshot_parser = subparsers.add_parser(
        SnapshotCommand.SNAPSHOT,
        help="Snapshot given VG/LVs",
        parents=[common_parser, req_space_parser],
    )
    snapshot_parser.set_defaults(func=snapshot_cmd)

    # sub-parser for 'check'
    check_parser = subparsers.add_parser(
        SnapshotCommand.CHECK,
        help="Check space for given VG/LV",
        parents=[common_parser, req_space_parser, verify_parser],
    )
    check_parser.set_defaults(func=check_cmd)

    # sub-parser for 'remove'
    remove_parser = subparsers.add_parser(
        SnapshotCommand.REMOVE,
        help="Remove snapshots",
        parents=[common_parser, verify_parser],
    )
    remove_parser.set_defaults(func=remove_cmd)

    # sub-parser for 'revert'
    revert_parser = subparsers.add_parser(
        SnapshotCommand.REVERT,
        help="Revert to snapshots",
        parents=[common_parser, verify_parser],
    )
    revert_parser.set_defaults(func=revert_cmd)

    # arguments for operations that deal with size
    size_parser = argparse.ArgumentParser(add_help=False)
    size_parser.add_argument(
        "-e",
        "--extendsize",
        dest="extend_size",
        required=False,
        type=str,  # choices=range(10,100)
        default=False,
        help="size to extend snapshot",
    )

    # sub-parser for 'extend'
    extend_parser = subparsers.add_parser(
        SnapshotCommand.EXTEND,
        help="Extend given LVs",
        parents=[common_parser, size_parser, verify_parser, req_space_parser],
    )
    extend_parser.set_defaults(func=extend_cmd)

    args = parser.parse_args()
    return_code, display_message = args.func(args)
    print_result(return_code, display_message)

    sys.exit(return_code)
