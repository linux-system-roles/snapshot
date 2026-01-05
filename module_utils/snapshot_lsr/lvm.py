from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import logging
import math
import sys

from ansible.module_utils.snapshot_lsr.consts import (
    SnapshotStatus,
    SnapshotCommand,
    get_command_env,
)
from ansible.module_utils.snapshot_lsr.lvm_utils import (
    percentof,
    round_up,
    verify_source_lvs_exist,
    lvm_lv_exists,
    LvmBug,
)
from ansible.module_utils.snapshot_lsr.utils import (
    mount_snapshot_set,
    umount_snapshot_set,
    get_fs_mount_points,
    lvm_get_snapshot_name,
    get_command_const,
)

logger = logging.getLogger("snapshot-role")

LVM_NOTFOUND_RC = 5
MAX_LVM_NAME = 127
CHUNK_SIZE = 65536


# Minimum LVM snapshot size (64MiB)
LVM_MIN_SNAPSHOT_SIZE = 64 * 1024**2


class LVSpaceState:
    lv_size = 0  # The size of the logical volume
    chunk_size = CHUNK_SIZE  # Unit size in a snapshot volume


class VGSpaceState:
    vg_extent_size = 0  # The size of the physical extents in the volume group
    vg_size = 0  # The size of the volume group
    vg_free = 0  # Size of the free space remaining in the volume group
    lvs = dict()


def lvm_get_required_percent_from_policy(policy):
    percent, _size = policy.split("%")

    return percent


def get_snapshot_size_required(lv_size, required_percent, extent_size):
    required = round_up(math.ceil(percentof(required_percent, lv_size)), extent_size)

    if required < LVM_MIN_SNAPSHOT_SIZE:
        return LVM_MIN_SNAPSHOT_SIZE
    else:
        return required


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

    if module_args["snapshot_lvm_bootable"]:
        args_dict["bootable"] = module_args["snapshot_lvm_bootable"]
    else:
        args_dict["bootable"] = False

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

    rc, output, stderr = module.run_command(
        report_command, environ_update=get_command_env()
    )

    if rc:
        logger.info("'fullreport' exited with code : {rc}", rc=rc)
        raise LvmBug("'fullreport' exited with code : %d: %s" % (rc, stderr))
    try:
        lvm_json = json.loads(output)
    except ValueError as error:
        logger.info(error)
        raise LvmBug("'fullreport' decode failed : %s" % error.args[0])

    return lvm_json


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
            fs_mount_points = get_fs_mount_points(module, block_path)
            fs_dict[block_path] = fs_mount_points

    top_level["volumes"] = vg_dict
    top_level["mounts"] = fs_dict
    return SnapshotStatus.SNAPSHOT_OK, top_level


def lvm_get_attr(module, vg_name, lv_name):
    lvs_command = ["lvs", "--reportformat", "json", vg_name + "/" + lv_name]

    rc, output, stderr = module.run_command(
        lvs_command, environ_update=get_command_env()
    )

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

    rc, output, stderr = module.run_command(
        lvs_command, environ_update=get_command_env()
    )

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

    rc, _output, stderr = module.run_command(
        remove_command, environ_update=get_command_env()
    )

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

    rc, output, stderr = module.run_command(
        revert_command, environ_update=get_command_env()
    )

    if rc:
        return SnapshotStatus.ERROR_REVERT_FAILED, stderr

    return SnapshotStatus.SNAPSHOT_OK, output


def extend_lv_snapshot(
    module, vg_name, lv_name, suffix, percent_space_required, check_mode
):
    snapshot_name = lvm_get_snapshot_name(lv_name, suffix)

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

    rc, output, stderr = module.run_command(
        extend_command, environ_update=get_command_env()
    )

    if rc != SnapshotStatus.SNAPSHOT_OK:
        return SnapshotStatus.ERROR_EXTEND_FAILED, stderr, changed

    return SnapshotStatus.SNAPSHOT_OK, output, True  # changed


def extend_check_size(module, vg_name, lv_name, snapshot_name, percent_space_required):
    rc, _message, current_space_dict = get_current_space_state(module)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, "extend_lv get_space_state failure", False, 0

    current_size = current_space_dict[vg_name].lvs[snapshot_name].lv_size
    required_size_for_extend = get_space_needed(
        vg_name, lv_name, percent_space_required, current_space_dict
    )
    logger.info(
        "extend_check_size : %s %s/%s current size : %d required size : %d",
        snapshot_name,
        vg_name,
        lv_name,
        current_size,
        required_size_for_extend,
    )

    if current_size >= required_size_for_extend:
        return (
            SnapshotStatus.SNAPSHOT_OK,
            "",
            True,
            required_size_for_extend,
        )
    return (
        SnapshotStatus.SNAPSHOT_OK,
        "current size too small",
        False,
        required_size_for_extend,
    )


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

        snapshot_name = lvm_get_snapshot_name(lv, snapset_name)

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

        rc, message, size_ok, _required_size = extend_check_size(
            module,
            vg,
            lv,
            snapshot_name,
            percent_space_required,
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
    snapshot_name = lvm_get_snapshot_name(lv_name, suffix)

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

    rc, output, stderr = module.run_command(
        snapshot_command, environ_update=get_command_env()
    )

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

        snapshot_name = lvm_get_snapshot_name(lv, snapset_name)

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

            snapshot_name = lvm_get_snapshot_name(lvs["lv_name"], suffix)

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
            module, vg, lvm_get_snapshot_name(lv, snapset_name), check_mode
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            if rc == SnapshotStatus.ERROR_LV_NOTFOUND:
                rc = SnapshotStatus.SNAPSHOT_OK  # already removed or reverted
            return rc, message, changed

        # if we got here at least 1 snapshot was reverted
        changed = True

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def remove_snapshot_set(module, snapset_json, check_mode):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("remove snapsset : %s", snapset_name)

    # check to make sure the set is removable before attempting to remove
    changed = False
    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]
        snapshot_name = lvm_get_snapshot_name(lv, snapset_name)

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

        snapshot_name = lvm_get_snapshot_name(lv, snapset_name)

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

        snapshot_name = lvm_get_snapshot_name(lv, snapset_name)

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

            snapshot_name = lvm_get_snapshot_name(lvs["lv_name"], suffix)

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


def verify_snapset_target_no_existing(module, snapset_json):
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]
    logger.info("verify snapsset : %s", snapset_name)

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        snapshot_name = lvm_get_snapshot_name(lv, snapset_name)

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

    # If this function has been called with bootable snapshot requested, return error
    # because snapm is required for bootable snapshots.
    if (
        snapset_json["snapshot_lvm_bootable"] is True
        or snapset_json["bootable"] is True
    ):
        return (
            SnapshotStatus.ERROR_BOOTABLE_NOT_SUPPORTED,
            "Bootable snapshots are not supported without snapm",
            changed,
        )

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


def print_result(result):
    json.dump(result, sys.stdout, indent=4)
    logger.info("exit code: %d: %s", result["return_code"], str(result["errors"]))


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
    logger.info("revert_cmd: %s", snapset_dict)

    changed = False

    if module_args["snapshot_lvm_verify_only"]:
        # revert reuses the remove verify since both commands should
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
