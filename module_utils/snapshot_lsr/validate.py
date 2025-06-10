from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging

from ansible.module_utils.snapshot_lsr.lvm import (
    check_required_space,
    verify_source_lvs_exist,
    lvm_is_snapshot,
    lvm_is_thinpool,
    vgs_lvs_iterator,
)
from ansible.module_utils.snapshot_lsr.consts import SnapshotStatus, SnapshotCommand
from ansible.module_utils.snapshot_lsr.utils import get_command_const

logger = logging.getLogger("snapshot-role")


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


def validate_json_request(snapset_json, check_percent_space_required):
    seen_volumes = set()
    duplicates = set()
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
        volume = list_item["vg"] + "/" + list_item["lv"]
        if volume in seen_volumes:
            duplicates.add(volume)
        else:
            seen_volumes.add(volume)

        if check_percent_space_required:

            if not list_item.get("percent_space_required"):
                return (
                    SnapshotStatus.ERROR_JSON_PARSER_ERROR,
                    "snapset percent_space_required entry not found",
                )
            rc, message = check_required_space(list_item["percent_space_required"])
            if rc != SnapshotStatus.SNAPSHOT_OK:
                return rc, message

    if duplicates:
        return (
            SnapshotStatus.ERROR_VERIFY_DUPLICATE_IN_SET,
            "duplicates in set: " + str(duplicates),
        )

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
