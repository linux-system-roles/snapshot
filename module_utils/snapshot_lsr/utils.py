import argparse
import logging
import os

from lvm import (
    verify_source_lvs_exist,
    lvm_is_snapshot,
    lvm_is_thinpool,
    vgs_lvs_iterator,
)
from consts import SnapshotCommand, SnapshotStatus

logger = logging.getLogger("snapshot-role")


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

    # Ansible ansible.builtin.script feature doesn't separate stdout
    # and stderr when the text is returned to the calling .yaml. Logging
    # to stdout will cause problems with ansible checking the return
    # strings from the python script.

    # stdout_handler = logging.StreamHandler(stream=sys.stdout)

    logger.addHandler(handler)


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

def compare_source_lists(source, target):

    if len(source) == 0 and len(target) == 0:
        return True

    if len(source) != len(target):
        return False

    for list_item in source:

        if list_item in target:
            continue
        else:
            return False
    
    return True