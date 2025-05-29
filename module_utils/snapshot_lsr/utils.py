from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
import os
from os.path import join as path_join
import stat

from ansible.module_utils.snapshot_lsr.consts import (
    SnapshotCommand,
    SnapshotStatus,
    get_command_env,
)
from ansible.module_utils.snapshot_lsr.lvm_utils import (
    to_bool,
    get_mounted_device,
    verify_source_lvs_exist,
    lvm_get_vg_lv_from_devpath,
)

DEV_PREFIX = "/dev"

logger = logging.getLogger("snapshot-role")


def lvm_get_snapshot_name(lv_name, suffix):
    if suffix:
        suffix_str = suffix
    else:
        suffix_str = ""

    return lv_name + "_" + suffix_str


def mgr_get_snapshot_name(module, vg_name, lv_name, snapshot_set):

    for snapshot in snapshot_set:

        rc, message, _vg_name, snapshot_lv_name = lvm_get_vg_lv_from_devpath(
            module, snapshot.devpath
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, None

        rc, message, _vg_name, origin_lv_name = lvm_get_vg_lv_from_devpath(
            module, snapshot.source
        )
        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, None

        if snapshot.vg_name == vg_name and lv_name == origin_lv_name:
            return SnapshotStatus.SNAPSHOT_OK, "", snapshot_lv_name

    return ""


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


def get_fs_mount_points(module, block_path):
    find_mnt_command = [
        "findmnt",
        block_path,
        "-P",
    ]
    mount_list = list()

    rc, output, stderr = module.run_command(
        find_mnt_command, environ_update=get_command_env()
    )
    if rc:
        logger.error("get_fs_mount_points' exited with code : %d: %s", rc, stderr)
        return None

    output = output.replace('"', "")

    for line in output.split("\n"):
        if len(line):
            mount_list.append(dict(arg.split("=", 1) for arg in line.split(" ") if arg))

    return mount_list


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


def umount_verify(module, mountpoint, vg_name, lv_to_check):
    blockdev = path_join(DEV_PREFIX, vg_name, lv_to_check)

    mount_list = get_fs_mount_points(module, mountpoint)

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

    rc, output, stderr = module.run_command(
        umount_command, environ_update=get_command_env()
    )

    if rc != 0:
        logger.error("failed to unmount %s: %s: %s", umount_target, output, stderr)
        return SnapshotStatus.ERROR_UMOUNT_FAILED, stderr
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


def umount_snapshot_set(
    module, snapset_json, verify_only, check_mode, snapm=False, snapset=None
):
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
            if snapm:
                rc, message, lv_to_check = mgr_get_snapshot_name(
                    module, vg_name, lv_name, snapset
                )
                if rc != SnapshotStatus.SNAPSHOT_OK:
                    return rc, message, changed
            else:
                if lv_name and snapset_name:
                    lv_to_check = lvm_get_snapshot_name(lv_name, snapset_name)
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
    module,
    snapset_json,
    verify_only,
    cmdline_mountpoint_create,
    check_mode,
    snapm=False,
    snapset=None,
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
            if snapm:
                rc, message, lv_to_check = mgr_get_snapshot_name(
                    module, vg_name, lv_name, snapset
                )
                if rc != SnapshotStatus.SNAPSHOT_OK:
                    return rc, message, changed
            else:
                lv_to_check = lvm_get_snapshot_name(lv_name, snapset_name)

        blockdev = path_join(DEV_PREFIX, vg_name, lv_to_check)

        if verify_only:
            rc, message = mount_verify(
                module, origin, mountpoint, blockdev, vg_name, lv_name, lv_to_check
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
                lv_to_check,
                check_mode,
            )
            if cmd_changed:
                changed = True

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, changed

    return SnapshotStatus.SNAPSHOT_OK, "", changed


def mount_verify(module, origin, mountpoint, blockdev, vg_name, lv_name, snapshot_lv):
    logger.info(
        "mount_verify_lv : %d %s %s %s %s",
        origin,
        mountpoint,
        vg_name,
        lv_name,
        snapshot_lv,
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

    if vg_name or lv_name:
        if origin:
            lv_to_check = lv_name
        else:
            lv_to_check = snapshot_lv

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

    mount_list = get_fs_mount_points(module, blockdev)

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
    lv_snapshot_name,
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
            lv_to_mount = lv_snapshot_name

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


def makedirs(path):
    if not os.path.isdir(path):
        os.makedirs(path, 0o755)


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

    rc, _output, stderr = module.run_command(
        mount_command, environ_update=get_command_env()
    )

    if rc != 0:
        logger.error("failed to mount: ".join(mount_command))
        logger.error(stderr)
        return SnapshotStatus.ERROR_MOUNT_FAILED, stderr

    return SnapshotStatus.SNAPSHOT_OK, ""
