import argparse
import os
import logging

from consts import SnapshotStatus

logger = logging.getLogger("snapshot-role")


def get_mounted_device(mount_target):
    """If mount_target is mounted, return the device that is mounted.
    If mount_target is not mounted, return None."""
    with open("/proc/mounts") as pm:
        for line in pm:
            params = line.split(" ")
            if mount_target == params[1]:
                return params[0]
    return None


def round_up(value, multiple):
    return value + (multiple - (value % multiple))


# what percentage is part of whole
def percentage(part, whole):
    return 100 * float(part) / float(whole)


# what is number is percent of whole
def percentof(percent, whole):
    return float(whole) / 100 * float(percent)


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


def to_bool(to_convert):
    if isinstance(to_convert, bool):
        return to_convert

    return to_convert.lower() in ["true", "1", "t", "y"]


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
