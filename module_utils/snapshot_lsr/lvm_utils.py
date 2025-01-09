import argparse
import logging
import json

from ansible.module_utils.snapshot_lsr.consts import SnapshotStatus

logger = logging.getLogger("snapshot-role")


class LvmBug(RuntimeError):
    """
    Things that are clearly a bug with lvm itself.
    """

    def __init__(self, msg):
        super().__init__(msg)

    def __str__(self):
        return "lvm bug encountered: %s" % " ".join(self.args)


def lvm_get_vg_lv_from_devpath(module, devpath):

    lvs_command = ["lvs", "--reportformat", "json", devpath]

    rc, output, _stderr = module.run_command(lvs_command)

    try:
        lvs_json = json.loads(output)
    except ValueError as error:
        logger.info(error)
        message = "lvm_get_vg_lv_from_devpath: json decode failed : %s" % error.args[0]
        return SnapshotStatus.ERROR_JSON_PARSER_ERROR, message, "", ""

    lv_list = lvs_json["report"]
    if len(lv_list) > 1 or len(lv_list[0]["lv"]) > 1:
        raise LvmBug("'lvs' returned more than 1 lv '%d'" % rc)

    return (
        SnapshotStatus.SNAPSHOT_OK,
        "",
        lv_list[0]["lv"][0]["vg_name"],
        lv_list[0]["lv"][0]["lv_name"],
    )


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
