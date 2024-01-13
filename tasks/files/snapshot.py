from __future__ import print_function

import argparse
import json
import logging
import math
import os
import subprocess
import sys

logger = logging.getLogger("snapshot-role")

MAX_LVM_NAME = 127


class LvmBug(RuntimeError):
    """
    Things that are clearly a bug with lvm itself.
    """

    def __init__(self, msg):
        super().__init__(msg)

    def __str__(self):
        return "lvm bug encountered: %s" % " ".join(self.args)


class SnapshotCommand:
    SNAPSHOT = "snapshot"
    SNAPSHOT_CHECK = "check"
    SNAPSHOT_CLEAN = "clean"


class SnapshotStatus:
    SNAPSHOT_OK = 0
    ERROR_INSUFFICIENT_SPACE = 1
    ERROR_ALREADY_DONE = 2
    ERROR_SNAPSHOT_FAILED = 3
    ERROR_REMOVE_FAILED = 4
    ERROR_REMOVE_FAILED_NOT_SNAPSHOT = 5
    ERROR_LVS_FAILED = 6
    ERROR_NAME_TOO_LONG = 7
    ERROR_ALREADY_EXISTS = 8
    ERROR_NAME_CONFLICT = 9
    ERROR_VG_NOTFOUND = 10
    ERROR_LV_NOTFOUND = 11
    ERROR_VERIFY_NOTSNAPSHOT = 12
    ERROR_VERIFY_COMMAND_FAILED = 13
    ERROR_VERIFY_NOT_FOUND = 14
    ERROR_CMD_INVALID = 15
    ERROR_VERIFY_REMOVE_FAILED = 16
    ERROR_VERIFY_REMOVE_SOURCE_SNAPSHOT = 17


# what percentage is part of whole
def percentage(part, whole):
    return 100 * float(part) / float(whole)


# what is number is percent of whole
def percentof(percent, whole):
    return float(whole) / 100 * float(percent)


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
        "vg_name,vg_uuid,vg_size,vg_free",
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
    lvs_command = ["lvs", "--reportformat", "json", vg_name + "/" + lv_name]

    rc, _output = run_command(lvs_command)

    if rc == 0:
        return SnapshotStatus.SNAPSHOT_OK, True
    else:
        return SnapshotStatus.SNAPSHOT_OK, False


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


def lvm_is_snapshot(vg_name, snapshot_name):
    lvs_command = ["lvs", "--reportformat", "json", vg_name + "/" + snapshot_name]

    rc, output = run_command(lvs_command)

    if rc:
        return SnapshotStatus.ERROR_LVS_FAILED, None

    lvs_json = json.loads(output)

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


def snapshot_lv(vg_name, lv_name, prefix, suffix, snap_size):
    snapshot_name = get_snapshot_name(lv_name, prefix, suffix)

    rc, lv_exists = lvm_lv_exists(vg_name, snapshot_name)

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


def check_name_for_snapshot(vg_name, lv_name, prefix, suffix):
    if prefix:
        prefix_len = len(prefix)
    else:
        prefix_len = 0

    if suffix:
        suffix_len = len(suffix)
    else:
        suffix_len = 0

    if len(vg_name) + len(lv_name) + prefix_len + suffix_len > MAX_LVM_NAME:
        return SnapshotStatus.ERROR_NAME_TOO_LONG
    else:
        return SnapshotStatus.SNAPSHOT_OK


def verify_created(snapshot_all, vg_name, lv_name, prefix, suffix):
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

            rc, lv_exists = lvm_lv_exists(verify_vg_name, snapshot_name)
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
                "source volume group does not exist",
            )
        if lv_name and not lv_found:
            return (
                SnapshotStatus.ERROR_LV_NOTFOUND,
                "source logical volume does not exist",
            )

    return SnapshotStatus.SNAPSHOT_OK, ""


def verify_snapshots_removed(vg_name, lv_name, prefix, suffix):
    lvm_json = lvm_full_report_json()
    report = lvm_json["report"]

    # if the vg_name and lv_name are supplied, make sure it is not a snapshot
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

            rc, lv_exists = lvm_lv_exists(verify_vg_name, snapshot_name)

            if lv_exists:
                return (
                    SnapshotStatus.ERROR_VERIFY_REMOVE_FAILED,
                    "volume exists that matches the pattern: "
                    + verify_vg_name
                    + "/"
                    + snapshot_name,
                )

            rc, is_snapshot = lvm_is_snapshot(verify_vg_name, snapshot_name)

    return SnapshotStatus.SNAPSHOT_OK, ""


def check_lvs(required_space, vg_name, lv_name, prefix, suffix):
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

            if check_name_for_snapshot(
                list_item["vg"][0]["vg_name"], lvs["lv_name"], prefix, suffix
            ):
                return (
                    SnapshotStatus.ERROR_NAME_TOO_LONG,
                    "resulting snapshot name would exceed LVM maximum",
                )

        lvs = list_item["lv"]
        volume_group = list_item["vg"][0]

        if check_space_for_snapshots(volume_group, lvs, lv_name, required_space):
            return (
                SnapshotStatus.ERROR_INSUFFICIENT_SPACE,
                "insufficient space for snapshots",
            )

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
            snap_size = round_up(math.ceil(percentof(required_space, lv_size)), 512)

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


def snapshot_cleanup(volume_group, logical_volume, prefix, suffix):
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
    return True


def snapshot_cmd(args):
    logger.info(
        "snapshot_cmd: %s %s %s %s %s %s",
        args.operation,
        args.required_space,
        args.volume_group,
        args.logical_volume,
        args.prefix,
        args.suffix,
    )

    validate_args(args)

    rc, message = snapshot_lvs(
        args.required_space,
        args.all,
        args.volume_group,
        args.logical_volume,
        args.prefix,
        args.suffix,
    )

    return rc, message


def check_cmd(args):
    logger.info(
        "check_cmd: %s %s %s %s %s %s %d",
        args.operation,
        args.required_space,
        args.volume_group,
        args.logical_volume,
        args.prefix,
        args.suffix,
        args.verify,
    )

    validate_args(args)

    if args.verify:
        rc, message = verify_created(
            args.all, args.volume_group, args.logical_volume, args.prefix, args.suffix
        )
    else:
        rc, message = check_lvs(
            args.required_space,
            args.volume_group,
            args.logical_volume,
            args.prefix,
            args.suffix,
        )

    return rc, message


def clean_cmd(args):
    logger.info(
        "clean_cmd: %s %s %s %s %s %d",
        args.operation,
        args.volume_group,
        args.logical_volume,
        args.suffix,
        args.prefix,
        args.verify,
    )

    if args.all and args.volume_group:
        print("-all and --volume_group are mutually exclusive: ", args.operation)
        sys.exit(1)

    if args.verify:
        return verify_snapshots_removed(
            args.volume_group, args.logical_volume, args.prefix, args.suffix
        )
    else:
        return snapshot_cleanup(
            args.volume_group, args.logical_volume, args.prefix, args.suffix
        )


def print_result(rc, message):
    if rc != SnapshotStatus.SNAPSHOT_OK:
        print(message, file=sys.stderr)
        logger.info("exit code: %d: %s", rc, message)


if __name__ == "__main__":
    set_up_logging()

    # Ensure that we get consistent output for parsing stdout/stderr and that we
    # are using the lvmdbusd profile.
    os.environ["LC_ALL"] = "C"
    os.environ["LVM_COMMAND_PROFILE"] = "lvmdbusd"

    parser = argparse.ArgumentParser(description="Snapshot Operations")

    # sub-parsers
    subparsers = parser.add_subparsers(dest="operation", help="Available operations")

    # sub-parser for 'snapshot'
    snapshot_parser = subparsers.add_parser("snapshot", help="Snapshot given VG/LVs")
    snapshot_parser.set_defaults(func=snapshot_cmd)
    snapshot_parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        default=False,
        dest="all",
        help="snapshot all VGs and LVs",
    )
    snapshot_parser.add_argument(
        "-vg",
        "--volumegroup",
        nargs="?",
        action="store",
        default=None,
        dest="volume_group",
        help="volume group to snapshot",
    )
    snapshot_parser.add_argument(
        "-lv",
        "--logicalvolume",
        nargs="?",
        action="store",
        default=None,
        dest="logical_volume",
        help="logical volume to snapshot",
    )
    # TODO: range check required space - setting choices to a range makes the help ugly.
    snapshot_parser.add_argument(
        "-r",
        "--requiredspace",
        dest="required_space",
        required=False,
        type=int,  # choices=range(10,100)
        default=20,
        help="percent of required space in the volume group to be reserved for snapshot",
    )
    snapshot_parser.add_argument(
        "-s",
        "--suffix",
        dest="suffix",
        type=str,
        help="suffix to add to volume name for snapshot",
    )
    snapshot_parser.add_argument(
        "-p",
        "--prefix",
        dest="prefix",
        type=str,
        help="prefix to add to volume name for snapshot",
    )

    # sub-parser for 'check'
    check_parser = subparsers.add_parser("check", help="Check space for given VG/LV")
    check_parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        default=False,
        dest="all",
        help="check all VGs and LVs",
    )
    check_parser.add_argument(
        "-v",
        "--verify",
        action="store_true",
        default=False,
        dest="verify",
        help="verify VGs and LVs have snapshots",
    )
    check_parser.add_argument(
        "-vg",
        "--volumegroup",
        nargs="?",
        action="store",
        default=None,
        dest="volume_group",
        help="volume group to check",
    )
    check_parser.add_argument(
        "-lv",
        "--logicalvolume",
        nargs="?",
        action="store",
        default=None,
        dest="logical_volume",
        help="logical volume to check",
    )
    # TODO: range check required space - setting choices to a range makes the help ugly.
    check_parser.add_argument(
        "-r",
        "--requiredspace",
        dest="required_space",
        default=20,
        required=False,
        type=int,  # choices=range(10,100),
        help="percent of required space in the volume group to be reserved for check",
    )
    check_parser.add_argument(
        "-s",
        "--suffix",
        dest="suffix",
        type=str,
        help="suffix to add to volume name for check - will verify no name conflicts",
    )
    check_parser.add_argument(
        "-p",
        "--prefix",
        dest="prefix",
        type=str,
        help="prefix to add to volume name for check - will verify no name conflicts",
    )
    check_parser.set_defaults(func=check_cmd)

    # sub-parser for 'clean'
    clean_parser = subparsers.add_parser("clean", help="Cleanup snapshots")
    clean_parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        default=False,
        dest="all",
        help="clean all VGs and LVs",
    )
    clean_parser.add_argument(
        "-v",
        "--verify",
        action="store_true",
        default=False,
        dest="verify",
        help="verify VG and LV snapshots have been cleaned",
    )
    clean_parser.add_argument(
        "-vg",
        "--volumegroup",
        nargs="?",
        action="store",
        default=None,
        dest="volume_group",
        help="volume group to cleanup/remove",
    )
    clean_parser.add_argument(
        "-lv",
        "--logicalvolume",
        nargs="?",
        action="store",
        default=None,
        dest="logical_volume",
        help="logical volume to cleanup/remove",
    )
    clean_parser.add_argument(
        "-s",
        "--suffix",
        dest="suffix",
        type=str,
        help="suffix to add to volume name for cleanup/remove",
    )
    clean_parser.add_argument(
        "-p",
        "--prefix",
        dest="prefix",
        type=str,
        help="prefix to add to volume name for cleanup/remove",
    )
    clean_parser.set_defaults(func=clean_cmd)

    args = parser.parse_args()
    return_code, display_message = args.func(args)
    print_result(return_code, display_message)

    sys.exit(return_code)
