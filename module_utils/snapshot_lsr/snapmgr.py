from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
from os.path import join as path_join
from ansible.module_utils.snapshot_lsr.consts import SnapshotStatus
from ansible.module_utils.snapshot_lsr.lvm import (
    verify_snapset_source_lvs_exist,
    snapshot_precheck_lv_set,
    extend_check_size,
    get_space_needed,
    get_current_space_state,
)
from ansible.module_utils.snapshot_lsr.utils import (
    DEV_PREFIX,
    mount_snapshot_set,
    umount_snapshot_set,
    lvm_get_vg_lv_from_devpath,
)

logger = logging.getLogger("snapshot-role")

snapshot_manager_imported = True

try:
    import snapm.manager as snap_manager
    import snapm
except ImportError:  # Snapshot Manager is not available.
    snapshot_manager_imported = False


SNAPM_DEFAULT_SIZE_POLICY = "20%SIZE"
SNAPM_MIN_VERSION = "0.4.0"


# NOTE: Because of PEP632, we cannot use distutils.
# In addition, because of the wide range of python
# versions we have to support, there isn't a good
# version parser across all of them, that is provided
# with Ansible.
def lsr_parse_version(v_str):
    v_ary = v_str.split(".")
    v = []
    for v_ary_str in v_ary:
        try:
            v.append(int(v_ary_str))
        except ValueError:
            v.append(0)
    return v


def use_snapshot_manager():

    if not snapshot_manager_imported or lsr_parse_version(
        snapm.__version__
    ) < lsr_parse_version(SNAPM_MIN_VERSION):
        return False

    return True


def mgr_get_snapshot_lv(module, origin_vg, origin_lv, snapshot_set):

    for snapshot in snapshot_set[0].snapshots:

        rc, message, origin_vg_name, origin_lv_name = lvm_get_vg_lv_from_devpath(
            module, snapshot.origin
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, None, None

        if origin_vg == origin_vg_name and origin_lv == origin_lv_name:
            return rc, message, snapshot.vg_name, snapshot.lv_name

    return (
        SnapshotStatus.ERROR_EXTEND_NOT_FOUND,
        "mgr_get_snapshot_lv failure",
        None,
        None,
    )


def mgr_extend_required(
    vg_name, lv_origin_name, snapshot_lv, percent_space_required, current_space_dict
):

    current_size = current_space_dict[vg_name].lvs[snapshot_lv].lv_size
    extent_size = current_space_dict[vg_name].vg_extent_size
    required_size = get_space_needed(
        vg_name, lv_origin_name, percent_space_required, current_space_dict
    )

    logger.debug(
        "current size: %d required size %d extent size: %d",
        current_size,
        required_size,
        extent_size,
    )
    if current_size >= required_size:
        return SnapshotStatus.SNAPSHOT_OK, "", False

    return SnapshotStatus.SNAPSHOT_OK, "", True


# Note: snapm extend command raises an exception when the lvs in the list
# are already at the requested state.  Check the source list and make
# sure it requires being extended.
def mgr_get_source_list_for_extend(module, volume_list, snapshot_set):

    source_list = list()
    logger.info("mgr_get_source_list_for_extend: %s", volume_list)
    logger.info(snapshot_set)

    rc, _message, current_space_dict = get_current_space_state(module)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, "mgr_extend_required failure", False

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]
        percent_space_required = list_item["percent_space_required"]

        rc, message, _snapshot_vg, snapshot_lv = mgr_get_snapshot_lv(
            module, vg, lv, snapshot_set
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, None

        rc, message, extend_required = mgr_extend_required(
            vg, lv, snapshot_lv, percent_space_required, current_space_dict
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            logger.error("mgr_extend_required error")
            return rc, message, None

        if extend_required:
            source_list.append(
                path_join(DEV_PREFIX, vg, lv) + ":" + percent_space_required + "%SIZE"
            )

    return rc, message, source_list


def mgr_get_source_list_for_create(volume_list):
    source_list = list()

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]
        percent_space_required = list_item["percent_space_required"]

        source_list.append(
            path_join(DEV_PREFIX, vg, lv) + ":" + percent_space_required + "%SIZE"
        )

    return source_list


def mgr_check_verify_set(manager, snapset_name):

    snapshot_set = manager.find_snapshot_sets(snapm.Selection(name=snapset_name))

    if not snapshot_set:
        return (
            SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED,
            "check verify: set does not exist",
            False,
        )

    return SnapshotStatus.SNAPSHOT_OK, "", False


def mgr_check_verify_lvs_set(manager, module, snapset_json):
    snapset_name = snapset_json["name"]
    logger.info("mgr_check_verify_lvs_set: %s", snapset_name)

    # Check to make sure all the source vgs/lvs exist
    rc, message = verify_snapset_source_lvs_exist(module, snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message, False

    # Verify that the set is created
    return mgr_check_verify_set(manager, snapset_name)


def mgr_snapshot_cmd(module, module_args, snapset_json):
    bootable = None
    snapset_name = snapset_json["name"]
    logger.info("mgr_snapshot_cmd: %s", snapset_name)
    changed = False
    message = ""
    check_mode = module_args["ansible_check_mode"]

    rc, message = verify_snapset_source_lvs_exist(module, snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return {"return_code": rc, "errors": message, "changed": changed}

    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]

    # Bootable gloabal varaible is set
    if module_args["snapshot_lvm_bootable"]:
        bootable = module_args["snapshot_lvm_bootable"]

    # Global is not set, check the snapset
    if bootable is None:
        if "bootable" in snapset_json:
            bootable = snapset_json["bootable"]
        else:
            bootable = False
    else:  # Global is set, check for conflict
        if (
            "bootable" in snapset_json
            and snapset_json["bootable"] is not None
            and bootable != snapset_json["bootable"]
        ):
            return {
                "return_code": SnapshotStatus.ERROR_BOOTABLE_CONFLICT,
                "errors": "Conflicting values for bootable",
                "changed": False,
            }

    source_list = mgr_get_source_list_for_create(volume_list)

    if check_mode:
        return {rc, "Would call function manager.create_snapshot_set()", False}

    manager = snap_manager.Manager()

    try:
        manager.create_snapshot_set(
            snapset_name,
            source_list,
            SNAPM_DEFAULT_SIZE_POLICY,
            boot=bootable,
        )
        changed = True
    except snapm.SnapmError as snap_err:
        # if the set already exists, return ok
        if not isinstance(snap_err, snapm.SnapmExistsError):
            rc = SnapshotStatus.ERROR_CREATE_FAILED
            message = "".join(snap_err.args)
    # Snapshot Manager should only raise SnapmError - there is a bug if an
    # Exception is raised
    except Exception as err:
        rc = SnapshotStatus.ERROR_SNAPM_INTERNAL_ERROR
        message = str(err)
        logger.error(message)

    return {"return_code": rc, "errors": message, "changed": changed}


def mgr_check_cmd(module, module_args, snapset_json):
    snapset_name = snapset_json["name"]
    logger.info("check_cmd: %s", snapset_name)

    if module_args["snapshot_lvm_verify_only"]:
        manager = snap_manager.Manager()
        rc, message, _changed = mgr_check_verify_lvs_set(manager, module, snapset_json)
    else:
        rc, message, _current_space_dict = snapshot_precheck_lv_set(
            module, snapset_json
        )

    return {"return_code": rc, "errors": message, "changed": False}


def mgr_remove_cmd(module_args, snapset_json):
    snapset_name = snapset_json["name"]
    logger.info("remove_cmd: %s", snapset_name)
    changed = False
    rc = SnapshotStatus.SNAPSHOT_OK
    message = ""
    check_mode = module_args["ansible_check_mode"]

    if check_mode:
        return {
            "return_code": rc,
            "errors": "Would run function " + " " + "manager.delete_snapshot_sets()",
            "changed": changed,
        }

    manager = snap_manager.Manager()
    snapshot_set = manager.find_snapshot_sets(snapm.Selection(name=snapset_name))
    if len(snapshot_set) == 0:
        return {"return_code": rc, "errors": message, "changed": changed}

    if module_args["snapshot_lvm_verify_only"]:
        if len(snapshot_set) != 0:
            return {
                "return_code": SnapshotStatus.ERROR_VERIFY_REMOVE_FAILED,
                "errors": "snapset exists",
                "changed": changed,
            }

    try:
        manager.delete_snapshot_sets(snapm.Selection(name=snapset_name))
        changed = True
    except snapm.SnapmError as snap_err:
        if not isinstance(snap_err, snapm.SnapmNotFoundError):
            message = "".join(snap_err.args)
            rc = SnapshotStatus.ERROR_REMOVE_FAILED
    # Snapshot Manager should only raise SnapmError - there is a bug if an
    # Exception is raised
    except Exception as err:
        rc = SnapshotStatus.ERROR_SNAPM_INTERNAL_ERROR
        message = str(err)
        logger.error(message)

    return {"return_code": rc, "errors": message, "changed": changed}


def mgr_get_percent_space_required(source_vg, source_lv, volume_list):

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]

        if vg == source_vg and lv == source_lv:
            return SnapshotStatus.SNAPSHOT_OK, "", list_item["percent_space_required"]

    return (
        SnapshotStatus.ERROR_EXTEND_NOT_FOUND,
        "source volume not found with name: " + source_vg + "/" + source_lv,
        0,
    )


def mgr_extend_verify_snapshot_set(module, manager, snapset_name, volume_list):
    rc = SnapshotStatus.SNAPSHOT_OK
    message = ""
    current_vg = ""
    snapshot_set = manager.find_snapshot_sets(snapm.Selection(name=snapset_name))

    for snapshot in snapshot_set[0].snapshots:

        if current_vg != snapshot.vg_name:
            current_vg = snapshot.vg_name

        rc, message, origin_vg_name, origin_lv_name = lvm_get_vg_lv_from_devpath(
            module, snapshot.origin
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, False

        rc, message, percent_space_required = mgr_get_percent_space_required(
            origin_vg_name, origin_lv_name, volume_list
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, False

        rc, message, _vg_name, snapshot_lv_name = lvm_get_vg_lv_from_devpath(
            module, snapshot.devpath
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, False

        rc, message, size_ok, _required_size = extend_check_size(
            module,
            origin_vg_name,
            origin_lv_name,
            snapshot_lv_name,
            percent_space_required,
        )

        if rc != SnapshotStatus.SNAPSHOT_OK:
            return rc, message, False

        if not size_ok:
            return (
                SnapshotStatus.ERROR_EXTEND_VERIFY_FAILED,
                "verify failed due to insufficient space for: "
                + origin_lv_name
                + "/"
                + origin_lv_name,
                False,
            )

    return rc, message, False


def mgr_extend_cmd(module, module_args, snapset_json):
    snapset_name = snapset_json["name"]
    logger.info("extend snapsset : %s", snapset_name)
    changed = False
    check_mode = module_args["ansible_check_mode"]

    manager = snap_manager.Manager()
    logger.info("snap_manager.Manager : %s", snapset_name)

    volume_list = snapset_json["volumes"]

    if module_args["snapshot_lvm_verify_only"]:
        rc, message, _changed = mgr_extend_verify_snapshot_set(
            module, manager, snapset_name, volume_list
        )
        return {"return_code": rc, "errors": message, "changed": False}

    snapshot_set = manager.find_snapshot_sets(snapm.Selection(name=snapset_name))
    logger.info(snapshot_set)

    rc, message, source_list = mgr_get_source_list_for_extend(
        module, volume_list, snapshot_set
    )

    logger.info("list for extend %s ", source_list)

    if rc != SnapshotStatus.SNAPSHOT_OK:
        return {"return_code": rc, "errors": message, "changed": False}

    if check_mode:
        return {
            rc,
            "Would run function "
            + " manager.resize_snapshot_set() with ".join(source_list),
        }

    # there are no LVs that require an extend operation, return OK.
    if len(source_list) == 0:
        return {"return_code": rc, "errors": "source list emmpty", "changed": changed}

    try:
        manager.resize_snapshot_set(source_list, snapset_name)
        changed = True
    except snapm.SnapmError as snap_err:
        message = "".join(snap_err.args)
        if message == "lvresize failed with: No size change":
            rc = SnapshotStatus.SNAPSHOT_OK
    # Snapshot Manager should only raise SnapmError - there is a bug if an
    # Exception is raised
    except Exception as err:
        rc = SnapshotStatus.ERROR_SNAPM_INTERNAL_ERROR
        message = str(err)
        logger.error(message)
    return {"return_code": rc, "errors": message, "changed": changed}


def mgr_revert_cmd(module_args, snapset_json):
    snapset_name = snapset_json["name"]
    logger.info("extend snapsset : %s", snapset_name)
    changed = False
    rc = SnapshotStatus.SNAPSHOT_OK
    message = ""
    check_mode = module_args["ansible_check_mode"]

    if check_mode:
        return {
            rc,
            "Would run function "
            + " manager.revert_snapshot_set with ".join(snapset_name),
        }

    manager = snap_manager.Manager()
    try:
        manager.revert_snapshot_set(snapset_name)
        changed = True
    except snapm.SnapmError as snap_err:
        # Ignore not found errors - the snapset has already benn reverted
        if not isinstance(snap_err, snapm.SnapmNotFoundError):
            message = str(snap_err)
    # Snapshot Manager should only raise SnapmError - there is a bug if an
    # Exception is raised
    except Exception as err:
        rc = SnapshotStatus.ERROR_SNAPM_INTERNAL_ERROR
        message = str(err)
        logger.error(message)

    return {"return_code": rc, "errors": message, "changed": changed}


def mgr_mount_cmd(module, module_args, snapset_json):
    snapset_name = snapset_json["name"]
    logger.info(
        "mount_cmd: %s %d %d %d %s ",
        snapset_name,
        module_args["snapshot_lvm_verify_only"],
        module_args["snapshot_lvm_mountpoint_create"],
        module_args["ansible_check_mode"],
        snapset_json,
    )

    manager = snap_manager.Manager()
    snapshot_set = manager.find_snapshot_sets(snapm.Selection(name=snapset_name))

    if snapshot_set is None or len(snapshot_set) == 0:
        return {
            "return_code": SnapshotStatus.ERROR_MOUNT_FAILED,
            "errors": "snnapshot not found:" + snapset_name,
            "changed": False,
        }

    rc, message, changed = mount_snapshot_set(
        module,
        snapset_json,
        module_args["snapshot_lvm_verify_only"],
        module_args["snapshot_lvm_mountpoint_create"],
        module_args["ansible_check_mode"],
        True,
        snapshot_set[0].snapshots,
    )

    return {"return_code": rc, "errors": message, "changed": changed}


def mgr_umount_cmd(module, module_args, snapset_json):
    snapset_name = snapset_json["name"]
    logger.info(
        "umount_cmd: %s %d %s %s",
        snapset_name,
        module_args["ansible_check_mode"],
        module_args["snapshot_lvm_mountpoint"],
        snapset_json,
    )

    manager = snap_manager.Manager()
    snapshot_set = manager.find_snapshot_sets(snapm.Selection(name=snapset_name))

    if snapshot_set is None or len(snapshot_set) == 0:
        return {
            "return_code": SnapshotStatus.ERROR_MOUNT_FAILED,
            "errors": "snnapshot not found:" + snapset_name,
            "changed": False,
        }

    rc, message, changed = umount_snapshot_set(
        module,
        snapset_json,
        module_args["snapshot_lvm_verify_only"],
        module_args["ansible_check_mode"],
        True,
        snapshot_set[0].snapshots,
    )

    return {"return_code": rc, "errors": message, "changed": changed}
