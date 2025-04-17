import logging
from os.path import join as path_join
from consts import SnapshotStatus
from lvm import verify_snapset_source_lvs_exist, check_verify_lvs_set, snapshot_precheck_lv_set, DEV_PREFIX
from utils import compare_source_lists
from packaging.version import Version

logger = logging.getLogger("snapshot-role")

snapshot_manager_available = True

try:
    import snapm.manager as snap_manager
    import snapm
except ImportError: # Snapshot Manger is not available.
    snapshot_manager_available = False


SNAPM_DEFAULT_SIZE_POLICY = "20%SIZE"
SNAPM_MIN_VERSION = "0.4.0"

def use_snapshot_manager():
    global snapshot_manager_available
    if Version(snapm.__version__) < Version(SNAPM_MIN_VERSION):
        return False
    snapshot_manager_available = False
    return snapshot_manager_available

def get_source_list(volume_list):

    source_list = list()

    for list_item in volume_list:
        vg = list_item["vg"]
        lv = list_item["lv"]
        percent_space_required = list_item["percent_space_required"]
        source_list.append(path_join(DEV_PREFIX, vg, lv) + ":" + percent_space_required + "%SIZE")
    
    return source_list

def mgr_check_verify_set_matches(manager, snapset_name, volume_list):
    rc = SnapshotStatus.SNAPSHOT_OK
    message = ""

    snapshot_set = manager.find_snapshot_sets(snapm.Selection(name=snapset_name))

    if not snapshot_set:
        return SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED, "check verify: set does not exist"

    print(snapshot_set[0].devices)

    if compare_source_lists(snapshot_set[0].devices, volume_list):
        return SnapshotStatus.ERROR_VERIFY_COMMAND_FAILED, "snapshot sets contain different origins"

    return {"return_code": rc, "errors": message, "changed": False}


def mgr_check_verify_lvs_set(manager, module, snapset_json):
    snapset_name = snapset_json["name"]
    logger.info("mgr_check_verify_lvs_set: %s", snapset_name)
    volume_list = snapset_json["volumes"]
    logger.info("check snapsset : %s", snapset_name)

    # Check to make sure all the source vgs/lvs exist
    rc, message = verify_snapset_source_lvs_exist(module, snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message

    # Verify that the set is created
    return mgr_check_verify_set_matches(manager, snapset_name, volume_list)



def mgr_snapshot_cmd(module, module_args, snapset_json):
    snapset_name = snapset_json["name"]
    logger.info("mgr_snapshot_cmd: %s", snapset_name)
    
    changed = False
    rc = SnapshotStatus.SNAPSHOT_OK
    message = ""
    check_mode = module_args["ansible_check_mode"]


    rc, message = verify_snapset_source_lvs_exist(module, snapset_json)
    if rc != SnapshotStatus.SNAPSHOT_OK:
        return rc, message, changed
    
    snapset_name = snapset_json["name"]
    volume_list = snapset_json["volumes"]

    source_list = get_source_list(volume_list)

    if check_mode:
        return rc, "Would call function manager.create_snapshot_set()"
    
    manager = snap_manager.Manager()

    try:
        manager.create_snapshot_set(snapset_name , source_list, SNAPM_DEFAULT_SIZE_POLICY)
        changed = True
    except snapm.SnapmError as snap_err:
        # if the set already exists, return ok
        if not isinstance(snap_err, snapm.SnapmExistsError):
            rc = SnapshotStatus.ERROR_CREATE_FAILED
            message = ''.join(snap_err.args)

    return {"return_code": rc, "errors": message, "changed": changed}


def mgr_check_cmd(module, module_args, snapset_json):
    snapset_name = snapset_json["name"]
    logger.info("check_cmd: %s", snapset_name)

    if module_args["snapshot_lvm_verify_only"]:
        manager = snap_manager.Manager()
        rc, message = mgr_check_verify_lvs_set(manager, module, snapset_json)
    else:
        rc, message, _current_space_dict = snapshot_precheck_lv_set(
            module, snapset_json
        )

    return {"return_code": rc, "errors": message, "changed": False}

def mgr_remove_cmd(module_args, snapset_json):
    changed = False
    rc = SnapshotStatus.SNAPSHOT_OK
    message = ""
    check_mode = module_args["ansible_check_mode"]
    
    if check_mode:
        return rc, "Would run command " + " " + "manager.delete_snapshot_sets()"

    snapset_name = snapset_json["name"]
    manager = snap_manager.Manager()

    try:
        manager.delete_snapshot_sets(snapm.Selection(name=snapset_name))
    except snapm.SnapmError as snap_err:
        if not isinstance(snap_err, snapm.SnapmNotFoundError):
            message = ''.join(snap_err.args)
            rc = SnapshotStatus.ERROR_REMOVE_FAILED

    return {"return_code": rc, "errors": message, "changed": changed}



def mgr_extend_cmd(module_args, snapset_json):
    snapset_name = snapset_json["name"]
    logger.info("extend snapsset : %s", snapset_name)
    changed = False
    rc = SnapshotStatus.SNAPSHOT_OK
    message = ""
    check_mode = module_args["ansible_check_mode"]

    volume_list = snapset_json["volumes"]
    source_list = get_source_list(volume_list)

    if check_mode:
        return rc, "Would run command " + " manager.resize_snapshot_set() with ".join(source_list)

    snapset_name = snapset_json["name"]
    manager = snap_manager.Manager()

    try:
        manager.resize_snapshot_set(source_list, snapset_name)
    except snapm.SnapmError as snap_err:
        message = ''.join(snap_err.args)

    return {"return_code": rc, "errors": message, "changed": changed}

def mgr_revert_cmd(module_args, snapset_json):
    changed = False
    rc = SnapshotStatus.SNAPSHOT_OK
    message = ""
    check_mode = module_args["ansible_check_mode"]

    snapset_name = snapset_json["name"]    
    if check_mode:
        return rc, "Would run command " + " manager.revert_snapshot_set with ".join(snapset_name)

    manager = snap_manager.Manager()
    try:
        manager.revert_snapshot_set(snapset_name)
    except snapm.SnapmError as snap_err:
        # Ignore not found errors - the snapset has already benn reverted
        if not isinstance(snap_err, snapm.SnapmNotFoundError):
            message = ''.join(snap_err.args)

    return {"return_code": rc, "errors": message, "changed": changed}

