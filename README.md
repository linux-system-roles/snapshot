# linux-system-roles/snapshot

[![ansible-lint.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/ansible-lint.yml) [![ansible-test.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/ansible-test.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/ansible-test.yml) [![codeql.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/codeql.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/codeql.yml) [![integration.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/integration.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/integration.yml) [![markdownlint.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/markdownlint.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/markdownlint.yml) [![python-unit-test.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/python-unit-test.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/python-unit-test.yml) [![shellcheck.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/shellcheck.yml) [![woke.yml](https://github.com/linux-system-roles/snapshot/actions/workflows/woke.yml/badge.svg)](https://github.com/linux-system-roles/snapshot/actions/workflows/woke.yml) [![Coverage Status](https://coveralls.io/repos/github/linux-system-roles/snapshot/badge.svg)](https://coveralls.io/github/linux-system-roles/snapshot) [![Code Style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black) [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/linux-system-roles/snapshot.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/linux-system-roles/snapshot/context:python)


![template](https://github.com/linux-system-roles/snapshot/workflows/tox/badge.svg)


The `snapshot` role enables users to add/remove snapshots on target machines.
This role can be used to configure snapshots via:

- LVM

## Requirements

Any prerequisites that may not be covered by Ansible itself or the role should
be mentioned here.  This includes platform dependencies not managed by the
role, hardware requirements, external collections, etc.  There should be a
distinction between *control node* requirements (like collections) and
*managed node* requirements (like special hardware, platform provisioning).

### Collection requirements

For instance, if the role depends on some collections and
has a `meta/collection-requirements.yml` file for installing those
dependencies, it should be mentioned here that the user should run

```bash
ansible-galaxy collection install -vv -r meta/collection-requirements.yml
```

on the *control node* before using the role.

## Role Variables

A description of all input variables (i.e. variables that are defined in
`defaults/main.yml`) for the role should go here as these form an API of the
role.  Each variable should have its own section e.g.

### template_foo

This variable is required.  It is a string that lists the foo of the role.
There is no default value.

### template_bar

This variable is optional.  It is a boolean that tells the role to disable bar.
The default value is `true`.

Variables that are not intended as input, like variables defined in
`vars/main.yml`, variables that are read from other roles and/or the global
scope (ie. hostvars, group vars, etc.) can be also mentioned here but keep in
mind that as these are probably not part of the role API they may change during
the lifetime.

Example of setting the variables:

```yaml
template_foo: "oof"
template_bar: false
```

## Variables Exported by the Role

This section is optional.  Some roles may export variables for playbooks to
use later.  These are analogous to "return values" in Ansible modules.  For
example, if a role performs some action that will require a system reboot, but
the user wants to defer the reboot, the role might set a variable like
`template_reboot_needed: true` that the playbook can use to reboot at a more
convenient time.

Example:

### template_reboot_needed

Default `false` - if `true`, this means a reboot is needed to apply the changes
made by the role

## Example Playbook

Including an example of how to use your role (for instance, with variables
passed in as parameters) is always nice for users too:

```yaml
- name: Manage the snapshot subsystem
  hosts: all
  vars:
    snapshot_foo: "foo foo!"
    snapshot_bar: false
  roles:
    - linux-system-roles.snapshot
```

More examples can be provided in the [`examples/`](examples) directory. These
can be useful, especially for documentation.

## License

Whenever possible, please prefer MIT.

## Author Information

An optional section for the role authors to include contact information, or a
website (HTML is not allowed).
