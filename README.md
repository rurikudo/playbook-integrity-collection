## What's this?

This is an Ansible collection to sign / verify playbooks and roles in a SCM repository.
You can sign your own playbooks and roles, and also verify them by calling this module in a playbook.
This is useful for checking playbook file integrity before actual PlaybookRun.

## Usage

```
# sign
$ ansible-playbook playbooks/sign-playbook.yml -e repo=<PATH/TO/REPO>

$ verify
$ ansible-playbook playbooks/verify-playbook.yml -e repo=<PATH/TO/REPO>
```
