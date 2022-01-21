## What's this?

This is a Ansible collection to sign / verify Ansible playbook repository.
You can sign your own playbooks and roles, and also verify them by calling this module in a playbook.
This is useful for checking playbook file integrity before calling them.

## Usage

```
# sign
$ ansible-playbook playbooks/sign-playbook.yml -e target=<PATH/TO/REPO>

$ verify
$ ansible-playbook playbooks/verify-playbook.yml -e target=<PATH/TO/REPO>
```
