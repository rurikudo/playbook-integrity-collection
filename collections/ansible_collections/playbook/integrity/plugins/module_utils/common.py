
import os
import platform
import subprocess


TYPE_PLAYBOOK = "playbook"

SIGNATURE_TYPE_GPG = "gpg"
SIGNATURE_TYPE_SIGSTORE = "sigstore"
SIGNATURE_TYPE_SIGSTORE_KEYLESS = "sigstore_keyless"

SIGSTORE_TARGET_TYPE_FILE = "file"

SCM_TYPE_GIT = "git"

DIGEST_FILENAME = "sha256sum.txt"
SIGNATURE_FILENAME_GPG = "sha256sum.txt.gpg"
SIGNATURE_FILENAME_SIGSTORE = "sha256sum.txt.sig"

CHECKSUM_OK_IDENTIFIER = ": OK"
TMP_GNUPG_HOME_DIR = "/tmp/gpghome"
TMP_COSIGN_PATH = "/tmp/cosign"

class Digester:
    def __init__(self, path):
        self.path = path
        self.type = self.get_scm_type(path)

    # TODO: implement this
    def get_scm_type(self, path):
        return SCM_TYPE_GIT

    def gen(self):
        result = None
        if self.type == SCM_TYPE_GIT:
            result = self.gen_git()
        else:
            raise ValueError("this SCM type is not supported: {}".format(self.type))
        return result
    
    def check(self):
        tmp_check_out = "/tmp/digest_check_output.txt"
        cmd = "cd {}; sha256sum --check {} > {} 2>&1".format(self.path, DIGEST_FILENAME, tmp_check_out)
        result = execute_command(cmd)
        if result["returncode"] != 0:
            check_out_str = ""
            with open(tmp_check_out, "r") as f:
                check_out_str = f.read()
            err_str = result["stderr"]
            for line in check_out_str.splitlines():
                if CHECKSUM_OK_IDENTIFIER in line:
                    continue
                err_str = "{}{}\n".format(err_str, line)
            result["stderr"] = err_str
        return result

    def gen_git(self):
        cmd1 = "cd {}; git ls-tree -r HEAD --name-only | grep -v {}".format(self.path, DIGEST_FILENAME)
        result = execute_command(cmd1)
        if result["returncode"] != 0:
            return result
        raw_fname_list = result["stdout"]
        fname_list = ""
        for line in raw_fname_list.splitlines():
            fpath = os.path.join(self.path, line)
            if os.path.islink(fpath):
                continue
            fname_list = "{}{}\n".format(fname_list, line)
        tmp_fname_list_file = "/tmp/fname_list.txt"
        with open(tmp_fname_list_file, "w") as f:
            f.write(fname_list)
        cmd2 = "cd {}; cat {} | xargs sha256sum > {}".format(self.path, tmp_fname_list_file, DIGEST_FILENAME)
        result = execute_command(cmd2)
        return result

def result_object_to_dict(obj):
    if not isinstance(obj, subprocess.CompletedProcess):
        return {}
    
    return dict(
        returncode=obj.returncode,
        stdout=obj.stdout,
        stderr=obj.stderr,
    )

def execute_command(cmd="", env_params=None, timeout=None):
    env = None
    if env_params is not None:
        env = os.environ.copy()
        env.update(env_params)
    result = subprocess.run(
            cmd, shell=True, env=env, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result_object_to_dict(result)


def get_cosign_path():
    cmd1 = "command -v cosign"
    result = execute_command(cmd1)
    if result["returncode"] == 0:
        return "cosign"

    if os.path.exists(TMP_COSIGN_PATH):
        return TMP_COSIGN_PATH

    os_name = platform.system().lower()
    machine = platform.uname().machine
    arch = "unknown"
    if machine == "x86_64":
        arch = "amd64"
    elif machine == "aarch64":
        arch = "arm64"
    elif machine == "ppc64le":
        arch = "ppc64le"
    elif machine == "s390x":
        arch = "s390x"
    else:
        arch = machine

    cmd2 = "curl -sL -o {} https://github.com/sigstore/cosign/releases/download/v1.4.1/cosign-{}-{}".format(TMP_COSIGN_PATH, os_name, arch)
    result = execute_command(cmd2)
    if result["returncode"] == 0:
        cmd3 = "{} initialize".format(TMP_COSIGN_PATH)
        execute_command(cmd3)
        return TMP_COSIGN_PATH
    else:
        raise ValueError("failed to install cosign command; {}".format(result["stderr"]))
