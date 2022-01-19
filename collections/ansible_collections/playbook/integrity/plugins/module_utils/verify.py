
import os
import subprocess
import ansible_collections.playbook.integrity.plugins.module_utils.common as common


class Verifier:
    def __init__(self, params):
        self.type = params.get("type", "")
        self.target = params.get("target", "")
        self.signature_type = params.get("signature_type", "gpg")
        self.public_key = params.get("public_key", "")
        self.keyless_signer_id = params.get("keyless_signer_id", "")

    def verify(self):
        result = {}
        if self.type == common.TYPE_PLAYBOOK:
            result = self.verify_playbook()
        else:
            raise ValueError("type must be one of [{}]".format([common.TYPE_PLAYBOOK]))
        return result

    def verify_playbook(self):
        result = {"failed": False}
        digester = common.Digester(self.target)
        result["digest_result"] = digester.check()
        if result["digest_result"]["returncode"] != 0:
            result["failed"] = True
            return result

        if self.signature_type == common.SIGNATURE_TYPE_GPG:
            result["verify_result"] = self.verify_gpg(self.target, common.SIGNATURE_FILENAME_GPG, self.public_key)
        elif self.signature_type in [common.SIGNATURE_TYPE_SIGSTORE, common.SIGNATURE_TYPE_SIGSTORE_KEYLESS]:
            keyless = True if self.signature_type == common.SIGNATURE_TYPE_SIGSTORE_KEYLESS else False
            type = common.SIGSTORE_TARGET_TYPE_FILE
            result["verify_result"] = self.verify_sigstore(self.target, target_type=type, keyless=keyless)
        else:
            raise ValueError("this signature type is not supported: {}".format(self.signature_type))
        if result["verify_result"]["returncode"] != 0:
            result["failed"] = True
            return result

        return result

    def verify_gpg(self, path, sigfile, publickey=""):
        if not os.path.exists(path):
            raise ValueError("the directory \"{}\" does not exists".format(path))

        if not os.path.exists(os.path.join(path, sigfile)):
            raise ValueError("signature file \"{}\" does not exists in path \"{}\"".format(sigfile, path))
        
        gpghome_option = ""
        keyring_option = ""
        if publickey != "":
            try:
                os.makedirs(common.TMP_GNUPG_HOME_DIR)
            except Exception:
                pass
            gpghome_option = "GNUPGHOME={}".format(common.TMP_GNUPG_HOME_DIR)
            keyring_option = "--no-default-keyring --keyring {}".format(publickey)
        cmd = "cd {}; {} gpg --verify {} {}".format(path, gpghome_option, keyring_option, sigfile)
        result = common.execute_command(cmd)
        return result

    def verify_sigstore(self, target, target_type=common.SIGSTORE_TARGET_TYPE_FILE, keyless=False):
        result = None
        if target_type == common.SIGSTORE_TARGET_TYPE_FILE:
            result = self.verify_sigstore_file(self.target, keyless=keyless, msgfile=common.DIGEST_FILENAME, sigfile=common.SIGNATURE_FILENAME_SIGSTORE)
        else:
            raise ValueError("this target type \"{}\" is not supported for sigstore signing".format(target_type))
        return result

    def verify_sigstore_file(self, path, keyless=False, msgfile=common.DIGEST_FILENAME, sigfile=common.SIGNATURE_FILENAME_SIGSTORE):
        if not os.path.exists(path):
            raise ValueError("the directory \"{}\" does not exists".format(path))

        if not os.path.exists(os.path.join(path, sigfile)):
            raise ValueError("signature file \"{}\" does not exists in path \"{}\"".format(sigfile, path))
        
        cosign_cmd = common.get_cosign_path()
        experimental_option=""
        key_option = ""
        if keyless:
            experimental_option = "COSIGN_EXPERIMENTAL=1"
        else:
            key_option = "--key {}".format(self.public_key)
        cmd = "cd {}; {} {} verify-blob {} --signature {} {}".format(path, experimental_option, cosign_cmd, key_option, sigfile, msgfile)
        result = common.execute_command(cmd)
        return result