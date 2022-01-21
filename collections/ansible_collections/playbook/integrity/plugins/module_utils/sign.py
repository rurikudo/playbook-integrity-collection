
import os
import ansible_collections.playbook.integrity.plugins.module_utils.common as common


class Signer:
    def __init__(self, params):
        self.type = params.get("type", "")
        self.target = params.get("target", "")
        if self.target.startswith("~/"):
            self.target = os.path.expanduser(self.target)
        self.signature_type = params.get("signature_type", "gpg")
        self.private_key = params.get("private_key", "")
        self.public_key = params.get("public_key", "")
        self.keyless_signer_id = params.get("keyless_signer_id", "")

    def sign(self):
        result = {}
        if self.type == common.TYPE_PLAYBOOK:
            result = self.sign_playbook()
        else:
            raise ValueError("type must be one of [{}]".format([common.TYPE_PLAYBOOK]))
        return result

    def sign_playbook(self):
        result = {"failed": False}
        digester = common.Digester(self.target)
        result["digest_result"] = digester.gen()
        if result["digest_result"]["returncode"] != 0:
            result["failed"] = True
            return result

        if self.signature_type == common.SIGNATURE_TYPE_GPG:
            sig_file = os.path.join(self.target, common.SIGNATURE_FILENAME_GPG)
            if os.path.exists(sig_file):
                os.remove(sig_file) # remove privious signature before signing
            result["sign_result"] = self.sign_gpg(self.target, common.DIGEST_FILENAME)
        elif self.signature_type in [common.SIGNATURE_TYPE_SIGSTORE, common.SIGNATURE_TYPE_SIGSTORE_KEYLESS]:
            keyless = True if self.signature_type == common.SIGNATURE_TYPE_SIGSTORE_KEYLESS else False
            type = common.SIGSTORE_TARGET_TYPE_FILE
            result["sign_result"] = self.sign_sigstore(self.target, target_type=type, keyless=keyless, filename=common.DIGEST_FILENAME)
        else:
            raise ValueError("this signature type is not supported: {}".format(self.signature_type))
        if result["sign_result"]["returncode"] != 0:
            result["failed"] = True
            return result

        return result

    def sign_gpg(self, path, filename):
        if self.private_key != "":
            raise ValueError("using a specific private key is not supported yet")

        if not os.path.exists(path):
            raise ValueError("the directory \"{}\" does not exists".format(path))

        cmd = "cd {}; gpg --detach-sign {}".format(path, filename)
        result = common.execute_command(cmd)
        return result

    def sign_sigstore(self, target, target_type=common.SIGSTORE_TARGET_TYPE_FILE, keyless=False, filename=common.DIGEST_FILENAME):
        result = None
        if target_type == common.SIGSTORE_TARGET_TYPE_FILE:
            result = self.sign_sigstore_file(self.target, filename=filename, keyless=keyless)
        else:
            raise ValueError("this target type \"{}\" is not supported for sigstore signing".format(target_type))
        return result
    
    def sign_sigstore_file(self, path, filename, keyless=False, sigfile=common.SIGNATURE_FILENAME_SIGSTORE):
        if not os.path.exists(path):
            raise ValueError("the directory \"{}\" does not exists".format(path))
        
        cosign_cmd = common.get_cosign_path()
        output_option = "--output-signature {}".format(sigfile)
        experimental_option=""
        key_option = ""
        idtoken_option = ""
        if keyless:
            experimental_option = "COSIGN_EXPERIMENTAL=1"
            idtoken_option = "--identity-token {}".format(self.keyless_signer_id)
        else:
            key_option = "--key {}".format(self.private_key)

        cmd = "cd {}; {} {} sign-blob {} {} {} {}".format(path, experimental_option, cosign_cmd, key_option, idtoken_option, output_option, filename)
        result = common.execute_command(cmd)
        return result        


