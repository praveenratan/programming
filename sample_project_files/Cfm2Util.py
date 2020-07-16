'''
High level API module
'''

import allure
from liquidsec.lib.app import App
from liquidsec.lib.linux_utils import duplicate_device
from common.logger import MtafLogger
from common.utils import utils
from liquidsec.utils import liquidsec_exception
from liquidsec.api.base_hapi import Meta

LOG = MtafLogger.get_logger(__name__)


class Cfm2Util(metaclass=Meta):
    '''
    High levle API class for Cfm2Util application
    '''

    def __init__(self, device):
        self.device = device
        self.cfm2util = App(self.device, "Cfm2Util")
        self.error_list = list()
        self.trace = list()
        self.trace_func = list()
        self.func_pass = list()

    def login_hsm(self, *args, force=True, **kwargs):
        '''
        Login to the HSM providing the user type and password.
        :param force: If force is set to True then logoutHSM will be
                      performed in case of loginHSM fails
                      logoutHSM possible expected Errors:
                      '0xa0': RET_USER_NOT_LOGGED_IN(No user is logged in
                                                     to do this operation)
                      '0x82': RET_INVALID_COMMAND(Invalid command in the
                                                  current state/configuration)
        :param username:
            specifies the user name
        :param usertype:
            specifies the user type as "CO" or "CU" or "AU"or "PO/PRECO"
        :param password:
            specifies the user password
        :param possession_factor:
            specifies intention to use possession factor
        :param  fakey:
            specifies the key used for 2FA network
        :param faport:
            specifies the port used for 2FA network
        :param facert:
            specifies the certificate used for 2FA network
        :param pek_path:
            specifies the path where PEK is stored(Optional)
        :return: TextFSM parsed output from loginHSM low level API
        '''
        with allure.step('Logging in to HSM with {}'.format(kwargs)):
            output = self.cfm2util.loginHSM(*args, **kwargs[self.function_name])

            with allure.step('verifying the login status'):
                login_status = self.login_status(*args, **kwargs)
                expected_utype = kwargs[self.function_name]["usertype"]
                actual_usertype = login_status['UserType']
                if (expected_utype == "PRECO" and actual_usertype == "Pre-CO"):
                    expected_utype = "Pre-CO"

                utils.validate([actual_usertype, f'== {expected_utype}', 'same user type is'
                                                                         'logged in'])
        return output

    def login_default(self, *args, force=True, **kwargs):
        '''
        Login to the HSM with default CO credentials, when HSM is not
        yet initialized.
        :param force: If force is set to True then logoutHSM will be
                      performed in case of loginHSM fails
                      logoutHSM possible expected Errors:
                      '0xa0': RET_USER_NOT_LOGGED_IN(No user is logged in
                                                     to do this operation)
                      '0x82': RET_INVALID_COMMAND(Invalid command in the
                                                  current state/configuration)
        :return output:
            TextFSM parsed output from loginHSM low level API
        '''
        with allure.step('Logging in to HSM with {}'.format(kwargs[self.function_name])):

            output = self.cfm2util.loginHSM(username="cavium", password="default", usertype="CO")

            with allure.step('verifying the login status'):
                login_status = self.cfm2util.loginStatus(*args, **kwargs)
                expected_utype = "Default CO"
                actual_usertype = login_status['UserType']
                utils.validate([actual_usertype, f'== {expected_utype}', 'same user type is'
                                                                         'logged in'])
        return output

    def zeroize_hsm(self, *args, force=True, **kwargs):
        '''
        zeroize the HSM
        :param force: If force is set to True
                      1> login to the HSM if CO credentials are provided
                      2> if Cfm2Util sessions exists, close partition Sessions
                      loginHSM possible expected Errors Excluded:
                      '0x9f': RET_USER_ALREADY_LOGGED_IN(This type of user has already logged in)
        :param factory_reset:
            Zeroize the partition and removes the partition certificates and
            re-generates new ones for the current FIPS state
        :return output:
            TextFSM parsed output from zeroize_hsm low level API
        '''
        with allure.step('zerozie_hsm'):
            if force is True:
                try:
                    output = self.cfm2util.zeroizeHSM(*args, **kwargs[self.function_name])
                except liquidsec_exception.RET_SESSION_EXISTS as Error:
                    part_info = self.get_partition_info(*args, **kwargs)
                    if part_info["FIPSstate"] == "-1 [zeroized]":
                        dup_device = duplicate_device(self.device)
                        kill_sessions = dup_device.execute(
                                        'ps -ef | grep -i "/[C]fm2Util" | awk \'{print $2}\'')
                        for session in kill_sessions.split():
                            dup_device.execute("kill -s SIGTERM {}".format(session))
                        dup_device.disconnect()

                        self.device.disconnect()
                        self.device.connect()
                        output = self.cfm2util.zeroizeHSM(*args, **kwargs[self.function_name])
                    else:
                        raise Error
            else:
                output = self.cfm2util.zeroizeHSM(*args, **kwargs[self.function_name])

            with allure.step('getPartitionInfo after zeroizeHSM'):
                partition_info = self.get_partition_info(*args, **kwargs)
                actual_fips = partition_info["FIPSstate"]
                total_users = partition_info["MaxUsers"]
                actual_users = partition_info["AvailableUsers"]
                OccupiedSessionKeys = partition_info["OccupiedSessionKeys"]
                OccupiedTokenKeys = partition_info["OccupiedTokenKeys"]
                CertAuth = partition_info["CertAuth"]
                CloningMethod = partition_info["CloningMethod"]
                BlockDeleteUserWithKeys = partition_info["BlockDeleteUserWithKeys"]
                Exportwithuserkeys = partition_info["Exportwithuserkeys"]
                GroupID = partition_info["GroupID"]
                HungAcclrDevCount = partition_info["HungAcclrDevCount"]
                KekMethod = partition_info["KekMethod"]
                KeyExport = partition_info["KeyExport"]
                KeyImport = partition_info["KeyImport"]
                Nvalue = partition_info["Nvalue"]
                MCObackuprestore = partition_info["MCObackuprestore"]
                MValueAUDITMGMT = partition_info["MValueAUDITMGMT"]
                MValueBACKUPBYCO = partition_info["MValueBACKUPBYCO"]
                MValueCLONING = partition_info["MValueCLONING"]
                MValueUSERMGMT = partition_info["MValueUSERMGMT"]
                MinPswdLen = partition_info["MinPswdLen"]
                MaxPswdLen = partition_info["MaxPswdLen"]
                NodeID = partition_info["NodeID"]
                AuditLogs = partition_info["AuditLogs"]
                AuditLogStatus = partition_info["AuditLogStatus"]
                TwoKeyBackup = partition_info["TwoKeyBackup"]
                OccupiedSSLCtxs = partition_info["OccupiedSSLCtxs"]
                expected_PCOfkey = kwargs[self.function_name].get("PCOfixedkeyfingerprint")
                SessionCount = partition_info["SessionCount"]
                status = partition_info["status"]
                verify_z = list()
                verify_z.append([[actual_fips, "== -1 [zeroized]", 'fips state after zerozieHSM'],
                                [int(actual_users), f"== 1024", 'Number of users available to'
                                                                'create'],
                                [int(OccupiedSessionKeys), f"== 0", 'OccupiedSesssionKeys after'
                                                                    'zerozieHSM'],
                                [int(OccupiedTokenKeys), f"== 0", 'OccupiedTokenKeys after'
                                                                  'zerozieHSM'],
                                [status, "== occupied", 'partition Status'],
                                [int(total_users), "== 1024", "max Users"],
                                [int(OccupiedSSLCtxs), "== 0", "occupied ssl contexts"],
                                [int(HungAcclrDevCount), "== 0", "HungAcclerDevCount"],
                                [int(SessionCount), "== 1", "Session Count"],
                                [int(MaxPswdLen), "== 32", "max password length"],
                                [int(MinPswdLen), "== 7", "min password length"],
                                [CloningMethod, "== ECDH", "cloning method"],
                                [int(KekMethod), "== 0", "KEK Method"],
                                [int(CertAuth), "== 0", "certificate Authentication"],
                                [int(TwoKeyBackup), "== 0", "TwoKeyBackup"],
                                [int(BlockDeleteUserWithKeys), "== 0", "BlockDeleteUserWithKeys"],
                                [int(Nvalue), "== 0", "Nvalue"],
                                [KeyImport, "== Enabled", "KeyImport"],
                                [KeyExport, "== Enabled", "KeyExport"],
                                [int(MValueBACKUPBYCO), "== 0", "MValue[BACKUP_BY_CO]"],
                                [int(MValueCLONING), "== 0", "MValue[CLONING] "],
                                [int(MValueUSERMGMT), "== 0", "MValue[USER_MGMT] "],
                                [int(MValueAUDITMGMT), "== 0", "MValue[AUDIT_MGMT] "],
                                [int(NodeID), "== 0", "NodeId"],
                                [GroupID, "== group0", "GroupId"],
                                [Exportwithuserkeys, "in [Disabled, Enabled]", 'Exportwithuserkeys'
                                                                               'Status'],
                                [MCObackuprestore, "in [Disabled, Enabled]", 'MCObackuprestore'
                                                                             'Status'],
                                [AuditLogs, "in [Enabled, Disabled]", "AuditLog Setting"],
                                [AuditLogStatus, "in [Disabled, Not Finalized]",
                                 "AuditLog Status"]])
                if expected_PCOfkey:
                    actual_PCOfkey = partition_info["PCOfixedkeyfingerprint"]
                    verify_z[0].append([expected_PCOfkey, f"== {repr(actual_PCOfkey)}",
                                       "PCOfixedkeyfingerprint"])

                utils.validate([validate for validate in verify_z[0]])

        return output

    def init_hsm(self, *args, force=True, **kwargs):
        '''
        check the HSM state, try to initialize the HSM, if not already initialized
        Initializes the HSM with a CO Password, User Password, HSM Label and a FIPS enabled flag.
        :param force: If force is set to True
                      1> login to the HSM using default credentials, assuming HSM in zeroized state
                      2> if HSM is not zerozied, zeroize the HSM
                      loginHSM possible expected Errors Excluded:
                      '0x82': RET_INVALID_COMMAND(Invalid command in the current
                                                  state/configuration)
                      '0xce':  RET_USER_DOES_NOT_EXIST(This user doesn't exist)
        :param co_password:
            specifies the CO password
        :param co_username:
            specifies the CO username
        :param use_possession_factor:
            specifies intention to use possession factor
        :param pre_officer:
            pecifies needs a pre-officer initialization
        :param cu_password:
            specifies the CU password (Optional)
        :param cu_username:
            specifies the CU username (Optional)
        au_username:
            specify the AU username
        :param auth_mode:
            specifies the authentication mode (Used only when configuration is specified by a file)
        :param configuration_file:
            specifies the HSM configuration file
        :param fips_state:
            specifies the fips level [2],
        :param login_fail_count:
            specifies login failure count [20]
        :param max_passowrd_legnth:
            specifies maxium password length [32]
        :param min_passowrd_length:
            specifies minimum password length [7]
        :param cloning_method:
            specifies cloning method [1],
        :param kek_method:
            specifies KEK method [0],
        :param cert_auth:
            specifies cert_auth [0],
        :param backup_by_mco:
            specifies if MCO can backup and restore without PCO's fixed key
        :param support_secret_key_wrap:
            support for secret key wrapping [1]
        :param support_secret_key_unwrap:
            support for secret key unwrapping[1]
        :param label:
            specifies HSM label [cavium]
        :param group_id:
            specifies cloning group [group0]
        :param node_id:
            specifies the node id for the partition
        :param pek_path:
            specifies the path to store secondary copy of PEK
        :param block_delete_user:
            to block user deletion when user owns some keys
        :param twofa_network_key:
            specifies the key used for 2FA network
        :param twofa_network_port:
            specifies the port used for 2FA network
        :param twofa_network_certificate:
            specifies the certificate used for 2FA network
        :param smartcard_pubkey_path:  #specifies the smartcard public key path
        :return output:
            TextFSM parsed output from init_hsm low level API:
        '''

        with allure.step('initializing HSM with {}'.format(kwargs)):
            output = self.cfm2util.initHSM(*args, **kwargs[self.function_name])
        return output

    def generate_rsa_keypair(self, *args, **kwargs):
        '''
        Generate RSA key pair specifying modulus length, public exponent and key label.

        API takes no positional parameters
        :param modulus_length:
            specifies the modulus length: eg. 2048
        :param public_exponent:
            specifies the public exponent: any odd number typically >= 65537 to 2^31-1
        :param key_label:
            specifies the key label
        :param ssession_key:
            specifies key as session key
        :param keyid:
            specifies key ID
        :param non_extractable:
            set the key as non-extractable
        :param users_list_to_share:
            specifies the list of user-ids to share with (separated by ,) (optional)
        :param sessions_list:
            specifies the list of sessions to share with (separated by ,)
            (optional, valid only for session keys)
        :param total_users_to_approve:
            specifies the number of users to approve for any key service
        :param attestation_check:
            performs the attestation check on the firmware response
        :param sub_attributes_wrap_file:
            specifies the file containing sub-attributes of WRAP_TEMPLATE attribute
        :param sub_attributes_unwrap_file:
            specifies the file containing sub-attributes of UNWRAP_TEMPLATE attribute
        :param pub_attribute_file:
            specifies public attribute file (optional)
        :param priv_attribute_file:
            specifies private attribute file (optional)
        :param cu_username:
            CU username who creates these RSA Keys (optional, for validation only)
        :return parsed output:
        '''
        validation_list = list()
        with allure.step(f'generating RSA key pair with arguments: {kwargs}'):
            with allure.step(f'getting PartitionInfo before generating RSAkeys'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])
            with allure.step(f'executing genRSAKeyPair Command'):
                if not kwargs[self.function_name].get("timeout"):
                    kwargs[self.function_name]["timeout"] = 480
                output = self.cfm2util.genRSAKeyPair(*args, **kwargs[self.function_name])
            pubkey = output["PublickeyHandle"]
            privkey = output["PrivatekeyHandle"]

            find_key = {}
            if "session_key" in kwargs[self.function_name].keys():
                find_key.update({"session_key": "1"})
                key_type = "session"
                session_keys_before += 2
            else:
                find_key.update({"session_key": "0"})
                key_type = "Token"
                token_keys_before += 2

            find_key.update({"key_class": "2", "key_type": "RSA"})
            SharedUsers = kwargs[self.function_name].get("users_list_to_share")
            if SharedUsers:
                find_key.update({"users_list_to_share": SharedUsers})
            keyid = kwargs[self.function_name].get("keyid")
            if keyid:
                find_key.update({"keyid": keyid})
            with allure.step("Verifying the generated public Key using findKey Command"):
                findkey = self.find_key(**{"find_key": find_key})
            total_pubkey = findkey["Keysfound"]

            find_key.update({"key_class": "3"})
            with allure.step("Verifying the generated private Key using findKey Command"):
                findkey = self.find_key(**{"find_key": find_key})
            total_priv_keys = findkey["Keysfound"]

            validation_list.append([pubkey, f"in {total_pubkey}", "pubkey in findkey"])
            validation_list.append([privkey, f"in {total_priv_keys}", "private key in findkey"])

            with allure.step(f'getting PartitionInfo after generating RSAkeys'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_after = partinfo["OccupiedTokenKeys"]
                session_keys_after = partinfo["OccupiedSessionKeys"]

            validation_list.append([session_keys_before, f"== {session_keys_after}",
                                    "session Keys before and after key generation"])
            validation_list.append([token_keys_before, f"== {token_keys_after}",
                                   "token keys before and after key generation"])
            non_extractable = kwargs[self.function_name].get("non_extractable")
            # How to check a key is non extractable
            LOG.warning(f'{non_extractable} not verfied, please verify it')

            total_users_to_approve = kwargs[self.function_name].get("total_users_to_approve")
            # How to validate
            LOG.warning(f'{total_users_to_approve} not verfied, please verify it')

            attestation_check = kwargs[self.function_name].get("attestation_check")
            if attestation_check in ['', ' ']:
                AttestationCheck = output.get("AttestationCheck", False)
                validation_list.append([AttestationCheck, f'is {AttestationCheck}',
                                        'AttestationCheck'])

            pub_attribute_file = kwargs[self.function_name].get("pub_attribute_file")
            # How to validate
            LOG.warning(f'{pub_attribute_file} not verfied, please verify it')

            priv_attribute_file = kwargs[self.function_name].get("priv_attribute_file")
            # How to validate
            LOG.warning(f'{priv_attribute_file} not verfied, please verify it')

            # check if the generated key is a session key or token,
            # and the key belongs to same CU user, who generated the Key
            get_key_dict = {"key_type": key_type}

            cu_username = kwargs[self.function_name].get("cu_username")
            if cu_username:
                get_key_dict.update({"cu_name": cu_username})

            for key in [pubkey, privkey]:
                get_key_dict.update({"key_handle": key})
                if key == privkey and SharedUsers:
                    get_key_dict.update({"SharedUsers": SharedUsers})
                self.get_key_info(**{"get_key_info": get_key_dict})
            # add code to verify the keys in findallKeys
            utils.validate(validation_list)

        return output

    def create_user(self, *args, **kwargs):
        '''
        Create a new CO/CU/AU with the given name and password
        API takes no positional parameters
        :param username:
            name of the user to create
        :return output:
            parsed output
        '''
        with allure.step('creating user'):
            with allure.step('Executing getPartitionInfo before createUser'):
                partinfo = self.get_partition_info(*args, **kwargs[self.function_name])
                users_before = partinfo["AvailableUsers"]
            with allure.step('Executing creating user with {}'.format(kwargs)):
                output = self.cfm2util.createUser(*args, **kwargs[self.function_name])
            with allure.step('Executing getPartitionInfo after createUser'):
                partinfo = self.get_partition_info(*args, **kwargs[self.function_name])
                users_after = partinfo["AvailableUsers"]
            with allure.step('getting users list'):
                list_users = self.list_users(*args, **kwargs[self.function_name])
	        #converting list_users dict keys to a list for validation 
            utils.validate([[output["CUName"].lower(), f'in {list(list_users.keys())}',
                             "checking username in listUsers list"],
                            [int(users_after)+1, f"== {users_before}", 'available users to'
                                                                       'create decreased after'
                                                                       'creating user']])
        return output

    def create_n_users(self, *args, **kwargs):
        '''
        Create no.of users with the given name and password

        :param username:
            name of the user to create [CU/AU/CO]
            user_count: No. of users count
        :return output:
            created usernames list
        '''
        if 'user_count' in kwargs:
            no_of_users = int(kwargs['user_count'])    
        else: 
            return None
        output_userlist =[]
        uname = kwargs[self.function_name]['username']
        with allure.step('creating user'):
            with allure.step('Executing getPartitionInfo before createUser'):
                partinfo = self.get_partition_info(*args, **kwargs)
                users_before = partinfo["AvailableUsers"]
            for eachuser in range(1,int(no_of_users)+1):
                #updating the username for each iteration
                kwargs[self.function_name]['username'] = f'{uname+str(eachuser)}'
                with allure.step('Executing create user with {}'.format(kwargs[self.function_name])):
                    output = self.cfm2util.createUser(*args, **kwargs[self.function_name])
                    #storing the created users username in a list for further validation
                    output_userlist.append(output["CUName"].lower())
            with allure.step('Executing getPartitionInfo after createUser'):
                partinfo = self.get_partition_info(*args, **kwargs)
                users_after = partinfo["AvailableUsers"]
            with allure.step('getting users list'):
                list_users = self.list_users(*args, **kwargs)

            uname_validation = [[username, f'in {list(list_users.keys())}',
                             "username in listUsers output"] for username in output_userlist]
            available_users_check = [(int(users_after)+ int(no_of_users)), f"== {users_before}", 'available users to'
                                                                       'create decreased after'
                                                                       'creating user']

            uname_validation.append(available_users_check)
            utils.validate(uname_validation)
        return output_userlist

    def logout_hsm(self, *args, **kwargs):
        '''
        logout from HSM
        :return output:
           parsed output
        '''
        with allure.step('logging out of HSM'):
            output = self.cfm2util.logoutHSM(*args, **kwargs)
            with allure.step('checking loginStatus'):
                login_status = self.login_status(*args, **kwargs)
            utils.validate(["No user", f'== {login_status["UserType"]}', "no user logged in"])
        return output

    def get_partition_info(self, *args, **kwargs):
        '''
        getPartitionInfo returns Partition's information
        '''
        with allure.step('get Partition Information'):
            output = self.cfm2util.getPartitionInfo(*args, **kwargs)
        return output

    def generate_pek(self, *args, **kwargs):
        '''
        generate PEK
        API takes no positional parameters
        :param co_username:
            CO username for login before generating PEK (optional)
        :param co_password:
            CO password for login before generating PEK (optional)
        :return output:
            parsed output
        '''
        with allure.step('generate PEK'):
            output = self.cfm2util.generatePEK(*args, **kwargs)
        return output

    def generate_kek(self, *args, **kwargs):
        '''
        generate KEK

        API takes no positional parameters
        :return output:
            parsed output
        '''
        with allure.step('generate KEK'):
            output = self.cfm2util.generateKEK(*args, **kwargs)
        return output

    def delete_user(self, *args, **kwargs):
        '''
        Delete an user of given name
        API takes no positional parameters

        :param username:
            name of the user to delete
        :return output:
            parsed output
        '''
        with allure.step(f'deleting user with {kwargs}'):

            with allure.step('Executing getPartitionInfo before deleteUser'):
                partinfo = self.get_partition_info(*args, **kwargs)
                users_before = partinfo["AvailableUsers"]
            with allure.step('executing delete user'):
                output = self.cfm2util.deleteUser(*args, **kwargs[self.function_name])

            with allure.step('Executing getPartitionInfo after deleteUser'):
                partinfo = self.get_partition_info(*args, **kwargs)
                users_after = partinfo["AvailableUsers"]
            with allure.step('getting users list'):
                list_users = self.list_users(*args, **kwargs)

            username = kwargs[self.function_name]["username"]
	        #converting list_users dict keys to a list for validation
            utils.validate([[username.lower(), f'not in {list(list_users.keys())}',
                             "checking username in listUsers list"],
                            [int(users_after)-1, f"== {users_before}", 'available users to '
                                                                       'create increased after '
                                                                       'deleteing user']])
        return output

    def delete_all_users(self, *args, **kwargs):
        '''
        Deletes all users based on user_type
        API takes no positional parameters

        :param username:
            dynamically updated from listUsers
        :return output:
            returns list of deleted usernames
        '''
        user_deleted = 0
        output_userlist =[]
        user_type = kwargs[self.function_name]['usertype']
        with allure.step(f'deleting all {user_type} users '):
            with allure.step('Executing getPartitionInfo before delete Users'):
                partinfo = self.get_partition_info(*args, **kwargs)
                users_before = partinfo["AvailableUsers"]
            with allure.step('getting users list'):
                list_users_before = self.list_users(*args, **kwargs)
            with allure.step(f'Executing delete user for all {user_type} users'):
                for eachuser in list_users_before.keys():
                    if isinstance(list_users_before[eachuser], dict) and list_users_before[eachuser]['UserType'] == user_type:
                        #updating the username in params to delete the user
                        kwargs[self.function_name]['username'] = eachuser
                        output = self.cfm2util.deleteUser(*args, **kwargs[self.function_name])
                        #counting the deleted users for further validation
                        user_deleted+=1
                        #storing the created users username in a list for further validation
                        output_userlist.append(eachuser)
                if not output_userlist:
                    with allure.step(f'No {user_type}  users to delete'):
                        return
            with allure.step('Executing getPartitionInfo after deleteUsers'):
                partinfo = self.get_partition_info(*args, **kwargs)
                users_after = partinfo["AvailableUsers"]
            with allure.step('getting users list'):
                list_users = self.list_users(*args, **kwargs)

            uname_validation =[[username.lower(), f'not in {list(list_users.keys())}',
                             "username in listUsers output"] for username in output_userlist]
            available_users_check =[(int(users_after)-int(user_deleted)), f"== {users_before}", 'available users to '
                                                                       'create increased after'
                                                                        'deleting user']
            uname_validation.append(available_users_check)
            utils.validate(uname_validation)

        return output_userlist

    def close_partition_sessions(self, *args, **kwargs):
        '''
        Closes all the sessions opened in the partition
        '''
        with allure.step('close partition sessions'):
            output = self.cfm2util.closePartitionSessions(*args, **kwargs)
        return output

    def change_pswd(self, *args, **kwargs):
        '''
        Change the user's password or challenge
        :param usertype:
            specifies the user type as "CO" or "CU" or "AU" or "PO/PRECO"
        :param new_password:
            specifies the new user password
        :param username:
            specifies the user name
        :param use_possession_factor:
            specifies intention to use possession factor
        :param twofa_network_key:
            specifies the key used for 2FA network
        :param twofa_network_port:
            specifies the port used for 2FA network
        :param twofa_network_certificate:
            specifies the certificate used for 2FA network
        :param smartcard_pubkey_path:
            specifies the smartcard public key path
        :param pek_path:
            specifies the path where PEK is stored(Optional)
        '''
        # need to verify twofa_network_certificate, twofa_network_port, twofa_network_key
        # use_possession_factor
        with allure.step('change password {}'.format(kwargs)):
            output = self.cfm2util.changePswd(*args, **kwargs[self.function_name])

            verify = kwargs[self.function_name].get("verify", True)
            if verify:
                login_hsm = kwargs[self.function_name]
                login_hsm["password"] = login_hsm["new_password"]
                with allure.step('verifying the changed user credentials'):
                    self.login_hsm(*args, **{"login_hsm": login_hsm})
        return output

    def set_hsm_config(self, *args, **kwargs):
        '''
        Set HSM config
        :param config_type:
            specifies the HSM config type
        :return output:
            parsed output
        '''
        with allure.step('set HSM config'):
            output = self.cfm2util.setHSMConfig(*args, **kwargs[self.function_name])
        return output

    def set_mvalue(self, *args, **kwargs):
        '''
        Sets new M Value for a CO service
        :param service_number:
            Service Number
        :param mvalue:
            New M Value

        :return output:
            parsed output
        '''
        with allure.step(f'set M value: {kwargs}'):
            with allure.step('executing set mvalue'):
                output = self.cfm2util.setMValue(*args, **kwargs[self.function_name])
                service_toset = kwargs[self.function_name]['service_number']
                mvalue_toset = kwargs[self.function_name]['mvalue']
                actual_mvalue = self.get_mvalue(**{"get_mvalue": {"service_number": service_toset}})
                return_mvalue = actual_mvalue[actual_mvalue['MValueid']]
                utils.validate([int(mvalue_toset), f'== {return_mvalue}',
                                                   f"Mvalue for {service_toset}"])
        return output

    def list_tokens(self, *args, **kwargs):
        '''
        Gets all approved tokens
        :param validate:
            validate is the mapping between TOkenId and it's token details
            this can be formed and sent in a dictionary so that presence of
            TokenId and its corresponding details can be verified against
            list_tokens output
        '''
        with allure.step('list tokens'):
            output = self.cfm2util.listTokens(*args, **kwargs)
            return_output = dict()

            if isinstance(output, dict):
                output = [output]
            for token_info in output:
                token_id = token_info["TokenId"]
                return_output.update({token_id: token_info})
            else:
                return_output.update({'HSMReturn': token_info['HSMReturn'],
                                      'ReturnCode': token_info['ReturnCode'],
                                      'NoOfTokens': token_info['NoOfTokens']})
            validate = kwargs[self.function_name].get("validate")
            if validate:
                validation_list = list()
                for TokenId, TokenDict in validate.items():
                    utils.validate([TokenId, f"in {return_output.keys()}"])
                    if TokenId in return_output.keys():
                        list_dict = return_output[TokenId]
                        for tokenkey, value in TokenDict.items():
                            if list_dict.get(tokenkey):
                                rvalue = repr(list_dict[tokenkey])
                                validation_list.append([value, f"== {rvalue}"])
                    else:
                        validation_list.append([TokenId, f"in {return_output.keys()}"])
                utils.validate(validation_list)

        return return_output

    def get_key_hash(self, *args, **kwargs):
        '''
        Gets the hash of all the keys in the current partition
        '''
        with allure.step('get key hash'):
            output = self.cfm2util.getKeyHash(*args, **kwargs[self.function_name])
        return output

    def get_single_key_hash(self, *args, **kwargs):
        '''
        Gets the hash of all the properties of a single key
        '''
        with allure.step('get single key hash'):
            output = self.cfm2util.getSingleKeyHash(*args, **kwargs[self.function_name])
        return output

    def set_node_id(self, *args, **kwargs):
        '''
        Sets the node id for a partition

        :param nodeid_number:
            to specify the node id number
        :return output:
            parsed output
        '''
        with allure.step('setting node Id'):
            output = self.cfm2util.setNodeId(*args, **kwargs[self.function_name])
            with allure.step('getPartitionInfo for verifying NodeId'):
                part_info = self.get_partition_info(*args, **kwargs)
                utils.validate([kwargs[self.function_name]["nodeid_number"],
                                f'== \"{part_info["NodeID"]}\"',
                                "NodeId, after settingit"])
        return output

    def generate_dsa_keypair(self, *args, **kwargs):
        '''
        Generate DSA key pair specifying modulus length and key label
        API takes no positional paramters
        :param modulus_length:
            specifies the modulus length in bits
        :param key_label:
            specifies the key label
        :param session_key:
            specifies key as session key
        :param keyid:
            specifies key ID
        :param non_extractable_key:
            set the key as non-extractable
        :param users_list_to_share:
            specifies the list of users to share with (separated by ,) (optional)
        :param sessions_list:
            specifies the list of sessions to share with (separated by ,)
            (optional, valid only for session keys)
        :param total_users_to_approve:
            specifies the number of users to approve for any key service
        :param attestation_check:
            performs the attestation check on the firmware response
        :param pub_attribute_file:
            specifies public attribute file (optional)
        :param specifies private attribute file (optional)
        :param cu_username:
            specify the CU username who generates DSA keys(optional, for validation only)
        :return parsed output:
        '''
        with allure.step(f'generating DSA Key pair with: {kwargs}'):

            with allure.step(f'getting PartitionInfo before generating DSAkeys'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])
            with allure.step(f'executing genDSAKeyPair command'):
                if not kwargs[self.function_name].get("timeout"):
                    kwargs[self.function_name]["timeout"] = 480
                output = self.cfm2util.genDSAKeyPair(*args, **kwargs[self.function_name])
                pubkey = output["PublickeyHandle"]
                privkey = output["PrivatekeyHandle"]

                # modulus length not verfied
                find_key = dict()
                if "session_key" in kwargs[self.function_name].keys():
                    key_type = "session"
                    session_keys_before += 2
                    find_key.update({"session_key": '1'})
                else:
                    key_type = "Token"
                    token_keys_before += 2
                    find_key.update({"session_key": '0'})
                find_key.update({"key_class": "2", "key_type": "DSA"})
                SharedUsers = kwargs[self.function_name].get("users_list_to_share")
                if SharedUsers:
                    find_key.update({"users_list_to_share": SharedUsers})
                keyid = kwargs[self.function_name].get("keyid")
                if keyid:
                    find_key.update({"keyid": keyid})
                with allure.step("Verifying the generated public Key using findKey Command"):
                    findkey = self.find_key(**{"find_key": find_key})
                total_pubkey = findkey["Keysfound"]

                find_key.update({"key_class": "3"})
                with allure.step("Verifying the generated private Key using findKey Command"):
                    findkey = self.find_key(**{"find_key": find_key})
                total_priv_keys = findkey["Keysfound"]

                validation_list = list()
                validation_list.append([pubkey, f"in {total_pubkey}", "pubkey in findkey"])
                validation_list.append([privkey, f"in {total_priv_keys}", "private key in findkey"])

                with allure.step(f'getting PartitionInfo after generating DSAkeys'):
                    partinfo = self.get_partition_info(*args, **kwargs)
                    token_keys_after = partinfo["OccupiedTokenKeys"]
                    session_keys_after = partinfo["OccupiedSessionKeys"]

                validation_list.append([session_keys_before, f"== {session_keys_after}",
                                        "session Keys before and after key generation"])
                validation_list.append([token_keys_before, f"== {token_keys_after}",
                                       "token keys before and after key generation"])
                non_extractable = kwargs[self.function_name].get("non_extractable")
                # How to validate
                LOG.warning(f'{non_extractable} not verfied, please verify it')

                total_users_to_approve = kwargs[
                        "generate_dsa_keypair"].get("total_users_to_approve")
                # How to validate
                LOG.warning(f'{total_users_to_approve} not verfied, please verify it')

                if "attestation_check" in kwargs[self.function_name]:
                    AttestationCheck = output.get("AttestationCheck", False)
                    validation_list.append([AttestationCheck, f'== PASS',
                                            'AttestationCheck'])

                pub_attribute_file = kwargs[self.function_name].get("pub_attribute_file")
                # How to validate
                LOG.warning(f'{pub_attribute_file} not verfied, please verify it')

                priv_attribute_file = kwargs[self.function_name].get("priv_attribute_file")
                # How to validate
                LOG.warning(f'{priv_attribute_file} not verfied, please verify it')

                # check if the generated key is a session key or token,
                # and the key belongs to same CU user, who generated the Key
                get_key_dict = {"key_type": key_type}
                cu_username = kwargs[self.function_name].get("cu_username")

                if cu_username:
                    get_key_dict.update({"cu_name": cu_username})

                for key in [pubkey, privkey]:
                    get_key_dict.update({"key_handle": key})
                    if key == privkey and SharedUsers:
                        get_key_dict.update({"SharedUsers": SharedUsers})
                    self.get_key_info(**{"get_key_info": get_key_dict})
                # add code to verify the keys in findallKeys
                utils.validate(validation_list)

        return output

    def generate_ecc_keypair(self, *args, **kwargs):
        '''
        Generate ECC key pair specifying the curve id and key label
        following params needs to be passed through kwargs for command
        execution
        API takes no positional parameters

        :param curve_id:
            specifies the Curve ID
        :param key_label:
            specifies the key label
        :param session_key:
            specifies key as session key
        :param keyid:
            specifies key ID
        :param non_extractable_key:
            set the key as non-extractable
        :param users_list_to_share:
            specifies the list of users to share with (separated by ,) (optional)
        :param sessions_list:
            specifies the list of sessions to share with (separated by ,)
            (optional, valid only for session keys)
        :param total_users_to_approve:
            specifies the number of users to approve for any key service (optional)
        :param attestation_check:
            performs the attestation check on the firmware response(optional)
        :param pub_attribute_file:
            specifies public attribute file (optional)
        :param priv_attribute_file:
            specifies private attribute file (optional)
        :param cu_username:
            CU username who generates ECC keypairs (optional, for validation only)
        :return parsed output:
        '''
        with allure.step(f'generating ECC Key pair with {kwargs}'):

            with allure.step(f'getting PartitionInfo before generating ECCkeys'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])
            with allure.step('generating ECC Key pair'):
                output = self.cfm2util.genECCKeyPair(*args, **kwargs[self.function_name])
                pubkey = output["PublickeyHandle"]
                privkey = output["PrivatekeyHandle"]

                # Ecc cureve id not validated
                # -mvalue not validated
                # session list not validated
                # public and private attribute not validated
                find_key = dict()
                if "session_key" in kwargs[self.function_name].keys():
                    find_key.update({"session_key": "1"})
                    key_type = "session"
                    session_keys_before += 2
                else:
                    find_key.update({"session_key": "0"})
                    key_type = "Token"
                    token_keys_before += 2

                find_key.update({"key_class": "2", "key_type": "ECC"})
                SharedUsers = kwargs[self.function_name].get("users_list_to_share")
                if SharedUsers:
                    find_key.update({"users_list_to_share": SharedUsers})
                keyid = kwargs[self.function_name].get("keyid")
                if keyid:
                    find_key.update({"keyid": keyid})
                with allure.step("Verifying the generated public Key using findKey Command"):
                    findkey = self.find_key(**{"find_key": find_key})
                total_pubkey = findkey["Keysfound"]

                find_key.update({"key_class": "3"})
                with allure.step("Verifying the generated private Key using findKey Command"):
                    findkey = self.find_key(**{"find_key": find_key})
                total_priv_keys = findkey["Keysfound"]

                validation_list = list()
                validation_list.append([pubkey, f"in {total_pubkey}", "pubkey in findkey"])
                validation_list.append([privkey, f"in {total_priv_keys}", "private key in findkey"])

                with allure.step(f'getting PartitionInfo after generating ECCkeys'):
                    partinfo = self.get_partition_info(*args, **kwargs)
                    token_keys_after = partinfo["OccupiedTokenKeys"]
                    session_keys_after = partinfo["OccupiedSessionKeys"]

                validation_list.append([session_keys_before, f"== {session_keys_after}",
                                        "session Keys before and after key generation"])
                validation_list.append([token_keys_before, f"== {token_keys_after}",
                                       "token keys before and after key generation"])
                non_extractable = kwargs[self.function_name].get("non_extractable")
                # How to validate
                LOG.warning(f'{non_extractable} not verfied, please verify it')

                total_users_to_approve = kwargs[
                        "generate_ecc_keypair"].get("total_users_to_approve")
                # How to validate
                LOG.warning(f'{total_users_to_approve} not verfied, please verify it')

                attestation_check = kwargs[self.function_name].get("attestation_check")
                if attestation_check in ['', ' ']:
                    AttestationCheck = output.get("AttestationCheck", False)
                    validation_list.append([AttestationCheck, f'== PASS',
                                            'AttestationCheck'])

                pub_attribute_file = kwargs[self.function_name].get("pub_attribute_file")
                # How to validate
                LOG.warning(f'{pub_attribute_file} not verfied, please verify it')

                priv_attribute_file = kwargs[self.function_name].get("priv_attribute_file")
                # How to validate
                LOG.warning(f'{priv_attribute_file} not verfied, please verify it')

                # check if the generated key is a session key or token,
                # and the key belongs to same CU user, who generated the Key
                get_key_dict = {"key_type": key_type}
                cu_username = kwargs[self.function_name].get("cu_username")
                if cu_username:
                    get_key_dict.update({"cu_name": cu_username})

                for key in [pubkey, privkey]:
                    get_key_dict.update({"key_handle": key})
                    if key == privkey and SharedUsers:
                        get_key_dict.update({"SharedUsers": SharedUsers})
                    self.get_key_info(**{"get_key_info": get_key_dict})
            # add code to verify the keys in findallKeys
            utils.validate(validation_list)

        return output

    def generate_pbe_key(self, *args, **kwargs):
        '''
        Generates a PBE DES3 key

        :param key_label:
            specifies the key label
        :param password:
            specifies the password
        :param salt_value:
            specifies the salt value, eg. name
        :param iteration_count:
            specifies the iteration count <= 10000, eg. 10
        :param session_key:
            specifies key as session key
        :param keyid:
            specifies key ID
        :param non_extractable_key:
            set the key as non-extractable
        :param users_list_to_share:
            specifies the list of users to share with (separated by ,) (optional)
        :param sessions_list:
            specifies the list of sessions to share with (separated by ,)
            (optional, valid only for session keys)
        :param attestation_check:
            performs the attestation check on the firmware response
        :param cu_username:
            name of the User who is generating this Key (optional, for validation only)
        :return output:
            parsed output
        '''
        with allure.step('generating PBE Key with kwargs: {}'.format(kwargs)):
            with allure.step(f'getting PartitionInfo before generating PBE key'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])
            with allure.step('generating PBE Key'):
                output = self.cfm2util.genPBEKey(*args, **kwargs[self.function_name])
                KeyHandle = int(output["PBEKey"])

                find_key = dict()
                if "session_key" in kwargs[self.function_name].keys():
                    find_key.update({"session_key": "1"})
                    key_type = "session"
                    session_keys_before += 1
                else:
                    find_key.update({"session_key": "0"})
                    key_type = "Token"
                    token_keys_before += 1

                find_key.update({"key_class": "4"})
                find_key.update({"key_type": "21"})
                SharedUsers = kwargs[self.function_name].get("users_list_to_share")
                if SharedUsers:
                    find_key.update({"users_list_to_share": SharedUsers})
                keyid = kwargs[self.function_name].get("keyid")
                if keyid:
                    find_key.update({"keyid": keyid})

                with allure.step("Verifying the generated PBE Key using findKey Command"):
                    findkey = self.find_key(**{"find_key": find_key})
                secrete_keys = findkey["Keysfound"]
                validation_list = list()
                validation_list.append([str(KeyHandle), f"in {secrete_keys}",
                                        "PBE key in findkey"])

                with allure.step(f'getting PartitionInfo after generating PBE keys'):
                    partinfo = self.get_partition_info(*args, **kwargs)
                    token_keys_after = partinfo["OccupiedTokenKeys"]
                    session_keys_after = partinfo["OccupiedSessionKeys"]

                validation_list.append([session_keys_before, f"== {session_keys_after}",
                                        "session Keys before and after key generation"])
                validation_list.append([token_keys_before, f"== {token_keys_after}",
                                       "token keys before and after key generation"])
                non_extractable = kwargs[self.function_name].get("non_extractable")
                # How to validate
                LOG.warning(f'{non_extractable} not verfied, please verify it')

                total_users_to_approve = kwargs[self.function_name].get("total_users_to_approve")
                # How to validate
            LOG.warning(f'{total_users_to_approve} not verfied, please verify it')

            if "attestation_check" in kwargs[self.function_name].keys():
                AttestationCheck = output.get("AttestationCheck", False)
                validation_list.append([AttestationCheck, f'== PASS',
                                        'AttestationCheck'])
            utils.validate(validation_list)
            get_key_dict = dict({"key_handle": str(KeyHandle), "key_type": key_type})
            cu_username = kwargs[self.function_name].get("cu_username")
            if cu_username:
                get_key_dict.update({"cu_name": cu_username})
            if SharedUsers:
                get_key_dict.update({"SharedUsers": SharedUsers})
            self.get_key_info(**{"get_key_info": get_key_dict})
        return output

    def get_audit_logs(self, *args, **kwargs):
        '''
        Prints Audit Logs

        :param max_logs:
            specifies the maximum number of logs that may be returned by the firmware.
            Default value is the max, 30720
        :param logs_path:
            specifies the path to which to write logs in binary format
        :param rsa_sign_path:
            specifies the path at which the RSA signature will be written to
        :return output:
            parsed output
        '''
        with allure.step('retrive audit logs'):
            output = self.cfm2util.getAuditLogs(*args, **kwargs[self.function_name])
        return output

    def get_cert(self, *args, **kwargs):
        '''
        Gets Partition's Certificate Request from the HSM
        :param cert_file_name:
            cert_file_name
        :param cert_owner:
            specifies owner of the certificate
        :return output:
            parsed output
        '''
        with allure.step('get the Certificate'):
            output = self.cfm2util.getCert(*args, **kwargs[self.function_name])
        return output

    def get_cert_req(self, *args, **kwargs):
        '''
        get certificate request
        :param cert_request_file_name:
            specifies the certificate req file name
        :return output:
            parsed output
        '''
        with allure.step('get the Certificate Request'):
            output = self.cfm2util.getCertReq(*args, **kwargs[self.function_name])
        return output

    def login_status(self, *args, **kwargs):
        '''
        loginStatus informs if CU or CO is logged into the initialized
        HSM through current application
        '''
        with allure.step('get the login status'):
            output = self.cfm2util.loginStatus(*args, **kwargs)
        return output

    def get_login_fail_count(self, *args, **kwargs):
        '''
        Gets current login failure count of a particular user
        :param usertype:
            specifies the user type as "PO" or "CO" or "CU" or "AU"
        :param username:
            specifies the user name
        :param output:
            parsed output
        '''
        with allure.step('get the login failure count'):
            output = self.cfm2util.getLoginFailCount(*args, **kwargs[self.function_name])
            list_users = self.list_users(*args, **kwargs)
            username = kwargs[self.function_name]["username"].lower()
            utils.validate([int(output["LoginFailureCount"]),
                            f'== {list_users[username]["LoginFailureCnt"]}',
                            "login failure count using listUsers"])
            return output

    def close_all_sessions(self, *args, **kwargs):
        '''
        CloseAllSessions closes all the sessions opened in the current application
        '''
        with allure.step('close all sessions for the partition'):
            output = self.cfm2util.closeAllSessions(*args, **kwargs)
        return output

    def get_fw_version(self, *args, **kwargs):
        '''
        getFWVersion returns current firmware version loaded onto the HSM
        '''
        with allure.step('getting firmware version'):
            output = self.cfm2util.getFWVersion(*args, **kwargs)
            get_hsm = self.get_hsm_info(*args, **kwargs)
            utils.validate([output["FirmwareInfo"], f'== {get_hsm["FirmwareID"]}',
                            "Firmware Information using getHSM Info"])
        return output

    def list_users(self, *args, **kwargs):
        '''
        listUsers lists all users of the current partition
        API takes no positional parameters
        :return return_output:
                 return_output = {parsed_output: parsed_output
                                  user_details: {userid: username}}
        '''
        with allure.step('list Users'):
            output = self.cfm2util.listUsers(*args, **kwargs[self.function_name])
        # flag = "UserName,UserID"
        flag = kwargs[self.function_name].get("flag")
        Filter = kwargs[self.function_name].get("Filter")
        return_output = {}
        if flag:
            key, *value = flag.split(",")
            key = key.strip()
            # Filter = "UserType=CU"
            if Filter:
                Fkey, Fvalue = Filter.split("=")
                for record in output:
                    tmp = dict()
                    if not record.get(key):
                        continue
                    if record[Fkey] == Fvalue:
                        for each_value in value:
                            each_value = each_value.strip()
                            tmp.update({each_value: record.get(each_value)})
                        return_output.update({record.get(key): tmp})
            else:
                for record in output:
                    tmp = dict()
                    if not record.get(key):
                        continue
                    for each_value in value:
                        each_value = each_value.strip()
                        tmp.update({each_value: record.get(each_value)})
                    return_output.update({record.get(key): tmp})
        else:
            if Filter:
                Fkey, Fvalue = Filter.split("=")
            for record in output:
                if Filter:
                    if not record.get(Fkey) == Fvalue:
                        continue
                user_id = record.get("UserID")
                if user_id:
                    return_output.update({record["UserName"]:
                                          {"UserType": record["UserType"],
                                           "MofnPubKey": record["MofnPubKey"],
                                           "twoFA": record["twoFA"],
                                           "LoginFailureCnt": record["LoginFailureCnt"],
                                           "USERID": user_id}})

                total_users = record.get("TotalUsers")
                if total_users:
                    return_output.update({"TotalUsers": total_users,
                                          "ReturnCode": record["ReturnCode"],
                                          "HSMReturn": record["HSMReturn"],
                                          "ApiName": record["ApiName"]})

        return return_output

    def get_hsm_info(self, *args, **kwargs):
        '''
        getHSMInfo returns HSM information
        '''
        with allure.step('getting  HSM Information'):
            output = self.cfm2util.getHSMInfo(*args, **kwargs)
        return output

    def get_mvalue(self, *args, **kwargs):
        '''
        Gets current M Value of a CO service
        :param service_number:
            Service Number
        :return output:
            parsed output
            output will also have a key that is requested CO service(-n value) and it's
            corrresponding CO service value
        '''
        with allure.step('get_mvalue'):
            output = self.cfm2util.getMValue(*args, **kwargs[self.function_name])
            output.update({output["MValueid"]: output["Mvalue"]})
        return output

    def get_token_timeout(self, *args, **kwargs):
        '''
        Get timeout values of tokens
        '''
        with allure.step('get_token_timeout'):
            output = self.cfm2util.getTokenTimeout(*args, **kwargs)
        return output

    def set_token_timeout(self, *args, **kwargs):
        '''
        set timeout values of tokens
        :param token_create_timeout:
            set token creation timeout in seconds
        :param token_approve_timeout:
            set token approval timeout in seconds
        :return output:
            parsed output
        '''
        with allure.step(f'set_token_timeout: {kwargs}'):
            with allure.step(f'executing set_token_timeout'):
                output = self.cfm2util.setTokenTimeout(*args, **kwargs[self.function_name])
                get_token = self.get_token_timeout(*args, **kwargs)
                token_create_timeout = kwargs[self.function_name].get("token_create_timeout")
                token_approve_timeout = kwargs[self.function_name].get("token_approve_timeout")
                validation_list = []
                if token_create_timeout:
                    validation_list.append([int(token_create_timeout),
                                            f'== {get_token["TokenCreationTimeoutSec"]}',
                                            "token create timeout after modifcation"])
                if token_approve_timeout:
                    validation_list.append([int(token_approve_timeout),
                                            f'== {get_token["TokenApprovalTimeoutSec"]}',
                                            "token approval timeout  after modification"])
                utils.validate(validation_list)

        return output

    def exit(self, *args, **kwargs):
        '''
        exit from Cfm2Util prompt
        '''
        with allure.step('exiting from Cfm2Util'):
            output = self.cfm2util.exit(*args, **kwargs)
        return output

    def error2_string(self, *args, **kwargs):
        '''
        convert a response code to Error String

        :param response_code:
            specifies response code to be converted
        :return output:
            parsed output
        '''
        with allure.step('error2string'):
            output = self.cfm2util.Error2String(*args, **kwargs[self.function_name])
        return output

    def isvalid_keyhandle_file(self, *args, **kwargs):
        '''
        Checks given key file has key handle or real key

        :param key_file_name:
            specifies the RSA private key file name
            Note: Multiple key_file_names can be passed as a list
                  for this paramter
        :return output:
            parsed output
        '''
        with allure.step('isvalidkeyhandlefile'):
            key_file_name = kwargs[self.function_name].get("key_file_name")
            key_file_name = [key_file_name] if isinstance(key_file_name, str) else key_file_name
            return_output = []
            for key_file in key_file_name:
                kwargs[self.function_name]["key_file_name"] = key_file
                output = self.cfm2util.IsValidKeyHandlefile(
                        *args, **kwargs[self.function_name])
                value = output.pop("ValidkeyHandleFile")
                output[key_file] = value
                return_output.append(output)
            return_output = return_output[0] if len(return_output) == 1 else return_output
        return return_output

    def aes_wrap_unwrap(self, *args, **kwargs):
        '''
        Wraps/Unwraps data with specified AES key
        :param wrap_key_handle:
            specifies the handle of the AES wrapping/unwrapping key
        :param key_file_name:
            file to be wrapped or unwrapped (Supported file size is <= 4K bytes)
        :param wrap_mode:specifies the mode:
            wrap - 1; unwrap - 0;
        :param wrap_mechanism:
            specifies the mechanism:
        :param iv_to_use:
            specifies the IV to be used (optional)
        :param new_file_name:
            file to write the wrapped or unwrapped data out (optional)
        :param output:
             return output
        '''
        with allure.step('aeswrapunwrap'):
            output = self.cfm2util.aesWrapUnwrap(*args, **kwargs[self.function_name])
        return output

    def approve_token(self, *args, **kwargs):
        '''
        Approves an MxN protected service identified by Token
        :param approval_blob_file:
            approval blob file
        '''
        with allure.step('approvetoken'):
            with allure.step('approvetoken'):
                output = self.cfm2util.approveToken(*args, **kwargs[self.function_name])
        return output

    def backup_partition(self, *args, **kwargs):
        '''
        Backup the Partition's configuration and user details

        :param absolute_directory:
            Absolute directory to store backup files
        :param wrap_mechanism:
            KBK wrap mechanism
        :return output:
            parsed output
        '''
        with allure.step('backuppartition'):
            output = self.cfm2util.backupPartition(*args, **kwargs[self.function_name])
        return output

    def clone_source_end(self, *args, **kwargs):
        '''
        Push Clone Target output into Clone Source

        :param clone_source_file:
             <file1> File from Clone Target for Clone Source
        :param clone_target_file:
             <file2> File from Clone Source for Clone Target
        '''
        with allure.step('clonesourceend'):
            output = self.cfm2util.cloneSourceEnd(*args, **kwargs[self.function_name])
        return output

    def clone_source_start(self, *args, **kwargs):
        '''
        Fetch value for Clone Target Init

        :param clone_source_file:
            Filename to get values from Clone Source
        :return output:
            parsed output
        '''
        with allure.step('clonesourcestart'):
            output = self.cfm2util.cloneSourceStart(*args, **kwargs[self.function_name])
        return output

    def clone_target_end(self, *args, **kwargs):
        '''
        Fetch value for Clone Target End

        :param clone_source_file:
            <file> Filename to get values from Clone Source
        :return output:
            parsed output
        '''
        with allure.step('clonetargetend'):
            output = self.cfm2util.cloneTargetEnd(*args, **kwargs[self.function_name])
        return output

    def clone_target_start(self, *args, **kwargs):
        '''
        Push Clone Source output into Clone Target

        :param clone_target_file:
            File from Clone Source for Clone Target
        :param clone_source_file:
            File from Clone Target for Clone Source
        :return output:
            parsed output
        '''
        with allure.step('clonetargetstart'):
            output = self.cfm2util.cloneTargetStart(*args, **kwargs[self.function_name])
        return output

    def convert2_cavium_priv_key(self, *args, **kwargs):
        '''
        Imports an RSA Private Key and saves key_handle in Cavium's fake PEM format

        :param key_label:
            specifies the private key label
        :param key_file_name:
            specifies the filename containing the key to import
        :param wrap_key_handle:
            specifies the wrapping key handle, 4 for KEK
        :param new_file_name:
            specifies the file to write the Private Key in Fake PEM format
        :param session_key:
            specifies key as session key
        :param keyid:
            specifies key ID
        :param users_list_to_share:
            specifies the list of users to share with (separated by ,) (optional)
        :param sessions_list:
            specifies the list of sessions to share with (separated by ,)
            (optional, valid only for session keys)
        :param cu_username:
            CU Username, who imports this RSA private key, (optional, for validation only)
        :param output:
            parsed output
        '''
        with allure.step('convert2caviumprivkey'):
            with allure.step(f'getting PartitionInfo before executing convert2CaviumPrivKey'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])
            output = self.cfm2util.convert2CaviumPrivKey(*args,
                                                         **kwargs[self.function_name])
            KeyHandle = output["KeyHandle"]
            find_key = dict()
            if "session_key" in kwargs[self.function_name].keys():
                find_key.update({"session_key": "1"})
                key_type = "session"
                session_keys_before += 1
            else:
                find_key.update({"session_key": "0"})
                key_type = "Token"
                token_keys_before += 1

            # sessions_list need to verify
            find_key.update({"key_class": "3"})
            find_key.update({"key_type": "0"})
            SharedUsers = kwargs[self.function_name].get("users_list_to_share")
            if SharedUsers:
                find_key.update({"users_list_to_share": SharedUsers})
            keyid = kwargs[self.function_name].get("keyid")
            if keyid:
                find_key.update({"keyid": keyid})
            with allure.step("Verifying the imported privateKey using findKey Command"):
                findkey = self.find_key(**{"find_key": find_key})
                secrete_keys = findkey["Keysfound"]
                validation_list = list()
                validation_list.append([str(KeyHandle), f"in {secrete_keys}",
                                        "Symm key in findkey"])

            with allure.step(f'getting PartitionInfo after generating Symmetric keys'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_after = partinfo["OccupiedTokenKeys"]
                session_keys_after = partinfo["OccupiedSessionKeys"]

            validation_list.append([session_keys_before, f"== {session_keys_after}",
                                    "session Keys before and after key generation"])
            validation_list.append([token_keys_before, f"== {token_keys_after}",
                                   "token keys before and after key generation"])
            utils.validate(validation_list)
            get_key_dict = dict({"key_handle": str(KeyHandle), "key_type": key_type})
            cu_username = kwargs[self.function_name].get("cu_username")

            if cu_username:
                get_key_dict.update({"cu_name": cu_username})
            if SharedUsers:
                get_key_dict.update({"SharedUsers": SharedUsers})
            self.get_key_info(**{"get_key_info": get_key_dict})
        return output

    def create_public_key(self, *args, **kwargs):
        '''
        Creates RSA public key

        :param modulus:
            specifies the modulus in hex format
        :param exponent:
            specifies the exponent: eg. 3
            ex: modulus can be extracted using
                "openssl rsa -in <key file> -modulus" from host keys and
                "getAttribute -o <obj handle> -a 288 -out <file> " of Cfm2Util from HSM keys
        :param label:
            specifies the label
        :param session_key:
            specifies key as session key
        :param keyid:
            specifies key ID
        :param sub_attributes_wrap_file:
            specifies the file containing sub-attributes of WRAP_TEMPLATE attribute
        :param attribute_file:
            specifies attribute file(optional)
        :param cu_username:
            CU username who created this key (optional, for validation only)
        '''
        with allure.step('createpublickey'):
            with allure.step(f'getting PartitionInfo before creating public key'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])
            with allure.step(f'createPublickKey: {kwargs}'):
                output = self.cfm2util.createPublicKey(*args, **kwargs[self.function_name])
                pubkey = output["PublickeyHandle"]

                validation_list = []
                find_key = dict()
                if "session_key" in kwargs[self.function_name].keys():
                    key_type = "session"
                    session_keys_before += 1
                    find_key.update({"session_key": "1"})
                else:
                    key_type = "Token"
                    token_keys_before += 1
                    find_key.update({"session_key": "0"})

                find_key.update({"key_class": "2", "key_type": "0"})
                with allure.step("Verifying the imported public Key using findKey Command"):
                    findkey = self.find_key(**{"find_key": find_key})
                    total_pub_keys = findkey["Keysfound"]

                validation_list.append([pubkey, f"in {total_pub_keys}", "public key in findkey"])

                with allure.step(f'getting PartitionInfo after importing public key'):
                    partinfo = self.get_partition_info(*args, **kwargs)
                    token_keys_after = partinfo["OccupiedTokenKeys"]
                    session_keys_after = partinfo["OccupiedSessionKeys"]

                validation_list.append([session_keys_before, f"== {session_keys_after}",
                                        "session Keys before and after importing pub key"])
                validation_list.append([token_keys_before, f"== {token_keys_after}",
                                        "token keys before and after importing pub key"])

                get_key_dict = dict({"key_handle": pubkey})
                cu_username = kwargs[self.function_name].get("cu_username")
                if cu_username:
                    get_key_dict.update({"cu_name": cu_username})
                if key_type:
                    get_key_dict.update({"key_type": key_type})

                self.get_key_info(**{"get_key_info": get_key_dict})
                # add code to verify the keys in findallKeys
                utils.validate(validation_list)

        return output

    def del_token(self, *args, **kwargs):
        '''
        delete one or more  mofn token
        :param token_file_name:
            file which represents the token to be deleted
        :param delete_flag:
            -f #Delete Flags
            #2 for all tokens of Partitions
            #4 for all tokens of user
        '''
        with allure.step('deltoken'):
            output = self.cfm2util.delToken(*args, **kwargs[self.function_name])
            # How to verify which token got deleted
        return output

    def delete_key(self, *args, **kwargs):
        '''
        Delete a key specifying a key handle

        :param key_handle (single key or list of keys):
            key_hanlde = "8" or key_handle = ["5", "6", "7"]
            specifies the key handle to delete
        :return output:
            parsed output
        '''
        with allure.step('deletekey'):
            validate = []
            key_handle = kwargs[self.function_name].get("key_handle")
            key_handles = [key_handle] if isinstance(key_handle, str) else key_handle
            for key in key_handles:
                kwargs[self.function_name].update({"key_handle": key})
                output = self.cfm2util.deleteKey(*args, **kwargs[self.function_name])

            find_key = self.find_key(*args, **kwargs)
            keys_found = find_key["Keysfound"]
            for key in key_handles:
                validate.append([key, f"not in {keys_found}", "deleted key not found in listUsers"])

            utils.validate(validate)
        return output

    def delete_tombstone_key(self, *args, **kwargs):
        '''
        Mark the specified key handle invalid

        :param key_handle:
            specifies the key handle to delete
        :return output:
            return parsed_output
        '''
        with allure.step('deletetombstonekey'):
            validate = []
            key_handle = kwargs[self.function_name].get("key_handle")
            if isinstance(key_handle, str) or isinstance(key_handle, int):
                key_handles = [key_handle]
            else:
                key_handles = key_handle
            for key in key_handles:
                kwargs[self.function_name].update({"key_handle": key})
                deleteTombstoneKey = {"key_handle": key}
                with allure.step(f"executing tombstonekey for: {key}"):
                    output = self.cfm2util.deleteTombstoneKey(*args, **deleteTombstoneKey)
            with allure.step("Validating deleted tombstoned key not found in findKey command"):
                find_key = self.find_key(*args, **kwargs)
                keys_found = find_key["Keysfound"]
                for key in key_handles:
                    validate.append([key, f"not in {keys_found}", "deleted tombstoned key not"
                                                                  "found in findKey"])
        return output

    def derive_sym_key(self, *args, **kwargs):
        '''
        Derive a Symmetric  key

        :param basekey_handle:
            base key handle
        :param prf_label:
            specifies the Prf Label
        :param derive_key_label:
            specifies the Derive key Label
        :param prf_context:
            specifies the Prf Context
        :param SP800_108_counterwidth:
            SP800_108_counterwidth(supported values 16, 32, 64)
        :param dkm_counter_width:
            DKM_counterwidth(supported values 8, 16, 32,64)
        :param key_type:
            specifies the key type
        :param key_size:
            specifies the key size in bytes
        :param session_key:
            specifies key as session key(Optional)
        :param keyid:
            specifies key ID
        :param extractable:
            set the key as extractable (1) or non-extractable (0)
            (optional, valid if base key is non-extractable else this option will be ignored)
        :param users_list_to_share:
            specifies the list of users to share with (separated by ,) (optional)
        :param sessions_list:
            specifies the list of sessions to share with (separated by ,)
            (optional, valid only for session keys)
        :param total_users_to_approve:
            specifies the number of users to approve for any key service
        :param hash_type:
            to specify the hash type (Optional)
        '''
        with allure.step(f'derivesymkey with args: {kwargs}'):
            with allure.step(f'getting PartitionInfo before generating symmetric key'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])
            with allure.step("executing deriveSymKey"):
                output = self.cfm2util.deriveSymKey(*args, **kwargs[self.function_name])
                KeyHandle = int(output["keyhandle"])
                key_size = kwargs[self.function_name].get("key_size")  # need to Validate
                LOG.warning(f"need to validate {key_size}")

                find_key = dict()
                if "session_key" in kwargs[self.function_name].keys():
                    find_key.update({"session_key": "1"})
                    key_type = "session"
                    session_keys_before += 1
                else:
                    find_key.update({"session_key": "0"})
                    key_type = "Token"
                    token_keys_before += 1
                if "keyid" in kwargs[self.function_name].keys():
                    find_key.update({"keyid": kwargs[self.function_name]["keyid"]})

                if "sessions_list" in kwargs[self.function_name].keys():
                    find_key.update({"sessions_list": kwargs[self.function_name]["sessions_list"]})

                if "users_list_to_share" in kwargs[self.function_name].keys():
                    find_key.update({"users_list_to_share":
                                     kwargs[self.function_name]["users_list_to_share"]})

                find_key.update({"key_class": "4"})
                find_key.update({"key_type": kwargs[self.function_name]["key_type"]})
                find_key.update({"key_label": kwargs[self.function_name]["derive_key_label"]})

                with allure.step("Verifying the derived Symmetric Key using findKey Command"):
                    findkey = self.find_key(**{"find_key": find_key})
                secrete_keys = findkey["Keysfound"]
                validation_list = list()
                validation_list.append([str(KeyHandle), f"in {secrete_keys}",
                                        "derived Symm key in findkey"])

                with allure.step(f'getting PartitionInfo after deriving Symmetric keys'):
                    partinfo = self.get_partition_info(*args, **kwargs)
                    token_keys_after = partinfo["OccupiedTokenKeys"]
                    session_keys_after = partinfo["OccupiedSessionKeys"]
                validation_list.append([session_keys_before, f"== {session_keys_after}",
                                        "session Keys before and after key generation"])
                validation_list.append([token_keys_before, f"== {token_keys_after}",
                                       "token keys before and after key generation"])
                extractable = kwargs[self.function_name].get("extractable")
                # How to validate
                LOG.warning(f'{extractable} not verfied, please verify it')

                total_users_to_approve = kwargs[self.function_name].get("total_users_to_approve")
                # How to validate
                LOG.warning(f'{total_users_to_approve} not verfied, please verify it')

                utils.validate(validation_list)
                get_key_dict = dict({"key_handle": str(KeyHandle), "key_type": key_type})
                cu_username = kwargs[self.function_name].get("cu_username")
                SharedUsers = kwargs[self.function_name].get("users_list_to_share")

                if cu_username:
                    get_key_dict.update({"cu_name": cu_username})
                if SharedUsers:
                    get_key_dict.update({"SharedUsers": SharedUsers})
                self.get_key_info(**{"get_key_info": get_key_dict})

        return output

    def ex_sym_key(self, *args, **kwargs):
        '''
        Exports a Symmetric key

        :param wrap_key_handle:
            specifies the handle of the wrapping key
        :param key_handle:
            specifies the handle of the key to export:3DES/AES/RC4 key handle
        :param wrap_mechanism:
            specifies the wrapping mechanism (Optional)
        :param new_file_name:
            specifies the file to write the exported key
        :return output:
            parsed output
        '''
        with allure.step(f'performing export Symmetric Key with :{kwargs}'):
            with allure.step(f"Executing exSymKey"):
                output = self.cfm2util.exSymKey(*args, **kwargs[self.function_name])
        return output

    def export_private_key(self, *args, **kwargs):
        '''
        Export a private key

        :param priv_key_handle:
            specifies the private key handle to export
        :param wrap_key_handle:
            specifies the wrapping key handle
        :param wrap_mechanism:
            specifies the wrapping mechanism (Optional)
        :param new_file_name:
            specifies the file to write the exported private key
        :return output:
            parsed output
        '''
        with allure.step('exportprivatekey'):
            output = self.cfm2util.exportPrivateKey(*args, **kwargs[self.function_name])
        return output

    def export_pub_key(self, *args, **kwargs):
        '''
        Export a public key in PEM encoded format

        :param  pubkey_handle:
            specifies the public key handle
        :param new_file_name:
            specifies the file to write the exported public key
        :return output:
            parsed output
        '''
        with allure.step('exportpubkey'):
            output = self.cfm2util.exportPubKey(*args, **kwargs[self.function_name])
        return output

    def extract_masked_object(self, *args, **kwargs):
        '''
        Extracts a masked object

        :param object_handle:
            specifies the object handle to mask
        :param user_object:
            indicates that object to be extracted is user
        :param new_file_name:
            specifies the file to write the masked object
        :return output:
            parsed output
        '''
        with allure.step('extractmaskedobject'):
            output = self.cfm2util.extractMaskedObject(*args, **kwargs[self.function_name])
        return output

    def extract_masked_object_with_user_info(self, *args, **kwargs):
        '''
        Extracts a masked object with user details

        :param object_handle:
            specifies the object handle to mask
        :param new_file_name:
            specifies the file to write the masked object
        :return output:
            parsed output
        '''
        with allure.step('extractmaskedobjectwithuserinfo'):
            output = self.cfm2util.\
                     extractMaskedObjectWithUserInfo(
                                                     *args, **kwargs[
                                                         "extract_masked_object_with_user_info"])
        return output

    def find_key(self, *args, **kwargs):
        '''
        Find keys optionally matching the specified key class, key label and modulus

        :param key_class:
            specifies the key class to find (optional)
              2 = public
              3 = private
              4 = secret
        :param key_type:
            specifies the key type to find (optional)
              0  = RSA
              1  = DSA
              3  = EC
              16 = GENERIC_SECRET
              18 = RC4
              19 = DES
              21 = DES3
              31 = AES
        :param label:
            specifies the key label to find (optional)
        :param keyid_hex:
            specifies key ID in Hex (optional)
        :param session_key:
            specifies option to find only session keys(1) or only token keys(0) (optional)
        :param users_list_to_share:
            specifies the list of users shared with (separated by ,) (optional)
        :param sessions_list:
            specifies the list of sessions shared with (separated by ,)
            (optional, valid only for session keys)
        :param binary_rsa_file:
            specifies the binary file containing RSA modulus to match with (optional)
        :param key_check_value:
            specifies the Key Check Value to be searched for (optional)
        :param extended_key_check_value:
            specifies the Extended Key Check Value to be searched for (optional)
        :param der_attr_set_unset:
            specifies option to find only keys with derive attribute set(1) or
            only unset(0) (optional)
        :param sub_attributes_wrap_file:
            specifies the file containing sub-attributes of WRAP_TEMPLATE attribute(optional)
        :param sub_attributes_unwrap_file:
            specifies the file containing sub-attributes of UNWRAP_TEMPLATE attribute(optional)
        :param  attribute_file: specifies attribute file (optional)
        '''
        with allure.step(f'findKey with {kwargs}'):
            find_key = kwargs.get("find_key", dict())
            output = self.cfm2util.findKey(*args, **find_key)
            NumberofKeys = output["NumberofKeys"]
            if NumberofKeys:
                NumberofKeys = int(NumberofKeys)

            Keysfound = output["Keysfound"]
            if Keysfound:
                Keysfound = [key.strip() for key in Keysfound.split(",")]
            else:
                Keysfound = []
            output.update({"NumberofKeys": NumberofKeys, "Keysfound": Keysfound})
        return output

    def find_all_keys(self, *args, **kwargs):
        '''
        Find all keys of a partition, optionally matching specified user
        '''
        with allure.step('findallkeys'):
            output = self.cfm2util.findAllKeys(*args, **kwargs[self.function_name])
            NumberofKeys = output["NumberofKeys"]
            if NumberofKeys:
                NumberofKeys = int(NumberofKeys)

            Keysfound = output["Keysfound"]
            KeyStartIndices = output["KeyStartIndex"]
            KeyEndIndices = output["KeyEndIndex"]
            Keys = []
            if Keysfound and KeyStartIndices and KeyEndIndices:
                for key_value, key_start, key_end in zip(Keysfound, KeyStartIndices, KeyEndIndices):
                    keys = [key.strip() for key in key_value.split(",")]
                    utils.validate([int(key_start), f"in [0, {keys[0]}]",
                                    "Key Starting Index validation"])
                    Keys += keys
                    utils.validate([int(key_end), f"== {len(keys)}",
                                    "Key Ending Index validation"])

            utils.validate([NumberofKeys, f"== {len(Keys)}",
                            "Number of Keys validation"])
            output.update({"NumberofKeys": NumberofKeys, "Keysfound": Keys})
        return output

    def find_all_keys_as_count(self, *args, **kwargs):
        '''
        Find all keys of a partition, optionally matching specified user
        :param users_id:
            specifies the user id(optional)
        :return output:
            parsed output
        '''
        with allure.step('findallkeysascount'):
            output = self.cfm2util.findAllKeysAsCount(
                    *args, **kwargs[self.function_name])
            NumberofKeys = output["NumberofKeys"]
            if NumberofKeys:
                NumberofKeys = int(NumberofKeys)

            Keysfound = output["Keysfound"]
            if Keysfound:
                Keysfound = [key.strip() for key in Keysfound.split(",")]
            else:
                Keysfound = []
            output.update({"NumberofKeys": NumberofKeys, "Keysfound": Keysfound})
        return output

    def find_key_as_count(self, *args, **kwargs):
        '''
        Find keys optionally matching the specified key class, key label and modulus

        :param key_class:
            specifies the key class to find(optional)
        :param key_type:
            specifies the key type to find (optional)
        :param label:
            specifies the key label to find (optional)
        :param keyid:
            specifies key ID (optional)
        :param session_key:
            specifies option to find only session keys(1) or only token keys(0) (optional)
        :param users_list_to_share:
            specifies the list of users shared with (separated by ,) (optional)
        :param sessions_list:
            specifies the list of sessions shared with (separated by ,)
            (optional, valid only for session keys)
        :param rsa_file:
            specifies the file containing RSA modulus to match with (optional)
        :return output:
            parsed output
        '''
        with allure.step('findkeyascount'):
            output = self.cfm2util.findKeyAsCount(*args, **kwargs[self.function_name])
            NumberofKeys = output["NumberofKeys"]
            if NumberofKeys:
                NumberofKeys = int(NumberofKeys)

            TotalKeys = output["TotalKeys"]
            if TotalKeys:
                TotalKeys = int(TotalKeys)

            Keysfound = output["Keysfound"]
            if Keysfound:
                Keysfound = [key.strip() for key in Keysfound.split(",")]
            else:
                Keysfound = []
            output.update({"NumberofKeys": NumberofKeys, "Keysfound": Keysfound,
                           "TotalKeys": TotalKeys})
        return output

    def gen_sym_key(self, *args, validate=True, **kwargs):
        '''
        Generates a Symmetric  keys
        API takes no positional parameters
        :param key_label:
            specifies the Key Label
        :param key:
            specifies the key type
            (16 = GENERIC_SECRET, 18 = RC4, 21 = DES3, 31 = AES)
        :param key_size:
            specifies the key size in bytes
            for AES: 16, 24, 32  3DES: 24  RC4: <= 256, GENERIC_SECRET: <= 800
        :param session_key:
            specifies key as session key
        :param keyid:
            specifies key ID
        :param non_extractable_key:
            set the key as non-extractable
        :param attestation_check:
            does the attestation check for the received firmware response
        :param users_list_to_share:
            specifies the list of users to share with (separated by ,) (optional)
        :param sessions_list:
            specifies the list of sessions to share with (separated by ,)
            (optional, valid only for session keys)
        :param total_users_to_approve:
            specifies the number of users to approve for any key service
        :param sub_attributes_wrap_file:
            specifies the file containing sub-attributes of WRAP_TEMPLATE attribute
        :param sub_attributes_unwrap_file:
            specifies the file containing sub-attributes of UNWRAP_TEMPLATE attribute
        :param attribute_file:
            specifies attribute file (optional)
        :param cu_username:
            CU username  generating Sym Keys(optional, for validation only)
        :return  parsed output:
        '''
        with allure.step('gensymkey: {kwargs}'):

            with allure.step(f'getting PartitionInfo before generating symmetric key'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])
            with allure.step('generating Symmetric Key'):
                output = self.cfm2util.genSymKey(*args, **kwargs[self.function_name])
                KeyHandle = int(output["KeyHandle"])

                #Some testcases doesn't require validation
                if not validate:
                    return output

                key_size = kwargs[self.function_name].get("key_size")  # need to Validate
                LOG.warning(f"need to validate {key_size}")

                find_key = dict()
                if "session_key" in kwargs[self.function_name].keys():
                    find_key.update({"session_key": "1"})
                    key_type = "session"
                    session_keys_before += 1
                else:
                    find_key.update({"session_key": "0"})
                    key_type = "Token"
                    token_keys_before += 1

                find_key.update({"key_class": "4"})
                # kwargs.update({"find_key": find_key})
                SharedUsers = kwargs[self.function_name].get("users_list_to_share")
                if SharedUsers:
                    find_key.update({"users_list_to_share": SharedUsers})
                keyid = kwargs[self.function_name].get("keyid")
                if keyid:
                    find_key.update({"keyid": keyid})
                with allure.step("Verifying the generated Symmetric Key using findKey Command"):
                    # findkey = self.find_key(**kwargs[self.function_name])
                    findkey = self.find_key(**{"find_key": find_key})
                secrete_keys = findkey["Keysfound"]
                validation_list = list()
                validation_list.append([str(KeyHandle), f"in {secrete_keys}",
                                        "Symm key in findkey"])

                with allure.step(f'getting PartitionInfo after generating Symmetric keys'):
                    partinfo = self.get_partition_info(*args, **kwargs)
                    token_keys_after = partinfo["OccupiedTokenKeys"]
                    session_keys_after = partinfo["OccupiedSessionKeys"]

                validation_list.append([session_keys_before, f"== {session_keys_after}",
                                        "session Keys before and after key generation"])
                validation_list.append([token_keys_before, f"== {token_keys_after}",
                                       "token keys before and after key generation"])
                non_extractable = kwargs[self.function_name].get("non_extractable")
                # How to validate
                LOG.warning(f'{non_extractable} not verfied, please verify it')

                total_users_to_approve = kwargs[self.function_name].get("total_users_to_approve")
                # How to validate
            LOG.warning(f'{total_users_to_approve} not verfied, please verify it')

            if "attestation_check" in kwargs[self.function_name].keys():
                AttestationCheck = output.get("AttestationCheck", False)
                validation_list.append([AttestationCheck, f'== PASS',
                                        'AttestationCheck'])
            utils.validate(validation_list)
            get_key_dict = dict({"key_handle": str(KeyHandle), "key_type": key_type})
            cu_username = kwargs[self.function_name].get("cu_username")
            if cu_username:
                get_key_dict.update({"cu_name": cu_username})
            if SharedUsers:
                get_key_dict.update({"SharedUsers": SharedUsers})
            self.get_key_info(**{"get_key_info": get_key_dict})
        return output

    def get_attribute(self, *args, **kwargs):
        '''
        Get an attribute from an object
        API takes no positional parameters

        :param validate:
            dictionary of attribute_name to expected attribute value
            default is None, a dictionary can be passed to validate for validation
            example: Cfm2Util.get_attribute(validate={"OBJ_ATTR_KCV": "0x74ee1d"},
                                            **{"object_handle": eccpubkey, "read_attribute": "512",
                                               "new_file_name": "/home/attr_file"})
        :param object_handle:
            specifies the object handle
        :param read_attribute:
            specifies the attribute to read.(512 for all attributes)
        :param new_file_name:
            specifies the file to write the attribute value
        :param attestation_check:
            performs the attestation check on the firmware response
        :param undefined_value:
            Gets no defined values as 0xFF (Optional)
        :param cu_password:
            CU username for login before executing getattribute(password)
        :return return_output:
            {"attribute_dict": "key_attr_dict",
             "parsed_output": "parsed_output"}
        '''
        with allure.step('getattribute: {kwargs}'):
            with allure.step('executing getattribute'):
                output = self.cfm2util.getAttribute(*args, **kwargs[self.function_name])
                attribute_file = output["Writtento"]
                if attribute_file:
                    self.device_ssh = duplicate_device(self.device)
                    attribute_content = self.device_ssh.execute(f"cat {attribute_file}")
                    attribute_content = attribute_content.split("\n")
                    attribute_dict = {attribute_content[i]: attribute_content[i+1] for i in
                                      range(len(attribute_content)-1) if i % 2 == 0}
                    self.device_ssh.disconnect()
            return_output = dict()
            return_output.update({"attribute_dict": attribute_dict, "parsed_output": output})

            validate = kwargs[self.function_name].get("validate")
            if validate:
                validation_list = []
                attr_dict = self.list_attributes(*args, **kwargs)
                for set_attribute, attr_value in validate.items():
                    try:
                        int(set_attribute)
                        attr_name = attr_dict[set_attribute]
                    except ValueError:
                        attr_name = set_attribute

                    actual_atrr_value = attribute_dict[attr_name]
                    # revist for other attribute types especially for file types
                    if actual_atrr_value in ['0x01', '0x00']:
                        if attr_value == "1":
                            attr_value = "0x01"
                        elif attr_value == "0":
                            attr_value = "0x00"
                    validation_list.append([actual_atrr_value, f'== "{attr_value}"',
                                            f"attribute value for {attr_name}"])

                utils.validate(validation_list)

        return return_output

    def get_cavium_priv_key(self, *args, **kwargs):
        '''
        Creates PrivateKey file for specified RSA private key handle

        :param privkey_handle:
            specifies the RSA private key handle
        :param new_file_name:
            specifies the file to write fake RSA private key
        :return output:
            parsed output
        '''
        with allure.step('getcaviumprivkey'):
            output = self.cfm2util.getCaviumPrivKey(*args, **kwargs[self.function_name])
        return output

    def get_key_info(self, *args, **kwargs):
        '''
        Show key info specifying a key handle
        :param key_handle:
            key handle for which the Information to be obtained
        :param key_type:
            type of the Key, session or Token/Flash (optional)
        :param cu_name:
            username of the owner of this key to verify if the
            given key_handle is actually owned by this User(cu_name) (optional)
        :param SharedUsers:
            a list of Users with whom this Key is shared with (optional, for validation only)
        :return output:
            parsed output
        '''
        with allure.step('getkeyinfo: {kwargs}'):
            with allure.step('executing getKeyInfo command'):
                output = self.cfm2util.getKeyInfo(*args, **kwargs[self.function_name])

            key_type = kwargs[self.function_name].get("key_type")
            cu_name = kwargs[self.function_name].get("cu_name")
            SharedUsers = kwargs[self.function_name].get("SharedUsers")
            validation_list = list()
            if key_type:
                actual_keytype = output['key_type']
                if key_type.upper() == "SESSION":
                    expected_keytype = "Owned by session"
                elif key_type.upper() in ["TOKEN", "FLASH", "TOKEN/FLASH"]:
                    expected_keytype = "Token/Flash Key"
                else:
                    LOG.error("Unkown expected keytype specified")
                    expected_keytype = key_type
                validation_list.append([actual_keytype, F"== {expected_keytype}",
                                        "current key type and actual key type"])

            if cu_name:
                owner_id = output["OwnedbyUser"]
                LOG.debug(f'Keyid {kwargs[self.function_name]["key_handle"]}'
                          f'is owned by user id {owner_id}')
                list_users = {"Filter": f"UserID={owner_id}"}
                list_users = self.list_users(*args, **{"list_users": list_users})
                actual_cuname = list(list_users.keys())[-1].upper()
                validation_list.append([cu_name, f"== {actual_cuname}",
                                        "current key owner and actual key owner"])
            if SharedUsers:
                if isinstance(SharedUsers, str):
                    SharedUsers = SharedUsers.split(",")
                actual_shared = output["SharedUsers"]
                for user in SharedUsers:
                    validation_list.append([user.strip(), f"in {actual_shared}",
                                            "user in actual shared list"])
            if output["SharedUserCount"] and output["UserApprovalCount"]:
                validation_list.append([int(output["SharedUserCount"]),
                                        f'>= {output["UserApprovalCount"]}',
                                        "SharedUserCount and Number of Users "
                                        "to approve for any Key service are same"])
            if validation_list:
                LOG.debug(f"validating key information: {validation_list}")
                utils.validate(validation_list)
        return output

    def get_policy(self, *args, **kwargs):
        '''
        getPolicy returns current HSM policies
        :param validate:
            dictionary of policyId to policyvalue  for validation only
        '''
        with allure.step('getpolicy'):
            output = self.cfm2util.getPolicy(*args, **kwargs)

        return_output = dict()
        for policy_dict in output:
            if policy_dict['Policyid']:
                policy_type, policy_name = policy_dict['Policyid'].split(":")
                policy_type = policy_type.strip()
                policy_name, policy_id = policy_name.split("[")
                policy_name = policy_name.strip()
                policy_id = policy_id.split("]")[0].strip()
                return_output.update({policy_name: {"Policyid": policy_id,
                                                    "policy_type": policy_type,
                                                    "policyvalue": policy_dict['policyvalue']},
                                      policy_id: {"policy_name": policy_name,
                                                  "policy_type": policy_type,
                                                  "policyvalue": policy_dict['policyvalue']}})
            else:
                return_output.update({"ReturnCode": policy_dict["ReturnCode"],
                                      "HSMReturn": policy_dict["HSMReturn"]})

        validate = kwargs.get("get_policy", dict()).get("validate")
        if validate:
            validation_list = []
            for key, value in validate.items():
                validation_list.append([return_output[key]["policyvalue"],
                                        f"== \"{value}\"", "after changing the policy value"])
            utils.validate(validation_list)
        return return_output

    def get_source_random(self, *args, **kwargs):
        '''
        Gets Source Random required for mutual trust protocol

        :param file_name:
            specifies the file to which source random has to be written
        :return output:
            parsed output
        '''
        with allure.step('getsourcerandom'):
            output = self.cfm2util.getSourceRandom(*args, **kwargs[self.function_name])
        return output

    def get_token(self, *args, **kwargs):
        '''
        Initiates an MxN auth service and returns a token
        :param flags:
            flags
        :param service_number:
            Service Number
        :param key_to_approve:
            Key to be approved (applicable only for USE_KEY and MANAGE_KEY services)
        :param username:
            user name
        :param token_file_name:
            File name to write the token
        :return output:
            return Parsed output
        '''
        with allure.step(f'gettoken: {kwargs}'):
            with allure.step(f'executing gettoken'):
                output = self.cfm2util.getToken(*args, **kwargs[self.function_name])
                validation = output
                validation.pop("HSMReturn")
                validation.pop("ReturnCode")
                validate_dict = {validation["TokenId"]: validation}
                self.list_tokens(**{"list_tokens": {"validate": validate_dict}})
        return output

    def get_token_info(self, *args, **kwargs):
        '''
        Get Token Info
        :param token_file:
            token file
        :return output:
            parsed output
        '''
        with allure.step(f'gettokeninfo: {kwargs}'):
            with allure.step('executing gettokenInfo'):
                output = self.cfm2util.getTokenInfo(*args, **kwargs[self.function_name])
                validation = output
                validation.pop("HSMReturn")
                validation.pop("ReturnCode")
                validate_dict = {validation["TokenId"]: validation}
                self.list_tokens(**{"list_tokens": {"validate": validate_dict}})
        return output

    def im_symkey(self, *args, validate=True, **kwargs):
        '''
        Imports a symmetric key
        :param key-label:
            specifies the new key's Label
        :param key_type:
            specifies the key type
        :param key_file_name:
            specifies the filename containing the key to import
        :param wrap_key_handle:
            specifies the wrapper key handle, 4 for KEK
        :param session_key:
            specifies key as session key
        :param keyid:
            specifies key ID
        :param users_list_to_share:
            specifies the list of users to share with (separated by ,) (optional)
        :param sessions_list:
            specifies the list of sessions to share with (separated by ,)
            (optional, valid only for session keys)
        :param attestation_check:
            performs the attestation check on the firmware response
        :param sub_attributes_wrap_file:
            specifies the file containing sub-attributes of WRAP_TEMPLATE attribute
        :param sub_attributes_unwrap_file:
            specifies the file containing sub-attributes of UNWRAP_TEMPLATE attribute
        :param attribute_file:
            specifies attribute file (optional)
        :param cu_username:
            specify the CU username importing the symmetric key(optional, for validation only)
        '''
        with allure.step('imsymkey'):

            with allure.step(f'getting PartitionInfo before importing symmetric key'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])
            with allure.step('importing Symmetric Key'):
                output = self.cfm2util.imSymKey(*args, **kwargs[self.function_name])
                KeyHandle = int(output["KeyHandle"])
                
                #Some testcases doesn't require validation
                if not validate:
                    return output
                wrap_key_handle = kwargs[self.function_name].get("wrap_key_handle")
                if wrap_key_handle:
                    LOG.info("need to verify imported key is wrapped with this key handle")

                find_key = dict()
                if "session_key" in kwargs[self.function_name].keys():
                    find_key.update({"session_key": "1"})
                    key_type = "session"
                    session_keys_before += 1
                else:
                    find_key.update({"session_key": "0"})
                    key_type = "Token"
                    token_keys_before += 1

                find_key.update({"key_class": "4"})
                SharedUsers = kwargs[self.function_name].get("users_list_to_share")
                if SharedUsers:
                    find_key.update({"users_list_to_share": SharedUsers})
                keyid = kwargs[self.function_name].get("keyid")
                if keyid:
                    find_key.update({"keyid": keyid})
                with allure.step("Verifying the imported Symmetric Key using findKey Command"):
                    findkey = self.find_key(**{"find_key": find_key})
                secrete_keys = findkey["Keysfound"]
                validation_list = list()
                validation_list.append([KeyHandle, f"in {secrete_keys}", "Symm key in findkey"])

                with allure.step(f'getting PartitionInfo after importing Symmetric keys'):
                    partinfo = self.get_partition_info(*args, **kwargs)
                    token_keys_after = partinfo["OccupiedTokenKeys"]
                    session_keys_after = partinfo["OccupiedSessionKeys"]

                validation_list.append([session_keys_before, f"== {session_keys_after}",
                                        "session Keys before and after importing key"])
                validation_list.append([token_keys_before, f"== {token_keys_after}",
                                       "token keys before and after importing key"])
                non_extractable = kwargs[self.function_name].get("non_extractable")
                # How to validate
                LOG.warning(f'{non_extractable} not verfied, please verify it')

                total_users_to_approve = kwargs[self.function_name].get("total_users_to_approve")
                # How to validate
                LOG.warning(f'{total_users_to_approve} not verfied, please verify it')

            attestation_check = kwargs[self.function_name].get("attestation_check")
            if attestation_check in ['', ' ']:
                AttestationCheck = output.get("AttestationCheck", False)
                validation_list.append([AttestationCheck, f'== PASS',
                                        'AttestationCheck'])
            get_key_dict = dict({"key_handle": str(KeyHandle), "key_type": key_type})

            cu_username = kwargs[self.function_name].get("cu_username")

            if SharedUsers:
                get_key_dict.update({"SharedUsers": SharedUsers})
            if cu_username:
                get_key_dict.update({"cu_name": cu_username})
            self.get_key_info(**{"get_key_info": get_key_dict})

        return output

    def import_private_key(self, *args, **kwargs):
        '''
        Imports RSA/DSA/EC Private Key
        API takes no positional parameters
        :param key_label:
            specifies the private key label
        :param key_file_name:
            specifies the filename containing the key to import
        :param wrap_key_handle:
            specifies the wrapping key handle (KEK handle - 4)
        :param session_key:
            specifies key as session key
        :param keyid:
            specifies key ID
        :param users_list_to_share:
            specifies the list of users to share with (separated by ,) (optional)
        :param sessions_list:
            specifies the list of sessions to share with (separated by ,)
            (optional, valid only for session keys)
        :param attestation_check:
            performs the attestation check on the firmware response
        :param sub_attributes_unwrap_file:
            specifies the file containing sub-attributes of UNWRAP_TEMPLATE attribute
        :param attribute_file:
            specifies attribute file (optional)
        :param cu_username:
            CU username importing private key (optional, for validation only)
        :return output:
            parsed output
        '''

        validation_list = list()
        with allure.step(f'importing private key with arguments: {kwargs}'):

            with allure.step(f'getting PartitionInfo before importing private key'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])
            with allure.step('importprivatekey'):
                output = self.cfm2util.importPrivateKey(*args, **kwargs[self.function_name])
                privkey = output["PrivatekeyHandle"]

                find_key = dict()
                if "session_key" in kwargs[self.function_name].keys():
                    key_type = "session"
                    session_keys_before += 1
                    find_key.update({"session_key": "1"})
                else:
                    key_type = "Token"
                    token_keys_before += 1
                    find_key.update({"session_key": "0"})

                find_key.update({"key_class": "3"})
                SharedUsers = kwargs[self.function_name].get("users_list_to_share")
                if SharedUsers:
                    find_key.update({"users_list_to_share": SharedUsers})
                keyid = kwargs[self.function_name].get("keyid")
                if keyid:
                    find_key.update({"keyid": keyid})
                with allure.step("Verifying the imported private Key using findKey Command"):
                    findkey = self.find_key(**{"find_key": find_key})
                    total_priv_keys = findkey["Keysfound"]

                validation_list.append([privkey, f"in {total_priv_keys}", "private key in findkey"])

                with allure.step(f'getting PartitionInfo after importing private keys'):
                    partinfo = self.get_partition_info(*args, **kwargs)
                    token_keys_after = partinfo["OccupiedTokenKeys"]
                    session_keys_after = partinfo["OccupiedSessionKeys"]

                validation_list.append([session_keys_before, f"== {session_keys_after}",
                                        "session Keys before and after importing private key"])
                validation_list.append([token_keys_before, f"== {token_keys_after}",
                                        "token keys before and after importing private key"])

                attestation_check = kwargs[self.function_name].get("attestation_check")
                if attestation_check in ['', ' ']:
                    AttestationCheck = output.get("AttestationCheck", False)
                    validation_list.append([AttestationCheck, f'== PASS',
                                            'AttestationCheck'])

                get_key_dict = dict({"key_handle": privkey})
                cu_username = kwargs[self.function_name].get("cu_username")

                if SharedUsers:
                    get_key_dict.update({"SharedUsers": SharedUsers})
                if cu_username:
                    get_key_dict.update({"cu_name": cu_username})
                if key_type:
                    get_key_dict.update({"key_type": key_type})

                self.get_key_info(**{"get_key_info": get_key_dict})
                # add code to verify the keys in findallKeys
                utils.validate(validation_list)

        return output

    def import_pub_key(self, *args, **kwargs):
        '''
        Import a PEM encoded public key onto HSM
        API takes no positional parameters
        :param key_label:
            label for the new key
        :param pem_pubkey_file:
            file containing the PEM encoded public key
        :param session_key:
            specifies key as session key
        :param keyid:
            specifies key ID
        :param sub_attributes_wrap_file:
            specifies the file containing sub-attributes of WRAP_TEMPLATE attribute
        :param attribute_file:
            specifies attribute file (optional)
        :param cu_username:
            cu username importing pub key (optional, for validation only)
        :return parsed output:
        '''

        validation_list = list()
        with allure.step(f'importing public key with arguments: {kwargs}'):

            with allure.step(f'getting PartitionInfo before importing public key'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])
            with allure.step('importpublickey'):
                output = self.cfm2util.importPubKey(*args, **kwargs[self.function_name])
                pubkey = output["PublickeyHandle"]

                find_key = dict()
                if "session_key" in kwargs[self.function_name].keys():
                    key_type = "session"
                    session_keys_before += 1
                    find_key.update({"session_key": "1"})
                else:
                    key_type = "Token"
                    token_keys_before += 1
                    find_key.update({"session_key": "0"})

                find_key.update({"find_key": "2"})
                with allure.step("Verifying the imported public Key using findKey Command"):
                    findkey = self.find_key(**{"find_key": find_key})
                    total_pub_keys = findkey["Keysfound"]

                validation_list.append([pubkey, f"in {total_pub_keys}", "public key in findkey"])

                with allure.step(f'getting PartitionInfo after importing public key'):
                    partinfo = self.get_partition_info(*args, **kwargs)
                    token_keys_after = partinfo["OccupiedTokenKeys"]
                    session_keys_after = partinfo["OccupiedSessionKeys"]

                validation_list.append([session_keys_before, f"== {session_keys_after}",
                                        "session Keys before and after importing pub key"])
                validation_list.append([token_keys_before, f"== {token_keys_after}",
                                        "token keys before and after importing pub key"])

                get_key_dict = dict({"key_handle": pubkey})
                cu_username = kwargs[self.function_name].get("cu_username")
                if cu_username:
                    get_key_dict.update({"cu_name": cu_username})
                if key_type:
                    get_key_dict.update({"key_type": key_type})

                self.get_key_info(**{"get_key_info": get_key_dict})
                # add code to verify the keys in findallKeys
                utils.validate(validation_list)

        return output

    def import_rawrsa_private_key(self, *args, **kwargs):
        '''
        Imports RSA Private Key
        API takes no positional paramters
        :param key_label:
            specifies the private key label
        :param key_file_name:
            specifies the filename containing the key to import
        :param wrap_key_handle:
            specifies the wrapping key handle (KEK handle - 4)
        :param session_key:
             specifies key as session key
        :param cu_username:
            specify the CU username importing key(optional, validation only)
        :return output:
            parsed output
        '''
        validation_list = list()
        with allure.step(f'importing private key with arguments: {kwargs}'):

            with allure.step(f'getting PartitionInfo before importing rawrsaprivate key'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])
            with allure.step('importrawrsaprivatekey'):
                output = self.cfm2util.\
                        importRawRSAPrivateKey(*args, **kwargs[self.function_name])
                privkey = output["PrivatekeyHandle"]

                find_key = dict()
                if "session_key" in kwargs[self.function_name].keys():
                    key_type = "session"
                    session_keys_before += 1
                    find_key.update({"session_key": "1"})
                else:
                    key_type = "Token"
                    token_keys_before += 1
                    find_key.update({"session_key": "0"})

                find_key.update({"key_type": "RSA", "key_class": "3"})

                with allure.step("Verifying the imported rawrsaprivate Key using findKey Command"):
                    findkey = self.find_key(**{"find_key": find_key})
                    total_priv_keys = findkey["Keysfound"]

                validation_list.append([privkey, f"in {total_priv_keys}",
                                        "rawrsaprivate key in findkey"])

                with allure.step(f'getting PartitionInfo after importing rawrsaprivate key'):
                    partinfo = self.get_partition_info(*args, **kwargs)
                    token_keys_after = partinfo["OccupiedTokenKeys"]
                    session_keys_after = partinfo["OccupiedSessionKeys"]

                validation_list.append([session_keys_before, f"== {session_keys_after}",
                                        "session Keys before & after importing rawrsaprivate key"])
                validation_list.append([token_keys_before, f"== {token_keys_after}",
                                        "token keys before and after importing rawrsaprivate key"])

                attestation_check = kwargs[self.function_name].get("attestation_check")
                if attestation_check in ['', ' ']:
                    AttestationCheck = output.get("AttestationCheck", False)
                    validation_list.append([AttestationCheck, f'is {AttestationCheck}',
                                            'AttestationCheck'])

                get_key_dict = dict({"key_handle": privkey})
                get_key_dict.update({"key_type": key_type})

                cu_username = kwargs[self.function_name].get("cu_username")
                if cu_username:
                    get_key_dict.update({"cu_name": cu_username})

                self.get_key_info(**{"get_key_info": get_key_dict})
                # add code to verify the keys in findallKeys
                utils.validate(validation_list)

        return output

    def insert_masked_object(self, *args, **kwargs):
        '''
        Inserts a masked object
        :param key_file_name:
            specifies the file containing the masked key
        :param object_handle:
            request object/user handle (Optional)
        :param user_object:
            indicates that object to be inserted is user
        :param cu_username:
            CU username who inserts this masked object(optional, for validation only)
        :param key_type:
            whether a TOKEN KEY or SESSION KEY, (optional, for validation only)
        :return output:
            parsed output
        '''
        # object_handle case to be handled
        with allure.step('insertmaskedobject'):
            key_type = kwargs[self.function_name].get("key_type")
            if key_type:
                part_info = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(part_info["OccupiedTokenKeys"])
                session_keys_before = int(part_info["OccupiedSessionKeys"])

            output = self.cfm2util.insertMaskedObject(*args, **kwargs[self.function_name])
            KeyHandle = output["NewHandle"]

            validation_list = []
            foundkey = self.find_key()
            validation_list.append([KeyHandle, f'in {foundkey["Keysfound"]}',
                                    "inserted masked object in findKey"])
            get_key_dict = {"key_handle": KeyHandle}
            if key_type:
                get_key_dict.update({"key_type": kwargs[self.function_name]["key_type"]})
                part_info = self.get_partition_info(*args, **kwargs)
                token_keys_after = int(part_info["OccupiedTokenKeys"])
                session_keys_after = int(part_info["OccupiedSessionKeys"])
                if "SESSION" in key_type.upper():
                    validation_list.append([session_keys_after, f"== {session_keys_before+1}",
                                            "session keys incremented by 1 after"
                                            "masked object insertion"])
                    validation_list.append([token_keys_after, f"== {token_keys_before}",
                                            "token keys are not incremented"])
                elif "TOKEN" in key_type.upper() or "FLASH" in key_type.upper():
                    validation_list.append([token_keys_after, f"== {token_keys_before+1}",
                                            "token keys incremented by 1 after masked"
                                            "object insertion"])
                    validation_list.append([session_keys_after, f"== {session_keys_before}",
                                            "session keys keys are not incremented"])
            utils.validate(validation_list)
            if kwargs[self.function_name].get("cu_username"):
                get_key_dict.update({"cu_name": kwargs[self.function_name]["cu_username"]})
            self.get_key_info(**{"get_key_info": get_key_dict})

        return output

    def insert_masked_object_with_user_info(self, *args, **kwargs):
        '''
        Inserts a masked object with user details

        :param key_file_name:
            specifies the file containing the masked key
        :param object_handle:
            request object handle (Optional)
        :param force_insert:
            force insert (on certain cases) if object handle is already used (Optional)
        :param cu_username:
            CU username who inserts this masked object(optional, for validation only)
        :param key_type:
            whether a TOKEN KEY or SESSION KEY, (optional, for validation only)
        :return output:
            parsed output
        '''
        with allure.step('insertmaskedobjectwithuserinfo'):
            key_type = kwargs[self.function_name].get("key_type")
            if key_type:
                part_info = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(part_info["OccupiedTokenKeys"])
                session_keys_before = int(part_info["OccupiedSessionKeys"])

            output = self.cfm2util.insertMaskedObjectWithUserInfo(
                            *args, **kwargs[self.function_name])
            KeyHandle = output["NewHandle"]

            validation_list = []
            output = self.login_status(*args, **kwargs[self.function_name])
            if output['UserType'] == "CO":
                foundkey = self.find_all_keys()
            elif output['UserType'] == "CU":
                foundkey = self.find_key()
            validation_list.append([KeyHandle, f'in {foundkey["Keysfound"]}',
                                    "inserted masked object in findKey"])
            get_key_dict = {"key_handle": KeyHandle}
            if key_type:
                get_key_dict.update({"key_type": kwargs[self.function_name]["key_type"]})
                part_info = self.get_partition_info(*args, **kwargs)
                token_keys_after = int(part_info["OccupiedTokenKeys"])
                session_keys_after = int(part_info["OccupiedSessionKeys"])
                if "SESSION" in key_type.upper():
                    validation_list.append([session_keys_after, f"== {session_keys_before+1}",
                                            "session keys incremented by 1 after"
                                            "masked object insertion"])
                    validation_list.append([token_keys_after, f"== {token_keys_before}",
                                            "token keys are not incremented"])
                elif "TOKEN" in key_type.upper() or "FLASH" in key_type.upper():
                    validation_list.append([token_keys_after, f"== {token_keys_before+1}",
                                            "token keys incremented by 1 after masked"
                                            "object insertion"])
                    validation_list.append([session_keys_after, f"== {session_keys_before}",
                                            "session keys keys are not incremented"])

            utils.validate(validation_list)
            if kwargs[self.function_name].get("cu_username"):
                get_key_dict.update({"cu_name": kwargs[self.function_name]["cu_username"]})
            self.get_key_info(**{"get_key_info": get_key_dict})

        return output

    def list_attributes(self, *args, **kwargs):
        '''
        possible attribute values for getAttributes
        return: dictionary of attribute name and correspodning value and vice versa
        '''
        with allure.step('listattributes'):
            output = self.cfm2util.listAttributes(*args, **kwargs.get("list_attributes", dict()))
            ret_output = {each["Attrname"]: each["Attrvalue"] for each in output}
            ret_output.update({value: key for key, value in ret_output.items()})
        return ret_output

    def list_ecccurveid(self, *args, **kwargs):
        '''
        HSM supported ECC CurveIds
        '''
        with allure.step('listecccurveids'):
            output = self.cfm2util.listECCCurveIds(*args, **kwargs.get("list_ecccurveid", dict()))
            output = {each['Eccname']: each['Eccvalue'] for each in output}
        return output

    def register_mofn_pubkey(self, *args, **kwargs):
        '''
        Register user's MofN public key
        :param usertype:
            specifies the user type as "CO(for CO/PCO)" or "CU"
        :param auth_tag:
            <any char string> specifies the authentication tag
        :param username:
            specifies the user name
        :param rsa2k_pkey_file_path:
            RSA 2K private key file path
        :return output:
            parsed output
        '''
        with allure.step(f'registermofnpubkey: {kwargs}'):
            with allure.step('executing registermofnpubkey'):
                output = self.cfm2util.registerMofnPubKey(*args, **kwargs[self.function_name])
                list_users = self.list_users(*args, **kwargs)
                username = kwargs[self.function_name]["username"]
                utils.validate([list_users[username.lower()]["MofnPubKey"], "== YES",
                                "MofnPubKey status in listUsers"])
        return output

    def restore_partition(self, *args, **kwargs):
        '''
        Restore the Partition's configuration and user details

        :param absolute_directory:
            Absolute directory containing backed-up files
        :param restoration_flag:
            flag to indicate type of restoration.
        :param mechanism:
            mechanism
        :param integrity_check:
            Does integrity check of restored content, if it fail, partition will be zeroized
        :param kbk_file:
            File containing the KBK in plain (Optional, valid only when
            using KBK_WRAP_WITH_KEK or KBK_WRAP_WITH_CERT_AUTH_DERIVED_KEY)
        :param return output:
            parsed output
        '''
        with allure.step('restorepartition'):
            output = self.cfm2util.restorePartition(*args, **kwargs[self.function_name])
        return output

    def set_attribute(self, *args, **kwargs):
        '''
        Set an attribute value for an object
        :param object_handle:
            specifies the Object Handle
        :param attribute:
            specifies the Attribute to set
        :param attribute_value:
            specifies the value of the Attribute to be set
        :return output:
            parsed output
        '''
        with allure.step(f'setattribute {kwargs}'):
            with allure.step(f'executing setAttribute Command'):
                output = self.cfm2util.setAttribute(*args, **kwargs[self.function_name])
            key_handle = kwargs[self.function_name]["object_handle"]
            set_attribute = kwargs[self.function_name]["attribute"]
            attribute_value = kwargs[self.function_name]["attribute_value"]

            self.get_attribute(**{"get_attribute": {"validate": dict({set_attribute:
                               attribute_value}),
                                                    "object_handle": key_handle,
                                                    "read_attribute": "512",
                                                    "new_file_name":
                                                    f"Mtaf_attr_file_{key_handle}"}})
        return output

    def set_auditudd(self, *args, **kwargs):
        '''
        Set/Clear the audit UDD, This is appended to the audit log for next command

        :param data_max_length:
            to specify the user defined data Max Length 32
            (optional. If not specified, clears the Audit UDD)
        :param clear_on_use:
            clear on use (optional, and should be used only with -d option) (default: FALSE)
        :return output:
            parsed output
        '''
        with allure.step('setauditudd'):
            output = self.cfm2util.setAuditUDD(*args, **kwargs[self.function_name])
        return output

    def set_policy(self, *args, **kwargs):
        '''
        Sets HSM policy

        :param policy_id:
            policy ID. To see the list of supported policies, run getPolicy command
        :param value:
            value of the policy to be set
        :return output:
            parsed output
        '''
        with allure.step('setpolicy'):
            output = self.cfm2util.setPolicy(*args, **kwargs[self.function_name])
            with allure.step("validating setPolicy"):

                self.get_policy(validate={kwargs[self.function_name]["policy_id"]:
                                kwargs[self.function_name]["value"]})
        return output

    def share_key(self, *args, **kwargs):
        '''
        Share a key specifying a key handle
        :param unshare_key:
            unshare key
        :param key_handle:
            specifies the key handle to share/unshare
        :param users_list_to_share:
            specifies the list of users to share/unshare with
        :param sessions_list:
            specifies the list of sessions to share/unshare with, Decimal value required.
        :return output:
            parsed output
        '''
        with allure.step(f'Share_key {kwargs}'):
            with allure.step('executing shaereKey'):
                share_key = self.cfm2util.shareKey(*args, **kwargs[self.function_name])
            key_handle = kwargs[self.function_name]["key_handle"]
            users_list_to_share = kwargs[self.function_name].get("users_list_to_share")
            output = self.get_key_info(**{"get_key_info": {"key_handle": key_handle}})
            actual_share_list = output["SharedUsers"]

            if users_list_to_share:
                if isinstance(users_list_to_share, str):
                    users_list_to_share = users_list_to_share.split(",")
                if "unshare_key" in kwargs[self.function_name]:
                    utils.validate([[userid, f"not in {actual_share_list}",
                                     f"{userid} not in {actual_share_list}"]
                                    for userid in users_list_to_share])
                else:
                    utils.validate([[userid, f"in {actual_share_list}",
                                     f"{userid} in {actual_share_list}"]
                                    for userid in users_list_to_share])

            # have to validate session sharing

        return share_key

    def sign(self, *args, **kwargs):
        '''
        Generates signature on the given data with given Private Key

        :param message_file:
            Message File
        :param privkey_handle:
            Private key handle
        :param signature_mechanism:
            Signature Mechanism
            SHA1_RSA_PKCS       - 0
            SHA256_RSA_PKCS     - 1
            SHA384_RSA_PKCS     - 2
            SHA512_RSA_PKCS     - 3
            SHA224_RSA_PKCS     - 4
            SHA1_RSA_PKCS_PSS   - 5
            SHA256_RSA_PKCS_PSS - 6
            SHA384_RSA_PKCS_PSS - 7
            SHA512_RSA_PKCS_PSS - 8
            SHA224_RSA_PKCS_PSS - 9
            DSA_SHA1            - 10
            DSA_SHA224          - 11
            DSA_SHA256          - 12
            DSA_SHA384          - 13
            DSA_SHA512          - 14
            ECDSA_SHA1          - 15
            ECDSA_SHA224        - 16
            ECDSA_SHA256        - 17
            ECDSA_SHA384        - 18
            ECDSA_SHA512        - 19
        :param new_file_name:
            file name to write the signature
        :return output:
            parsed output
        '''
        with allure.step('sign'):
            output = self.cfm2util.sign(*args, **kwargs[self.function_name])
        return output

    def source_key_exchange(self, *args, **kwargs):
        '''
        Get's Key Exchange Message from HSM

        :param key_file_name:
            specifies the file to write source key exchange message
        :return output:
            parsed output
        '''
        with allure.step('sourcekeyexchange'):
            output = self.cfm2util.sourceKeyExchange(*args, **kwargs[self.function_name])
        return output

    def store_cert(self, *args, **kwargs):
        '''
        Stores Certificate in the HSM

        :param cert_file_name:
            cert_file_name
        :param cert_owner:
            specifies owner of the certificate
        :return output:
            parsed output
        '''
        with allure.step('storecert'):
            output = self.cfm2util.storeCert(*args, **kwargs[self.function_name])
        return output

    def store_user_fixedkey(self, *args, **kwargs):
        '''
        Stores User fixed key

        :param key_file_name:
            specifies the fixed key file
        :param wrap_mechanism:
            specify the transport mechanism
        :return output:
            parsed output
        '''
        with allure.step('storeuserfixedkey'):
            output = self.cfm2util.storeUserFixedKey(*args, **kwargs[self.function_name])
        return output

    def target_key_exchange(self, *args, **kwargs):
        '''
        Validates's Key Exchange Message from Peer

        :param key_file_name:
            specifies the file containing tar
        :return output:
            parsed output
        '''
        with allure.step('targetkeyexchange'):
            output = self.cfm2util.targetKeyExchange(*args, **kwargs[self.function_name])
        return output

    def tombstone_key(self, *args, **kwargs):
        '''
        Mark the specified key handle invalid
        :param key_handle:
            specifies the key handle to delete
        '''
        with allure.step('tombstonekey'):
            validate = []
            key_handle = kwargs[self.function_name].get("key_handle")

            if isinstance(key_handle, str) or isinstance(key_handle, int):
                key_handles = [key_handle]
            else:
                key_handles = key_handle

            for key in key_handles:
                tombstoneKey = {"key_handle": key}
                with allure.step("executing tombstonekey"):
                    output = self.cfm2util.tombstoneKey(*args, **tombstoneKey)
            with allure.step("Validating tombstoned key not found in findKey command"):
                find_key = self.find_key(*args, **kwargs)
            keys_found = find_key["Keysfound"]
            for key in key_handles:
                validate.append([key, f"not in {keys_found}", "tombstonekey not found in findKey"])
            utils.validate(validate)
        return output

    def unwrap_key(self, *args, **kwargs):
        '''
        Unwraps sensitive keys onto HSM

        :para wrap_key_file:
            specifies the filename containing the Wrapped key
        :param unwrap_key_handle:
            specifies the unwrapping key handle (KEK handle - 4)
        :param wrap_mechanism:
            specifies the wrapping mechanism (Optional)
        :param hash_type:
            to specify the hash type (Optional) valid for RSA_AES, RSA_OAEP
        :param session_key:
            specifies key as session key
        :param aad_file_name:
            specifies the filename containing AAD for AES GCM mechanism (Optional)
        :param tag_length:
            specifies the Tag length(8 or 12 or 16) for AES GCM mechanism (Optional)
        :param  attestation_check:
            performs the attestation check on the firmware response
        :param cu_username:
            CU Username unwraping key(optional, for validation only)
        '''
        with allure.step('unwrapkey'):
            with allure.step(f'getting PartitionInfo before executing unwrapkey'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])

            with allure.step('Executing unwarpkey'):
                output = self.cfm2util.unWrapKey(*args, **kwargs[self.function_name])

            validation_list = list()
            with allure.step('Executing find key'):
                if "session_key" in kwargs[self.function_name].keys():
                    find_key = self.find_key(**{"find_key": {"session_key": "1"}})
                    session_keys_before += 1
                    key_type = "Session"
                else:
                    find_key = self.find_key(**{"find_key": {"session_key": "0"}})
                    token_keys_before += 1
                    key_type = "token"

            with allure.step(f'getting PartitionInfo after executing unWrapKey'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_after = partinfo["OccupiedTokenKeys"]
                session_keys_after = partinfo["OccupiedSessionKeys"]

                validation_list.append([session_keys_before, f"== {session_keys_after}",
                                        "session Keys before and after importing key"])
                validation_list.append([token_keys_before, f"== {token_keys_after}",
                                       "token keys before and after importing key"])
            if "attestation_check" in kwargs[self.function_name]:
                validation_list.append([output["AttestationCheck"], "== PASS", "attestationCheck"])
            validation_list.append([output["UnwrappedKeyHandle"], f'in {find_key["Keysfound"]}',
                                   'unwrappedkey in findKey'])

            get_key_dict = dict({"key_handle": str(output["UnwrappedKeyHandle"]),
                                 "key_type": key_type})
            cu_username = kwargs[self.function_name].get("cu_username")
            if cu_username:
                get_key_dict.update({"cu_name": cu_username})
            self.get_key_info(**{"get_key_info": get_key_dict})

            utils.validate(validation_list)
        return output

    def unwrap_key2(self, *args, **kwargs):
        '''
        Unwraps sensitive keys onto HSM

        :para wrap_key_file:
            specifies the filename containing the Wrapped key
        :param unwrap_key_handle:
            specifies the unwrapping key handle (KEK handle - 4)
        :param wrap_mechanism:
            specifies the wrapping mechanism (Optional)
        :param hash_type:
            to specify the hash type (Optional) valid for RSA_AES, RSA_OAEP
        :param session_key:
            specifies key as session key
        :param aad_file_name:
            specifies the filename containing AAD for AES GCM mechanism (Optional)
        :param tag_length:
            specifies the Tag length(8 or 12 or 16) for AES GCM mechanism (Optional)
        :param  attestation_check:
            performs the attestation check on the firmware response
        :param cu_username:
            CU Username unwraping key(optional, for validation only)
        '''
        with allure.step('unwrapkey2'):

            with allure.step(f'getting PartitionInfo before executing unwrapkey'):
                partinfo = self.get_partition_info(*args, **kwargs[self.function_name])
                token_keys_before = int(partinfo["OccupiedTokenKeys"])
                session_keys_before = int(partinfo["OccupiedSessionKeys"])

            with allure.step('Executing unwarpkey2'):
                output = self.cfm2util.unWrapKey2(*args, **kwargs[self.function_name])

            validation_list = list()
            with allure.step('Executing find key'):
                if "session_key" in kwargs[self.function_name].keys():
                    find_key = self.find_key(**{"find_key": {"session_key": "1"}})
                    session_keys_before += 1
                    key_type = "session"
                else:
                    find_key = self.find_key(**{"find_key": {"session_key": "0"}})
                    token_keys_before += 1
                    key_type = "token"

            with allure.step(f'getting PartitionInfo after executing unWrapKey2'):
                partinfo = self.get_partition_info(*args, **kwargs)
                token_keys_after = partinfo["OccupiedTokenKeys"]
                session_keys_after = partinfo["OccupiedSessionKeys"]

                validation_list.append([session_keys_before, f"== {session_keys_after}",
                                        "session Keys before and after importing key"])
                validation_list.append([token_keys_before, f"== {token_keys_after}",
                                       "token keys before and after importing key"])
            if "attestation_check" in kwargs[self.function_name]:
                validation_list.append([output["AttestationCheck"], "== PASS", "attestationCheck"])
            validation_list.append([output["UnwrappedKeyHandle"], f'in {find_key["Keysfound"]}',
                                   'unwrappedkey in findKey'])

            get_key_dict = dict({"key_handle": str(output["UnwrappedKeyHandle"]),
                                 "key_type": key_type})
            cu_username = kwargs[self.function_name].get("cu_username")
            if cu_username:
                get_key_dict.update({"cu_name": cu_username})
            self.get_key_info(**{"get_key_info": get_key_dict})

            utils.validate(validation_list)

        return output

    def validate_cert(self, *args, **kwargs):
        '''
        Validates Certificate

        :param certificate_file:
            specifies the file containing peer's certificate
        :param random_file:
            specifies the file containing peer's random
        :param data_file:
            specifies the file containing peer's key exchagne data
        :param src_random_number_file:
            specifies the file to write source random number
        :param src_key_exchange_file:
            specifies the file to write source key exchagne data
        :return output:
            parsed output
        '''
        with allure.step('validatecert'):
            output = self.cfm2util.validateCert(*args, **kwargs[self.function_name])
        return output

    def verify(self, *args, **kwargs):
        '''
        Verifies signature on the given data with give Public Key
        :param message_file_name:
            Message File
        :param signature_file:
            Signature File
        :param pubkey_handle:
            Public key handle
        :param verification_mechanism:
            Verification Mechanism
        :return output
            parsed output
        '''
        with allure.step('verify'):
            output = self.cfm2util.verify(*args, **kwargs[self.function_name])
        return output

    def wrap_key(self, *args, **kwargs):
        '''
        Wraps sensitive keys from HSM to host

        :param key_handle:
            handle of the key to be wrapped
        :param wrap_key_handle:
            specifies the wrapping key handle (KEK handle - 4)
        :param wrap_mechanism:
            specifies the wrapping mechanism (Optional)
        :param hash_type:
            to specify the hash type (Optional) valid for RSA_AES, RSA_OAEP
        :param new_file_name:
            specifies the file to write the wrapped key data
        :param aad_file_name:
            specifies the filename containing AAD for AES GCM mechanism (Optional)
        :return output:
            parsed output
        '''
        with allure.step('wrapkey'):
            output = self.cfm2util.wrapKey(*args, **kwargs[self.function_name])
        return output

    def wrap_key2(self, *args, **kwargs):
        '''
        Wraps sensitive keys from HSM to host
        :param key_handle:
            handle of the key to be wrapped
        :param wrap_key_handle:
            specifies the wrapping key handle (KEK handle - 4)
        :param wrap_mechanism:
            specifies the wrapping mechanism (Optional)
        :param hash_type:
            to specify the hash type (Optional) valid for RSA_AES, RSA_OAEP
        :param new_file_name:
            specifies the file to write the wrapped key data
        :param aad_file_name:
            specifies the filename containing AAD for AES GCM mechanism (Optional)
        :return output:
            parsed output
        '''
        with allure.step('wrapkey2'):
            output = self.cfm2util.wrapKey2(*args, **kwargs[self.function_name])
        return output

    def compute_mac(self, *args, **kwargs):
        '''
        Computes MAC for given input data

        :param key_handle: AES key key_handle. Can pass gensymkey/imsymkey to get
                           Keyhandle from respective functions
        :param msg_len: Length of the message passed
        :param msg_file:  Message File
        :param out:Output file
        '''
        with allure.step('Compute MAC'):
            if kwargs[self.function_name]['key_handle'] == "gensymkey":
                output = self.gen_sym_key(*args, **kwargs)
                key_handle = output['KeyHandle']
                LOG.info(f"gen_sym_key Key handle {key_handle} updated in compute_mac HAPI")
                kwargs[self.function_name].update({"key_handle": key_handle})
            elif kwargs[self.function_name]['key_handle'] == "imsymkey":
                output = self.im_symkey(*args, **kwargs)
                key_handle = output['KeyHandle']
                LOG.info(f"im_symkey Key handle {key_handle} updated in compute_mac HAPI")
                kwargs[self.function_name].update({"key_handle": key_handle})
            output = self.cfm2util.computeMAC(*args, **kwargs[self.function_name])
        return output
