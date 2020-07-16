"""
Test Class for Cfm2Util, Init_HSM in FIPSstate 2- Share Key -Test cases
"""
class TestFS2ShareKey():
    """
    Test Class for Cfm2Util, Init_HSM in FIPSstate 2- Test cases
    """
    def setup_method(self, method):
        """
        setup_method to get test data 
        """
        Data.testcases = Data.testsuites[__class__.__name__]['testcases']
        if method.__name__ in Data.testcases:
            Data.param = Data.testcases[method.__name__]
        else:
            Data.param = Data.testsuites['shared_data']

    def setup_class(cls):
        """
        This method sets the FIPS state of the HSM to 2.
        Create and Initialize Partitions.
        Create crypto_users.
        """
        Data.shared = Data.testsuites[__class__.__name__]['shared_data']
        #DisConnect cfm2util
        Data.cfm2utilapi.device.disconnect()
        time.sleep(2)
        #Zeroizing the HSM using Cfm2MasterUtil
        Data.cfm2masterutilapi.zeroize_hsm(**Data.shared)
        # Login with default login credentials
        Data.cfm2masterutilapi.login_hsm_default_co(**Data.shared)
        # Initialize the HSM
        Data.cfm2masterutilapi.init_hsm1(**Data.shared)
        #Login HSM with CO user
        Data.cfm2masterutilapi.login_hsm(**Data.shared)
        #Create Partition
        Data.cfm2masterutilapi.create_partition2(**Data.shared)
        #Connect cfm2util
        Data.cfm2utilapi.device.connect()
        time.sleep(2)
        #Gets the information of the HSM
        Data.cfm2utilapi.get_hsm_info()
        #zeroize the HSM using Cfm2Util
        Data.cfm2utilapi.zeroize_hsm()
        #Login HSM with default credentials
        Data.cfm2utilapi.login_default()
        #Inititializing the HSM using Cfm2Util
        Data.cfm2utilapi.init_hsm4(**Data.shared)
        #Login HSM with crypto_officer
        Data.cfm2utilapi.login_hsm(**Data.shared)
        #Create a new CU with the given username and password
        Data.cfm2utilapi.create_user(**Data.shared)
        #Create 10 CU with the given username and password
        cu_username = ['crypto_user%s '%str(i) for i in range(1, 11)]
        for crypto_user in cu_username:
            Data.shared["create_user"].update({'username': crypto_user})
            Data.cfm2utilapi.create_user(**Data.shared)
        #Connect Cfm2Util partition session
        part_name = Data.shared['partition_name']
        dev = connect_session(device=Data.cfm2utilapi, part_name=part_name)
        #Get HSM Info
        dev.get_hsm_info()
        #zeroize the HSM using Cfm2Util
        dev.zeroize_hsm()
        #Login HSM with default credentials
        dev.login_default()
        #Inititializing the HSM using Cfm2Util
        dev.init_hsm4(**Data.shared)
        #Login HSM with crypto_officer
        dev.login_hsm(**Data.shared)
        #Create a new CU with the given username and password
        Data.shared["create_user"].update({'username': 'crypto_user'})
        #time.sleep(1)
        dev.create_user(**Data.shared)
        #Create 7 CU with the given username and password
        cu_username = ['crypto_user%s '%str(i) for i in range(1, 8)]
        for crypto_user in cu_username:
            Data.shared["create_user"].update({'username': crypto_user})
            dev.create_user(**Data.shared)

    @allure.feature('LSFW-2.x-2438-1')
    def test_share_token_rsa_keys_while_generating_keys(self):
        """
        Share token RSA keys to random users while generating keys and
             to remaining users using share key.
            step1: Get Partition Info
            step2: Login HSM with crypto_user
            step3: Sharing keys with users while generating RSA token Keys
            step4: Sharing the keys
            step5: updating dictionary with key handle
            step6: Get Partition Info and Compare OccupiedTokenKeys
        """
        #Get partition info
        part_info = Data.cfm2utilapi.get_partition_info()
        occupiedtokenkeys_before = part_info['OccupiedTokenKeys']
        #Login HSM with crypto_user
        Data.cfm2utilapi.login_hsm2(**Data.param)
        #Sharing keys with users while generating RSA Key
        for m_l in range(2048, 4352, 256):
            Data.param["generate_rsa_keypair"].update({'modulus_length': str(m_l)})
            gen_rsa_key = Data.cfm2utilapi.generate_rsa_keypair(**Data.param)
            key = gen_rsa_key['PrivatekeyHandle']
            #Sharing the keys
            Data.param["share_key"].update({"key_handle": key})
            Data.cfm2utilapi.share_key(**Data.param)
        #Get Partition Info and Compare OccupiedTokenKeys
        part_info = Data.cfm2utilapi.get_partition_info()
        occupiedtokenkeys_after = part_info['OccupiedTokenKeys']
        total_occupiedtokenkeys = int(occupiedtokenkeys_after) - int(occupiedtokenkeys_before)
        utils.validate([total_occupiedtokenkeys, "== 18", 'Validating Total Occupied Keys'])

    @allure.feature('LSFW-2.x-2438-2')
    def test_share_session_rsa_keys_while_generating_keys(self):
        """
        Share session RSA keys to random users while generating keys and
             to remaining users using share key.
            step1: Get Partition Info
            step2: Login HSM with crypto_user
            step3: Sharing keys with users while generating RSA session Keys
            step4: Sharing the keys
            step5: Get Partition Info and Compare OccupiedTokenKeys
        """
        #Get partition info
        part_info = Data.cfm2utilapi.get_partition_info()
        occupiedtokenkeys_before = part_info['OccupiedTokenKeys']
        #Login HSM with crypto_user
        Data.cfm2utilapi.login_hsm2(**Data.param)
        #Sharing keys with users while generating RSA Key
        for m_l in range(2048, 4352, 256):
            Data.param["generate_rsa_keypair"].update({'modulus_length': str(m_l)})
            gen_rsa_key = Data.cfm2utilapi.generate_rsa_keypair(**Data.param)
            key = gen_rsa_key['PrivatekeyHandle']
            #Sharing the keys
            Data.param["share_key"].update({"key_handle": key})
            Data.cfm2utilapi.share_key(**Data.param)
        #Get Partition Info and Compare OccupiedTokenKeys
        part_info = Data.cfm2utilapi.get_partition_info()
        occupiedtokenkeys_after = part_info['OccupiedTokenKeys']
        total_occupiedtokenkeys = int(occupiedtokenkeys_after) - int(occupiedtokenkeys_before)
        utils.validate([total_occupiedtokenkeys, "== 0", 'Validating Total Occupied Keys'])

    @allure.feature('LSFW-2.x-2438-3')
    def test_share_token_dsa_keys_while_generating_keys(self):
        """
        Share token DSA keys to max users while generating keys.
            step1: Get Partition Info
            step2: Login HSM with crypto_user
            step3: Sharing keys with users while generating DSA token Keys
            step4: Sharing the keys
            step5: Get Partition Info and Compare OccupiedTokenKeys
        """
        #Get partition info
        part_info = Data.cfm2utilapi.get_partition_info()
        occupiedtokenkeys_before = part_info['OccupiedTokenKeys']
        #Login HSM with crypto_user
        Data.cfm2utilapi.login_hsm2(**Data.param)
        #Sharing keys with users while generating DSA Key
        for m_l in range(2048, 4096, 1024):
            Data.param["generate_dsa_keypair"].update({'modulus_length': str(m_l)})
            gen_dsa_key = Data.cfm2utilapi.generate_dsa_keypair(**Data.param)
            key = gen_dsa_key['PrivatekeyHandle']
            #Sharing the keys
            Data.param["share_key"].update({"key_handle": key})
            Data.cfm2utilapi.share_key(**Data.param)
        #Get Partition Info and Compare OccupiedTokenKeys
        part_info = Data.cfm2utilapi.get_partition_info()
        occupiedtokenkeys_after = part_info['OccupiedTokenKeys']
        total_occupiedtokenkeys = int(occupiedtokenkeys_after) - int(occupiedtokenkeys_before)
        utils.validate([total_occupiedtokenkeys, "== 4", 'Validating Total Occupied Keys'])

    @allure.feature('LSFW-2.x-2438-4')
    def test_share_session_dsa_keys_while_generating_keys(self):
        """
        Share session DSA keys to random users while
            generating keys and to remaining users using share key.
            step1: Get Partition Info
            step2: Login HSM with crypto_user
            step3: Sharing keys with users while generating DSA session Keys
            step4: Sharing the keys
            step5: Get Partition Info and Compare OccupiedTokenKeys
        """
        #Get partition info
        part_info = Data.cfm2utilapi.get_partition_info()
        occupiedtokenkeys_before = part_info['OccupiedTokenKeys']
        #Login HSM with crypto_user
        Data.cfm2utilapi.login_hsm2(**Data.param)
        #Sharing keys with users while generating DSA Key
        for m_l in range(2048, 4096, 1024):
            Data.param["generate_dsa_keypair"].update({'modulus_length': str(m_l)})
            gen_dsa_key = Data.cfm2utilapi.generate_dsa_keypair(**Data.param)
            key = gen_dsa_key['PrivatekeyHandle']
            #Sharing the keys
            Data.param["share_key"].update({"key_handle": key})
            Data.cfm2utilapi.share_key(**Data.param)
        #Get Partition Info and Compare OccupiedTokenKeys
        part_info = Data.cfm2utilapi.get_partition_info()
        occupiedtokenkeys_after = part_info['OccupiedTokenKeys']
        total_occupiedtokenkeys = int(occupiedtokenkeys_after) - int(occupiedtokenkeys_before)
        utils.validate([total_occupiedtokenkeys, "== 0", 'Validating Total Occupied Keys'])

    @allure.feature('LSFW-2.x-2438-5')
    def test_share_token_ecc_keys_while_generating_keys(self):
        """
        Share token ECC keys to random users while generating keys and to
            remaining users using share key.
            step1: Get Partition Info
            step2: Login HSM with crypto_user
            step3: Sharing keys with users while generating ECC token Keys
            step4: Sharing the keys
            step5: Get Partition Info and Compare OccupiedTokenKeys
        """
        #Get partition info
        part_info = Data.cfm2utilapi.get_partition_info()
        occupiedtokenkeys_before = part_info['OccupiedTokenKeys']
        #Login HSM with crypto_user
        Data.cfm2utilapi.login_hsm2(**Data.param)
        #Sharing keys with users while generating ECC Key
        for c_i in range(5, 17):
            Data.param["generate_ecc_keypair"].update({'curve_id': str(c_i)})
            gen_ecc_key = Data.cfm2utilapi.generate_ecc_keypair(**Data.param)
            key = gen_ecc_key['PrivatekeyHandle']
            #Sharing the keys
            Data.param["share_key"].update({"key_handle": key})
            Data.cfm2utilapi.share_key(**Data.param)
        #Get Partition Info and Compare OccupiedTokenKeys
        part_info = Data.cfm2utilapi.get_partition_info()
        occupiedtokenkeys_after = part_info['OccupiedTokenKeys']
        total_occupiedtokenkeys = int(occupiedtokenkeys_after) - int(occupiedtokenkeys_before)
        utils.validate([total_occupiedtokenkeys, "== 24", 'Validating Total Occupied Keys'])

    @allure.feature('LSFW-2.x-2438-6')
    def test_share_session_ecc_keys_while_generating_keys(self):
        """
        Share session ECC keys to max users while generating keys.
            step1: Get Partition Info
            step2: Login HSM with crypto_user
            step3: Sharing keys with users while generating ECC session Keys
            step4: Sharing the keys
            step5: Get Partition Info and Compare OccupiedTokenKeys
        """
        #Get partition info
        part_info = Data.cfm2utilapi.get_partition_info()
        occupiedtokenkeys_before = part_info['OccupiedTokenKeys']
        #Login HSM with crypto_user
        Data.cfm2utilapi.login_hsm2(**Data.param)
        #Sharing keys with users while generating ECC Key
        for c_i in range(5, 16):
            Data.param["generate_ecc_keypair"].update({'curve_id': str(c_i)})
            gen_ecc_key = Data.cfm2utilapi.generate_ecc_keypair(**Data.param)
            key = gen_ecc_key['PrivatekeyHandle']
            #Sharing the keys
            Data.param["share_key"].update({"key_handle": key})
            Data.cfm2utilapi.share_key(**Data.param)
        #Get Partition Info and Compare OccupiedTokenKeys
        part_info = Data.cfm2utilapi.get_partition_info()
        occupiedtokenkeys_after = part_info['OccupiedTokenKeys']
        total_occupiedtokenkeys = int(occupiedtokenkeys_after) - int(occupiedtokenkeys_before)
        utils.validate([total_occupiedtokenkeys, "== 0", 'Validating Total Occupied Keys'])

    @allure.feature('LSFW-2.x-2438-11')
    def test_share_rsa_keys_with_users_in_descending_order(self):
        """
        Share key with users with index in
            #descending order for RSA Key
            step1: Login HSM with crypto_user
            step2: Sharing keys with users in descending order for RSA Key
            step3: Sharing the keys
            step4: Get Partition Info and Compare OccupiedTokenKeys
        """
        #Login HSM with crypto_user
        Data.cfm2utilapi.login_hsm2(**Data.param)
        #Sharing keys with users while generating RSA Key
        for m_l in range(2048, 4352, 256):
            Data.param["generate_rsa_keypair"].update({'modulus_length': str(m_l)})
            gen_rsa_key = Data.cfm2utilapi.generate_rsa_keypair(**Data.param)
            key = gen_rsa_key['PrivatekeyHandle']
            #Sharing the keys
            Data.param["share_key"].update({"key_handle": key})
            Data.cfm2utilapi.share_key(**Data.param)

    @allure.feature('LSFW-2.x-2439-1')
    def test_import_private_key_as_token_keys_and_share(self):
        """
        import private key as token keys and share among random users
            (Less than 7 users)
            step1: DisConnect cfm2util
            step2: Connect cfm2util
            step3: Login HSM with crypto_user
            step4: Generate RSA key-pair
            step5: Generate a Symmetric  key.
            step6: Export private key
            step7: Disconnect cfm2util
            step8: Get HSM info
            step9: Zeroizing the HSM using Cfm2Util
            step10: Login HSM with default user
            step11: Inititializing the HSM using Cfm2Util
            step12: Login HSM with crypto_officer
            step13: Create 10 CU with the given username and password
            step14: set usertype value to default as crypto_user
            step15: Create a new CU with the given username and password
            step16: logout from HSM
            step17: Login HSM with crypto_user
            step18: Generate a Symmetric  key
            step19: Import private key
            step20: Share the key
            step21: Get Partition Info and Compare OccupiedTokenKeys
        """
        #DisConnect cfm2util
        Data.cfm2utilapi.device.disconnect()
        time.sleep(2)
        #Connect cfm2util
        Data.cfm2utilapi.device.connect()
        #Login HSM with crypto_user
        Data.cfm2utilapi.login_hsm2(**Data.param)
        #Generate RSA key-pair
        key_list = []
        for m_l in range(2048, 4352, 256):
            Data.param["generate_rsa_keypair"].update({'modulus_length': str(m_l)})
            gen_rsa_key = Data.cfm2utilapi.generate_rsa_keypair(**Data.param)
            key1 = gen_rsa_key['PrivatekeyHandle']
            key_list.append(key1)
        #Generate a Symmetric  key.
        gen_sym = Data.cfm2utilapi.gen_sym_key(**Data.param)
        #Export private key
        key3 = gen_sym['KeyHandle']
        for key1 in key_list:
            # updating dictionary with key handle
            Data.param["export_private_key"].update({"priv_key_handle": str(key1)})
            Data.param["export_private_key"].update({"wrap_key_handle": key3})
            Data.cfm2utilapi.export_private_key(**Data.param)
        #Connect Cfm2Util partition session
        part_name = Data.param['partition_name']
        dev = connect_session(device=Data.cfm2utilapi, part_name=part_name)
        #Get partition info
        part_info = dev.get_partition_info()
        occupiedtokenkeys_before = part_info['OccupiedTokenKeys']
        cu_username = ['crypto_user%s '%str(i) for i in range(1, 8)]
        #Login HSM with crypto_user
        Data.shared["login_hsm2"].update({'username': 'crypto_user'})
        dev.login_hsm2(**Data.shared)
        #Generate a Symmetric  key.
        gen_sym = dev.gen_sym_key(**Data.param)
        key3 = gen_sym['KeyHandle']
        # updating dictionary with key handle
        Data.param["import_private_key"].update({"wrap_key_handle": key3})
        for key in key_list:
            #Import private key
            im_pri_key = dev.import_private_key(**Data.param)
            key4 = im_pri_key['PrivatekeyHandle']
            #Sharing the keys
            Data.param["share_key"].update({"key_handle": key4})
            dev.share_key(**Data.param)
        #Verifying the shared keys with shared users
        for crypto_user in cu_username:
            #logout from HSM
            dev.logout_hsm()
            Data.param["login_hsm2"].update({'username': crypto_user})
            #Login HSM with crypto_user
            dev.login_hsm2(**Data.param)
            # find key handle for shared users
            dev.find_key(**Data.param)
        #Get Partition Info and Compare OccupiedTokenKeys
        part_info = dev.get_partition_info()
        occupiedtokenkeys_after = part_info['OccupiedTokenKeys']
        total_occupiedtokenkeys = int(occupiedtokenkeys_after) - int(occupiedtokenkeys_before)
        utils.validate([total_occupiedtokenkeys, "== 10", 'Validating Total Occupied Keys'])

    @allure.feature('LSFW-2.x-2439-2')
    def test_import_private_key_as_session_keys_and_share(self):
        """
        import private key as session keys and share among random users
            (Less than 7 users)
            step1: DisConnect cfm2util
            step2: Connect cfm2util
            step3: Login HSM with crypto_user
            step4: Generate RSA key-pair
            step5: Generate a Symmetric  key.
            step6: Export private key
            step7: Disconnect cfm2util
            step8: Get HSM info
            step9: Zeroizing the HSM using Cfm2Util
            step10: Login HSM with default user
            step11: Inititializing the HSM using Cfm2Util
            step12: Login HSM with crypto_officer
            step13: Create 7 CU with the given username and password
            step14: set usertype value to default as crypto_user
            step15: Create a new CU with the given username and password
            step16: logout from HSM
            step17: Login HSM with crypto_user
            step18: Generate a Symmetric  key
            step19: Import private key
            step20: Share the key
            step21: Get Partition Info and Compare OccupiedTokenKeys
        """
        #DisConnect cfm2util
        Data.cfm2utilapi.device.disconnect()
        time.sleep(2)
        #Connect cfm2util
        Data.cfm2utilapi.device.connect()
        #Login HSM with crypto_user
        Data.cfm2utilapi.login_hsm2(**Data.param)
        #Generate RSA key-pair
        key_list = []
        for m_l in range(2048, 4352, 256):
            Data.param["generate_rsa_keypair"].update({'modulus_length': str(m_l)})
            gen_rsa_key = Data.cfm2utilapi.generate_rsa_keypair(**Data.param)
            key1 = gen_rsa_key['PrivatekeyHandle']
            key_list.append(key1)
        #Generate a Symmetric  key.
        gen_sym = Data.cfm2utilapi.gen_sym_key(**Data.param)
        #Export private key
        key3 = gen_sym['KeyHandle']
        for key1 in key_list:
            # updating dictionary with key handle
            Data.param["export_private_key"].update({"priv_key_handle": str(key1)})
            Data.param["export_private_key"].update({"wrap_key_handle": key3})
            Data.cfm2utilapi.export_private_key(**Data.param)
        #Connect Cfm2Util partition session
        part_name = Data.param['partition_name']
        dev = connect_session(device=Data.cfm2utilapi, part_name=part_name)
        #Get partition info
        part_info = dev.get_partition_info()
        occupiedtokenkeys_before = part_info['OccupiedTokenKeys']
        cu_username = ['crypto_user%s '%str(i) for i in range(1, 8)]
        #Login HSM with crypto_user
        Data.shared["login_hsm2"].update({'username': 'crypto_user'})
        dev.login_hsm2(**Data.shared)
        #Generate a Symmetric  key.
        gen_sym = dev.gen_sym_key(**Data.param)
        key3 = gen_sym['KeyHandle']
        # updating dictionary with key handle
        Data.param["import_private_key"].update({"wrap_key_handle": key3})
        for key in key_list:
            #Import private key
            im_pri_key = dev.import_private_key(**Data.param)
            key4 = im_pri_key['PrivatekeyHandle']
            #Sharing the keys
            Data.param["share_key"].update({"key_handle": key4})
            dev.share_key(**Data.param)
        #Verifying the shared keys with shared users
        for crypto_user in cu_username:
            #logout from HSM
            dev.logout_hsm()
            Data.param["login_hsm2"].update({'username': crypto_user})
            #Login HSM with crypto_user
            dev.login_hsm2(**Data.param)
            # find key handle for shared users
            dev.find_key(**Data.param)
        #Get Partition Info and Compare OccupiedTokenKeys
        part_info = dev.get_partition_info()
        occupiedtokenkeys_after = part_info['OccupiedTokenKeys']
        total_occupiedtokenkeys = int(occupiedtokenkeys_after) - int(occupiedtokenkeys_before)
        utils.validate([total_occupiedtokenkeys, "== 1", 'Validating Total Occupied Keys'])

    @allure.feature('LSFW-2.x-2439-3')
    def test_import_raw_rsa_private_key_as_token_keys_and_share(self):
        """
        import raw rsa private key as token keys and share among random users
            (Less than 7 users)
            step:1 Login HSM with CO user
            step:2 Create Partition
            step3: Login HSM with crypto_user
            step4: Generate RSA key-pair
            step5: Generate a Symmetric  key.
            step6: Export private key
            step7: Disconnect cfm2util
            step8: Get HSM info
            step9: Zeroizing the HSM using Cfm2Util
            step10: Login HSM with default user
            step11: Inititializing the HSM using Cfm2Util
            step12: Login HSM with crypto_officer
            step13: Create 7 CU with the given username and password
            step14: set usertype value to default as crypto_user
            step15: Create a new CU with the given username and password
            step16: logout from HSM
            step17: Login HSM with crypto_user
            step18: Generate a Symmetric  key
            step19: Import raw rsa private key
            step20: Share the key
            step21: Get Partition Info and Compare OccupiedTokenKeys
            step22: Login with crypto_officer login credentials
            step23: Delete Partition
        """
        #DisConnect cfm2util
        Data.cfm2utilapi.device.disconnect()
        time.sleep(2)
        #Connect cfm2util
        Data.cfm2utilapi.device.connect()
        #Login HSM with crypto_user
        Data.cfm2utilapi.login_hsm2(**Data.param)
        #Generate RSA key-pair
        key_list = []
        for m_l in range(2048, 4352, 256):
            Data.param["generate_rsa_keypair"].update({'modulus_length': str(m_l)})
            gen_rsa_key = Data.cfm2utilapi.generate_rsa_keypair(**Data.param)
            key1 = gen_rsa_key['PrivatekeyHandle']
            key_list.append(key1)
        #Generate a Symmetric  key.
        gen_sym = Data.cfm2utilapi.gen_sym_key(**Data.param)
        #Export private key
        key3 = gen_sym['KeyHandle']
        for key1 in key_list:
            # updating dictionary with key handle
            Data.param["export_private_key"].update({"priv_key_handle": str(key1)})
            Data.param["export_private_key"].update({"wrap_key_handle": key3})
            Data.cfm2utilapi.export_private_key(**Data.param)
        #Connect Cfm2Util partition session
        part_name = Data.param['partition_name']
        dev = connect_session(device=Data.cfm2utilapi, part_name=part_name)
        #Get partition info
        part_info = dev.get_partition_info()
        occupiedtokenkeys_before = part_info['OccupiedTokenKeys']
        cu_username = ['crypto_user%s '%str(i) for i in range(1, 8)]
        #Login HSM with crypto_user
        Data.shared["login_hsm2"].update({'username': 'crypto_user'})
        dev.login_hsm2(**Data.shared)
        #Generate a Symmetric  key.
        gen_sym = dev.gen_sym_key(**Data.param)
        key3 = gen_sym['KeyHandle']
        # updating dictionary with key handle
        Data.param["import_rawrsa_private_key"].update({"wrap_key_handle": key3})
        for key in key_list:
            #Import private key
            im_pri_key = dev.import_rawrsa_private_key(**Data.param)
            key4 = im_pri_key['PrivatekeyHandle']
            #Sharing the keys
            Data.param["share_key"].update({"key_handle": key4})
            dev.share_key(**Data.param)
        #Verifying the shared keys with shared users
        for crypto_user in cu_username:
            #logout from HSM
            dev.logout_hsm()
            Data.param["login_hsm2"].update({'username': crypto_user})
            #Login HSM with crypto_user
            dev.login_hsm2(**Data.param)
            # find key handle for shared users
            dev.find_key(**Data.param)
        part_info = dev.get_partition_info()
        occupiedtokenkeys_after = part_info['OccupiedTokenKeys']
        total_occupiedtokenkeys = int(occupiedtokenkeys_after) - int(occupiedtokenkeys_before)
        utils.validate([total_occupiedtokenkeys, "== 10", 'Validating Total Occupied Keys'])

    @allure.feature('LSFW-2.x-2439-4')
    def test_import_raw_rsa_private_key_as_session_keys_and_share(self):
        """
        import RAW RSA private key as session keys and
              #share among random users (Less than 7 users)
            step:1 Login HSM with CO user
            step:2 Create Partition
            step3: Login HSM with crypto_user
            step4: Generate RSA key-pair
            step5: Generate a Symmetric  key.
            step6: Export private key
            step7: Disconnect cfm2util
            step8: Get HSM info
            step9: Zeroizing the HSM using Cfm2Util
            step10: Login HSM with default user
            step11: Inititializing the HSM using Cfm2Util
            step12: Login HSM with crypto_officer
            step13: Create 10 CU with the given username and password
            step14: set usertype value to default as crypto_user
            step15: Create a new CU with the given username and password
            step16: logout from HSM
            step17: Login HSM with crypto_user
            step18: Generate a Symmetric  key
            step19: Import raw rsa private key
            step20: Share the key
            step21: Get Partition Info and Compare OccupiedTokenKeys
            step22: Login with crypto_officer login credentials
            step23: Delete Partition
        """
        #DisConnect cfm2util
        Data.cfm2utilapi.device.disconnect()
        time.sleep(2)
        #Connect cfm2util
        Data.cfm2utilapi.device.connect()
        #Login HSM with crypto_user
        Data.cfm2utilapi.login_hsm2(**Data.param)
        #Generate RSA key-pair
        key_list = []
        for m_l in range(2048, 4352, 256):
            Data.param["generate_rsa_keypair"].update({'modulus_length': str(m_l)})
            gen_rsa_key = Data.cfm2utilapi.generate_rsa_keypair(**Data.param)
            key1 = gen_rsa_key['PrivatekeyHandle']
            key_list.append(key1)
        #Generate a Symmetric  key.
        gen_sym = Data.cfm2utilapi.gen_sym_key(**Data.param)
        #Export private key
        key3 = gen_sym['KeyHandle']
        for key1 in key_list:
            # updating dictionary with key handle
            Data.param["export_private_key"].update({"priv_key_handle": str(key1)})
            Data.param["export_private_key"].update({"wrap_key_handle": key3})
            Data.cfm2utilapi.export_private_key(**Data.param)
        #Connect Cfm2Util partition session
        part_name = Data.param['partition_name']
        dev = connect_session(device=Data.cfm2utilapi, part_name=part_name)
        #Get partition info
        part_info = dev.get_partition_info()
        occupiedtokenkeys_before = part_info['OccupiedTokenKeys']
        cu_username = ['crypto_user%s '%str(i) for i in range(1, 8)]
        #Login HSM with crypto_user
        Data.shared["login_hsm2"].update({'username': 'crypto_user'})
        dev.login_hsm2(**Data.param)
        #Generate a Symmetric  key.
        gen_sym = dev.gen_sym_key(**Data.param)
        key3 = gen_sym['KeyHandle']
        # updating dictionary with key handle
        Data.param["import_rawrsa_private_key"].update({"wrap_key_handle": key3})
        for key in key_list:
            #Import private key
            im_pri_key = dev.import_rawrsa_private_key(**Data.param)
            key4 = im_pri_key['PrivatekeyHandle']
            #Sharing the keys
            Data.param["share_key"].update({"key_handle": key4})
            dev.share_key(**Data.param)
        #Verifying the shared keys with shared users
        for crypto_user in cu_username:
            #logout from HSM
            dev.logout_hsm()
            Data.param["login_hsm2"].update({'username': crypto_user})
            #Login HSM with crypto_user
            dev.login_hsm2(**Data.param)
            # find key handle for shared users
            dev.find_key(**Data.param)
        part_info = dev.get_partition_info()
        occupiedtokenkeys_after = part_info['OccupiedTokenKeys']
        total_occupiedtokenkeys = int(occupiedtokenkeys_after) - int(occupiedtokenkeys_before)
        utils.validate([total_occupiedtokenkeys, "== 1", 'Validating Total Occupied Keys'])
        # Login with crypto_officer login credentials
        Data.cfm2masterutilapi.login_hsm(**Data.param)
        #Delete Partition
        Data.cfm2masterutilapi.delete_partition2(**Data.param)
