import os
import sys
from subprocess import Popen, PIPE
import re
import random
import string
import time
import filecmp
import allure
from common.logger import MtafLogger
from common import base
from liquidsec.utils import liquidsec_exception
from common.utils import utils
from common.utils import mtaf_exception
from liquidsec.api.Cfm2Util import Cfm2Util 
from liquidsec.api.Cfm2MasterUtil import Cfm2MasterUtil 
from liquidsec.config.firmware import *
import subprocess

class Data():
    '''
    To load the parameters from the testbed.yaml and input.yaml.
    '''
    params = ''
    log = MtafLogger.get_logger('Cfm2Util', level=10)


# To import all .py files in current directory
FILES = os.listdir("./")
for filename in FILES:
    if filename == "{}.py".format(__name__): continue
    # execute only .py files
    if  os.path.isfile(filename) and filename.endswith(".py"):
        data = open(filename, "rb").read()
        exec(compile(data, filename, "exec"))

def setup_module():
    '''
     Sets up the  required variables  before starting the test execution.
    '''
    params = base.ztp()
    Data.log.debug('Params:{}'.format(Data.params))
    dut = list(params['input']['tests']['dut'][0].keys())[0]
    dut_libs = params['input']['tests']['dut'][0][dut]
    Data.dut_libs = dut_libs
    testbed = params['testbed']
    Data.testbed = testbed
    dut_dict = {}
    for lib in dut_libs.keys():
        dut_dict.update({ lib : testbed.get_device(dut, alias=lib, lib_path=dut_libs[lib])})
        try:
            dut_dict[lib].connect()
        except Exception as e:
            dut_dict[lib].disconnect()
            Data.log.info('Connection failed for {}. Assuming this is taken care in setupclass'.format(lib))
    dut_dict.update({ 'host' : testbed.get_device(dut, alias='host', lib_path='/bin/bash')})
    dut_dict['host'].connect()
    cfm2masterutil = dut_dict['Cfm2MasterUtil']
    cfm2util = dut_dict['Cfm2Util']
    linux = dut_dict['host']
    Data.cfm2util_input = dut
    Data.cfm2masterutilapi = Cfm2MasterUtil(cfm2masterutil)
    Data.cfm2utilapi = Cfm2Util(cfm2util)
    Data.linux = linux
    Data.testsuites = params['input']['tests']

def connect_session(device='', lib_path='', part_name=''):
    """
    Connecting Cfm2Util partition session

    :param device: Cfm2util object or device name
    :param lib_path: Cfm2util lib path 
    :param part_name: Partition to be connected
    :return : Cfm2Util HAPI object
    """
    if isinstance(device, Cfm2Util):
        dut = device.device.name
        dut_lib_path = device.device.lib_path
    else:
        dut = device
    if lib_path:
        dut_lib_path = lib_path
    lib_path = dut_lib_path + f" -p {part_name}"
    dev_object = Data.testbed.get_device(dut, lib_path=lib_path)
    session_details = dev_object.connect().split('\n')
    dev_object.session_handle = re.findall(r'\w+(.*)',session_details[4])[0].strip()
    return Cfm2Util(dev_object)

