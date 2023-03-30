"""
Python program for listing the vms on an ESX / vCenter host
"""

import atexit
import argparse
import getpass
import ssl
import os
import base64

from pyVim import connect
from pyVmomi import vmodl
from pyVmomi import vim

from credentials import get_vcenter_credentials

def prompt_for_password(args):
    if not args.user or not args.password:
        vcenter_username, vcenter_password = get_vcenter_credentials()
        if vcenter_username and vcenter_password:
            args.user = vcenter_username
            args.password = vcenter_password
        else:
            if not args.user:
                args.user = input("Enter vCenter username: ")
            if not args.password:
                args.password = getpass.getpass(prompt="Enter vCenter password: ")

    return args



def setup_args():
    parser = argparse.ArgumentParser(description='Process args for connecting to vCenter')
    parser.add_argument('-s', '--host', required=True, action='store', help='Remote host to connect to')
    parser.add_argument('-o', '--port', type=int, default=443, action='store', help='Port to use, default 443')
    parser.add_argument('-u', '--user', required=False, action='store', help='User name to use when connecting to host')
    parser.add_argument('-p', '--password', required=False, action='store', help='Password to use when connecting to host')
    return prompt_for_password(parser.parse_args())


def main():
    args = setup_args()
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode = ssl.CERT_NONE

        service_instance = connect.SmartConnect(host=args.host,
                                                user=args.user,
                                                pwd=args.password,
                                                port=int(args.port),
                                                sslContext=context)

        atexit.register(connect.Disconnect, service_instance)

        content = service_instance.RetrieveContent()
        container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
        vm_list = container.view

        print("Virtual Machines in the vCenter:")
        for vm in vm_list:
            print(vm.summary.config.name)

    except vmodl.MethodFault as error:
        print("Caught vmodl fault : " + error.msg)
        return -1

    return 0


# Start program
if __name__ == "__main__":
    main()
