"""
Python program for retrieving information of a specific VM on an ESX / vCenter host
and checking the /var/logs directory
"""

import atexit
import argparse
import getpass
import ssl
import os
import base64
import time

from pyVim import connect
from pyVmomi import vmodl
from pyVmomi import vim


class VMInfo:
    def __init__(self, host, user, password, port, vm_name):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.vm_name = vm_name
        self.service_instance = None
        self.connect_to_vcenter()

    def connect_to_vcenter(self):
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode = ssl.CERT_NONE

        self.service_instance = connect.SmartConnect(host=self.host,
                                                     user=self.user,
                                                     pwd=self.password,
                                                     port=self.port,
                                                     sslContext=context)

        atexit.register(connect.Disconnect, self.service_instance)

    def get_vm(self):
        content = self.service_instance.RetrieveContent()
        container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
        vm_list = container.view

        for vm in vm_list:
            if vm.summary.config.name == self.vm_name:
                return vm
        return None

    def check_vmware_tools_status(self, vm):
        if not vm:
            print("VM not found")
            return

        tools_status = vm.guest.toolsStatus
        tools_running_status = vm.guest.toolsRunningStatus

        print(f"VMware Tools status: {tools_status}")
        print(f"VMware Tools running status: {tools_running_status}")

        if tools_status == 'toolsOk' and tools_running_status == 'guestToolsRunning':
            print("VMware Tools is installed and running.")
        else:
            print("VMware Tools is either not installed or not running.")

    def check_var_logs(self, vm):
        if not vm:
            print(f"No VM found with the name '{self.vm_name}'")
            return

        content = self.service_instance.RetrieveContent()

        guest_base64_username = os.environ.get("GUEST_BASE64_USERNAME")
        guest_base64_password = os.environ.get("GUEST_BASE64_PASSWORD")

        if guest_base64_username and guest_base64_password:
            guest_username = base64.b64decode(guest_base64_username).decode('utf-8')
            guest_password = base64.b64decode(guest_base64_password).decode('utf-8')
        else:
            print("Error: Guest username and password not found in environment variables.")
            return

        content = self.service_instance.RetrieveContent()
        creds = vim.vm.guest.NamePasswordAuthentication(username='guest_username', password='guest_password')
        try:
            cmdspec = vim.vm.guest.ProcessManager.ProgramSpec(arguments='-la /var/logs', programPath='/bin/ls')
            cmd_pid = content.guestOperationsManager.processManager.StartProgramInGuest(vm=vm, auth=creds, spec=cmdspec)

            # Wait for the command to finish
            time.sleep(2)

            exit_code = content.guestOperationsManager.processManager.ListProcessesInGuest(vm=vm, auth=creds, pids=[cmd_pid])[0].exitCode
            if exit_code == 0:
                print("Access to /var/logs directory is successful.")
            else:
                print("Error accessing /var/logs directory. Exit code:", exit_code)

        except vim.fault.InvalidGuestLogin as e:
            print("Invalid guest login:", e.msg)
        except vim.fault.GuestPermissionDenied as e:
            print("Guest permission denied:", e.msg)
        except Exception as e:
            print("Error while checking /var/logs directory:", str(e))

    def print_vm_info(self, vm):
        if vm:
            print(f"VM Name: {vm.summary.config.name}")
            print(f"VM Guest OS: {vm.summary.config.guestFullName}")
            print(f"VM State: {vm.summary.runtime.powerState}")
        else:
            print(f"No VM found with the name '{self.vm_name}'")


def prompt_for_password(args):
    if not args.user:
        args.user = input("Enter vCenter username: ")

    if not args.password:
        base64_password = os.environ.get("VCENTER_BASE64_PASSWORD")
        if base64_password:
            args.password = base64.b64decode(base64_password).decode('utf-8')
        else:
            args.password = getpass.getpass(prompt="Enter vCenter password: ")

    return args


def setup_args():
    parser = argparse.ArgumentParser(description='Process args for connecting to vCenter')
    parser.add_argument('-s', '--host', required=True, action='store', help='Remote host to connect to')
    parser.add_argument('-o', '--port', type=int, default=443, action='store', help='Port to use, default 443')
    parser.add_argument('-u', '--user', required=False, action='store', help='User name to use when connecting to host')
    parser.add_argument('-p', '--password', required=False, action='store', help='Password to use when connecting to host')
    parser.add_argument('-n', '--vm_name', required=True, action='store', help='Name of the VM to retrieve information for')
    return prompt_for_password(parser.parse_args())


def main():
    args = setup_args()
    vm_info = VMInfo(args.host, args.user, args.password, args.port, args.vm_name)
    vm = vm_info.get_vm()
    vm_info.print_vm_info(vm)
    vm_info.check_vmware_tools_status(vm)
    vm_info.check_var_logs(vm)


# Start program
if __name__ == "__main__":
    main()

