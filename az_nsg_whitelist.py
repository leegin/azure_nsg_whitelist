from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.v2017_03_01.models import NetworkSecurityGroup
import azure.mgmt.network.v2017_03_01.models
from azure.mgmt.resource.resources import ResourceManagementClient
from ipaddress import ip_network, ip_address
from msrestazure.azure_exceptions import CloudError
import datetime
import getpass, subprocess,socket
import os,requests,json
from yaspin import yaspin
import creds
from msrest.exceptions import  SerializationError
import random


#service principal credentials
LOCATION = 'southeastasia'
AZURE_SUBSCRIPTION_ID = '<Subscription-id>'
AZURE_TENANT_ID = '<Tenant-id>'
AZURE_CLIENT_ID = '<client-id>'
AZURE_CLIENT_SECRET = '<client-secret>'


subscription_id = AZURE_SUBSCRIPTION_ID
credentials = ClientSecretCredential(
	client_id = AZURE_CLIENT_ID,
	client_secret = AZURE_CLIENT_SECRET,
	tenant_id = AZURE_TENANT_ID
)



resource_client = ResourceManagementClient(credentials, subscription_id)
network_client = NetworkManagementClient(credentials, subscription_id)
compute_client = ComputeManagementClient(credentials, subscription_id)



#check if the endpoint is pointing to a VM. If it is a VM, then this block will give the NSG name, RG name and the private IP of the instance.
def vms(Destination):
	instance_list = compute_client.virtual_machines.list_all()
	for i, instance in enumerate(instance_list):
		ni_reference = instance.network_profile.network_interfaces[0]
		ni_reference = ni_reference.id.split('/')
		ni_group = ni_reference[4]
		ni_name = ni_reference[8]
		try:
			net_interface = network_client.network_interfaces.get(ni_group, ni_name)
			ip_reference = net_interface.ip_configurations[0].public_ip_address
			if ip_reference is not None:
				ip_reference = ip_reference.id.split('/')
				ip_group = ip_reference[4]
				ip_name = ip_reference[8]
				public_ip = network_client.public_ip_addresses.get(ip_group, ip_name)
				public_ip = public_ip.ip_address
				if Destination  == public_ip:
					vm_ip = net_interface.ip_configurations[0].private_ip_address
					sub=net_interface.ip_configurations[0].subnet
					if sub is not None:
						sub_name = sub.id.split('/')[10]
						sub_rg= sub.id.split('/')[4]
						sub_vnet= sub.id.split('/')[8]
						nsg=network_client.subnets.get(sub_rg,sub_vnet,sub_name)
						nsg1=nsg.network_security_group
						if nsg1 is not None:
							rg=nsg1.id.split('/')[4]
							sg=nsg1.id.split('/')[8]
						elif nsg1 is None:
							pass
						return sg,rg,vm_ip
						break
					elif sub is None:
						pass
			elif ip_reference is None:
				vm_ip = net_interface.ip_configurations[0].private_ip_address
				if Destination  == vm_ip:
					sub=net_interface.ip_configurations[0].subnet
					if sub is not None:
						sub_name = sub.id.split('/')[10]
						sub_rg= sub.id.split('/')[4]
						sub_vnet= sub.id.split('/')[8]
						nsg=network_client.subnets.get(sub_rg,sub_vnet,sub_name)
						nsg1=nsg.network_security_group
						if nsg1 is not None:
							rg=nsg1.id.split('/')[4]
							sg=nsg1.id.split('/')[8]
						elif nsg1 is None:
							pass
						return sg,rg,vm_ip
						break
					elif sub is None:
						pass
		except CloudError as ex:
			pass


#Block to check if the given host is an application gateway. If it is a app gateway, then this block will give the NSG name, RG name and the private IP of the app gateway.
def app_gateways(Destination):
	instance_list = network_client.application_gateways.list_all()
	for i,instance in enumerate(instance_list):
		try:
			ip_reference = instance.frontend_ip_configurations[0].public_ip_address
			if ip_reference is not None:
				ip_reference = ip_reference.id.split('/')
				ip_group = ip_reference[4]
				ip_name = ip_reference[8]
				public_ip = network_client.public_ip_addresses.get(ip_group, ip_name)
				public_ip = public_ip.ip_address
				if Destination  == public_ip:
					pools = instance.backend_address_pools[0].backend_ip_configurations[0].id
					out = pools.split('/')
					result = network_client.network_interfaces.get(out[4],out[8])
					vm_ip = result.ip_configurations[0].private_ip_address
					sub=result.ip_configurations[0].subnet
					if sub is not None:
						sub_name = sub.id.split('/')[10]
						sub_rg= sub.id.split('/')[4]
						sub_vnet= sub.id.split('/')[8]
						nsg=network_client.subnets.get(sub_rg,sub_vnet,sub_name)
						nsg1=nsg.network_security_group
						if nsg1 is not None:
							rg=nsg1.id.split('/')[4]
							sg=nsg1.id.split('/')[8]
						elif nsg1 is None:
							pass
						return sg,rg,vm_ip
						break
					elif sub is None:
						pass
			elif ip_reference is None:
				ip_reference = instance.frontend_ip_configurations[0].private_ip_address
				if Destination == ip_reference:
					pools = instance.backend_address_pools[0].backend_ip_configurations[0].id
					out = pools.split('/')
					result = network_client.network_interfaces.get(out[4],out[8])
					vm_ip = result.ip_configurations[0].private_ip_address
					sub=result.ip_configurations[0].subnet
					if sub is not None:
						sub_name = sub.id.split('/')[10]
						sub_rg= sub.id.split('/')[4]
						sub_vnet= sub.id.split('/')[8]
						nsg=network_client.subnets.get(sub_rg,sub_vnet,sub_name)
						nsg1=nsg.network_security_group
						if nsg1 is not None:
							rg=nsg1.id.split('/')[4]
							sg=nsg1.id.split('/')[8]
						elif nsg1 is None:
							pass
						return sg,rg,vm_ip
						break
					elif sub is None:
						pass
		except CloudError as ex:
			pass

#Block to check if the given host is an LB. If it is a LB, then this block will give the NSG name, RG name and the private IP of the LB.
def load_balancer(Destination):
	lbs = network_client.load_balancers.list_all()
	for i, lb in enumerate(lbs):
		try:
			ip_reference1 = lb.frontend_ip_configurations[0].public_ip_address
			if ip_reference1 is not None:
				ip_reference = ip_reference1.id.split('/')
				ip_group = ip_reference[4]
				ip_name = ip_reference[8]
				public_ip = network_client.public_ip_addresses.get(ip_group, ip_name)
				public_ip = public_ip.ip_address
				if Destination  == public_ip:
					pools = lb.backend_address_pools[0].backend_ip_configurations[0].id
					out = pools.split('/')
					result = network_client.network_interfaces.get(out[4],out[8])
					vm_ip = result.ip_configurations[0].private_ip_address
					sub=result.ip_configurations[0].subnet
					if sub is not None:
						sub_name = sub.id.split('/')[10]
						sub_rg= sub.id.split('/')[4]
						sub_vnet= sub.id.split('/')[8]
						nsg=network_client.subnets.get(sub_rg,sub_vnet,sub_name)
						nsg1=nsg.network_security_group
						if nsg1 is not None:
							rg=nsg1.id.split('/')[4]
							sg=nsg1.id.split('/')[8]
						elif nsg1 is None:
							pass
						return sg,rg,vm_ip
						break
					elif sub is None:
						pass
			if ip_reference1 is  None:
				pass
		except CloudError as ex:
			pass

#Function that creates a rule in the NSG based on the inputs and output of other fuctions.
def create_nsg_rule(Priority, Name, Protocol, State, d_port, Source, Destination1, resource_group_name, network_security_group_name):
	resource_client.providers.register('Microsoft.Network')
	try:
		security_rule = network_client.security_rules.begin_create_or_update(resource_group_name, network_security_group_name, Name,
        	        {
                	        'access':azure.mgmt.network.v2017_03_01.models.SecurityRuleAccess.allow,
            	'description': State+' rule for port '+d_port,
           	 'destination_address_prefix': Destination1,
           	 'destination_port_range': d_port,
           	 'direction':azure.mgmt.network.v2017_03_01.models.SecurityRuleDirection.inbound,
           	 'protocol': Protocol,
           	 'source_address_prefixes': Source,
           	 'source_port_range': '*',
                	}
        	)
	except SerializationError as ex:
		security_rule = network_client.security_rules.begin_create_or_update(resource_group_name, network_security_group_name, Name,
                        {
                                'access':azure.mgmt.network.v2017_03_01.models.SecurityRuleAccess.allow,
                'description': State+' rule for port '+d_port,
                 'destination_address_prefix': Destination1,
                 'destination_port_range': d_port,
                 'direction':azure.mgmt.network.v2017_03_01.models.SecurityRuleDirection.inbound,
                 'priority': Priority,
                 'protocol': Protocol,
                 'source_address_prefix': Source,
                 'source_port_range': '*',
                        }
                )

#Before we create a rule in NSG, we will if the NSG already have any existing rule for the same port, source and destination IP addresses.
def check_rule_exist(d_port, Priority, Source, Destination,resource_group_name, network_security_group_name):
	global matched
	resource_client.providers.register('Microsoft.Network')
	security_rule = network_client.security_rules.list(resource_group_name, network_security_group_name)
	for r in security_rule:
		matched = False
		if r.__dict__['destination_port_range'] == d_port and r.__dict__['source_address_prefix'] == Source or Source in r.__dict__['source_address_prefixes'] and r.__dict__['destination_address_prefix'] == Destination:
			matched = True
	return matched


#This block will get the priorities of all the rules in a NSG
def get_priorities(resource_group_name, network_security_group_name):
	global priorities
	priorities = []
	security_rule = network_client.security_rules.list(resource_group_name, network_security_group_name)
	for r in security_rule:
        	priorities.append(r.__dict__['priority'])
	return priorities

#This bock will generate a random number between 100 and 4096 which is range of priorities which are allowed by azure. Here we check if we have any other rule with the same priority number and regnerate a new one.
def set_priority():
	pri=random.randint(100, 4096)
	if pri not  in priorities:
		priority=pri
	else:
		set_priority()
	return priority


#This is the function where we will get the IP address of the enpoint which we are going to whitelist. We are getting the details from the route53 backup server.
def dns_check(dom_name):
	print('\n'"Fetching the DNS file from route53 machine .......")
	with yaspin().white.bold.shark.on_blue as spinner:
		ssh_user = getpass.getuser().replace('.', '')
		jump_host = '<Jump-host-IP>'
		cmd = "rsync -avr --progress -e 'ssh -oStrictHostKeyChecking=no'  <Route53-hostname>:/tmp/backup_zones_`date +%F`_00-00*.txt . $2>/dev/null"
		ssh_call = ['ssh', '-A', '-oStrictHostKeyChecking=no', ssh_user + '@' + jump_host, cmd]
		subprocess.run(['ssh-add'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		p1 = subprocess.Popen(ssh_call, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
		(p1.communicate())
		cmd2 = ['rsync', "-avr", "--progress", ssh_user + '@' + jump_host + ":~/backup_zones_`date +%F`_00-00*.txt", '.']
		p2 = subprocess.Popen(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
		(p2.communicate())
		spinner.ok("✅ Finished")
	now = datetime.date.today()
	backupfile=os.popen("ls backup_zones_`date +%F`_00-00*.txt|head -1|awk '{print $1}'").read()
	dns_file = backupfile.rstrip("\n")
	domain = dom_name
	flag = 0

	with open(dns_file, 'r') as file_read:
		for line in file_read.readlines():
			if domain in line:
				flag = 1
				type_dns = line.split()[3]
				if type_dns == 'A':
					pub_ip = line.split()[4]
					return pub_ip
				elif type_dns == 'CNAME':
					host_dns_name = line.split()[4]
					pub_ip = socket.gethostbyname(host_dns_name.strip())
					return pub_ip
	if flag == 0:
		if 'stg' in domain:
			d=domain.split('.')
			new_domain = "*."+'.'.join(d[1:])
			with open(dns_file, 'r') as file_read:
				for line in file_read.readlines():
					if new_domain in line:
						type_dns = line.split()[3]
						if type_dns == 'A':
							pub_ip = line.split()[4]
							return pub_ip
						elif type_dns == 'CNAME':
							host_dns_name = line.split()[4]
							pub_ip = socket.gethostbyname(host_dns_name.strip())
							return pub_ip
		else:
			print("Domain doesn't exist in DNS"'\n\n')

#This function determines whether the endpoint points to a VM or App gw or an LB
def find_destination(Destination):
	ip = vms(Destination)
	if ip is not None:
		return ip[2]
	ip = app_gateways(Destination)
	if ip is not None:
		return ip[2]
	ip = load_balancer(Destination)
	if ip is not None:
		return ip[2]

#This function will get the NSG of the VM or App gw or an LB.
def get_network_group(Destination):
	nsg = vms(Destination)
	if nsg is not None:
		return nsg[0]
	nsg = app_gateways(Destination)
	if nsg is not None:
		return nsg[0]
	return load_balancer(Destination)[0]

#Function to get the RG name of VM or App gw or an LB
def get_resource_group(Destination):
	rg = vms(Destination)
	if rg is not None:
		return rg[1]
	rg = app_gateways(Destination)
	if rg is not None:
		return rg[1]
	return load_balancer(Destination)[1]

#Function to check if we want to whitelist more than 1 endpoint
def multiple_endpoints():
	decision=input("Do you want to whitelist any more endpoints?")
	yes = ['yes', 'y', 'ye', 'Y', 'Yes']
	no = ['no', 'n']
	if decision in yes:
		yes_no(verify)
	else:
		return

#Function where we get user input like JIRA ID, ports, source IP etc
def yes_no(verify):
	yes = ['yes', 'y', 'ye', 'Y', 'Yes']
	no = ['no', 'n', 'No']
	if verify in yes:
		while True:
			Name = input("Enter the rule name: ")
			if Name:
				break
			else:
				print("Invalid Rule name! Please enter a valid name for the rule")
				continue
		while True:
			d_port= input("Enter the destination port: ")
			if d_port:
				break
			else:
				print("Invalid desination port! Please enter a valid port number")
				continue
		while True:
			Protocol = input("Enter the protocol(Allowed values: Icmp,Tcp,Udp,*): ")
			proto = ['Icmp', 'Tcp' , 'Udp' , '*']
			if Protocol in proto:
				break
			else:
				print("Invalid protocol! Please enter the protocol from the available values")
				continue
		confirm = input("Are you whitelisting more than one source IP address?(Yes/No) ")
		if confirm in yes:
			IPs = input("Enter the source IP addresses: ")
			Source = IPs.split(',')
		else:
			Source = input("Enter the source IP address: ")
		while True:
			Host = input("Enter the endpoint: ")
			if Host:
				break
			else:
				print("Invalid endpoint! Please enter a valid endpoint")
				continue
		while True:
			State = input("allow or deny: ")
			if State:
				break
			else:
				print("Invalid state! Please enter a valid state")
				continue
		public_ip = dns_check(Host)
		print('\n'"Fetching the destination IP .....")
		with yaspin().white.bold.shark.on_blue as spinner:
			Destination = find_destination(public_ip)
			spinner.ok("✅ Finished")
		print("The Destination IP is "+Destination+'\n')
		print("Fetching the NSG in which the IP is to be whitelisted.....")
		with yaspin().white.bold.shark.on_blue as spinner:
			network_security_group_name = get_network_group(public_ip)
			spinner.ok("✅ Finished")
		print("The NSG is "+network_security_group_name+'\n')
		print("Fetching the Resource Group in which the IP is to be whitelisted.....")
		with yaspin().white.bold.shark.on_blue as spinner:
			resource_group_name = get_resource_group(public_ip)
			spinner.ok("✅ Finished")
		print("The RG is "+resource_group_name+'\n')
		Get_Priority = get_priorities(resource_group_name, network_security_group_name)
		Priority = set_priority()
		print("Checking if there is an existing rule for this IP or port .....")
		with yaspin().white.bold.shark.on_blue as spinner:
			check_rule_exist(d_port, Priority,  Source, Destination, resource_group_name, network_security_group_name)
			spinner.ok("✅ Finished")
			if matched == True:
				print("The rule already exist for the IP address or the priority number is already taken.")
			else:
				print("There is no existing rule for this IP address"'\n')
				print("Creating a rule in the NSG....")
				with yaspin().white.bold.shark.on_blue as spinner:
					create_nsg_rule(Priority, Name, Protocol, State, d_port, Source, Destination, resource_group_name, network_security_group_name)
					spinner.ok("✅ Finished")

	elif verify in no:
		print("Please verify manually from JIRA ID " + str(jira) + " and proceed")
	else:
		print("Please respond with 'yes' or 'no'")
		pass
	multiple_endpoints()

if __name__ == "__main__":
	jira = input("Enter the JIRA ID :: ")
	print('\n'"Following are the comments in the JIRA:" '\n')
	print("=" * 40)
	jira_url = "<JIRA-HOST>" + str(jira) + ""
	headers = {'Authorization': 'Basic <KEY>','Content-Type': 'application/json'}
	resp = requests.get(jira_url, headers=headers)
	response = json.loads(resp.content)
	for data in response['fields']['comment']['comments']:
        	author = data['author']['displayName']
        	body = data['body']
        	print('\n' + author + ' Commented as :' '\n' + body + '\n')
        	print("=" * 50)
	verify = input("If verification is completed please proceed :: press y/n:"'\n')
	yes_no(verify)
