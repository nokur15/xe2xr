from sys import argv
from ciscoconfparse import CiscoConfParse
import re
from pprint import pprint
from jinja2 import Template

class xe2xr_template():
    def __init__(self):
        self.l2_trunk_template = '''
        interface {{interface}}.{{vlan}} l2transport
         {%- if description != None %}
         description {{description}}
         {%- endif %}
         encapsulation dot1q {{vlan}} exact
         rewrite ingress tag pop {{native}} symmetric

         l2vpn
          bridge group BVI
           bridge-domain {{vlan}}
            storm-control multicast kbps 400
            storm-control broadcast kbps 400
            interface {{interface}}.{{vlan}}
            !
            routed interface BVI{{vlan}}
        !
        '''
        self.l3_interface_template = '''
        {%- for l3_interface in l3_interfaces %}
        interface {{l3_interface['interface']}}
         {%- if vrf != None %}
         vrf {{vrf}}
         {%- endif %}
         {%- if l3_interface['description'] != None %}
         description {{l3_interface['description']}}
         {%- endif %}
         {%- if l3_interface['ipv4'] != None %}
         ipv4 address {{l3_interface['ipv4']}} {{l3_interface['netmask']}}
         {%- endif %}
         load-interval 30
         {%- if l3_interface['arp_timeout'] %}
         arp timeout {{l3_interface['arp_timeout']}}
         {%- endif %}
         {%- if l3_interfaces['shutdown'] == False %}
         shutdown
         {%- endif %}
        !
        {%- if l3_interface['hsrp_enable'] %}
        router hsrp
         interface {{l3_interface['interface']}}
          address-family ipv4
          {%- if l3_interface['hsrp_version'] != None %}
          hsrp version {{l3_interface['hsrp_version']}}
          {%- endif %}
          hsrp {{l3_interface['hsrp_group']}}
          {%- if l3_interface['hsrp_preempt'] == True %}
          preempt
          {%- endif %}
          {%- if l3_interface['hsrp_priority'] %}
          priotiy {{l3_interface['hsrp_priority']}}
          {%- endif %}
          address {{l3_interface['hsrp_ip']}}
        !
        {%- endif %}
        {%- endfor %}
        '''
        self.static_route = '''
        router static
        {%- if vrf != None %} 
         vrf {{vrf}}
        {%- endif %}
         address-family ipv4 unicast
          {%- for network in networks %}
          {{network['dst_network']}} {{network['netmask']}} {{network['gateway']}} {% if network['tag'] != None %}tag {{network['tag']}}{% endif %} {% if network['description'] != None %}description {{network['description']}}{% endif %}
          {%- endfor %}
        '''
    
    def xr_static_route(self, vrf=None, networks=[]):        
        static_route = Template(self.static_route)
        result = static_route.render(vrf=vrf, networks=networks)
        return result

    def xr_trunk_interface(self, interface=None, description=None, mode='access', vlan=[], native=None, protocol=None):
        data_trunk = {
            'interface' : interface,
            'description' : description,
            'native' : native
        }
        result = str()
        for vl in vlan:
            trunk_interface = Template(self.l2_trunk_template)
            result += trunk_interface.render(**data_trunk, vlan=vl)
        
        return result
            
    def xr_l3_interface(self, vrf=None, l3_interfaces=[]):
        l3_interface = Template(self.l3_interface_template)
        result = l3_interface.render(vrf=vrf, l3_interfaces=l3_interfaces)
        return result
    
class xe2xr():
    def __init__(self, file):
        self.ciscoparse = CiscoConfParse(file)
    
    def find_vrf_interface(self):
        vrfes_cmd = self.ciscoparse.find_objects_w_child(parentspec=r'interface', childspec=r'ip vrf forwarding')
        vrfes = []
        for vrf_cmd in vrfes_cmd:
            for vrf in vrf_cmd.children:
                if 'ip vrf forwarding' in vrf.text:
                    vrf_re = re.search('ip vrf forwarding (\S+)', vrf.text)
                    vrfes.append(vrf_re.group(1))
        
        return set(vrfes)

    def find_l2_interface(self):
        interfaces_cmd = self.ciscoparse.find_objects_w_child(parentspec=r'interface', childspec=r'switchport')
        interfaces = list()
        for interface_cmd in interfaces_cmd:
            interface = {
                'interface' : None,
                'description' : None,
                'mode' : 'access',
                'vlan' : 1
            }
            trunk = {
                'protocol' : 'dot1q',
                'vlan' : 'all',
                'native' : 1
            }
            int_name = re.search('interface (\S+)', interface_cmd.text)
            interface['interface'] = int_name.group(1).replace('Port-Channel', 'Bundle-Ether')
            for cmd in interface_cmd.children:
                if 'description' in cmd.text:
                    int_desc = re.search('description (.+)', cmd.text)
                    interface['description'] = int_desc.group(1)
                elif 'switchport mode trunk' in cmd.text:
                    interface['mode'] = 'trunk'
                elif 'switchport trunk encapsulation' in cmd.text:
                    trunk_protocol = re.search('switchport trunk encapsulation (\w+)', cmd.text)
                    trunk['protocol'] = trunk_protocol.group(1)
                elif 'switchport trunk allowed vlan' in cmd.text:
                    vlans = re.findall('\d+', cmd.text)
                    trunk['vlan'] = vlans
                elif 'switchport trunk native vlan' in cmd.text:
                    native = re.search('\d+', cmd.text)
                    trunk['native'] = int(native.group(0))
                    interface['vlan'] = int(native.group(0))
            if interface['mode'] == 'trunk':
                interface.update(trunk)
            interfaces.append(interface)
        return interfaces
  
    def find_l3_interface(self, vrf='default'):
        interfaces = []
        if vrf != 'default':
            interfaces_cmd = self.ciscoparse.find_objects_w_child(parentspec=r'interface', childspec=r'ip vrf forwarding %s' % vrf)
        else:
            interfaces_cmd = self.ciscoparse.find_objects_w_child(parentspec=r'interface', childspec=r'ip address')

        for interface_cmd in interfaces_cmd:
            interface = {
                'interface' : None,
                'vrf' : None,
                'description' : None,
                'ipv4' : None,
                'netmask' : None,
                'shutdown' : False
            }
            hsrp = {
                'hsrp_enable' : False,
                'hsrp_group' : None,
                'hsrp_version' : 1,
                'hsrp_preempt' : False,
                'hsrp_priority' : None,
                'hsrp_ip' : None
            }
            int_name = re.search('interface (\S+)', interface_cmd.text)
            interface['interface'] = int_name.group(1).replace('Vlan', 'BVI')
            for cmd in interface_cmd.children:
                if 'description' in cmd.text:
                    desc = re.search('description (.+)', cmd.text)
                    interface['description'] = desc.group(1)
                elif 'ip address' in cmd.text:
                    ip = re.search('ip address (\S+) (\S+)', cmd.text)
                    if ip:
                        interface['ipv4'] = ip.group(1)
                        interface['netmask'] = ip.group(2)
                elif 'arp timeout' in cmd.text:
                    arp_timeout = re.search('arp timeout (\d+)', cmd.text)
                    interface['arp_timeout'] = int(arp_timeout.group(1))
                elif 'shutdown' in cmd.text:
                    interface['shutdown'] = True
                elif 'standby' in cmd.text:
                    hsrp_version = re.search('standby version (2)', cmd.text)
                    hsrp_preempt = re.search('standby \d+ preempt', cmd.text)
                    hsrp_ip = re.search('standby (\d+) ip (\S+)', cmd.text)
                    hsrp_priority = re.search('standby \d+ priority (\d+)', cmd.text)
                    if hsrp_version:
                        hsrp['hsrp_version'] = int(hsrp_version.group(1))
                    elif hsrp_preempt:
                        hsrp['hsrp_preempt'] = True
                    elif hsrp_ip:
                        hsrp['hsrp_group'] = hsrp_ip.group(1)
                        hsrp['hsrp_ip'] = hsrp_ip.group(2)
                        hsrp['hsrp_enable'] = True
                    elif hsrp_priority:
                        hsrp['hsrp_priority'] = int(hsrp_priority.group(1))
                elif 'ip vrf forwarding' in cmd.text:
                    interface_vrf = re.search('ip vrf forwarding (\S+)', cmd.text)
                    interface['vrf'] = interface_vrf.group(1)
            if hsrp['hsrp_enable'] == True:
                interface.update(hsrp)
            interfaces.append(interface)
        return interfaces
    
    def find_static_route(self, vrf='default'):
        if vrf != 'default':
            static_route_cmd = self.ciscoparse.find_objects(r'ip route vrf %s' % vrf)
        else:
            static_route_cmd = self.ciscoparse.find_objects(r'ip route [^(vrf)]')
        static_routes = list()
        for static_route in static_route_cmd:
            route = {
                'vrf' : None,
                'dst_network' : None,
                'netmask' : None,
                'gateway' : None,
                'description' : None,
                'tag' : None
            }

            vrf = re.search('ip route vrf (\S+)', static_route.text)
            dst_network = re.search('ip route\s?(vrf)?\s?(\S*) (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)', static_route.text)
            tag = re.search('ip route\s?(vrf)?\s?(\S*) (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+) tag (\d+)', static_route.text)
            description = re.search('ip route\s?(vrf)?\s?(\S*) (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)\s?(tag)?\s?(\d*)\s?name (\S+)', static_route.text)
            
            if vrf:
                route['vrf'] = vrf.group(1)
            if dst_network:
                route['dst_network'] = dst_network.group(3)
                route['netmask'] = dst_network.group(4)
                route['gateway'] = dst_network.group(5)
            if description:
                route['description'] = description.group(8)[:30]
            if tag:
                route['tag'] = tag.group(6)
            
            static_routes.append(route)
        
        return static_routes
    
def main():
    config = xe2xr(file=argv[1])
    vrfes = config.find_vrf_interface()
    l2_interfaces = config.find_l2_interface()
    xr_template = xe2xr_template()
    if len(vrfes) > 0:
        for vrf in vrfes:
            print('------------ vrf %s -------------' % vrf)
            print('*** l3 interface ***')
            l3_interfaces = config.find_l3_interface(vrf)
            l3_interfaces_template = xr_template.xr_l3_interface(vrf=vrf, l3_interfaces=l3_interfaces)
            print(l3_interfaces_template)
            
            print('*** static route ***')
            static_routes = config.find_static_route(vrf)
            static_route_template = xr_template.xr_static_route(vrf=vrf, networks=static_routes)
            print(static_route_template)
    
    print('------------ layer 2 interfaces --------------')
    for l2_interface in l2_interfaces:
        l2_interface_template = xr_template.xr_trunk_interface(**l2_interface)
        print(l2_interface_template)
    
    
    
    
if __name__ == "__main__":
    main()