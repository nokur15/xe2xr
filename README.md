# xe2xr

This tools has function to simplify convert configuration from IOS XE flavor to IOS XR flavor

Python 3.6

### Required

* ciscoconfparse==1.3.32
* colorama==0.4.1
* dnspython==1.16.0
* Jinja2==2.10
* MarkupSafe==1.1.1
* passlib==1.7.1

### Tutorial

clone repository :

```
± % git clone https://github.com/akrommusajid/xe2xr.git
```

activate virtual environment

```
± % cd xe2xr
± % source bin/activate
```

Get ready for your XE flavor configuration :

```
± % cat config.txt                                                                                                                                                                                    !5498
interface Vlan3442
 description cluster_vlan3442
 ip vrf forwarding abc
 ip address 10.247.137.92 255.255.255.240
 no ip redirects
 no ip proxy-arp
 standby version 2
 standby 3442 ip 10.247.137.94
 standby 3442 priority 110
 standby 3442 preempt
 arp timeout 7200
!
interface Vlan2400
 description cluster_vlan2400
 ip vrf forwarding def
 ip address 10.249.179.158 255.255.255.224
 no ip redirects
 no ip proxy-arp
 shutdown
!
interface GigabitEthernet2/2
 description trunk_interface
 switchport
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 3142,3394,3682
 switchport mode trunk
 shutdown
 mls qos vlan-based
 storm-control broadcast level 0.10
 storm-control multicast level 0.10
!
interface Port-Channel10
 description to_other_city
 switchport
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 3142,3394,3682
 switchport trunk native vlan 99
 switchport mode trunk
 shutdown
 mls qos vlan-based
 storm-control broadcast level 0.10
 storm-control multicast level 0.10
!
ip route 10.247.48.8 255.255.255.248 10.247.141.49 tag 113101 name this_is_static_routing
ip route vrf abc 10.247.48.16 255.255.255.248 10.247.141.50
ip route 10.247.48.24 255.255.255.248 10.247.141.51 name this_is_static_routing
ip route vrf def 10.247.48.32 255.255.255.248 10.247.141.52 tag 113101 name this_is_static_routing

```

Execute with this command :

```
± % python xe2xr.py config.txt
layer 3 interface
========================================================

        --------------------------------------------------------
        interface BVI3442
         vrf abc
         description cluster_vlan3442
         ipv4 address 10.247.137.92 255.255.255.240
         load-interval 30
         arp timeout 7200
         shutdown

        router hsrp
         interface BVI3442
          address-family ipv4
          hsrp version 2
          hsrp 3442
          preempt
          priotiy 110
          address 10.247.137.94
        --------------------------------------------------------


        --------------------------------------------------------
        interface BVI2400
         vrf def
         description cluster_vlan2400
         ipv4 address 10.249.179.158 255.255.255.224
         load-interval 30

layer 2 interface
========================================================

        --------------------------------------------------------
        interface GigabitEthernet2/2.3142 l2transport
         description trunk_interface
         encapsulation dot1q 3142 exact
         rewrite ingress tag pop 1 symmetric

         l2vpn
          bridge group BVI
           bridge-domain 3142
            storm-control multicast kbps 400
            storm-control broadcast kbps 400
            interface GigabitEthernet2/2.3142
            !
            routed interface BVI3142
        --------------------------------------------------------

        --------------------------------------------------------
        interface GigabitEthernet2/2.3394 l2transport
         description trunk_interface
         encapsulation dot1q 3394 exact
         rewrite ingress tag pop 1 symmetric

         l2vpn
          bridge group BVI
           bridge-domain 3394
            storm-control multicast kbps 400
            storm-control broadcast kbps 400
            interface GigabitEthernet2/2.3394
            !
            routed interface BVI3394
        --------------------------------------------------------

        --------------------------------------------------------
        interface GigabitEthernet2/2.3682 l2transport
         description trunk_interface
         encapsulation dot1q 3682 exact
         rewrite ingress tag pop 1 symmetric

         l2vpn
          bridge group BVI
           bridge-domain 3682
            storm-control multicast kbps 400
            storm-control broadcast kbps 400
            interface GigabitEthernet2/2.3682
            !
            routed interface BVI3682
        --------------------------------------------------------


        --------------------------------------------------------
        interface Bundle-Ether10.3142 l2transport
         description to_other_city
         encapsulation dot1q 3142 exact
         rewrite ingress tag pop 99 symmetric

         l2vpn
          bridge group BVI
           bridge-domain 3142
            storm-control multicast kbps 400
            storm-control broadcast kbps 400
            interface Bundle-Ether10.3142
            !
            routed interface BVI3142
        --------------------------------------------------------

        --------------------------------------------------------
        interface Bundle-Ether10.3394 l2transport
         description to_other_city
         encapsulation dot1q 3394 exact
         rewrite ingress tag pop 99 symmetric

         l2vpn
          bridge group BVI
           bridge-domain 3394
            storm-control multicast kbps 400
            storm-control broadcast kbps 400
            interface Bundle-Ether10.3394
            !
            routed interface BVI3394
        --------------------------------------------------------

        --------------------------------------------------------
        interface Bundle-Ether10.3682 l2transport
         description to_other_city
         encapsulation dot1q 3682 exact
         rewrite ingress tag pop 99 symmetric

         l2vpn
          bridge group BVI
           bridge-domain 3682
            storm-control multicast kbps 400
            storm-control broadcast kbps 400
            interface Bundle-Ether10.3682
            !
            routed interface BVI3682
        --------------------------------------------------------

Static Route
========================================================

        router static
         address-family ipv4 unicast
          10.247.48.8 255.255.255.248 10.247.141.49 tag 113101 description this_is_static_routing


        router static
         vrf abc
         address-family ipv4 unicast
          10.247.48.16 255.255.255.248 10.247.141.50


        router static
         address-family ipv4 unicast
          10.247.48.24 255.255.255.248 10.247.141.51  description this_is_static_routing


        router static
         vrf def
         address-family ipv4 unicast
          10.247.48.32 255.255.255.248 10.247.141.52 tag 113101 description this_is_static_routing

```

### Question/Discussion
if you find any issue in xe2xr, then open an issue right here : 

[https://github.com/akrommusajid/xe2xr/issues](https://github.com/akrommusajid/xe2xr/issues)

if you have any question or would like to discussion please contact me to a.musajid@gmail.com

---
Akrom Musajid

https://www.linkedin.com/in/akrommusajid/


