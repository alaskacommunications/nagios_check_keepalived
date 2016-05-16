Nagios Check Keepalived
=======================

   Nagios plugins for monitoring Keepalived VRRP and IPVS subsystems via SNMP. This package contains the following Nagios checks:

   * check_keepalived_vrrp.pl - Checks VRRP subsystem
   * check_keepalived_ipvs.pl - Checks IPVS subsystem

Script Usage
------------

   check_keepalived_ipvs.pl:

        Usage: check_keepalived_ipvs.pl [OPTIONS]
        OPTIONS:
          -a agent        SNMP agent address
          -c community    SNMP community string
          -e count        CRIT, if more than count servers are down
          -E percent      CRIT, if percentage of servers is below percent
          -h              display this message
          -n pattern      include virtual servers matching pattern
          -Q              ignore quorum if not met
          -q              quiet output
          -t              display terse details
          -V              display program version
          -v version      SNMP version
          -w count        WARN, if more than count servers are down
          -W percent      WARN, if percentage of servers is below percent
          -x pattern      exclude virtual servers matching pattern

   check_keepalived_vrrp.pl:

        Usage: check_keepalived_vrrp.pl [OPTIONS]
        OPTIONS:
          -a agent        SNMP agent address
          -b              verify VRRP instance is backup
          -c community    SNMP community string
          -m              verify VRRP instance is master
          -n name         VRRP instance name
          -h              display this message
          -q              quiet output
          -t              display terse details
          -V              display program version
          -v version      SNMP version
          -w weight       weight threshold of master instance
          -x pattern      exclude virtual routers matching pattern


Example Output (IPVS)
---------------------

        syzdek@nagios$ /usr/libexec/nagios/check_keepalived_ipvs.pl -a dnslvs1.example.com -c public
        Virtual Servers: 2 OKAY - Keepalived v1.2.19 (04/19,2016)|
        -
        Router ID:     dnslvs1.example.com
        IPVS Count:    2
        -
        IPVS fwmark:153 (udp) (OKAY)
        IP Virtual Server:    fwmark wrr dr
        Capacity:             7 of 7 (100%) real servers up
        Quorum Weights:       quorum met, min: 1, recovery: 0, current: 70
        Active Connections:   0 connections, 0 connections/s
        Bytes In:             0 bytes, 0 bytes/s
        Bytes Out:            0 bytes, 0 bytes/s
        Packets In:           0 packets, 0 packets/s
        Packets Out:          0 packets, 0 packets/s
        Real Server:          [2001:4948:f:53::130]:0 (alive), 10 weight, 0 connections, 0 connections/s
        Real Server:          [2001:4948:f:53::131]:0 (alive), 10 weight, 0 connections, 0 connections/s
        Real Server:          [2001:4948:f:53::132]:0 (alive), 10 weight, 0 connections, 0 connections/s
        Real Server:          [2001:4948:f:53::133]:0 (alive), 10 weight, 0 connections, 0 connections/s
        Real Server:          [2001:4948:f:53::134]:0 (alive), 10 weight, 0 connections, 0 connections/s
        Real Server:          [2001:4948:f:53::135]:0 (alive), 10 weight, 0 connections, 0 connections/s
        Real Server:          [2001:4948:f:53::136]:0 (alive), 10 weight, 0 connections, 0 connections/s
        -
        IPVS fwmark:53 (udp) (OKAY)
        IP Virtual Server:    fwmark wrr dr
        Capacity:             7 of 7 (100%) real servers up
        Quorum Weights:       quorum met, min: 1, recovery: 0, current: 70
        Active Connections:   1116330524 connections, 1095 connections/s
        Bytes In:             108151191577 bytes, 102498 bytes/s
        Bytes Out:            0 bytes, 0 bytes/s
        Packets In:           1537688411 packets, 1462 packets/s
        Packets Out:          0 packets, 0 packets/s
        Real Server:          216.67.109.130:0 (alive), 10 weight, 0 connections, 156 connections/s
        Real Server:          216.67.109.131:0 (alive), 10 weight, 2 connections, 156 connections/s
        Real Server:          216.67.109.132:0 (alive), 10 weight, 0 connections, 156 connections/s
        Real Server:          216.67.109.133:0 (alive), 10 weight, 0 connections, 156 connections/s
        Real Server:          216.67.109.134:0 (alive), 10 weight, 1 connections, 156 connections/s
        Real Server:          216.67.109.135:0 (alive), 10 weight, 1 connections, 156 connections/s
        Real Server:          216.67.109.136:0 (alive), 10 weight, 0 connections, 156 connections/s
        |
        syzdek@nagios$

Example Output (VRRP)
---------------------

       syzdek@nagios$ /usr/libexec/nagios/check_keepalived_vrrp.pl -a dnslvs1.example.com -c public
        Virtual Routers: 2 OKAY - Keepalived v1.2.19 (04/19,2016)|
        -
        Router ID:     dnslvs1.example.com
        Check Method:  by initial/current states
        vRouter Count: 2
        -
        dnsvrrp20.nwc (OKAY)
        Virtual Router ID:    20
        State (current):      master
        State (desired)::     master
        State (initial):      master
        Weight (base):        100
        Weight (effective):   100
        Virtual IP Address:   216.67.109.140 (set)
        Virtual IP Address:   [2001:4948:f:53::140] (set)
        Virtual IP Status:    allSet
        Primary Interface:    eth1.2009
        LVS Sync Daemon:      disabled
        -
        dnsvrrp21.nwc (OKAY)
        Virtual Router ID:    21
        State (current):      backup
        State (desired)::     backup
        State (initial):      backup
        Weight (base):        25
        Weight (effective):   25
        Virtual IP Address:   216.67.109.141 (unset)
        Virtual IP Status:    notAllSet
        Primary Interface:    eth1.2009
        LVS Sync Daemon:      disabled
        |
        syzdek@nagios$

Example Nagios Configurations (Command Objects)
-----------------------------------------------

   Example command object configurations for VRRP:

        # VRRP desired state is determined by initial state
        define command{
           command_name    check_keepalived_vrrp
           command_line    $USER1$/check_keepalived_vrrp.pl -c public -a $HOSTADDRESS$
        }
        
        # VRRP desired state is determined by effective weight
        # In this example, a master has an effective weight of 10 or more
        define command{
           command_name    check_keepalived_vrrp_by_weight
           command_line    $USER1$/check_keepalived_vrrp.pl -c public -a $HOSTADDRESS$  -w 10
        }

        # VRRP desired state is hardcoded
        define command{
           command_name    check_keepalived_vrrp_master
           command_line    $USER1$/check_keepalived_vrrp.pl -c public -a $HOSTADDRESS$ -m
        }
        define command{
           command_name    check_keepalived_vrrp_backup
           command_line    $USER1$/check_keepalived_vrrp.pl-c public -a $HOSTADDRESS$ -b
        }

   Example command object configurations for IPVS:

        # Use default paramters
        define command{
           command_name    check_keepalived_ipvs
           command_line    $USER1$/check_keepalived_ipvs.pl -c public -a $HOSTADDRESS$
        }
        
        # Warn if 2 servers are down and critical if less than 25% of the servers are up
        define command{
           command_name    check_keepalived_ipvs
           command_line    $USER1$/check_keepalived_ipvs.pl -c public -a $HOSTADDRESS$ -w 2 -C 25
        }
        
        # Warn if 25% of servers are down and critical if less than 50% of the servers are up
        # ignore quorum paramters
        define command{
           command_name    check_keepalived_ipvs
           command_line    $USER1$/check_keepalived_ipvs.pl -c public -a $HOSTADDRESS$ -W 75 -C 50 -Q
        }

   By default the checks provide both the default output text and long text.  If the checks are being called
   via NRPE, the long text can be shortened by enabling terse output with the `-t` option. Additionally, long
   text can be completely disabled by providing the '-q' option to the checks.

Example Nagios Configurations (Service Objects)
-----------------------------------------------

   VRRP service checks:

        define service{
           use                     generic-service
           host_name               dnslvs1.example.org
           display_name            VRRP
           service_description     VRRP
           check_command           check_keepalived_vrrp
        }

   IPVS service checks:

        define service{
           use                     generic-service
           host_name               dnslvs20.example.org
           display_name            IPVS
           service_description     IPVS
           check_command           check_keepalived_ipvs
        }

