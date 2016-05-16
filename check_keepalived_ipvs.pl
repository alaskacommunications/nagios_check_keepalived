#!/usr/bin/perl -Tw
#
#   Nagios Keepalived SNMP Checks
#   Copyright (c) 2016, David M. Syzdek <david@syzdek.net>
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#      1. Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#
#      2. Redistributions in binary form must reproduce the above copyright
#         notice, this list of conditions and the following disclaimer in the
#         documentation and/or other materials provided with the distribution.
#
#      3. Neither the name of the copyright holder nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
#   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
#   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# +-=-=-=-=-=-+
# |           |
# |  Headers  |
# |           |
# +-=-=-=-=-=-+

use warnings;
use strict;
use SNMP;
use Socket;
use Getopt::Std;

$|++;

our $PROGRAM_NAME    = 'check_keepalived_ipvs.pl';
our $VERSION         = '0.2';
our $DESCRIPTION     = 'Checks status of Keepalived IPVS/LVS process via SNMP';
our $AUTHOR          = 'David M. Syzdek <david@syzdek.net>';


# +-=-=-=-=-=-=-=+
# |              |
# |  Prototypes  |
# |              |
# +-=-=-=-=-=-=-=+

sub HELP_MESSAGE();
sub VERSION_MESSAGE();
sub chk_ipvs_analyze($);
sub chk_ipvs_config($);
sub chk_ipvs_detail($);
sub chk_ipvs_detail_terse($);
sub chk_ipvs_hex2inet($);
sub chk_ipvs_hex2inet6($);
sub chk_ipvs_nagios_code($);
sub chk_ipvs_print($$$);
sub chk_ipvs_walk($);

sub main(@);                     # main statement


# +-=-=-=-=-=-=-+
# |             |
# |  Functions  |
# |             |
# +-=-=-=-=-=-=-+

sub HELP_MESSAGE()
{
   printf STDERR ("Usage: %s [OPTIONS]\n", $PROGRAM_NAME);
   printf STDERR ("OPTIONS:\n");
   printf STDERR ("  -a agent        SNMP agent address\n");
   printf STDERR ("  -c community    SNMP community string\n");
   printf STDERR ("  -e count        CRIT, if more than count servers are down\n");
   printf STDERR ("  -E percent      CRIT, if percentage of servers is below percent\n");
   printf STDERR ("  -h              display this message\n");
   printf STDERR ("  -n pattern      include virtual servers matching pattern\n");
   printf STDERR ("  -Q              ignore quorum if not met\n");
   printf STDERR ("  -q              quiet output\n");
   printf STDERR ("  -t              display terse details\n");
   printf STDERR ("  -V              display program version\n");
   printf STDERR ("  -v version      SNMP version\n");
   printf STDERR ("  -w count        WARN, if more than count servers are down\n");
   printf STDERR ("  -W percent      WARN, if percentage of servers is below percent\n");
   printf STDERR ("  -x pattern      exclude virtual servers matching pattern\n");
   printf STDERR ("\n");
   printf STDERR ("NOTES:\n");
   printf STDERR ("  If an error percent and an error count are not specified, then a critical\n");
   printf STDERR ("  error is generated if the amount of real servers up drops below 50 percent \n");
   printf STDERR ("  of total real servers. If a warning percent and a warning count are not\n");
   printf STDERR ("  specified, then a warning is generated if 1 real server is reported down.\n");
   printf STDERR ("\n");
   return(0);
};


sub VERSION_MESSAGE()
{
   printf ("%s (%s)\n\n", $PROGRAM_NAME, $VERSION);
   return 0;
};


# displays instance detail 
sub chk_ipvs_analyze($)
{
   my $cnf     = shift;
   my $vinst;
   my $state;
   my $count;
   my $percent;


   # determine status of each router
   for $vinst (sort {$a->{'name'} cmp $b->{'name'}} @{$cnf->{'all'}})
   {
      if (($vinst->{'name'} =~ $cnf->{'include'}) && ($vinst->{'name'} !~ $cnf->{'exclude'}))
      {
         $count   = $vinst->{'realServersTotal'} - $vinst->{'realServersUp'};
         $percent = int(($vinst->{'realServersUp'} * 100) / $vinst->{'realServersTotal'});

         if ( ($vinst->{'quorumStatus'} ne 'met') && (!($cnf->{'ignoreQuorum'})) )
         {
            $cnf->{'crit'}->[@{$cnf->{'crit'}}] = $vinst;
            $vinst->{'nagios'} = 'CRIT';
         }
         elsif ( ($count >= $cnf->{'critCount'}) && (($cnf->{'critCount'})) )
         {
            $cnf->{'crit'}->[@{$cnf->{'crit'}}] = $vinst;
            $vinst->{'nagios'} = 'CRIT';
         }
         elsif ( ($percent <= $cnf->{'critPercent'}) && (($cnf->{'critPercent'})) )
         {
            $cnf->{'crit'}->[@{$cnf->{'crit'}}] = $vinst;
            $vinst->{'nagios'} = 'CRIT';
         }
         elsif ( ($count >= $cnf->{'warnCount'}) && (($cnf->{'warnCount'})) )
         {
            $cnf->{'warn'}->[@{$cnf->{'warn'}}] = $vinst;
            $vinst->{'nagios'} = 'WARN';
         }
         elsif ( ($percent <= $cnf->{'warnPercent'}) && (($cnf->{'warnPercent'})) )
         {
            $cnf->{'warn'}->[@{$cnf->{'warn'}}] = $vinst;
            $vinst->{'nagios'} = 'WARN';
         }
         else
         {
            $cnf->{'okay'}->[@{$cnf->{'okay'}}] = $vinst;
            $vinst->{'nagios'} = 'OKAY';
         };

         # set initial parameters
         $vinst->{'details'}              = $vinst->{'type'};
         $vinst->{'details'}             .= ' ' . $vinst->{'loadBalancingAlgo'};
         $vinst->{'details'}             .= ' ' . $vinst->{'loadBalancingKind'};
         $vinst->{'quorumDetail'}         = 'quorum ' . $vinst->{'quorumStatus'};
         $vinst->{'quorumDetail'}        .= ', min: ' . $vinst->{'quorum'};
         $vinst->{'quorumDetail'}        .= ', recovery: ' . $vinst->{'hysteresis'};
         $vinst->{'quorumDetail'}        .= ', current: ' . $vinst->{'weightTotal'};

         $vinst->{'percentUp'}            = $percent;
         $vinst->{'realServersDown'}      = $count;
         $vinst->{'realServersCapacity'}  = $vinst->{'realServersUp'} . ' of ' . $vinst->{'realServersTotal'};
         $vinst->{'realServersCapacity'} .= ' (' . $vinst->{'percentUp'} . '%) real servers up';
      };
   };


   $cnf->{'count_crit'} = @{$cnf->{'crit'}};
   $cnf->{'count_warn'} = @{$cnf->{'warn'}};
   $cnf->{'count_okay'} = @{$cnf->{'okay'}};
   $cnf->{'count_all'}  = @{$cnf->{'crit'}};
   $cnf->{'count_all'} += @{$cnf->{'warn'}};
   $cnf->{'count_all'} += @{$cnf->{'okay'}};


   return(0);
}


sub chk_ipvs_config($)
{
   my $cnf = shift;
   $cnf->{'crit'}                    = [];
   $cnf->{'warn'}                    = [];
   $cnf->{'okay'}                    = [];
   $cnf->{'all'}                     = [];


   $Getopt::Std::STANDARD_HELP_VERSION=1;


   if (!(getopts("a:c:E:e:hn:QqtVv:W:w:x:", $cnf)))
   {
      HELP_MESSAGE();
      return(3);
   };


   if (($cnf->{'h'}))
   {
      HELP_MESSAGE();
      return(3);
   };


   $cnf->{'terse'}        = defined($cnf->{'t'}) ? $cnf->{'t'} : 0;
   $cnf->{'ignoreQuorum'} = defined($cnf->{'Q'}) ? $cnf->{'Q'} : 0;
   $cnf->{'quiet'}        = defined($cnf->{'q'}) ? $cnf->{'q'} : 0;
   $cnf->{'agent'}        = defined($cnf->{'a'}) ? $cnf->{'a'} : 'localhost';
   $cnf->{'version'}      = defined($cnf->{'v'}) ? $cnf->{'v'} : '2c';
   $cnf->{'community'}    = defined($cnf->{'c'}) ? $cnf->{'c'} : 'public';
   $cnf->{'include'}      = defined($cnf->{'n'}) ? $cnf->{'n'} : '^.*$';
   $cnf->{'exclude'}      = defined($cnf->{'x'}) ? $cnf->{'x'} : '^$';
   $cnf->{'critCount'}    = defined($cnf->{'e'}) ? $cnf->{'e'} : 0;
   $cnf->{'critPercent'}  = defined($cnf->{'E'}) ? $cnf->{'E'} : 0;
   $cnf->{'warnCount'}    = defined($cnf->{'w'}) ? $cnf->{'w'} : 0;
   $cnf->{'warnPercent'}  = defined($cnf->{'W'}) ? $cnf->{'W'} : 0;


   if ($cnf->{'critCount'} =~ /^([\d]+)$/)
   {
      $cnf->{'critCount'} = $1;
   } else {
      printf("%s: count threshold must be a numeric value\n\n", $PROGRAM_NAME);
      return(3);
   };


   if ($cnf->{'critPercent'} =~ /^([\d]+)$/)
   {
      $cnf->{'critPercent'} = $1;
   } else {
      printf("%s: percent threshold must be a numeric value\n\n", $PROGRAM_NAME);
      return(3);
   };


   if ($cnf->{'warnCount'} =~ /^([\d]+)$/)
   {
      $cnf->{'warnCount'} = $1;
   } else {
      printf("%s: count threshold must be a numeric value\n\n", $PROGRAM_NAME);
      return(3);
   };


   if ($cnf->{'warnPercent'} =~ /^([\d]+)$/)
   {
      $cnf->{'warnPercent'} = $1;
   } else {
      printf("%s: percent threshold must be a numeric value\n\n", $PROGRAM_NAME);
      return(3);
   };

   if ( (!($cnf->{'critCount'})) && (!($cnf->{'critPercent'})) )
   {
      $cnf->{'critPercent'} = 50;
   };
   if ( (!($cnf->{'warnCount'})) && (!($cnf->{'warnPercent'})) )
   {
      $cnf->{'warnCount'} = 1;
   };

   return(0);
};


sub chk_ipvs_detail($)
{
   my $vrouter = shift;
   my $real;

   # virtual router ID
   printf("IPVS %s (%s)\n",                        $vrouter->{'name'}, $vrouter->{'nagios'});
   chk_ipvs_print($vrouter, 'details',              "IP Virtual Server");
   chk_ipvs_print($vrouter, 'realServersCapacity',  "Capacity");
   chk_ipvs_print($vrouter, 'quorumDetail',         "Quorum Weights");
   printf("Active Connections:   %s, %s\n",   $vrouter->{'statsConns'}, $vrouter->{'rateCps'});
   printf("Bytes In:             %s, %s\n",   $vrouter->{'statsInBytes'}, $vrouter->{'rateInBPS'});
   printf("Bytes Out:            %s, %s\n",   $vrouter->{'statsOutBytes'}, $vrouter->{'rateOutBPS'});
   printf("Packets In:           %s, %s\n",   $vrouter->{'statsInPkts'}, $vrouter->{'rateInPPS'});
   printf("Packets Out:          %s, %s\n",   $vrouter->{'statsOutPkts'}, $vrouter->{'rateOutPPS'});
   for $real (sort {$a->{'address'} cmp $b->{'address'}} @{$vrouter->{'realServers'}})
   {
      printf("Real Server:          %s:%s (%s), %s weight, %s, %s\n", $real->{'address'},
             $real->{'port'}, $real->{'status'}, $real->{'weight'},
             $real->{'statsActiveConns'}, $real->{'rateCps'});
   };

   return(0);
}


sub chk_ipvs_detail_terse($)
{
   my $vrouter = shift;

   # virtual router ID
   printf("IPVS %s (%s)\n",                        $vrouter->{'name'}, $vrouter->{'nagios'});
   chk_ipvs_print($vrouter, 'realServersCapacity',  "Capacity");
   chk_ipvs_print($vrouter, 'quorumDetail',         "Quorum Weights");

   return(0);
}


sub chk_ipvs_hex2inet($)
{
   my $hexstr = shift;
   my $oct;
   my @octs;
   $hexstr =~ s/"//g;
   for $oct (split(/ /, $hexstr))
   {
      $octs[@octs] = hex($oct);
   };
   return(join('.', @octs));
};


sub chk_ipvs_hex2inet6($)
{
   my $hexstr = shift;
   $hexstr =~ s/"//g;
   $hexstr =  lc($hexstr);
   $hexstr =~ s/([a-f\d]{2,2}) ([a-f\d]{2,2}) /$1$2:/g;
   $hexstr =~ s/(:0000)+:/::/;
   $hexstr =~ s/:0+([0-9a-f])/:$1/g;
   $hexstr =~ s/([0-9a-f]):$/$1/g;
   return('[' . $hexstr . ']');
};


sub chk_ipvs_nagios_code($)
{
   my $cnf = shift;
   if ($cnf->{'count_crit'} != 0)
   {
      return(2);
   };
   if ($cnf->{'count_warn'} != 0)
   {
      return(1);
   };
   return(0);
}


sub chk_ipvs_print($$$)
{
   my $vrouter = shift;
   my $key     = shift;
   my $desc    = shift;
   my $val;

   if (!( defined($vrouter->{$key}) ))
   {
      return(0);
   };

   if (ref($vrouter->{$key}) ne 'ARRAY')
   {
      printf("%-21s %s\n", $desc . ':', $vrouter->{$key});
   } else {
      for $val (sort(@{$vrouter->{$key}}))
      {
         printf("%-21s %s\n", $desc . ':', $val);
      };
   };

   return(0);
};


sub chk_ipvs_walk($)
{
   my $cnf = shift;

   my $lvs;
   my $vb;
   my $sess;
   my $key;
   my $oldkey;
   my $newkey;
   my $glb;
   my $vtable;
   my $rtable;
   my $vsgt;
   my $vsgmt;
   my $vinst;
   my $rinst;
   my $grp;
   my $addr;


   $lvs = [];
   $cnf->{'all'} = $lvs;


   # connects to agent
   $sess = new SNMP::Session(
      Community => $cnf->{'community'},
      DestHost  => $cnf->{'agent'},
      Version   => $cnf->{'version'},
      Timeout   => 1000000,
      Retries   => 1,
      RetryNoSuch => 0,
      UseSprintValue => '1'
   );
   if (!( defined($sess) ))
   {
      printf("VRRP UNKNOWN: SNMP error\n");
      return(3);
   };


   # retrieve keepalived version
   $vb = new SNMP::Varbind(['KEEPALIVED-MIB::version', 0]);
   $cnf->{'keepalived'} = $sess->get($vb);
   if ($sess->{ErrorNum})
   {
      printf("VRRP UNKNOWN: SNMP error: %s\n", $sess->{'ErrorStr'});
      return(3);
   };
   if ($cnf->{'keepalived'} =~ /^No Such Object available on this agent at this OID$/)
   {
      printf("VRRP CRITICAL: keepalived is not running\n");
      return(2);
   };
   $vb = new SNMP::Varbind(['KEEPALIVED-MIB::routerId', 0]);
   $cnf->{'routerId'} = $sess->get($vb);
   if ($sess->{ErrorNum})
   {
      printf("VRRP UNKNOWN: SNMP error: %s\n", $sess->{'ErrorStr'});
      return(3);
   };


   # load virtual server table
   $vtable = $sess->gettable('KEEPALIVED-MIB::virtualServerTable');
   if ($sess->{ErrorNum})
   {
      printf("VRRP UNKNOWN: SNMP error: %s\n", $sess->{'ErrorStr'});
      return(3);
   };
   if (!( defined($vtable) ))
   {
      printf("VRRP CRITICAL: keepalived does not have a virtual server table.\n");
      return(2);
   };
   if (keys(%{$vtable}) == 0)
   {
      printf("VRRP CRITICAL: keepalived does not have a virtual server table.\n");
      return(2);
   };
   for my $key (keys(%{$vtable}))
   {
      $vinst = $vtable->{$key};

      # clean up key names
      for my $oldkey (keys(%{$vinst}))
      {
         my $newkey = $oldkey;
         $newkey =~ s/^virtualServer//gi;
         $newkey = lcfirst($newkey);
         $vinst->{$newkey} = $vinst->{$oldkey};
         delete($vinst->{$oldkey});
      };

      # convert IP addresses from Hex to ASCII
      if ( ((defined($vinst->{'addrType'}))) && ((defined($vinst->{'address'}))) )
      {
         if ($vinst->{'addrType'} =~ /^ipv4$/)
         {
            $vinst->{'address'} = chk_ipvs_hex2inet($vinst->{'address'});
            $vinst->{'name'} = $vinst->{'address'} . ':' . $vinst->{'port'};
         };
         if ($vinst->{'addrType'} =~ /^ipv6$/)
         {
            $vinst->{'address'} = chk_ipvs_hex2inet6($vinst->{'address'});
            $vinst->{'name'} = '[' . $vinst->{'address'} . ']:' . $vinst->{'port'};
         };
         $vinst->{'name'} .= ' (' . $vinst->{'addrType'} . '/' . $vinst->{'protocol'} . ')';
      } elsif ((defined($vinst->{'fwMark'}))) {
            $vinst->{'name'} = 'fwmark:' . $vinst->{'fwMark'} . ' (' . $vinst->{'protocol'} . ')';
      };

      # set initial parameters
      $vinst->{'realServers'}          = [];
      $vinst->{'weightTotal'}          = 0;

      # save instance
      $lvs->[@{$lvs}] = $vinst;
   };


   # load real server table
   $rtable = $sess->gettable('KEEPALIVED-MIB::realServerTable');
   if ($sess->{ErrorNum})
   {
      printf("VRRP UNKNOWN: SNMP error: %s\n", $sess->{'ErrorStr'});
      return(3);
   };
   if (keys(%{$rtable}) == 0)
   {
      printf("VRRP CRITICAL: keepalived is missing real server table\n");
      return(2);
   };
   if (( defined($rtable) ))
   {
      for $key (keys(%{$rtable}))
      {
         $rinst = $rtable->{$key};
         $vinst = $vtable->{$rinst->{'virtualServerIndex'}};
         $vinst->{'realServers'}->[@{$vinst->{'realServers'}}] = $rinst;

         # clean up key names
         for my $oldkey (keys(%{$rinst}))
         {
            my $newkey = $oldkey;
            $newkey =~ s/^realServer//gi;
            $newkey = lcfirst($newkey);
            $rinst->{$newkey} = $rinst->{$oldkey};
            delete($rinst->{$oldkey});
         };

         # convert IP addresses from Hex to ASCII
         if ($rinst->{'addrType'} =~ /^ipv4$/)
         {
            $rinst->{'address'} = chk_ipvs_hex2inet($rinst->{'address'});
         };
         if ($rinst->{'addrType'} =~ /^ipv6$/)
         {
            $rinst->{'address'} = chk_ipvs_hex2inet6($rinst->{'address'});
         };

         # add weights to IPVS
         $vinst->{'weightTotal'} += $rinst->{'weight'};
      };
   };


   return(0);
};


# +-=-=-=-=-=-=-=-=-+
# |                 |
# |  Main  Section  |
# |                 |
# +-=-=-=-=-=-=-=-=-+
sub main(@)
{
   # grabs passed args
   my @argv = @_;

   my $cnf;
   my $rc;
   my $vrouter;

   $cnf = {};


   # Initialize the MIB (else you can't do queries).
   &SNMP::initMib();


   # parses CLI arguments
   if ((chk_ipvs_config($cnf)))
   {
      return(3);
   };


   # walks VRRP tree
   if (($rc = chk_ipvs_walk($cnf)) != 0)
   {
      return($rc);
   };


   # download instance information
   chk_ipvs_analyze($cnf);


   # print summary
   if ($cnf->{'count_all'} == 0)
   {
      printf("Keepalived is not running or is not configured properly.|\n");
      exit(2);
   };
   printf("Virtual Servers: ");
   if ($cnf->{'count_crit'} != 0)
   {
      printf("%i CRIT, ", $cnf->{'count_crit'});
   };
   if ($cnf->{'count_warn'} != 0)
   {
      printf("%i WARN, ", $cnf->{'count_warn'});
   };
   printf("%i OKAY - %s|\n", $cnf->{'count_okay'}, $cnf->{'keepalived'});
   if ($cnf->{'quiet'} == 1)
   {
      return(chk_ipvs_nagios_code($cnf));
   };


   # print details
   if ($cnf->{'terse'} == 0)
   {
      printf("-\n");
      printf("Router ID:     %s\n", $cnf->{'routerId'});
      printf("IPVS Count:    %i\n", $cnf->{'count_all'});
   };
   foreach $vrouter (@{$cnf->{'crit'}}, @{$cnf->{'warn'}}, @{$cnf->{'okay'}})
   {
      printf("-\n");
      if ($cnf->{'terse'} == 1)
      {
         chk_ipvs_detail_terse($vrouter);
      } else {
         chk_ipvs_detail($vrouter);
      };
   };
   printf("|\n");


   # ends function
   return(chk_ipvs_nagios_code($cnf));
};
exit(main(@ARGV));


# end of script
