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

our $PROGRAM_NAME    = 'check_keepalived_vrrp.pl';
our $VERSION         = '0.2';
our $DESCRIPTION     = 'Checks status of Keepalived VRRP process via SNMP';
our $AUTHOR          = 'David M. Syzdek <david@syzdek.net>';


# +-=-=-=-=-=-=-=+
# |              |
# |  Prototypes  |
# |              |
# +-=-=-=-=-=-=-=+

sub HELP_MESSAGE();
sub VERSION_MESSAGE();
sub chk_vrrp_analyze($);
sub chk_vrrp_config($);
sub chk_vrrp_detail($);
sub chk_vrrp_detail_terse($);
sub chk_vrrp_hex2inet($);
sub chk_vrrp_hex2inet6($);
sub chk_vrrp_nagios_code($);
sub chk_vrrp_print($$$);
sub chk_vrrp_walk($);

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
   printf STDERR ("  -b              verify VRRP instance is backup\n");
   printf STDERR ("  -c community    SNMP community string\n");
   printf STDERR ("  -m              verify VRRP instance is master\n");
   printf STDERR ("  -n name         VRRP instance name\n");
   printf STDERR ("  -h              display this message\n");
   printf STDERR ("  -q              quiet output\n");
   printf STDERR ("  -t              display terse details\n");
   printf STDERR ("  -V              display program version\n");
   printf STDERR ("  -v version      SNMP version\n");
   printf STDERR ("  -w weight       weight threshold of master instance\n");
   printf STDERR ("  -x pattern      exclude virtual routers matching pattern\n");
   printf STDERR ("\n");
   printf STDERR ("NOTES:\n");
   printf STDERR ("  By default, the desired state of an instance (backup or master) is determined by\n");
   printf STDERR ("  comparing an instance's current state to its intitial state. Use '-b' or '-m' to\n");
   printf STDERR ("  specify that an instance should be either in a backup state or a master state. If\n");
   printf STDERR ("  a weight is specified, an instance is assumed to be master if its effective\n");
   printf STDERR ("  priority (i.e. weight) is greater than or equal to the specified weight. The\n");
   printf STDERR ("  arguments '-b', '-m', and '-w' are incompatible.\n");
   printf STDERR ("\n");
   return(0);
};


sub VERSION_MESSAGE()
{
   printf ("%s (%s)\n\n", $PROGRAM_NAME, $VERSION);
   return 0;
};


# displays instance detail
sub chk_vrrp_analyze($)
{
   my $cnf     = shift;
   my $vrouter;
   my $state;


   # determine status of each router
   for $vrouter (sort {$a->{'name'} cmp $b->{'name'}} @{$cnf->{'vrouters'}})
   {
      if (($vrouter->{'name'} =~ $cnf->{'instance'}) && ($vrouter->{'name'} !~ $cnf->{'exclude'}))
      {
         $vrouter->{'desiredState'} = 'backup';
         if (( $cnf->{'state'} ))
         {
            $vrouter->{'desiredState'} = $cnf->{'state'};
         }
         elsif (( $cnf->{'weight'} ))
         {
            if ($cnf->{'weight'} <= $vrouter->{'effectivePriority'})
            {
               $vrouter->{'desiredState'} = 'master';
            };
         }
         else
         {
            $vrouter->{'desiredState'} = $vrouter->{'initialState'};
         };
         if  ($vrouter->{'state'} !~ /^$vrouter->{'desiredState'}$/)
         {
            if ($vrouter->{'desiredState'} =~ /^master$/i)
            {
               $vrouter->{'nagios'} = 'CRIT';
               $cnf->{'crit'}->[@{$cnf->{'crit'}}] = $vrouter;
            }
            else
            {
               $vrouter->{'nagios'} = 'WARN';
               $cnf->{'warn'}->[@{$cnf->{'warn'}}] = $vrouter;
            };
         }
         else
         {
            $vrouter->{'nagios'} = 'OKAY';
            $cnf->{'okay'}->[@{$cnf->{'okay'}}] = $vrouter;
         };
      };
   };


   $cnf->{'count_crit'} = @{$cnf->{'crit'}};
   $cnf->{'count_warn'} = @{$cnf->{'warn'}};
   $cnf->{'count_okay'} = @{$cnf->{'okay'}};
   $cnf->{'count_all'}  = @{$cnf->{'crit'}};
   $cnf->{'count_all'} += @{$cnf->{'warn'}};
   $cnf->{'count_all'} += @{$cnf->{'okay'}};


   return($vrouter);
}


sub chk_vrrp_config($)
{
   my $cnf = shift;
   $cnf->{'agent'}                   = 'localhost';
   $cnf->{'version'}                 = '2c';
   $cnf->{'community'}               = 'public';
   $cnf->{'state'}                   = 0;
   $cnf->{'weight'}                  = 0;
   $cnf->{'instance'}                = '^.*$';
   $cnf->{'exclude'}                 = '^$';
   $cnf->{'routers'}                 = [];
   $cnf->{'crit'}                    = [];
   $cnf->{'warn'}                    = [];
   $cnf->{'okay'}                    = [];
   $cnf->{'all'}                     = [];

   $Getopt::Std::STANDARD_HELP_VERSION=1;

   if (!(getopts("a:bc:h:mn:qtVv:w:x:", $cnf)))
   {
      HELP_MESSAGE();
      return(3);
   };
   if (($cnf->{'h'}))
   {
      HELP_MESSAGE();
      return(3);
   };

   if ( (( defined($cnf->{'b'}) )) && (( defined($cnf->{'m'}) )) )
   {
      HELP_MESSAGE();
      return(3);
   };

   $cnf->{'state'}       = defined($cnf->{'b'}) ? 'backup'    : $cnf->{'state'};
   $cnf->{'state'}       = defined($cnf->{'m'}) ? 'master'    : $cnf->{'state'};
   $cnf->{'terse'}       = defined($cnf->{'t'}) ? $cnf->{'t'} : 0;
   $cnf->{'quiet'}       = defined($cnf->{'q'}) ? $cnf->{'q'} : 0;
   $cnf->{'agent'}       = defined($cnf->{'a'}) ? $cnf->{'a'} : $cnf->{'agent'};
   $cnf->{'version'}     = defined($cnf->{'v'}) ? $cnf->{'v'} : $cnf->{'version'};
   $cnf->{'community'}   = defined($cnf->{'c'}) ? $cnf->{'c'} : $cnf->{'community'};
   $cnf->{'instance'}    = defined($cnf->{'n'}) ? $cnf->{'n'} : $cnf->{'instance'};
   $cnf->{'exclude'}     = defined($cnf->{'x'}) ? $cnf->{'x'} : $cnf->{'exclude'};
   $cnf->{'weight'}      = defined($cnf->{'w'}) ? $cnf->{'w'} : $cnf->{'weight'};

   if ( (($cnf->{'state'})) && (($cnf->{'weight'})) )
   {
      HELP_MESSAGE();
      return(3);
   };

   if ($cnf->{'weight'} =~ /^([\d]+)$/)
   {
      $cnf->{'weight'} = $1;
   } else {
      printf("%s: weight threshold must be a numeric value\n\n", $PROGRAM_NAME);
      return(3);
   };

   if (( $cnf->{'weight'} ))
   {
      $cnf->{'checkMethod'} = 'by weight';
   } elsif (( $cnf->{'state'} )) {
      $cnf->{'checkMethod'} = 'manually specified';
   } else {
      $cnf->{'checkMethod'} = 'by initial/current states';
   };

   return(0);
};


sub chk_vrrp_detail($)
{
   my $vrouter = shift;

   # virtual router ID
   printf("%s (%s)\n",                  $vrouter->{'name'}, $vrouter->{'nagios'});
   chk_vrrp_print($vrouter, 'virtualRouterId',     "Virtual Router ID");
   chk_vrrp_print($vrouter, 'syncGroupName',       "Sync Group");
   chk_vrrp_print($vrouter, 'syncGroupState',      "Sync Group State");
   chk_vrrp_print($vrouter, 'state',               "State (current)");
   chk_vrrp_print($vrouter, 'desiredState',     "State (desired):");
   #chk_vrrp_print($vrouter, 'wantedState',         "State (wanted)");
   chk_vrrp_print($vrouter, 'initialState',        "State (initial)");
   chk_vrrp_print($vrouter, 'basePriority',        "Weight (base)");
   chk_vrrp_print($vrouter, 'effectivePriority',   "Weight (effective)");
   chk_vrrp_print($vrouter, 'vips',                "Virtual IP Address");
   chk_vrrp_print($vrouter, 'vipsStatus',          "Virtual IP Status");
   chk_vrrp_print($vrouter, 'primaryInterface',    "Primary Interface");
   chk_vrrp_print($vrouter, 'lvsSyncDaemon',       "LVS Sync Daemon");
   chk_vrrp_print($vrouter, 'lvsSyncInterface',    "LVS Sync Interface");

   return(0);
}


sub chk_vrrp_detail_terse($)
{
   my $vrouter = shift;

   # virtual router ID
   printf("%s (vid: %i) (%s)\n",  $vrouter->{'name'}, $vrouter->{'virtualRouterId'}, $vrouter->{'nagios'});
   printf("State Current/Desired: %s/%s (vips: %s)\n", $vrouter->{'state'}, $vrouter->{'desiredState'}, $vrouter->{'vipsStatus'});

   return(0);
}


sub chk_vrrp_hex2inet($)
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


sub chk_vrrp_hex2inet6($)
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


sub chk_vrrp_nagios_code($)
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


sub chk_vrrp_print($$$)
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


sub chk_vrrp_walk($)
{
   my $cnf = shift;

   my $vrouters;
   my $vb;
   my $sess;
   my $key;
   my $vrrptable;;
   my $vaddrtable;
   my $synctable;
   my $membertable;
   my $inst;
   my $grp;


   $vrouters = [];
   $cnf->{'vrouters'} = $vrouters;


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


   # load VRRP instance table
   $vrrptable = $sess->gettable('KEEPALIVED-MIB::vrrpInstanceTable');
   if ($sess->{ErrorNum})
   {
      printf("VRRP UNKNOWN: SNMP error: %s\n", $sess->{'ErrorStr'});
      return(3);
   };
   if (!( defined($vrrptable) ))
   {
      printf("VRRP CRITICAL: keepalived does not have a  VRRP instances.\n");
      return(2);
   };
   if (keys(%{$vrrptable}) == 0)
   {
      printf("VRRP CRITICAL: keepalived does not have a  VRRP instances.\n");
      return(2);
   };
   for my $key (keys(%{$vrrptable}))
   {
      $inst = $vrrptable->{$key};
      for my $oldkey (keys(%{$inst}))
      {
         my $newkey = $oldkey;
         $newkey =~ s/^vrrpInstance//g;
         $newkey = lcfirst($newkey);
         $inst->{$newkey} = $inst->{$oldkey};
         delete($inst->{$oldkey});
      };
      $inst->{'vips'} = [];
      $vrouters->[@{$vrouters}] = $inst;
   };


   # load VRRP address table
   $vaddrtable = $sess->gettable('KEEPALIVED-MIB::vrrpAddressTable');
   if ($sess->{ErrorNum})
   {
      printf("VRRP UNKNOWN: SNMP error: %s\n", $sess->{'ErrorStr'});
      return(3);
   };
   if (keys(%{$vaddrtable}) == 0)
   {
      printf("VRRP CRITICAL: keepalived is missing virtual addresses\n");
      return(2);
   };
   if (( defined($vaddrtable) ))
   {
      for $key (keys(%{$vaddrtable}))
      {
         $inst = $vrrptable->{$vaddrtable->{$key}->{'vrrpInstanceIndex'}};
         if ($vaddrtable->{$key}->{'vrrpAddressType'} =~ /^ipv4$/)
         {
            $inst->{'vips'}->[@{$inst->{'vips'}}] = chk_vrrp_hex2inet($vaddrtable->{$key}->{'vrrpAddressValue'});
         };
         if ($vaddrtable->{$key}->{'vrrpAddressType'} =~ /^ipv6$/)
         {
            $inst->{'vips'}->[@{$inst->{'vips'}}] = chk_vrrp_hex2inet6($vaddrtable->{$key}->{'vrrpAddressValue'});
         };
         $inst->{'vips'}->[@{$inst->{'vips'}} - 1] .= ' (' . $vaddrtable->{$key}->{'vrrpAddressStatus'} . ')';
      };
   };


   # load VRRP group tables
   $synctable   = $sess->gettable('KEEPALIVED-MIB::vrrpSyncGroupTable');
   $membertable = $sess->gettable('KEEPALIVED-MIB::vrrpSyncGroupMemberTable');
   if (( defined($synctable) ))
   {
      for my $key (keys(%{$membertable}))
      {
         $inst = $vrrptable->{$membertable->{$key}->{'vrrpSyncGroupMemberInstanceIndex'}};
         $grp  = $synctable->{$membertable->{$key}->{'vrrpSyncGroupIndex'}};
         $inst->{'syncGroupName'}  = $grp->{'vrrpSyncGroupName'};
         $inst->{'syncGroupState'} = $grp->{'vrrpSyncGroupState'};
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
   if ((chk_vrrp_config($cnf)))
   {
      return(3);
   };


   # walks VRRP tree
   if (($rc = chk_vrrp_walk($cnf)) != 0)
   {
      return($rc);
   };


   # download instance information
   chk_vrrp_analyze($cnf);


   # print summary
   if ($cnf->{'count_all'} == 0)
   {
      printf("Keepalived is not running or is not configured properly.|\n");
      exit(2);
   };
   printf("Virtual Routers: ");
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
      return(chk_vrrp_nagios_code($cnf));
   };


   # print details
   if ($cnf->{'terse'} == 0)
   {
      printf("-\n");
      printf("Router ID:     %s\n", $cnf->{'routerId'});
      printf("Check Method:  %s\n", $cnf->{'checkMethod'});
      printf("vRouter Count: %i\n", $cnf->{'count_all'});
   };
   foreach $vrouter (@{$cnf->{'crit'}}, @{$cnf->{'warn'}}, @{$cnf->{'okay'}})
   {
      printf("-\n");
      if ($cnf->{'terse'} == 1)
      {
         chk_vrrp_detail_terse($vrouter);
      } else {
         chk_vrrp_detail($vrouter);
      };
   };
   printf("|\n");


   # ends function
   return(chk_vrrp_nagios_code($cnf));
};
exit(main(@ARGV));


# end of script
