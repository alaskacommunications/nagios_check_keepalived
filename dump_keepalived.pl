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

use warnings;
use strict;
use SNMP;
use Socket;
use Getopt::Std;
use Data::Dumper;
use IO::Socket;
use Socket qw(inet_pton inet_ntop AF_INET AF_INET6);

$|++;

my $sess;
my $mib;
my $vb;
my $suffix;
my $ref;
my $arg;
my @check;

if (@ARGV != 3)
{
   printf("Usage: dump_keepalived agent community [ vrrp | ipvs | all ]\n");
   exit 1;
};
if ($ARGV[2] =~ /^vrrp$/)
{
   $arg = 'vrrp'
} elsif ($ARGV[2] =~ /^ipvs$/) {
   $arg = 'ipvs'
} elsif ($ARGV[2] =~ /^all$/) {
   $arg = 'all'
} else {
   printf STDERR ("invalid option\n");
   exit 1;
};

&SNMP::loadModules('KEEPALIVED-MIB');
&SNMP::initMib();

# connects to agent
$sess = new SNMP::Session(
   Community => $ARGV[1],
   DestHost  => $ARGV[0],
   Version   => '2c',
   Timeout   => 1000000,
   Retries   => 2,
   UseSprintValue => '1'
);

$mib     = 'KEEPALIVED-MIB::vrrp';
$vb      = new SNMP::Varbind([$mib]);

@check = ();
if ($arg eq 'all')
{
   @check = (
      'KEEPALIVED-MIB::emailTable',
   );
};
if ( ($arg eq 'vrrp') || ($arg eq 'all') )
{
   @check = (
      @check,
      'KEEPALIVED-MIB::vrrpInstanceTable',
      'KEEPALIVED-MIB::vrrpTrackedInterfaceTable',
      'KEEPALIVED-MIB::vrrpTrackedScriptTable',
      'KEEPALIVED-MIB::vrrpScriptTable',
      'KEEPALIVED-MIB::vrrpAddressTable',
      'KEEPALIVED-MIB::vrrpSyncGroupTable', 
      'KEEPALIVED-MIB::vrrpSyncGroupMemberTable'
   );
};
if ( ($arg eq 'ipvs') || ($arg eq 'all') )
{
   @check = (
      @check,
      'KEEPALIVED-MIB::virtualServerTable',
      'KEEPALIVED-MIB::realServerTable',
      'KEEPALIVED-MIB::virtualServerGroupTable',
      'KEEPALIVED-MIB::virtualServerGroupMemberTable'
   );
};

for $suffix (@check)
{
   $ref = $sess->gettable($suffix);
   if ($sess->{ErrorNum})
   {
      printf("SNMP error: %s\n", $sess->{'ErrorStr'});
      return(3);
   };
   printf("=== %s ===\n", $suffix);
   print Dumper($ref);
   printf("\n\n");
};


exit 0;
