use strict;
use Test;
use vars qw($dns_tests);

BEGIN { $dns_tests = 3; plan tests => $dns_tests }

# See if the module compiles - it should...
eval "use DNS::ZoneParse;";
if ($@)
{
	ok(0) for (1 .. $dns_tests);
	exit;
} else {
	ok(1);
}

my $zone_data = <<END_ZONE;
;  Database file dns-zoneparse-test.net.dns for dns-zoneparse-test.net zone.
;      Zone version:  2000100501
@                       3600	IN	SOA	ns0.dns-zoneparse-test.net.	support.dns-zoneparse-test.net.	(
                        2000100501   ; serial number
                        10800       ; refresh
                        3600        ; retry
                        691200      ; expire
                        86400     ) ; minimum TTL

@                       IN	NS	ns0.dns-zoneparse-test.net.
@                       IN	NS	ns1.dns-zoneparse-test.net.

@                       IN	A	127.0.0.1
@                       IN	MX	10	mail
ftp                     IN	CNAME	www
localhost               IN	A	127.0.0.1
mail                    IN	A	127.0.0.1
www                     IN	A	127.0.0.1
END_ZONE

#create a DNS::ZoneParse object;

my $zonefile = DNS::ZoneParse->new(\$zone_data);
if ($zonefile) {
	ok(1);
} else {
	ok(0);
}

# See if the newSerial method works.

my $serial = $zonefile->soa->{serial};
$zonefile->newSerial;
my $newserial = $zonefile->soa->{serial};

if ($newserial > $serial)
{
	ok(1);
} else {
	ok(0);
}
