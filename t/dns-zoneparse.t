use strict;
use Test::More tests => 10;

# See if the module compiles - it should...
require_ok('DNS::ZoneParse');

my $zone_data = <<'END_ZONE';
;  Database file dns-zoneparse-test.net.dns for dns-zoneparse-test.net zone.
;      Zone version:  2000100501
$TTL 1H
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
                        in      a       10.0.0.2
                        IN      A       10.0.0.3
soup                    IN      TXT     "This is a text message"
END_ZONE

#create a DNS::ZoneParse object;

my $zonefile = DNS::ZoneParse->new(\$zone_data);
ok($zonefile, 'new obj from string');

# See if the new_serial method works.
my $serial = $zonefile->soa->{serial};
$zonefile->new_serial(1);
my $newserial = $zonefile->soa->{serial};
ok($newserial = $serial+1, 'new_serial( int )');
$serial = $zonefile->new_serial();
ok($serial > $newserial, 'new_serial()');

is_deeply($zonefile->soa, {
                 'minimumTTL' => '86400',
                 'serial' => $serial,
                 'ttl' => '3600',
                 'primary' => 'ns0.dns-zoneparse-test.net.',
                 'origin' => '@',
                 'email' => 'support.dns-zoneparse-test.net.',
                 'retry' => '3600',
                 'refresh' => '10800',
                 'expire' => '691200'
                }, 'SOA parsed ok');


is_deeply($zonefile->a, [
           {
            'ttl' => '', 'name' => '@', 'class' => 'IN', 'host' => '127.0.0.1'
           },
           {
            'ttl' => '','name' => 'localhost', 'class' => 'IN',
            'host' => '127.0.0.1'
           },
           {
            'ttl' => '', 'name' => 'mail','class' => 'IN','host' => '127.0.0.1'
           },
           {
            'ttl' => '', 'name' => 'www','class' => 'IN', 'host' => '127.0.0.1'
           },
           {
            'ttl' => '', 'name' => '', 'class' => 'IN', 'host' => '10.0.0.2'
           },
           {
            'ttl' => '', 'name' => '', 'class' => 'IN', 'host' => '10.0.0.3'
           }
          ], 'A records parsed OK');

is_deeply($zonefile->ns, [
          {
            'ttl' => '',
            'name' => '@',
            'class' => 'IN',
            'host' => 'ns0.dns-zoneparse-test.net.'
          },
          {
            'ttl' => '',
            'name' => '@',
            'class' => 'IN',
            'host' => 'ns1.dns-zoneparse-test.net.'
          }
         ], 'NS records parsed OK');

is_deeply($zonefile->mx, [
          {
            'priority' => '10',
            'ttl' => '',
            'name' => '@',
            'class' => 'IN',
            'host' => 'mail'
          }
        ], 'MX records parsed OK');

is_deeply($zonefile->cname, [
          {
            'ttl' => '',
            'name' => 'ftp',
            'class' => 'IN',
            'host' => 'www'
          }
        ], 'CNAME records parsed OK');


is_deeply($zonefile->txt, [
          {
            'text' => 'This is a text message',
            'ttl' => '',
            'name' => 'soup',
            'class' => 'IN'
          }
        ], 'TXT records parsed OK');

