use strict;
$^W++;
use Test::More tests => 19;
use File::Spec::Functions ':ALL';

# See if the module compiles - it should...
require_ok('DNS::ZoneParse');

my $filename = catfile( (splitpath(rel2abs($0)))[0,1], 'test-zone.db' );
local *FH;
open FH, "< $filename" or die "error loading test file $filename: $!";
my $zone_data = do {local $/; <FH>};
close FH;

#create a DNS::ZoneParse object;

my $str_zonefile = DNS::ZoneParse->new(\$zone_data);
ok($str_zonefile, 'new obj from string');
test_zone($str_zonefile);

my $str_zonefile = DNS::ZoneParse->new($filename);
ok($str_zonefile, 'new obj from filename');
test_zone($str_zonefile);

sub test_zone {
    my $zf = shift;

    # See if the new_serial method works.
    my $serial = $zf->soa->{serial};
    $zf->new_serial(1);
    my $newserial = $zf->soa->{serial};
    ok($newserial = $serial+1, 'new_serial( int )');
    $serial = $zf->new_serial();
    ok($serial > $newserial, 'new_serial()');

    is_deeply($zf->soa, {
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


    is_deeply($zf->a, [
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
            'ttl' => '', 'name' => 'www', 'class' => 'IN', 'host' => '10.0.0.2'
           },
           {
            'ttl' => '', 'name' => 'www', 'class' => '', 'host' => '10.0.0.4'
           },
           {
            'ttl' => '', 'name' => 'foo', 'class' => 'IN', 'host' => '10.0.0.5'
           },
            {
            'ttl' => '', 'name' => 'mini', 'class' => '', 'host' => '10.0.0.6'
           },
          ], 'A records parsed OK');

    is_deeply($zf->ns, [
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

    is_deeply($zf->mx, [
          {
            'priority' => '10',
            'ttl' => '',
            'name' => '@',
            'class' => 'IN',
            'host' => 'mail'
          },
          {
            'priority' => '10',
            'ttl' => '',
            'name' => 'www',
            'class' => 'IN',
            'host' => '10.0.0.3'
          },
        ], 'MX records parsed OK');

    is_deeply($zf->cname, [
          {
            'ttl' => '',
            'name' => 'ftp',
            'class' => 'IN',
            'host' => 'www'
          }
        ], 'CNAME records parsed OK');


    is_deeply($zf->txt, [
          {
            'text' => 'This is a text message',
            'ttl' => '',
            'name' => 'soup',
            'class' => 'IN'
          },
          {
            'text' => 'This is another text message',
            'ttl' => '',
            'name' => 'txta',
            'class' => ''
          }

        ], 'TXT records parsed OK');
}

