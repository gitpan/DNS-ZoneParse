# DNS::ZoneParse
# Parse and Manipulate DNS Zonefiles
# Version 0.30
# CVS: $Id: ZoneParse.pm,v 1.5 2001-05-21 13:00:51+01 simon Exp simon $
package DNS::ZoneParse;

require 5.005_03;
use vars qw($VERSION @ISA);
use strict;
use Carp;

require Exporter;
@ISA = qw(Exporter);
$VERSION = '0.35';


sub new {
    my $self = {};
    bless $self;
    $self->_initialize();
    return $self;
}


sub _initialize {
	my $self = shift;
	$self->{Zone} = { SOA => {},
			  AAAA => [],
			  A => [],
			  NS  => [],
			  CNAME => [],
			  MX  => [],
			  PTR => [],
			  TXT => [],			  
		};
	$self->{Identity} = {};
	return 1;
}


sub Prepare {		
	my ($self, $zonefile) = @_;
	if(ref($zonefile) eq "SCALAR")	
	{
		$self->{ZoneFile} = $$zonefile;
		$self->Parse();
	} else { 
		if (open(inZONE, "$zonefile")) {
			while (<inZONE>) { $self->{ZoneFile} .= $_ }
			close(inZONE);
			$self->Parse();
		} else {
			croak "DNS::ParseZone Could not open input file: \"$zonefile\" $!\n";
		}
	}
	if ($self->Parse()) { return 1; }
}


sub Parse {
	my $self=shift;
	my $chars = qr/[a-z\-\.0-9]+/i;
	$self->{ZoneFile} =~ /Database file ($chars)( dns)? for ($chars) zone/si;
	$self->{Identity} = { ZoneFile => $1, Origin => $3};

	$self->{RRs} = [];
	$self->_clean_records();
	my $valid_name = qr/[\@a-z\-\.0-9\*]+/i;
	my $rr_class = qr/in|hs|ch/i;
	my $rr_types = qr/ns|a|cname/i;
	my $rr_ttl = qr/\d+/;
		
	foreach my $RR (@{$self->{RRs}}) {
		
		if ($RR =~ /($valid_name)?\s+($rr_ttl)?\s*?($rr_class)?\s*?($rr_types)\s+($valid_name)/i)
		{
			my $class = uc $4;
			push (@{$self->{Zone}->{$class}}, {name => $1.'', class=> $3.'', host => $5.'',
							   ttl => $2.''});
		}
		elsif ($RR =~ /($valid_name)\s+($rr_ttl)?\s*?($rr_class)?\s*?mx\s(\d+)\s($valid_name)/i) 
		{
			push (@{$self->{Zone}->{MX}}, {name => $1.'', priority => $4.'', host => $5.'', 
							ttl => $2.'', class => $3});
		}
		elsif ($RR =~ /($valid_name)\s+($rr_ttl)?\s*?($rr_class)?\s*?SOA\s+($valid_name)\s+($valid_name)\s*?\(?\s*?($rr_ttl)\s+($rr_ttl)\s+($rr_ttl)\s+($rr_ttl)\s+($rr_ttl)\s*\)?/i) {
			$self->{Zone}->{SOA} = {origin => $1.'', ttl => $2.'', primary => $4.'', 
						email =>$5.'', serial => $6.'', refresh=> $7.'', 
						retry=> $8.'', expire=> $9.'', minimumTTL => $10.''};
		}
		elsif ($RR =~ /([\d\.]+)\s+($rr_ttl)?\s*?($rr_class)?\s*?PTR\s+($valid_name)/i) {
			push (@{$self->{Zone}->{PTR}}, {name => $1.'', class => $2.'', ttl => $3.'', 
							host => $4.''});
		}
		elsif ($RR =~ /($valid_name)\s+($rr_ttl)?\s*?($rr_class)?\s*?TXT\s+\"([^\"]*)\"/i) {
			push (@{$self->{Zone}->{TXT}}, {name => $1.'', ttl => $2.'', class => $3.'', 
							text=> $4.''});
		}
	}
	# comment the next two lines for debugging.
	undef $self->{ZoneFile};
	undef $self->{RRs};
	return 1;
}

sub _clean_records {
	my $self = shift;

	my $zone = $self->{ZoneFile};
	$zone =~ s/\;.{0,}$//mg;	# Remove comments
	$zone =~ s/^\s*?$//mg;		# Remove empty lines
	$zone =~ s#$/{2,}#$/#g;		# Remove double carriage returns
	
	# Concatenate everything split over multiple lines i.e. elements surrounded by parentheses can be 
	# split over multiple lines. See RFC 1035 section 5.1
	$zone=~ s{(\([^\)]*?\))}{_concatenate( $1)}egs;

	@{$self->{RRs}} = split (m#$/#, $zone);
	foreach (@{$self->{RRs}}) { s/\s+/\t/g; }

	return 1;
}

sub _concatenate {
	my $text_in_parenth= shift;
	$text_in_parenth=~ s{$/}{}g;
	return $text_in_parenth;
}

sub newSerial {
	my $self = shift;
	my $incriment = shift;
	carp "Parse RRs before incrimenting the serial number" unless $self->{Zone}->{SOA}->{serial};
	if ($incriment > 0) { 
		$self->{Zone}->{SOA}->{serial} += $incriment;
	} else {
		$self->{Zone}->{SOA}->{serial}++;
	}
	return 1;
}


sub PrintZone {
	my $self = shift;
	my @quick_classes = qw(A CNAME);	
	my $temp_zone_file = "";
	$temp_zone_file .= <<ZONEHEADER;
;
;  Database file $self->{Identity}->{ZoneFile} for $self->{Identity}->{Origin} zone.
;	Zone version: $self->{Zone}->{SOA}->{serial}
; 

$self->{Zone}->{SOA}->{origin}		$self->{Zone}->{SOA}->{ttl}	IN  SOA  $self->{Zone}->{SOA}->{primary} $self->{Zone}->{SOA}->{email} (
				$self->{Zone}->{SOA}->{serial}	; serial number
				$self->{Zone}->{SOA}->{refresh}	; refresh
				$self->{Zone}->{SOA}->{retry}	; retry
				$self->{Zone}->{SOA}->{expire}	; expire
				$self->{Zone}->{SOA}->{minimumTTL}	; minimum TTL

;
; Zone NS Records
;

ZONEHEADER

	foreach my $rr (@{$self->{Zone}->{NS}}) {
		$temp_zone_file .= "$rr->{name}	$rr->{ttl}	$rr->{class}	NS	$rr->{host}\n";
	}

	$temp_zone_file .= "\n\;\n\; Zone Records\n\;\n\n";

	foreach my $class (@quick_classes) {
		foreach my $rr (@{$self->{Zone}->{$class}}) {
			$temp_zone_file .= "$rr->{name}	$rr->{ttl}	$rr->{class}	$class	$rr->{host}\n";
		}
	}

	foreach my $rr (@{$self->{Zone}->{MX}}) {
		$temp_zone_file .= "$rr->{name}	$rr->{ttl}	$rr->{class}	MX	$rr->{pritority}  $rr->{host}\n";
	}

	$self->{ZoneFile}	 = $temp_zone_file;
	return $self->{ZoneFile};
}




1;
__END__

=head1 NAME

DNS::ZoneParse - Perl extension for parsing and manipulating DNS Zone Files.

=head1 SYNOPSIS

	use DNS::ZoneParse;

	my $dnsfile = DNS::ZoneParse->new();

	$dnsfile->Prepare("/path/to/dns/zonefile.db");

	print $dnsfile->{Zone}->{SOA}->{serial};
	$dnsfile->newSerial();
	print $dnsfile->{Zone}->{SOA}->{serial};
	
	print $dnsfile->PrintZone();

=head1 INSTALLATION

   perl Makefile.PL
   make
   make test
   make install

Win32 users substitute "make" with "nmake" or equivalent. 
nmake is available at http://download.microsoft.com/download/vc15/Patch/1.52/W95/EN-US/Nmake15.exe

=head1 DESCRIPTION

This module will parse a Zone File and put all the Resource Records (RRs) into an anonymous hash structure. At the moment, the following types of RRs are supported: SOA, NS, MX, A, CNAME, TXT, PTR. It could be useful for maintaining DNS zones, or for transferring DNS zones to other servers. If you want to generate an XML-friendly version of your zone files, it is easy to use XML::Simple with this module once you have parsed the zonefile.

The Prepare method scans the DNS zonefile - removes comments and seperates the file into it's constituent records. It then parses each record and stores the objects in the $object->{Zone} hash. Using Data::Dumper on that object will give you a better idea of what this looks like than I can describe.

You can access the objects in the $object->{Zone} hash to add\remove\modify RRs directly, and then you can call $object->PrintZone(), and it will return and create a new Zone File in the $object->{ZoneFile} string.

I will update this documentation - it's pretty sparse at the moment, but many more features coming...
	

=head2 METHODS

=over 4

=item new

This creates the DNS::ZoneParse Object

Example:
    my $dnsfile = DNS::ZoneParse->new();

=item Prepare

C<Prepare()> will do some preliminary checks and then parse the supplied DNS Zone File. You can pass it the text content from the DNS Zone File as a reference or the path to a filename.

Examples:

    $dnsfile->Prepare("/path/to/zonefile.db");

or

    my $zonefile;
    open (Zone, "/path/to/zonefile.db");
    while (<Zone>) { $zonefile .= $_ }
    close (Zone);

    $dnsfile->Prepare(\$zonefile);

=item Parse

C<Parse()> is called internally by the C<Prepare()> method. You can call it independently. It takes no arguments. All that is required is that $object->{ZoneFile} (string) contains a valid DNS Zone File.

=item newSerial

C<newSerial()> incriments the Zone serial number. You can pass a positive number to add to the current serial number or it will default to 1.

Examples:

    $dnsfile->newSerial();    # adds 1 to the original serial number
    $dnsfile->newSerial(50);    # adds 50 to the original serial number
    $dnsfile->newSerial(-50);    # adds 1 to the original serial number

=item PrintZone

C<PrintZone()> loops through the Resource Records and creates a zone file in $object->{ZoneFile}. It also returns the new zonefile.

=back

=head2 EXAMPLES

This script will print the A records in a zone file, add a new A record for the name "new" and then return the zone file.

    use strict;
    use DNS::ZoneParse;
    
    my $dnsfile = DNS::ZoneParse->new();
    $dnsfile->Prepare("/path/to/zonefile.db");
    
    print "Current A Records\n";
    foreach my $a (@{$dnsfile->{Zone}->{A}}) {
        print "$a->{name} resolves at $a->{host}\n";
    }

    push (@{$dnsfile->{Zone}->{A}}, { name => 'new', class => 'IN', host => '127.0.0.1', ttl => '' });

    $dnsfile->newSerial();
    my $newfile = $dnsfile->PrintZone();




This script will convert a DNS Zonefile to an XML file using XML::Simple.


    use strict;
    use DNS::ZoneParse;
    use XML::Simple;
    
    my $dnsfile = DNS::ZoneParse->new();
    $dnsfile->Prepare("/path/to/zonefile.db");

    my $new_xml = XMLout($dnsfile->{Zone}, noattr => 1, suppressempty => 1, rootname => $dnsfile->{Zone}->{SOA}->{serial});


=head1 EXPORT

None by default. Object-oriented interface.

=head1 TO DO

These are things that I need to do...

=over 4
Resource Records that have multiple entries\ip addresses

=item IPv6 compatability

There is already space for the AAAA records, but I need to read the rest of the RFCs before I finish this part.

=item More intelligent serial number generation.

Possibly add the option of date-based updates to serial number

=item Cleaner parsing

The parsing here does work on the tested systems, but there may be cleaner ways of doing it.

=item Better documentation

Come on, you know this is hopeless!

=back

=head1 BUGS & REQUESTS

Please let me know!


=head1 AUTHOR

S. Flack : perl@simonflack.com

=head1 SEE ALSO

DNS::ZoneFile

=cut
