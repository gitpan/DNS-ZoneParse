# DNS::ZoneParse
# Parse and Manipulate DNS Zonefiles
# Version 0.83
# CVS: $Id: ZoneParse.pm,v 1.2 2003/01/18 00:24:26 simonflack Exp $
package DNS::ZoneParse;

use vars qw($VERSION);
use strict;
use Carp;

$VERSION = '0.83';

sub new {
    my $class = shift;

    my $self = {};
    bless $self, $class;

	if (@_) {
	  $self->load_file(@_);
	} else {
	  $self->_initialize();
	}

    return $self;
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Accessor Methods
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

sub DESTROY {}

sub AUTOLOAD
{
	my $self = shift;
	(my $method = $DNS::ZoneParse::AUTOLOAD) =~ s/.*:://;
	
	my @accessors = map { lc } keys ( %{$self->{_Zone}} );
	croak "Invalid method called: $method" 
			unless grep { $_ eq $method } @accessors, qw(origin zonefile);
	
	return $self->{Identity}->{ZoneFile} if $method eq "zonefile";
	return $self->{Identity}->{Origin} if $method eq "origin";
	
	return $self->{_Zone}->{uc $method};
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Public OO Methods
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

sub Dump
{
	# returns a HOH for use with XML modules, etc
	return $_[0]->{_Zone};
}

sub newSerial {
	my $self = shift;
	my $incriment = shift || 0;
	if ($incriment > 0) { 
		$self->{_Zone}->{SOA}->{serial} += $incriment;
	} else {
		my ($day,$mon,$year) = ( localtime() )[3 .. 5];
		my $newserial = sprintf("%d%02d%02d01", $year + 1900, $mon+1, $day);
		
		for (1..10)
		{
			if ($newserial > $self->{_Zone}->{SOA}->{serial})
			{
				$self->{_Zone}->{SOA}->{serial} = $newserial;
				return 1;
			} else {
				$newserial++;
			}
		}

		$self->{_Zone}->{SOA}->{serial}++;
	}
	return 1;
}

sub PrintZone {
	my $self = shift;
	my @quick_classes = qw(A AAAA CNAME PTR);	
	my $temp_zone_file = "";
	$temp_zone_file .= <<ZONEHEADER;
;
;  Database file $self->{Identity}->{ZoneFile} for $self->{Identity}->{Origin} zone.
;	Zone version: $self->{_Zone}->{SOA}->{serial}
; 

\$TTL $self->{_Zone}->{SOA}->{ttl}
$self->{_Zone}->{SOA}->{origin}		$self->{_Zone}->{SOA}->{ttl}	IN  SOA  $self->{_Zone}->{SOA}->{primary} $self->{_Zone}->{SOA}->{email} (
				$self->{_Zone}->{SOA}->{serial}	; serial number
				$self->{_Zone}->{SOA}->{refresh}	; refresh
				$self->{_Zone}->{SOA}->{retry}	; retry
				$self->{_Zone}->{SOA}->{expire}	; expire
				$self->{_Zone}->{SOA}->{minimumTTL}	; minimum TTL
				)
;
; Zone NS Records
;

ZONEHEADER

	foreach my $rr (@{$self->{_Zone}->{NS}}) {
		$temp_zone_file .= "$rr->{name}	$rr->{ttl}	$rr->{class}	NS	$rr->{host}\n";
	}

	$temp_zone_file .= "\n\;\n\; Zone MX Records\n\;\n\n";
	foreach my $rr (@{$self->{_Zone}->{MX}}) {
		$temp_zone_file .= "$rr->{name}	$rr->{ttl}	$rr->{class}	MX	$rr->{priority}  $rr->{host}\n";
	}




	$temp_zone_file .= "\n\;\n\; Zone Records\n\;\n\n";

	foreach my $class (@quick_classes) {
		foreach my $rr (@{$self->{_Zone}->{$class}}) {
			$temp_zone_file .= "$rr->{name}	$rr->{ttl}	$rr->{class}	$class	$rr->{host}\n";
		}
	}

	$self->{ZoneFile}	 = $temp_zone_file;
	return $self->{ZoneFile};
}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Private Methods
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

sub _initialize {
	my $self = shift;
	$self->{_Zone} = { SOA => {},
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


sub load_file {		
	my ($self, $zonefile) = @_;
	if(ref($zonefile) eq "SCALAR")	
	{
		$self->{ZoneFile} = $$zonefile;
	} else { 
		if (open(inZONE, "$zonefile")) {
			while (<inZONE>) { $self->{ZoneFile} .= $_; }
			close(inZONE);
		} else {
			croak "DNS::ParseZone Could not open input file: \"$zonefile\" $!\n";
		}
	}
	if ($self->_parse( $zonefile )) { return 1; }
}


sub _parse {
	my ($self, $zonefile) = @_;
	$self->_initialize();
    
	my $chars = qr/[a-z\-\.0-9]+/i;
	$self->{ZoneFile} =~ /Database file ($chars)( dns)? for ($chars) zone/si;
	$self->{Identity} = { ZoneFile => $1||$zonefile, Origin => $3||'XXX'};

	$self->{RRs} = [];
	$self->_clean_records();
	my $valid_name = qr/[\@a-z_\-\.0-9\*]+/i;
	my $rr_class = qr/in|hs|ch/i;
	my $rr_types = qr/ns|a|cname/i;
	my $rr_ttl = qr/(?:\d+[wdhms]?)+/i;
		
	foreach my $RR (@{$self->{RRs}}) {
		
		if ($RR =~ /($valid_name)?\s+($rr_ttl)?\s*?($rr_class)?\s*?($rr_types)\s+($valid_name)/i)
		{
			my $class = uc $4;
			push (@{$self->{_Zone}->{$class}}, {name => $1||'', class=> $3||'', host => $5||'',
							   ttl => $2||''});
		}
		elsif ($RR =~ /($valid_name)?\s+($rr_ttl)?\s*?($rr_class)?\s*?mx\s(\d+)\s($valid_name)/i) 
		{
			push (@{$self->{_Zone}->{MX}}, {name => $1||'', priority => $4||'', host => $5||'', 
							ttl => $2||'', class => $3});
		}
		elsif ($RR =~ /($valid_name)\s+($rr_ttl)?\s*?($rr_class)?\s*?SOA\s+($valid_name)\s+($valid_name)\s*?\(?\s*?($rr_ttl)\s+($rr_ttl)\s+($rr_ttl)\s+($rr_ttl)\s+($rr_ttl)\s*\)?/i) {
			my $ttl = $self->{_Zone}->{SOA}->{ttl}||$2||'';
			$self->{_Zone}->{SOA} = {origin => $1||'', ttl => $ttl, primary => $4||'', 
						email =>$5||'', serial => $6||'', refresh=> $7||'', 
						retry=> $8||'', expire=> $9||'', minimumTTL => $10||''};
		}
		elsif ($RR =~ /([\d\.]+)\s+($rr_ttl)?\s*?($rr_class)?\s*?PTR\s+($valid_name)/i) {
			push (@{$self->{_Zone}->{PTR}}, {name => $1||'', class => $3||'', ttl => $2||'', 
							host => $4||''});
		}
		elsif ($RR =~ /($valid_name)\s+($rr_ttl)?\s*?($rr_class)?\s*?TXT\s+\"([^\"]*)\"/i) {
			push (@{$self->{_Zone}->{TXT}}, {name => $1||'', ttl => $2||'', class => $3||'', 
							text=> $4||''});
		}
		elsif ($RR =~ /\$TTL\s+($rr_ttl)/i) {
			$self->{_Zone}->{SOA}->{ttl} = $1;
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



1;
__END__

=head1 NAME

DNS::ZoneParse - Perl extension for parsing and manipulating DNS Zone Files.

=head1 SYNOPSIS

	use DNS::ZoneParse;

	my $dnsfile = DNS::ZoneParse->new("/path/to/dns/zonefile.db");

	# Get a reference to the MX records
	my $mx = $dnsfile->mx;
	
	# Change the first mailserver on the list
	$mx->[0] = { host => 'mail.localhost.com',
	             priority => 10,
	             name => '@' };

	# update the serial number
	$dnsfile->newSerial();
	
	# write the new zone file to disk 
	open NEWZONE, ">/path/to/dns/zonefile.db" or die "error";
	print NEWZONE $dnsfile->PrintZone();
	close NEWZONE;

=head1 INSTALLATION

   perl Makefile.PL
   make
   make test
   make install

Win32 users substitute "make" with "nmake" or equivalent. 
nmake is available at http://download.microsoft.com/download/vc15/Patch/1.52/W95/EN-US/Nmake15.exe

=head1 DESCRIPTION

This module will parse a Zone File and put all the Resource Records (RRs)
into an anonymous hash structure. At the moment, the following types of 
RRs are supported: SOA, NS, MX, A, CNAME, TXT, PTR. It could be useful for
maintaining DNS zones, or for transferring DNS zones to other servers. If
you want to generate an XML-friendly version of your zone files, it is
easy to use XML::Simple with this module once you have parsed the zonefile.

DNS::ZoneParse scans the DNS zonefile - removes comments and seperates
the file into it's constituent records. It then parses each record and
stores the records internally. See below for information on the accessor
methods.


=head2 METHODS

=over 4

=item new

This creates the DNS::ZoneParse Object and loads the zonefile

Example:
    my $dnsfile = DNS::ZoneParse->new("/path/to/zonefile.db");

We do some preliminary checks and then parse the supplied DNS Zone File. You
can pass it the text content from the DNS Zone File as a reference or the
path to a filename.

=item a(), cname(), mx(), ns(), ptr()

These methods return references to the resource records. For example:

    my $mx = $dnsfile->mx;

Returns the mx records in an array reference.

A, CNAME, NS, MX and PTR records have the following properties:
'ttl', 'class', 'host', 'name'

MX records also have a 'priority' property.

=item soa()

Returns a hash reference with the following properties:
'serial', 'origin', 'primary', 'refresh', 'retry', 'ttl', 'minimumTTL',
'email', 'expire'

=item Dump

Returns a hash reference of all the resource records. This might be useful if you want
to quickly transform the data into another format, such as XML.

=item newSerial

C<newSerial()> incriments the Zone serial number. It will generate a date-based
serial number. Or you can pass a positive number to add to the current serial
number.

Examples:

    $dnsfile->newSerial();    # generates a new serial number based on date:
                              # YYYYMMDD## format, incriments current serial
                              # by 1 if the new serial is still smaller than the current.
    $dnsfile->newSerial(50);  # adds 50 to the original serial number

=item PrintZone

C<PrintZone()> loops through the Resource Records and returns the new zonefile.


=item Prepare

(obsolete)

=item Parse

(obsolete)

=back

=head2 EXAMPLES

This script will print the A records in a zone file, add a new A record for the name
"new" and then return the zone file.

    use strict;
    use DNS::ZoneParse;
    
    my $dnsfile = DNS::ZoneParse->new("/path/to/zonefile.db");
    
    print "Current A Records\n";
    my $a_records = $dnsfile->a();
    
    foreach my $record (@$a_records) {
		print "$record->{name} resolves at $record->{host}\n";
    }

    push (@$a_records, { name => 'new', class => 'IN', host => '127.0.0.1', ttl => '' });

    $dnsfile->newSerial();
    my $newfile = $dnsfile->PrintZone();




This script will convert a DNS Zonefile to an XML file using XML::Simple.


    use strict;
    use DNS::ZoneParse;
    use XML::Simple;
    
    my $dnsfile = DNS::ZoneParse->new("/path/to/zonefile.db");

    my $new_xml = XMLout($dnsfile->Dump, 
                         noattr => 1, 
                         suppressempty => 1, 
                         rootname => $dnsfile->origin);

=head1 CHANGES

see F<Changes>

=head1 TODO

=over 4

=item Rewrite parser - Parse::RecDescent maybe?

=item User-supplied callbacks on record parse

=item cleaner API and code

=item add more tests

=back

=head1 EXPORT

None by default. Object-oriented interface.

=head1 AUTHOR

S. Flack : perl@simonflack.com

=head1 LICENSE

DNS::ZoneParse is free software which you can redistribute and/or modify under
the same terms as Perl itself.

=head1 SEE ALSO

DNS::ZoneFile

=cut
