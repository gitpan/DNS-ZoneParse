# DNS::ZoneParse
# Parse and Manipulate DNS Zonefiles
# Version 0.10
# CVS: $Id: ZoneParse.pm,v 1.2 2001-03-12 14:44:34+00 simon Exp simon $
package DNS::ZoneParse;

require 5.005_62;
use strict;

require Exporter;
our @ISA = qw(Exporter);
our $VERSION = '0.10';


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
		$self->{ZoneFile} = $zonefile;
		my $chars = qr/[a-z\-\.0-9]+/i;
		$$zonefile =~ /Database file ($chars)( dns)? for ($chars) zone/si;
		$self->{Identity} = { ZoneFile => $1, Origin => $3};
		$self->Parse();
	} else { return undef; }
	return 1;
}

sub Parse {
	my $self=shift;
	$self->{RRs} = [];
	$self->_clean_records();
	my $valid_name = qr/[\@a-z\-\.0-9\*]+/i;
	my $rr_class = qr/in|hs|ch/i;
	my $rr_types = qr/ns|a|cname/i;
	my $rr_ttl = qr/\d+/;
		
	foreach my $RR (@{$self->{RRs}}) {
		
		if ($RR =~ /($valid_name)\s+($rr_ttl)?\s*?($rr_class)?\s*?($rr_types)\s+($valid_name)/i)
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
		elsif ($RR =~ /($valid_name)\s+($rr_ttl)?\s*?($rr_class)?\s*?SOA\s+($valid_name)\s+($valid_name)\s*?\(?\s*?($rr_ttl)\s+($rr_ttl)\s+($rr_ttl)\s+($rr_ttl)\s+($rr_ttl)\s+\)?/i) {
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

	my $zone = ${$self->{ZoneFile}};
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
	warn "Parse RRs before incrimenting the serial number" unless $self->{Zone}->{SOA}->{serial};
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

	use C<DNS::ZoneParse>;

	my $dnsfile = C<DNS::ZoneParse>->new();

	open (FH, "/path/to/dns/zonefile.db");
	while (<FH>) { $zonefile .= $_ }
	close (FH);

	$dnsfile->Prepare(\$zonefile);

	print $dnsfile->{Zone}->{SOA}->{serial};
	$dnsfile->newSerial();
	print $dnsfile->{Zone}->{SOA}->{serial};
	
	print $dnsfile->PrintZone();

=head1 DESCRIPTION

This module will parse a Zone File and put all the Resource Records (RRs) into an anonymous hash structure. At the moment, the following types of RRs are supported: SOA, NS, MX, A, CNAME, TXT, PTR. It could be useful for maintaining DNS zones, or for transferring DNS zones to other servers. If you want to generate an XML-friendly version of your zone files, it is easy to use XML::Simple with this module once you have parsed the zonefile.

The Prepare method scans the DNS zonefile - removes comments and seperates the file into it's constituent records. It then parses each record and stores the objects in the $object->{Zone} hash. Using Data::Dumper on that object will give you a better idea of what this looks like than I can describe.

You can access the objects in the $object->{Zone} hash to add\remove\modify RRs directly, and then you can call $object->PrintZone(), and it will return and create a new Zone File in the $object->{ZoneFile} string.

I will update this documentation - it's pretty sparse at the moment, but many more features coming...
	
=head2 EXPORT

None by default.


=head1 AUTHOR

S. Flack : perl@simonflack.com

=head1 SEE ALSO

DNS::ZoneFile

=cut
