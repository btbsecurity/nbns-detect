#!/usr/bin/perl

use strict;
use warnings;

use IO::Socket;
use IO::Select;
use IO::Interface;
use Getopt::Long qw(:config no_ignore_case);
use POSIX qw/strftime/;
use Net::SMTP;
use Sys::Syslog qw(:DEFAULT setlogsock);

die "This script needs root privileges to run.
The Metasploit nbns_response module sends responses to port 137 regardless of the source port of the NBNS query.
That's fine, but it means we need to bind to 137, and that means root privileges\n" if $> != 0;

# Global and default values
my $port = 137;
my $name = 'BTB2351';
my $recv_timeout = 2;
my $transID = 0x092F;
my $delay = 10;
my $int;
my $email;
my $mailserver;
my $mailport = 25;
my $syslog;
my $syslogport = 514;
my $syslogfacility = 16;
my $sysloglevel = 6;
my $logfile;
my $help;
my $test;
my $verbose;
my $ipRegex = '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$';
my $hostnameRegex = '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$';
my $emailRegex = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$';

GetOptions(
	'interface|i=s'		=> \$int,
	'name|n=s'		=> \$name,
	'delay|d=i'		=> \$delay,
	'help|h'		=> \$help,
	'verbose|v'		=> \$verbose,
	'email=s'		=> \$email,
	'mailserver=s'		=> \$mailserver,
	'mailport=i'		=> \$mailport,
	'syslog=s'		=> \$syslog,
	'syslogport=i'		=> \$syslogport,
	'syslogfacility=i'	=> \$syslogfacility,
	'sysloglevel=i'		=> \$sysloglevel,
	'logfile|l=s'		=> \$logfile,
	'test'			=> \$test,
) or &usage;

# Usage Stuff
&usage if $help;
&usage if !($int);
die "[ERROR] Name should be no more than 16 characters from the following character sets: 0-9, a-z, A-Z.\n" if ($name !~ /^[0-9a-zA-Z\-]+$/||length($name) > 16);
die "[ERROR] Timeout value should not exceed 10 seconds. A longer timeout value can cause the receiving socket to block on noisy networks\n" if $recv_timeout > 10;
if ($email||$mailserver) {
	if ($email) {
		die "[ERROR] Please specify a proper email address.\n" if $email !~ /$emailRegex/;
	} else {
		die "[ERROR] Please specify an email address (--email).\n";
	}
	if ($mailserver) {
		die "[ERROR] Please specify a proper mail server address.\n" if $mailserver !~ /$ipRegex|$hostnameRegex/;
	} else {
		die "[ERROR] Please specify a mail server (--mailserver).\n";
	}
	die "[ERROR] Please specify a proper mail server port.\n" if !($mailport < 65536  && $mailport > 0);
}
if ($syslog) {
	die "[ERROR] Sys::Syslog version is less than 0.28. Please update Sys::Syslog to the latest version(installed version: $Sys::Syslog::VERSION).\n" if ($Sys::Syslog::VERSION < 0.28);
	die "[ERROR] Please specify a proper syslog server address.\n" if $syslog !~ /$ipRegex|$hostnameRegex/;
	die "[ERROR] Please specify a proper syslog port.\n" if !($syslogport < 65536  && $syslogport > 0);
	die "[ERROR] Please specify a proper syslog facility. See RFC 5424 for acceptable values - https://tools.ietf.org/html/rfc5424#section-6.2.1\n" if !($syslogfacility < 24  && $syslogfacility > -1);
	die "[ERROR] Please specify a proper syslog severity level. See RFC 5424 for acceptable values - https://tools.ietf.org/html/rfc5424#section-6.2.1\n" if !($sysloglevel < 8  && $sysloglevel > -1);
}

if ($logfile) {
	die "[ERROR] Specify a proper log file name\n" if $logfile =~ /^-/; # Just to make sure the user didn't forget to include the file name and kept going with other arguments.
	open my $test_fh, ">>", $logfile or die "[ERROR] Cannot open log file $logfile: $!\n";
	close $test_fh;
}

if ($test) {
	print "Sending test messages to the following destinations:\n";
	if ($syslog) {
		print "Syslog Server: $syslog:$syslogport; Syslog Facility/Level: $syslogfacility/$sysloglevel\n" if $syslog ne 'local';
		print "Syslog Server: $syslog; Syslog Facility/Level: $syslogfacility/$sysloglevel\n" if $syslog eq 'local';
	}
	print "Email: $email at $mailserver:$mailport\n" if $email;
	print "Log File: $logfile\n" if $logfile;	
	print "\n";
	
	my $date = strftime('%b %d %T',localtime);
	my @msg;
	push(@msg,$date);
	push(@msg, 'Test');
	push(@msg,'4.4.4.4');
	&mailer($email,$mailserver,$mailport,\@msg) if ($email);
	&syslogger($syslog,$syslogport,$syslogfacility,$sysloglevel,\@msg) if ($syslog);
	&locallog($logfile,\@msg) if ($logfile);
	exit;
}

my ($addr,$bcast) = &get_interface($int);

print "NetBIOS Name Service Spoofing Detection Script\n";
print "BTB Security - www.btbsecurity.com\n\n";
print "NetBIOS Name Request: $name\n";
print "Interface: $int\n";
print "Broadcast Address: $bcast\n";
print "Query delay: $delay seconds\n";
print "Syslog Server: $syslog; Syslog Facility/Level: $syslogfacility/$sysloglevel\n" if $syslog;
print "Email Alerts: $email at $mailserver\n" if $email;
print "Log File: $logfile\n" if $logfile;
print "\n";

while (1) {

	# Make Sender Socket
	my $send_sock = IO::Socket::INET->new( Proto => 'udp', LocalPort => $port) or die $!;
	$send_sock->sockopt(SO_BROADCAST() => 1);
	my $dest = sockaddr_in($port, inet_aton($bcast));
	
	# Make Payload
	my $data = &make_payload(uc($name));
	
	# Send Payload
	print strftime('%b %d %T',localtime)." - Broadcasting NBNS query for $name\n" if $verbose;
	$send_sock->send($data,0,$dest) or die "send() failed: $!";
	$send_sock->close;

	# Make the server
	my $sel = IO::Select->new;
	my $recv_socket = IO::Socket::INET->new(
		LocalAddr  => $addr,
		LocalPort  => $port,	# This requires us to run as root. Needed as the MSF nbns_response module ignores source port of request and sends to 137
		Broadcast  =>  1,
		Proto      => 'udp'
		) or die "Failed to bind to socket: $@";
	$sel->add($recv_socket);
	
	# Read from the server 
	# The script can block here if it continues to receive NBNS queries/responses before the timeout expires. Forcing shut after 15 seconds via alarm.
	eval {
		local $SIG{ALRM} = sub { die "[INFORMATION] Server is staying open too long, shutting it down.\n" }; #
		alarm 15;
		while (my @r = $sel->can_read($recv_timeout)) {
			$recv_socket->recv(my $buf, 1024);
			my $peerhost = $recv_socket->peerhost;
			my @msg;
			my $date = strftime('%b %d %T',localtime);
			
			my @rsp = validate_packet($buf);
			if ($rsp[0] == 1) {
				push(@msg,$date);
				push(@msg, $peerhost);
				if ($rsp[1] == 1) {
					push(@msg,$rsp[2]);
				} else {
					push(@msg,'RR_TYPE was not defined');
				}
				print $msg[0].' - NBNS Spoofing Detected - Peerhost: '.$msg[1].'; Spoofed IP: '.$msg[2]."\n";
				&mailer($email,$mailserver,$mailport,\@msg) if ($email);
				&syslogger($syslog,$syslogport,$syslogfacility,$sysloglevel,\@msg) if ($syslog);
				&locallog($logfile,\@msg) if ($logfile);
			}
		}
		alarm 0;
	}; warn $@ if $@;
	$recv_socket->close;
	sleep $delay;
}

sub usage {
	print "Usage:   nbns-detect.pl -i <interface>\n";
	print "Example: nbns-detect.pl -i eth0\n";
	print "\n";
	print "Logging Options\n";
	print "Local Logfile\n";
	print "nbns-detect.pl -i eth0 -l nbns.log\n";
	print "\n";
	print "Email Alerts\n";
	print "nbns-detect.pl -i eth0 --email test\@nowhere.com --mailserver mail.nowhere.com\n";
	print "nbns-detect.pl -i eth0 --email test\@nowhere.com --mailserver mail.nowhere.com --mailport 52525\n";
	print "\n";
	print "Syslog - Defaults to facility 16 severity 6 (Local0/Informational)\n";
	print "Please see RFC 5424 for acceptable facility and severity values - https://tools.ietf.org/html/rfc5424#section-6.2.1\n";
	print "nbns-detect.pl -i eth0 --syslog syslog.nowhere.com\n";
	print "nbns-detect.pl -i eth0 --syslog syslog.nowhere.com --syslogport 9999 --syslogfacility 17 --sysloglevel 3\n";
	print "nbns-detect.pl -i eth0 --syslog local\n";
	print "\n";
	print "Combination\n";
	print "nbns-detect.pl -i eth0 -l nbns.log --syslog syslog.nowhere.com --email test\@nowhere.com --mailserver mail.nowhere.com\n";
	print "\n";
	print "Additional Options\n";
	print " -n <name>\tSets NetBIOS name to broadcast (default: \"BTB2351\")\n";
	print " -d <delay>\tSets the time to wait between sending requests (default: 10s)\n";
	print " -v\t\tShows NBNS queries\n";
	print " -h\t\tThis menu\n";
	print " --test\t\tSends test logs to configured destinations to make sure everything is working as expected\n";
	exit;
}

sub validate_packet {
	my ($buf) = @_;

	# Header Section
	my @headers = unpack("n6",$buf); # NetBIOS Header is 96bits (16bit short * 6 = 96bits)

	# Get NetBIOS Transaction ID from Response (Should match $transID)
	my $rspID = $headers[0];
	
	# Get the response flag from the OPCODE field
	my $rsp_flag = ($headers[1] >> 15);

	if ($rspID == $transID && $rsp_flag == 1) {
		my ($rr_type) = unpack("n1",substr($buf, 46));
		if ($rr_type == 0x20) {
			my $ip = join('.',unpack("C*",substr($buf, 58)));
			return (1,1,$ip);
		} else {
			return (1,0);
		}
	} else {
		return (0,0);
	}
	
	# Other NBNS headers and such that might be valuable later
	# Get OPCODE, NM_FLAGS, RCODE, AA Flag, and the count values
	# Bit shifting and bitwise AND to get values
	#my $opcode = (($headers[1] >> 11) & 31);
	#my $nm_flags = (($headers[1] >> 4) & 127);
	#my $rcode = ($headers[1] & 15);
	#my $rsp_flag = ($opcode & 16) ? 1 : 0;	# From OPCODE
	#my $aa_flag = ($nm_flags & 64) ? 1 : 0;
	#my $qdcount = $headers[2];
	#my $ancount = $headers[3];
	#my $nscount = $headers[4];
	#my $arcount = $headers[5];
	
}

sub make_payload {	
	# RFC 1002 - http://tools.ietf.org/html/rfc1002
	# 4.2    NAME SERVICE PACKETS 7
	# 4.2.12 NAME QUERY REQUEST 21

	my ($name) = @_;
	my $header;
	my $payload;

	# Make NetBIOS Header (See RFC for precise fields)
	$header .= pack("n*",$transID,0x0110,1,0,0,0);

	# Make NetBIOS Question section
	$payload .= "\x20" . _encode($name) . "\x00";
	$payload .= pack("n*",0x20,1);

	my $packet = $header.$payload;
	return $packet;
}

sub _encode {
	my ($name) = @_;
	my $encoded;
	$name .= "\x20" x (16-length($name));   		# Pad with spaces to make a 16 character name
	for my $chr (unpack("C16",$name)) {
		$encoded .= chr(65 + (($chr & 0xF0) >> 4)); # First four bits (AND 11110000 shifted right)
		$encoded .= chr(65 + ($chr & 0xF));         # Last 4 bits (AND 00001111 no shift)
	}
	return $encoded;
}

sub _decode {
	my ($encoded) = @_;
	my $name;
	my @array = ($encoded =~ m/../g);
	foreach my $pair (@array) {
		my ($first,$second) = (unpack("C2",$pair));
		$name .= chr((($first - 65) << 4) + ($second - 65)); # Add the first and second set of bits
	}
	$name =~ s/\x20//g;
	return $name;
}

sub get_interface {
	my ($i1) = @_;
	my $s1 = IO::Socket::INET->new(Proto => 'udp');
	my $a1 = $s1->if_addr($i1);
	my $b1 = $s1->if_broadcast($i1);	
	die "[ERROR] Cannot get address information for interface: $int\n" if !($a1||$b1);
	return ($a1,$b1);
}

sub mailer {
	my ($e,$s,$p,$m) = @_;
	my ($g,$f) = split('@',$e);
	my $from = 'nbns-detect@'.$f;
	my $msg = $$m[0].' - NBNS Spoofing Detected - Peerhost: '.$$m[1].'; Spoofed IP: '.$$m[2]."\n";
	
	my $mailer = Net::SMTP->new(
        $s,
        Hello   =>	'btbsecurity.com',
        Port    => 	$p,
		Timeout	=>	10
	) or warn "Can't connect to mail server $s: $!\n";
	
	if ($mailer) {
		$mailer->mail($from);
		$mailer->to($e);
		$mailer->data;
		$mailer->datasend("From: NBNS Detection Script <$from>\n");
		$mailer->datasend("To: $e\n");
		$mailer->datasend("Subject: NBNS Detection Alert\n");
		$mailer->datasend("\n");
		$mailer->datasend($msg);
		$mailer->dataend;
		$mailer->quit;
	}
}

sub syslogger {
	# RFC 5424 should be referenced to identify the desired facility and level
	# https://tools.ietf.org/html/rfc5424#section-6.2.1
	
	my ($s,$p,$f,$l,$m) = @_;
		
	if ($s ne 'local') {
		setlogsock({ type => 'udp', host => $s, port => $p });
	}
	my $pri = ($f * 8) + $l;
	openlog('NBNS Detection Script', 'ndelay,pid', $f);
	syslog($pri, 'NBNS Spoofing Detected: Peerhost: '.$$m[1].'; Spoofed IP: '.$$m[2]);
	closelog();
		
}

sub locallog {
	my ($f,$m) = @_;
	my $msg = $$m[0].' - NBNS Spoofing Detected - Peerhost: '.$$m[1].'; Spoofed IP: '.$$m[2]."\n";
	open my $fh, ">>", $f or die "Can't open file $f: $!\n";
	print $fh $msg;
	close $fh;
}




