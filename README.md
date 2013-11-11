nbns-detect
===========

Deploy this script on subnets where you want to monitor for NetBIOS Name Spoofing attacks.

Usage pretty much covers all functionality in the script.

See the following blog for some insight into the script and why we wrote it.

https://www.btbsecurity.com/resources/blog/174-nbns-spoofing-and-knee-jerk-reactions


Usage:   nbns-detect.pl -i <interface>
Example: nbns-detect.pl -i eth0

Logging Options
Local Logfile
nbns-detect.pl -i eth0 -l nbns.log

Email Alerts
nbns-detect.pl -i eth0 --email test@nowhere.com --mailserver mail.nowhere.com
nbns-detect.pl -i eth0 --email test@nowhere.com --mailserver mail.nowhere.com --mailport 52525

Syslog - Defaults to facility 16 severity 6 (Local0/Informational)
Please see RFC 5424 for acceptable facility and severity values - https://tools.ietf.org/html/rfc5424#section-6.2.1
nbns-detect.pl -i eth0 --syslog syslog.nowhere.com
nbns-detect.pl -i eth0 --syslog syslog.nowhere.com --syslogport 9999 --syslogfacility 17 --sysloglevel 3
nbns-detect.pl -i eth0 --syslog local

Combination
nbns-detect.pl -i eth0 -l nbns.log --syslog syslog.nowhere.com --email test@nowhere.com --mailserver mail.nowhere.com

Additional Options
-n <name>	Sets NetBIOS name to broadcast (default: "BTB2351")
-d <delay>	Sets the time to wait between sending requests (default: 10s)
-v		Shows NBNS queries
-h		This menu
--test		Sends test logs to configured destinations to make sure everything is working as expected
