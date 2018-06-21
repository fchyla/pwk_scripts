#Automated recon scanner bash + nmap

if [ $# -eq 0 ]
	then
		echo "Missing arguments"
		echo "Usage autoscanner_basic.sh <ip or range nmap style> /path/to/directory  <scan type>"
		echo 'Scan types available:'
		echo 'no-intense : no service detection, TCP SYN on all 65k porst and UDP top 200'
		echo 'full : service detection and enumeration'
		echo 'allinonefile: -A -p1-65535, results in one xml file'
		echo
		echo "Run as root or sudo, requires nmap and xsltproc"
		exit 1
fi


path=$2
range=$1
scan_type=$3
xml_location=$path/$range.xml
ip_detected_list=$path/$range-detected-ip.txt

#Quick recon scan on provided IP or range
echo '=========================================='
echo
echo 'Quick reports will be created: '
echo
echo 'HTML: '$path/autoscanner_reports/$range-quick-recon-html-report.html
echo 'TXT: '$path/$range-quick-recon.txt
echo 'Detected IP list: '$ip_detected_list
echo
echo '=========================================='
echo

if [ ! -d "$path" ]; then
	echo 'Creating '$path
	mkdir -p $path
  fi

echo
echo "Running quick scan, please wait"
nmap -Pn -F -sSU -T4 -oX $xml_location $range | grep -v 'filtered|closed' > $path/$range-quick-recon.txt
wait

if [ ! -d "$path" ]; then
	mkdir -p $path/autoscanner_reports
  fi
#convert xml report to html
xsltproc $xml_location -o $path/autoscanner_reports/$range-quick-recon-html-report.html

# Create a lisf of detected ips found in the quick scan
grep addr $xml_location | grep ipv4 | awk {'print $2'} | cut -d "\"" -f 2 > $ip_detected_list


echo 'Starting stage 2 scan'
############################## STAGE 2

# Get ip count for more feedback
ip_count=$(grep addr $xml_location | grep ipv4 | awk {'print $2'} | cut -d "\"" -f 2| wc -l )

echo
echo "Running detailed port scans for "$ip_count" discovered IPs, this will take some time do something else"
echo
echo
echo
echo

if [ ! -d "$path/autoscanner_per_ip_scans" ]; then
	mkdir $path/autoscanner_per_ip_scans;
fi

for ip in $(cat $ip_detected_list);
	do
		mkdir $path/autoscanner_reports/$ip;
	done


# Run nmap with -iL input list to scan in paralell
# for live scan change to

function tcp_scanner {
	echo 'Running nmap TCP SYN scan on '$ip_count' IPs >> nmap -Pn -sS -T4 -p1-65535'
		for ip in $(cat $ip_detected_list);
			do
				mkdir $path/autoscanner_per_ip_scans/$ip;
				nmap -Pn -sS -T4 -p1-65535 -oX $path/autoscanner_per_ip_scans/$ip-all-TCP-ports.xml $ip | grep -v 'filtered|closed';
	   done
}

function tcp_scanner_all-in-one-file {
	echo 'Works like SHIT you were warned'
	echo 'Running nmap TCP SYN scan on '$ip_count' IPs >> nmap -Pn -sS -T4 -p1-65535'
	echo 'Results in a single xml file'
		for ip in $(cat $ip_detected_list);
			do
				mkdir $path/autoscanner_per_ip_scans/whole-range $range;
				nmap -Pn -sS -A -T4 -p1-65535 -oX $path/autoscanner_per_ip_scans/$range-all-TCP-ports.xml -iL $ip_detected_list | grep -v 'filtered|closed';
	   done
}

function tcp_scanner_intense {

	mkdir $path/autoscanner_per_ip_scans/intense_per_ip_results
	echo 'Running TCP SYN intense with version detection'
	for ip in $(cat $ip_detected_list);
		do
			nmap -nvv -Pn -sSV -T2 -p$(cat $path/autoscanner_per_ip_scans/$ip-all-TCP-ports.xml | grep portid | grep protocol=\"tcp\" | cut -d'"' -f4 | paste -sd "," -) --version-intensity 9 -oX $path/autoscanner_per_ip_scans/intense_per_ip_results/$ip-all-TCP-version-ports.xml $ip;
		done
	}

function udp_scanner {
	echo 'Running UDP top 200 ports scan on' $ip_count' IPs >> 	nmap -vv -Pn -A -sC -sU -T4 --top-ports 200'
	nmap -vv -Pn -A -sC -sU -T4 --top-ports 200 -iL $ip_detected_list -oX $path/autoscanner_per_ip_scans/$range-top200-UDP-ports.xml | grep -v 'filtered|closed';

	}


function http_enum {
  for ip in $(cat $ip_detected_list);
		do
			nmap -sV -Pn -vv -p$(cat $path/autoscanner_per_ip_scans/intense_per_ip_results/$ip-all-TCP-version-ports.xml | grep http | cut -d'"' -f4 | paste -sd "," -) $ip --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oX $path/autoscanner_per_ip_scans/$ip/$ip-http-enum.xml
		done
}

function ftp_enum {
  for ip in $(cat $ip_detected_list);
		do
			nmap -sV -Pn -vv -p$(cat $path/autoscanner_per_ip_scans/intense_per_ip_results/$ip-all-TCP-version-ports.xml | grep ftp | cut -d'"' -f4 | paste -sd "," -) $ip --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oX $path/autoscanner_per_ip_scans/$ip/$ip-ftp-enum.xml
		done
}
#scan type selection
case $scan_type in
	no-intense)
		udp_scanner&
		tcp_scanner
		tcp_scanner_intense
		wait
		;;
	full)
		udp_scanner&
		tcp_scanner
		tcp_scanner_intense
		wait
		http_enum&
		ftp_enum
		wait
		;;
	allinonefile)
		tcp_scanner_all-in-one-file
		wait
		;;
	*)
		echo '==================================================='
		echo "No option selected only quick detection scan performed"
		exit 1
esac

echo
echo
echo '===== All scans done ======'

bash ./Reporting_autoscanner.sh $path $range
wait
echo '==== Reports created in '$path'/autoscanner_reports'
