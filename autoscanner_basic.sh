#Automated recon scanner bash + nmap

if [ $# -eq 0 ]
	then
		echo "Missing arguments"
		echo "Usage autoscanner_basic.sh /path/to/directory <ip or range>"
		echo "Run as root or sudo, requires nmap and xsltproc"
		exit 1
fi

path=$1
range=$2
xml_location=$path/$range.xml
ip_detected_list=$path/$range-detected-ip.txt

#Quick recon scan on provided IP or range
echo "Running quick scan, please wait"
nmap -Pn -F -sSU -T5 -oX $xml_location $range | grep -v 'filtered|closed' > $path/$range-quick-recon.txt
wait

mkdir $path/autoscanner_reports

#convert xml report to html
xsltproc $xml_location -o $path/autoscanner_reports/$range-quick-recon-html-report.html

# Create a lisf of detected ips found in the quick scan
grep addr $xml_location | grep ipv4 | awk {'print $2'} | cut -d "\"" -f 2 > $ip_detected_list

echo '=========================================='
echo
echo 'Reports created: '
echo
echo 'HTML: '$path/autoscanner_reports/$range-quick-recon-html-report.html
echo 'TXT: '$path/$range-quick-recon.txt
echo 'Detected IP list: '$ip_detected_list
echo
echo '=========================================='
echo
echo
echo 'Starting stage 2 scan'
############################## STAGE 2

# Get ip count for more feedback
ip_count=$(grep addr $xml_location | grep ipv4 | awk {'print $2'} | cut -d "\"" -f 2| wc -l )

echo
echo "Running detailed port scans for "$ip_count" discovered IPs, this will take some time do something else"
mkdir $path/autoscanner_per_ip_scans

# Run nmap with -iL input list to scan in paralell
# for live scan change to

function tcp_scanner {
	echo 'Running nmap TCP SYN scan on '$ip_count' IPs'
		for ip in $(cat $ip_detected_list);
			do
				nmap -Pn -sS -T4 -p1-65535 -oX $path/autoscanner_per_ip_scans/$ip-all-TCP-ports.xml $ip | grep -v 'filtered|closed';
				wait;
				xsltproc $path/autoscanner_per_ip_scans/$ip-all-TCP-ports.xml -o $path/autoscanner_reports/$ip-all-TCP-ports.html-report.html;

			done

	mkdir $path/autoscanner_per_ip_scans/intense_per_ip_results
	echo 'Running TCP SYN with version detection'
	for ip in $(cat $ip_detected_list);
		do
			nmap -nvv -Pn -sSV -T1 -p$(cat $path/autoscanner_per_ip_scans/$ip-all-TCP-ports.xml | grep portid | grep protocol=\"tcp\" | cut -d'"' -f4 | paste -sd "," -) --version-intensity 9 -oX $path/autoscanner_per_ip_scans/intense_per_ip_r/$ip-all-TCP-version-ports.xml $ip;
			wait;
			xsltproc $path/autoscanner_per_ip_scans/intense_per_ip_r/$ip-all-TCP-version-ports.xml -o $path/autoscanner_reports/$ip-all-TCP-version-ports-report.html;
		done
	}

function udp_scanner {
	echo 'Running nmap UDP top 200 ports scan on '$ip_count' IPs'
	nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -iL $ip_detected_list -oX $path/autoscanner_per_ip_scans/$range-top200-UDP-ports.xml | grep -v 'filtered|closed';
	wait;
	xsltproc $path/autoscanner_per_ip_scans/$range-top200-UDP-ports.xml -o $path/autoscanner_reports/$range-top200-UDP-ports.html-report.html;

	}

	tcp_scanner &
	udp_scanner &
