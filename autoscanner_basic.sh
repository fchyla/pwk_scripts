#Automated recon scanner bash + nmap

if [ $# -eq 0 ]
	then
		echo "Missing arguments"
		echo "Usage autoscanner_basic.sh /path/to/directory <ip or range>"
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

echo
echo "Quick scan done see "$path"/"$range"-quick-recon.txt for results"

# Create a lisf of detected ips found in the quick scan
grep addr $xml_location | grep ipv4 | awk {'print $2'} | cut -d "\"" -f 2 > $ip_detected_list
# Get ip count for more feedback
ip_count=$(grep addr $xml_location | grep ipv4 | awk {'print $2'} | cut -d "\"" -f 2| wc -l )

echo
echo "Running detailed port scans for "$ip_count" discovered IPs, this will take some time do something else"

# Run nmap with -iL input list to scan in paralell
nmap -Pn -sSU -T4 -p1-65535 -oX $path/$range-all-ports.xml -iL $ip_detected_list --host-timeout 30m | grep -v 'filtered|closed';
