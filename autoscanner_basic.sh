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

#Quick recon scan on provided IP or range
echo "Running quick scan, please wait"
nmap -Pn -F -sSU -T5 -oX $xml_location $range | grep -v 'filtered|closed' > $path/$range-quick-recon.txt
wait

echo
echo "Quick scan done see "$path"/"$range"-quick-recon.txt for results"

#Run extended scan on all IPs found in the quick scan

ip_count=$(grep addr $xml_location | grep ipv4 | awk {'print $2'} | cut -d "\"" -f 2| wc -l )
ip_list_counter=1
echo
echo "Running detailed port scans for "$ip_count" discovered IPs, this will take some time do something else"

for ip in $(grep addr $xml_location | grep ipv4 | awk {'print $2'} | cut -d "\"" -f 2);
	do
		echo ">>> Scanning "$ip", "$ip_list_counter of $ip_count;
		nmap -Pn -sSU -T4 -p1-65535 -oX $path/$ip-all-ports.xml $ip | grep -v 'filtered|closed';
		let "ip_list_counter++"
	done
