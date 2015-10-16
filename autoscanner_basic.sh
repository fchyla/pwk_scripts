file=$1
range=$2

#Quick recon scan on provided IP or range
echo "Running quick scan see quick_recon_"$range".txt for results"
nmap -Pn -F -sSU -T5 -oX $file $range | grep -v 'filtered|closed' > ./quick_recon_$range.txt


#Run extended scan on all IPs found in the quick scan
for ip in `grep addr $file | grep ipv4 | awk {'print $2'} | cut -d "\"" -f 2`; 
	do 
		echo ">>> Scanning "$ip; 
		nmap -Pn -sSU -T4 -p1-65535 -oX /root/$ip-all-ports.xml $ip | grep -v 'filtered|closed'; 
	done

