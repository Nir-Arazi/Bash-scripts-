#/bin/bash

root=$(whoami)

if [[ "$root" == "root" ]];then

sudo apt install sublist3r -y >/dev/null 2>&1

echo "Who is your target?"
read -p "? " TARGET
echo "Starting the gathering. This may take some time..."
rm -r info_gatherer
mkdir info_gatherer
cd info_gatherer 
rm results
WHOIS() {

figlet "whois_host" >> results
whois $TARGET >> results

figlet "whois_server" >> results
IP_V=$( ping -4 "$TARGET" | grep -m1 "(" | awk -F"[()]" '{print $2}')
whois $IP_V >> results
}
WHOIS
DIG() {

figlet "DIG" >> results

figlet "IPV4" >> results
dig A $TARGET >> results
 
echo

figlet "IPV6" >> results
dig AAAA $TARGET >> results

echo
figlet "Mail" >> results
dig MX $TARGET >> results

echo
figlet "Text" >> results
dig TXT $TARGET >> results

echo
figlet "Name Servers" >> results
dig NS $TARGET >> results

}
DIG
HOST(){
figlet "Host" >> results
host -a $TARGET >> results
}
DIG

SUBLIST3R(){
figlet "sublist3r" >> results
sublist3r -d $TARGET >> results
}
SUBLIST3R
theHarvester() {
figlet "theHarvester" >> results
theHarvester -d "$TARGET" -b all >> results
}
theHarvester

echo "Have a nice day!"


else
echo "Please run the script as root."
exit
fi