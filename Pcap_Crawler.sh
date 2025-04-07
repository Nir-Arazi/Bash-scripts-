#!/bin/bash

if ! command -v geoiplookup &> /dev/null; then
    echo "Please install geoip-bin"
    exit
        fi

        if ! command -v jq &> /dev/null; then
                echo "Please install jq"
                exit
        fi

                if ! command -v foremost &> /dev/null; then
                        echo "Please install foremost"
                        exit
                fi

                        if ! command -v figlet &> /dev/null; then
                                echo "Please install figlet"
                                exit
                        fi

                                if ! command -v curl &> /dev/null; then
                                        echo "Please install curl"
                                        exit
                                fi

                                        if ! command -v tshark &> /dev/null; then
                                                echo "Please install tshark"
                                                exit
                                        fi

white='\033[1;97m'
reset='\033[0m' 
blue='\033[38;5;81m'
red='\033[1;31m '
blue2='\033[0;34m'
continue_check() {
echo
echo -e ""${red} "
Click on anything to continue "${reset}"  "
read
}
restart_check() {
echo -e ""${red} "
would you like to search more? [y/N] "${reset}" "
read  restart
if [[ "$restart" == "y" ]]; then 
sleep 2
clear
searching_options
else 
echo -e ""${red}"goodbye"${reset}" "
exit 1
fi
}

searching_options(){
echo
echo -e ""${blue}"what would you like to look for "${reset}""
echo -e "${red}" "
[1] shows info about the pcap                      [11] Port-Based Threat Detection

[2] shows all the protocols that have been used    [12] potential Nmap scans 

[3] shows user agents                              [13] commands extraction

[4] show domain names                              [14] extract OS (operating system)
                                                  
[5] show http.host                                 [15] SSL decryption

[6] show suspicious IPs                            [16] malware detection

[7] show MAC and vendor                            [17] Show IPv4 conversations

[8] extract credentials 

[9] show arp_duplicate

[10] show hostnames via SMB 
"${reset}"  "

echo "[?]"
read PCAP

case $PCAP in 

1)
echo -e ""${white}
capinfos $FILE
${reset} ""
continue_check
restart_check
;;
2) 
echo
echo -e ""${blue}"what would you like to see? "${reset}" "
echo -e "${red}" "
[1] protocol hierarchy statistics

[2] all the protocols that have been used
"${reset}" "
read -p "[?]" protocol
case $protocol in
1)
echo -e ""${blue}"extracting the protocols"${reset} ""
echo -e " "${white}
tshark -r $FILE -z io,phs | grep === -A 1000000000
 ${reset}" "
continue_check
restart_check
;;
2)
echo 
echo -e ""${blue}"extracting the protocols"${reset} ""
echo -e " "${white}
tshark -r $FILE  -Y ""  | awk '{print $6}'  | sort | uniq 
${reset}" "
continue_check
restart_check
esac


;;
3)

if [[ -z $(tshark -r  $FILE   -Y "http" -T fields  -e"ip.src" -e "ip.dst" -e "http.user_agent " | sort | uniq  | awk 'length >31') ]] ;then
echo 
echo -e ""${red} "
no user agents have been found "${reset} ""
restart_check
else
echo -e ""${blue} "
extracting user_agent "${reset}" "  
echo -e " "${red} "
-----------      ----------------        --------------
 source IP        Destination IP           user_agent 
-----------      ----------------        --------------
"${reset}" 
"${white} 
tshark -r  $FILE   -Y "http" -T fields  -e"ip.src" -e "ip.dst" -e "http.user_agent " | sort | uniq  | awk 'length >31'
 ${reset}
continue_check
restart_check
fi
;;
4)
sleep 2
clear
echo
echo -e  ""${blue}" 
would you like to see all the domain names or do you want to see the most requested one?  ""${reset}"

echo -e "${red} 
[1] show me all the domain names 

[2] show me the most requested domain name 
${reset} "
read -p "[?]" DNS
case $DNS in

1)
if [[ -z $(tshark -r  $FILE   -Y "dns" -T fields -e"dns.qry.name" | sort | uniq) ]] ; then 
echo
echo -e""${red}" 
no domain names were found 
"${reset}" "
else
echo
echo -e "${white}"
tshark -r  $FILE   -Y "dns" -T fields -e"dns.qry.name" | sort | uniq
"${reset}"
continue_check
restart_check
fi
;;
2)
if [[ -z $(tshark -r  $FILE    -Y "dns" -T fields -e"dns.qry.name" | sort | uniq -c | sort -n | tail -1 | awk '{print $2}') ]] ; then 
echo -e""${red}" 
no domain names were found 
"${reset}" "
else 
echo -e ""${blue}" the most requested domain name: "${reset}"" $(tshark -r  $FILE    -Y "dns" -T fields -e"dns.qry.name" | sort | uniq -c | sort -n | tail -1 | awk '{print $2}')      
sleep 2
echo 
echo -e ""${blue} "
would you like to see how many times the domain was requested [y/N]? "${reset} ""
read -p "[?]" qry
echo
if [[ "$qry" == "y" ]]; then 
echo -e ""${blue}"the number of times that the domain was requested is:"${reset}"" $( tshark -r  $FILE    -Y "dns" -T fields -e"dns.qry.name" | sort | uniq -c | sort -n | tail -1 | awk '{print $1}')
continue_check
restart_check
else
restart_check
fi
fi
esac
;;
5)
if [[ -z $(tshark -r  $FILE -Y "http" -T fields  -e "ip.src" -e "ip.dst" -e "http.host"  | sort | uniq | awk 'length >31') ]];then
echo -e ""${red}"
no http.host were found 
"${reset}""
restart_check
fi
echo
echo -e ""${blue}"
extracting http.host "${reset}" "  
echo -e ""${red}"
-----------      ----------------        --------------
 source ip         Destination ip           http.host 
-----------      ----------------        --------------
"${reset}""
echo -e ""${white}"" 
tshark -r  $FILE -Y "http" -T fields  -e "ip.src" -e "ip.dst" -e "http.host"  | sort | uniq | awk 'length >31'
${reset}
continue_check
echo -e ""${blue}"
would you like to get more info about the http.host's? "${reset}""
echo -e " "${red}"
[1] all the host's

[2] specific host 

[3] No
"${reset}""
read -p "[?]" host
case $host in 
1)
if [[ -z $(tshark -r  $FILE   -Y "http" -T fields  -e "ip.dst" -e "http.host"  | sort | uniq | awk 'length >16') ]] ; then
echo -e ""${red}"
no http_host were found "${reset}" "
fi
tshark -r  $FILE   -Y "http" -T fields  -e "ip.dst" -e "http.host"  | sort | uniq | awk 'length >16' > .ip_info.txt 
for i in $(cat .ip_info.txt | grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.|224\.|240\.)" | awk '{print $1}')
do 
echo -e ""${white}"" 
curl -s https://ipinfo.io/$i | grep -e ip -e hostname -e country -e city | grep -v "readme" | tr -d '"' 
${reset}""
echo -e ""${red}-------------------------------------------- " ${reset}" 
done 
continue_check
restart_check
;;
2)
echo
echo -e ""${blue}"
what IP would you like to check "${reset}" "
read -p "[?]" IP_CHECK
echo
echo -e ""${white}""
curl -s https://ipinfo.io/$IP_CHECK | grep -e ip -e hostname -e country -e city | grep -v "readme" | tr -d '"'
${reset}""
continue_check
restart_check
;;
3)
restart_check
esac
;;
6)
if [[ -z $(tshark -r $FILE -Y "ip.addr" -T fields -e ip.src -e ip.dst | awk '{ for(i=1;i<=NF;i++){ print $i }}' | sort | uniq > .sus_ip && for i in $(cat .sus_ip); do geoiplookup $i; echo $i; done | egrep -B1 -iw "RU|CN|KP|IR|BY|UA|RO|NG|VN|BR|ID|IN|TR|PK|KZ") ]] ; then 
echo -e ""${red}"
no malicious IPs were detected "${reset}" "
restart_check
else 
echo -e ""${white}""
tshark -r $FILE -Y "ip.addr" -T fields -e ip.src -e ip.dst | awk '{ for(i=1;i<=NF;i++){ print $i }}' | sort | uniq > .sus_ip && for i in $(cat .sus_ip); do geoiplookup $i; echo IP:$i; done | egrep -B1 -iw "RU|CN|KP|IR|BY|UA|RO|NG|VN|BR|ID|IN|TR|PK|KZ" 
${reset}""
continue_check
restart_check
fi
;;
7)
echo
echo -e ""${blue}"
extracting the MAC address info "${reset}" "
echo
echo -e ""${red}"
---------------------------------"${reset}""
tshark -r $FILE   -Y '' -T fields -e 'eth.src' -e 'eth.dst' | awk '{ for(i=1;i<=NF;i++){print $i}}' | sort | uniq > .mac_v 
for mac in $(cat .mac_v) ;do 
sleep 1 
echo -e ''${white}'
MAC:'$mac ${reset}
VENDOR=$(curl -s "https://api.maclookup.app/v2/macs/$mac/company/name")
echo -e ''${white}'vendor:'$VENDOR ${reset}
echo -e ""${red}"
---------------------------------"${reset}""

 done
continue_check
restart_check
;;
8) 
echo
echo -e " "${blue}"
from where would you like to extract the passwords TCP,HTTP "${reset}""
echo -e " "${red}"
[1] TCP 

[2] HTTP
"${reset}""
read -p "[?]" PASS
case $PASS in 
1)
echo
echo -e " "${blue}"
extracting credentials.."${reset}""
for i in $(tshark -r $FILE -T fields -e tcp.stream | sort | uniq | sort)
do 
tshark -r $FILE -z follow,tcp,ascii,$i >> .tcp
done
pass=$(cat .tcp | grep -a -i -E "pass|password|user|username" | sort |uniq | grep -vE "Request|Response|530|331|227|227|User-Agent:|mJf" )
if [[ -z $pass ]];then
echo -e ""${red}"
no credentials were found "${reset}""
echo "1HmroG]n4%.OdYL" > /dev/null 2>&1
restart_check
else 
echo -e ""${white}
cat .tcp | grep -a -i -E "pass|password|user|username" | sort |uniq | grep -vE "Request|Response|530|331|227|227|User-Agent:|mJf" 2>/dev/null
${reset}""
fi
sleep 4
rm .tcp 2>/dev/null1
sleep 2
continue_check
restart_check
;;
2)
echo
echo -e "  "${blue}"
extracting credentials.. "${reset}""
for i in $(tshark -r  $FILE -Y"http" -T fields -e tcp.stream | sort | uniq | sort)
do 
tshark -r $FILE -Y"http.request.method == "POST"" -z follow,http,ascii,$i >> .http
done
pass=$(cat .http | grep -a -i -E "pass|password|user|username" | sort |uniq | grep -vE "User-Agent:|for|href|<p>|mJf|User-Agent:" )
if [[ -z $pass ]];then
echo -e ""${red}"
no credentials were found "${reset}""
sleep 2
else 
echo -e ""${white}
cat .http | grep -a -i -E "pass|password|user|username|username=" | sort |uniq | grep -vE "User-Agent:|for|href|<p>|mJf|User-Agent:" 2>/dev/null
${reset}""
fi
sleep 4
rm .http 2>/dev/null
continue_check
restart_check
esac
;;
9)
echo
echo -e ""${blue}"
extracting all the duplicates, please stand by"${reset}""
echo
ARP=$(tshark -r $FILE  -Y"arp.duplicate-address-detected" | awk '{print $3,$4,$5,$7,$8,$9,$10,$11}' | sort | uniq | nl )
if [[ -z $ARP ]];then
echo -e ""${red}"
no duplicates were found" ${reset}""
restart_check
sleep 4
else 
echo -e ""${white}
tshark -r $FILE  -Y "arp.duplicate-address-detected" | awk '{print $3,$4,$5,$7,$8,$9,$10,$11}' | sort | uniq | nl  
${reset}""
continue_check
restart_check
fi
sleep 4
;;
10)
echo
echo -e ""${blue}"
from which protocol would you like to extract the name "${reset}" "
echo -e " "${red}"
[1] nbns

[2] smb 

[3] llmnr (computer name)
"${reset}" "
read -p "[?]" proto
case $proto in 
1)
if [[ -z $(tshark -r "$FILE" -Y"nbns" -T "fields" -e "nbns.name" | sort | uniq ) ]] ;then 
echo -e " "${red}" 
no names were found "${reset}" "
restart_check
fi
echo
echo -e " "${blue}" 
extracting names from NetBIOS "${reset}" "
echo -e ""${white}
tshark -r "$FILE" -Y"nbns" -T "fields" -e "nbns.name" | sort | uniq 
${reset}""
continue_check
restart_check
;;
2)
if [[ -z $(tshark -r "$FILE" -Y"smb" -T "fields" -e "browser.server" | sort | uniq ) ]] ;then 
echo -e " "${red}" 
no names were found "${reset}" "
restart_check
fi
echo
echo -e " "${blue}"
extracting names from SMB "${reset}" "
echo -e ""${white}
tshark -r "$FILE" -Y"smb" -T "fields" -e "browser.server" | sort | uniq
${reset}""
continue_check
restart_check
;;
3)
if [[ -z $(tshark -r "$FILE" -Y"llmnr" -T "fields" -e "dns.qry.name" | sort | uniq ) ]] ;then 
echo -e " "${red}" 
no names were found "${reset}" "
restart_check
fi
echo
echo -e " "${blue}"
extracting names from LLMNR "${reset}"  "
echo -e ""${white}
tshark -r "$FILE" -Y"llmnr" -T "fields" -e "dns.qry.name" | sort | uniq
${reset}" " 
continue_check
restart_check
esac
;;
11)
echo 
echo -e " "${blue}"
what would you like to look for  "${reset}"  "
echo -e " "${red}" 
[1] well-known ports for reverse shell and the source IP

[2] all the ports that are well-known for brute force and who contacted them and how many times
"${reset}" "
read -p "[?]" ports
case $ports in
1)
echo 
echo -e " "${blue}"
extracting the suspicious ports "${reset}" "
echo
Ports=$(tshark -r "$FILE" -T "fields" -e"ip.dst" -e  "tcp.srcport"  | sort -n | uniq  | sort -n   | egrep -w "1080|1433|1434|1521|1723|2049|2082|2083|3128|3306|3389|4444|5432|5900|5938|6379|8080|8443|8888|9200|10000|27017|3074|5060|5555|6667|6697|8000|8081|9100|9090|5985|5986|28017|6969|1337|12345|1111|2222|3333|5555|6666|7777|9999|3131|5353|7000|34567|8181|8008|27015|(4915[2-9]|491[6-9][0-9]|49[2-9][0-9]{2}|5[0-5][0-9]{3}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])" | grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.|224\.|240\.)" | awk '{print "Source IP:" ,$1 " Suspicious Port:", $2}') 
if [[ -z $Ports ]];then
echo -e " "${red}" 
no suspicious ports were found "${reset}" "
echo
restart_check
else 
echo "$Ports"
fi
continue_check
restart_check
;;
2)
brute=$(tshark -r  "$FILE" -T fields -e ip.dst -e tcp.dstport |grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.|224\.|240\.)" | egrep -w "22|21|25|3389|23" | sort | uniq -c | sort -n | awk '{print "Attempts:",$1 " Source IP:", $2, "Port:", $3}')
if [[ -z $brute ]];then
echo -e " "${red}"  
no brute force detected "${reset}" "
restart_check
else 
echo -e ""${white}
echo "$brute"
${reset}" "
continue_check
restart_check
fi
esac
;;
12)
echo 
echo -e ""${blue}"
would you like to search for internal IPs or external IPs"${reset}""
echo -e "  "${red}" 
[1] internal IPs

[2] external IPs
"${reset}""
read -p "[?]" ip
case $ip in
1)
ips=$(tshark -r  "$FILE" -Y "frame.len" -T fields -e "ip.src" -e "frame.len" | awk '$2 == 44 || $2 == 8 || $2 == 60 || $2 == 28' | grep -E "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)" | sort | uniq -c | sort -n | awk '{ print "Number_of_Packets:" $1 "<----->" "IP:" $2 }' | tail -5 )
if [[ -z $ips ]];then
echo -e ""${red}" Nmap wasn't detected "${reset}" "
restart_check
else 
echo -e "${white}$ips${reset}"
continue_check
restart_check
fi
;;
2)
Ips=$(tshark -r  "$FILE" -Y "frame.len" -T fields -e "ip.src" -e "frame.len" | awk '$2 == 44 || $2 == 8 || $2 == 60 || $2 == 28' | grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.|224\.|240\.)" | sort | uniq -c | sort -n | awk '{ print "Number_of_Packets:" $1 "<----->" "IP:" $2 }' | tail -5)
if [[ -z $Ips ]];then
echo -e "  "${red}" 
Nmap wasn't detected "${reset}" "
restart_check
else 
echo -e ""${white}
tshark -r  "$FILE" -Y "frame.len" -T fields -e "ip.src" -e "frame.len" | awk '$2 == 44 || $2 == 8 || $2 == 60 || $2 == 28' | grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.|224\.|240\.)" | sort | uniq -c | sort -n | awk '{ print "Number_of_Packets:" $1 "<----->" "IP:" $2 }' | tail -5 
${reset}" "
continue_check
restart_check
fi
esac
;;
13)
echo 
if [[ -z $(tshark -r "$FILE" -Y 'frame matches "whoami"' -T fields -e tcp.stream | sort | uniq | sort) ]] ; then
echo
echo -e ""${red}" 
no commands were found.. "${reset}" "
restart_check
else
echo -e ""${blue}"
where would you like to store the commands? "${reset}""
read -p "[?]" file_name
echo
touch "$file_name"
echo
if [[ -f $file_name ]] ; then 
echo -e ""${blue}" 
extracting commands .."${reset}""
echo
sleep 4
echo -e ""${blue}" 
commands have been stored in $file_name "${reset}"" 
for i in $(tshark -r "$FILE" -Y 'frame matches "whoami"' -T fields -e tcp.stream | sort | uniq | sort)
do
echo -e ""${white}
tshark -r "$FILE" -Y 'frame matches "whoami" || frame matches  "pwd" || frame matches "ls" || frame matches "uname" ' -z follow,tcp,ascii,$i  | grep -A 1000000000 === > $file_name
${reset}" "
done
continue_check
restart_check
else 
echo -e ""${red} "
file wasn't created, please try again " ${reset}""
continue_check
restart_check
fi
fi
;;
14)
echo
echo -e ""${red} "
[1] Linux 

[2] Windows 
 " ${reset}""
read -p "[?]" OS
case $OS in 
1)
echo -e " "${blue}" 
extracting Linux OS"${reset}""
sleep 4
echo -e ""${white}
tshark -r $FILE -Y 'ip.ttl' -T fields -e "ip.src"  -e "ip.ttl" | awk '$2 <=64 {print "Probably Linux:",$1 }' | sort | uniq  | sort -n
${reset}""
continue_check
restart_check
;;
2)
echo -e " "${blue}"
extracting Windows OS "${reset}""
echo -e ""${white}
tshark -r $FILE -Y 'ip.ttl' -T fields -e "ip.src"  -e "ip.ttl" | awk '$2 >64 {print "Probably Windows:",$1 }' | sort | uniq | sort -n
${reset}""
continue_check
restart_check
esac
;;
15)
echo 
echo -e ""${blue}"
if you don't remember the SSL file press 1 "${reset}""
read -p "[?]" help
if [[ $help == 1 ]] ; then 
echo $(ls | egrep -i "Keys|ssl" )
fi
echo -e ""${blue}"
please insert the SSL decryption file  "${reset}""
read -p "[?]" SSL
echo 

if [ ! -f "$SSL" ]; then
echo -e ""${red}"
Input file not found: $SSL "${reset}"" 
restart_check
fi
echo -e ""${blue}"
what would you like to call the file? "${reset}""
read -p "[?]" pcap
echo
echo -e ""${blue}"
decrypting file please wait "${reset}""
sleep 4
tshark -r $FILE -o tls.keylog_file:$SSL -w $pcap
if [[ -z $(ls | grep $pcap) ]] ; then 
echo -e ""${red}"
decryption failed "${reset}""
restart_check
else 
echo -e ""${blue}"
decryption succeeded "${reset}""
continue_check
restart_check
fi
;;
16)
echo
echo -e ""${blue}"
what name would you like to give the file"${reset}""
read -p "[?]" file_name
echo 
echo -e ""${blue}"
what protocol would you like to export the info from"${reset}""
read -p "[?]" protocol
tshark -qr $FILE --export-objects $protocol,$file_name
if [[ -z $file_name ]] ; then 
echo -e ""${red}"
directory is empty: $file_name
removing directory.. "${reset}"" 
rm -r $file_name
restart_check
else
echo
echo -e ""${blue}"
extract completed. What would you like to do? "${reset}"" 
echo -e ""${red}"

[1] send all the files to VirusTotal

[2] carve all the files

[3] carve all the files and send to VirusTotal
"${reset}"" 
fi
read -p "[?]" mal
case $mal in 
1)
if [[ -z $(ls  $file_name ) ]]; then
echo -e ""${red}"
no files were found"${reset}"" 
restart_check
fi
echo 
echo -e ""${blue}"
please insert your API key"${reset}"" 
read -p "[?]" API
echo 
cd "$file_name" || exit 1

output_file=~/Desktop/virus_total_output
> "$output_file"  # clear output file

for i in *.exe; do
    [ -e "$i" ] || continue  # skip if no .exe files

    echo -e "${blue}Uploading $i to VirusTotal...${reset}"

    # Upload and get analysis link
    HTTPS=$(curl -s --request POST \
        --url https://www.virustotal.com/api/v3/files \
        --header "x-apikey:$API" \
        --form "file=@$i" | jq -r '.data.links.self')

    echo -e "${blue}Waiting for VirusTotal analysis...${reset}"
    sleep 40

    # Retrieve the report
    curl -s --request GET \
        --url "$HTTPS" \
        --header "x-apikey:$API" | jq >> "$output_file"

    echo -e "${green}Finished analyzing $i ✔${reset}\n"
done

echo -e "${blue}Output extracted to: virus_total_output${reset}"

continue_check
restart_check

;;
2)
if [[ -z "$(ls -A "$file_name" 2>/dev/null)" ]]; then
    echo -e "${red}No files were extracted${reset}"
    restart_check
fi

echo ""
echo -e "${blue}Where would you like the carved files?${reset}"
read -p "[?] " carved

echo -e "${blue}Carving the files...${reset}"

cd "$file_name" || exit 1

# Carve only .exe files from all inputs
for i in *; do
    [ -f "$i" ] || continue
    foremost -i "$i" -t exe -o "malware_$i"
done

# Organize results
mkdir -p "$carved"
mv malware_* "./$carved"

# Move results to Desktop
mv "$carved" ~/Desktop/

echo -e "${blue}Everything has been extracted to ~/Desktop/$carved${reset}"

# Optional: remove the original extraction folder
cd ~/Desktop || exit
sleep 4
rm -rf "$file_name"
continue_check
restart_check
;;
3)
if [[ -z $(ls "$file_name") ]]; then
    echo -e "${red}No files were extracted.${reset}"
    restart_check
fi

echo
echo -e "${blue}Where would you like to save all the VirusTotal output?${reset}"
read -p "[?] " VT

cd "$file_name" || exit 1

# Carve only .exe files from the content
for i in *; do
    [ -f "$i" ] || continue
    foremost -i "$i" -t exe -o "malware_$i"
done

# Organize folders
mkdir -p db
mv malware_* ./db
cd db

# Gather all .exe files into one directory
mkdir -p exe_files

# Move .exe files if present
for i in malware_*/exe; do
    [ -d "$i" ] || continue
    find "$i" -type f -name "*.exe" -exec mv {} ./exe_files/ \;
done

cd exe_files || exit 1

# Ask for API Key
echo
echo -e "${blue}Please insert your VirusTotal API key:${reset}"
read -p "[?] " API

echo
output_path=~/Desktop/"$VT"
> "$output_path"  # Clear previous output

# Submit each .exe file to VirusTotal
for i in *; do
    [ -f "$i" ] || continue

    echo -e "${blue}Uploading $i to VirusTotal...${reset}"
    HTTPS=$(curl -s --request POST \
        --url https://www.virustotal.com/api/v3/files \
        --header "x-apikey:$API" \
        --form "file=@$i" | jq -r '.data.links.self')

    if [[ -z "$HTTPS" || "$HTTPS" == "null" ]]; then
        echo -e "${red}Failed to upload $i. Skipping...${reset}"
        continue
    fi

    echo -e "${blue}Waiting for analysis...${reset}"
    sleep 60

    curl -s --request GET \
        --url "$HTTPS" \
        --header "x-apikey:$API" | jq >> "$output_path"

    echo -e "${green}Finished scanning $i ✔${reset}\n"
done

echo
echo -e "${blue}Files have been saved to: $output_path${reset}"
continue_check
restart_check
esac
;;
17)
echo -e " "${white}
tshark -r $FILE -Y "" -z conv,ip -q
 ${reset}" "
;;
*)
echo
echo -e ""${red}"
$PCAP isn't recognized as an option. Try again."${reset}"" 
sleep 4
clear
continue_check
restart_check
esac
} 2>/dev/null
echo -e " "${blue}"
_________         .    .
(..       \\_    ,  |\\  /|
 \\       O  \\  /|  \\ \\/ /
  \\______    \\/ |   \\  / 
     vvvv\\    \\ |   /  |
     \\^^^^  ==   \\_/   |
      \\\_   ===    \\.  |
      / /\\_   \\ /      |
      |/   \\_  \\|      /
             \\/"

figlet " Welcome to Pcap_Crawler "
echo -e ""${reset}" "

echo -e " "${blue}"
please insert the pcap file "${reset}" "
echo -e " "${blue}"
if you don't remember the pcap name, please insert 1 "${reset}" "
read -p "[?]" pcap_search
if [[ "$pcap_search" == "1" ]] ; then 
file_chack=$(ls | grep pcap)
if [[ -z $file_chack ]] ; then
echo -e ""${red}"
echo "no pcap files were fund"
"${reset}""
exit
else
echo -e ""${white}
ls | grep pcap 
echo -e ""${reset}"" 
fi
else
clear
fi



file_existence_check() {
echo
echo -e " "${blue} "
please insert the pcap file  "${reset}" "
read -p "[?]" FILE
if [[ -s $FILE ]] ; then 
searching_options
else
echo -e ""${red} "
file doesn't exist! 
or it's empty, please try again"${reset}" "
sleep 4
file_existence_check
fi 
}
file_existence_check

# Pcap_Crawler Script
# Author: Nir Arazi
# Copyright © 2025 Nir Arazi. All Rights Reserved.
#
# This script is the original work of Nir Arazi.
# Redistribution, modification, or duplication of this script without explicit written permission is strictly prohibited.
# For educational and ethical use only. Ensure compliance with all applicable laws.