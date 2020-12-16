#!/bin/bash

RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
BLUE=$(tput setaf 4)
RESET=$(tput sgr0)

echo "${RED} ######################################################### ${RESET}"
echo "${RED} #                         Let's Hunt                    # ${RESET}"
echo "${RED} ######################################################### ${RESET}"

while getopts ":d:" input; do
        case "$input" in
        d)
                domain=${OPTARG}
                ;;
        esac
done
if [ -z "$domain" ]; then
        echo "${BLUE}Please give a domain like \"-d domain.com\"${RESET}"
        exit 1
fi

echo "${BLUE} ######################################################### ${RESET}"
echo "${BLUE} #                   Finding Subdomains                  # ${RESET}"
echo "${BLUE} ######################################################### ${RESET}"

sublist3r -d $domain -v -o op.txt
subfinder -d $domain -o op.txt
assetfinder --subs-only $domain | tee -a op.txt
amass enum -passive -d $doamin | tee -a op.txt
amass enum -active -d $domain -ip | tee -a amass_ips.txt
cat amass_ips.txt | awk '{print $1}' | tee -a op.txt
curl -s https://crt.sh/\?q\=$1\&output\=json | jq &>/dev/null | awk -F'"' '/value/{print $4}' | sed 's/*.//g;s/\\n/\n/g' | sed 's/ /\n/g' | tee -a op.txt
curl -s https://otx.alienvault.com/api/v1/indicators/domain/$1/passive_dns | jq &>/dev/null | awk -F': ' '/"hostname": "(.*'$1')"/{print $2}' | sed 's/[",]//g' | sed 's/ /\n/g' | tee -a op.txt
curl -s https://dns.bufferover.run/dns\?q\=.$1 | awk -F',' '/.*'$1'/{print $2}' | sed 's/"//g' | sed 's/ /\n/g' | tee -a op.txt
curl -s http://api.hackertarget.com/hostsearch/\?q\=$1 | cut -d',' -f1 | sed 's/ /\n/g' | tee -a op.txt
curl -s https://rapiddns.io/subdomain/$1\?full\=1 | awk -F'">' '/'$1'/{print $2}' | cut -d'<' -f1 | awk 'NF' | sed 's/ /\n/g' | tee -a op.txt
curl -s https://api.sublist3r.com/search.php\?domain\=$1 | jq &>/dev/null | awk -F'"' '/'$1'/{print $2}' | sed 's/ /\n/g' | tee -a op.txt
curl -s https://www.threatcrowd.org/searchApi/v2/domain/report/\?domain\=$1 | jq &>/dev/null | awk -F'"' '/\.'$1'/{print $2}' | sed 's/ //g' | sed 's/ /\n/g' | tee -a op.txt
cat op.txt | sort -u | tee -a all.txt


echo "${GREEN} ######################################################### ${RESET}"
echo "${GREEN} #                Subdomain Bruteforcing                 # ${RESET}"
echo "${GREEN} ######################################################### ${RESET}"

altdns -i all.txt -o data_output -w ~/tools/recon/patterns.txt -r -s results_output.txt
mv results_output.txt dns_op.txt
cat dns_op.txt >output.txt
cat output.txt | sort -u | tee -a all.txt


echo "${BLUE} ######################################################### ${RESET}"
echo "${BLUE} #              Checking for alive subdomains            # ${RESET}"
echo "${BLUE} ######################################################### ${RESET}"

cat all.txt | httprobe | tee -a alive2.txt
cat alive2.txt | sort -u | tee -a alive.txt


echo "${GREEN} ######################################################### ${RESET}"
echo "${GREEN} #                          MassDNS                      # ${RESET}"
echo "${GREEN} ######################################################### ${RESET}"

~/tools/massdns/bin/massdns -r ~/tools/massdns/lists/resolvers.txt -q -t A -o S -w massdns.raw all.txt
cat massdns.raw | grep -e ' A ' | cut -d 'A' -f 2 | tr -d ' ' >massdns.txt
cat *.txt | sort -V | uniq >final-ips.txt
echo -e "${BLUE}[*] Check the list of IP addresses at final-ips.txt${RESET}"


echo "${BLUE} ######################################################### ${RESET}"
echo "${BLUE} #                       Starting Nuclei                 # ${RESET}"
echo "${BLUE} ######################################################### ${RESET}"

mkdir nuclei_op
nuclei -l alive.txt -t "/root/tools/nuclei-templates/cves/*.yaml" -c 60 -o nuclei_op/cves.txt
nuclei -l alive.txt -t "/root/tools/nuclei-templates/files/*.yaml" -c 60 -o nuclei_op/files.txt
nuclei -l alive.txt -t "/root/tools/nuclei-templates/panels/*.yaml" -c 60 -o nuclei_op/panels.txt
nuclei -l alive.txt -t "/root/tools/nuclei-templates/security-misconfiguration/*.yaml" -c 60 -o nuclei_op/security-misconfiguration.txt
nuclei -l alive.txt -t "/root/tools/nuclei-templates/technologies/*.yaml" -c 60 -o nuclei_op/technologies.txt
nuclei -l alive.txt -t "/root/tools/nuclei-templates/tokens/*.yaml" -c 60 -o nuclei_op/tokens.txt
nuclei -l alive.txt -t "/root/tools/nuclei-templates/vulnerabilities/*.yaml" -c 60 -o nuclei_op/vulnerabilities.txt


echo "${GREEN} ######################################################### ${RESET}"
echo "${GREEN} #           Looking for CORS misconfiguration           # ${RESET}"
echo "${GREEN} ######################################################### ${RESET}"

python3 ~/tools/Corsy/corsy.py -i alive.txt -t 40 | tee -a corsy_op.txt


echo "${BLUE} ######################################################### ${RESET}"
echo "${BLUE} #                   Starting CMS detection              # ${RESET}"
echo "${BLUE} ######################################################### ${RESET}"

whatweb -i alive.txt | tee -a whatweb_op.txt


echo "${GREEN} ######################################################### ${RESET}"
echo "${GREEN} #                          WayBack                      # ${RESET}"
echo "${GREEN} ######################################################### ${RESET}"

mkdir wayback_data
for i in $(cat all.txt); do echo $i | waybackurls; done | tee -a wayback_data/wb.txt
cat wayback_data/wb.txt | sort -u | unfurl --unique keys | tee -a wayback_data/paramlist.txt
cat wayback_data/wb.txt | grep -P "\w+\.js(\?|$)" | sort -u | tee -a wayback_data/jsurls.txt
cat wayback_data/wb.txt | grep -P "\w+\.php(\?|$)" | sort -u | tee -a wayback_data/phpurls.txt
cat wayback_data/wb.txt | grep -P "\w+\.aspx(\?|$)" | sort -u | tee -a wayback_data/aspxurls.txt
cat wayback_data/wb.txt | grep -P "\w+\.jsp(\?|$)" | sort -u | tee -a wayback_data/jspurls.txt
cat wayback_data/wb.txt | grep -P "\w+\.txt(\?|$)" | sort -u | tee -a wayback_data/robots.txt


echo "${BLUE} ######################################################### ${RESET}"
echo "${BLUE} #            Looking for HTTP request smuggling         # ${RESET}"
echo "${BLUE} ######################################################### ${RESET}"

cat alive.txt | smuggler | tee -a smuggler_op.txt

# mkdir scripts
# mkdir scriptsresponse
# mkdir endpoints
# mkdir responsebody
# mkdir headers

# jsep() {
#         response() {
#                 echo "Gathering Response"
#                 for x in $(cat alive.txt); do
#                         NAME=$(echo $x | awk -F/ '{print $3}')
#                         curl -X GET -H "X-Forwarded-For: evil.com" $x -I >"headers/$NAME"
#                         curl -s -X GET -H "X-Forwarded-For: evil.com" -L $x >"responsebody/$NAME"
#                 done
#         }

#         jsfinder() {
#                 echo "Gathering JS Files"
#                 for x in $(ls "responsebody"); do
#                         printf "\n\n${RED}$x${NC}\n\n"
#                         END_POINTS=$(cat "responsebody/$x" | grep -Eoi "src=\"[^>]+></script>" | cut -d '"' -f 2)
#                         for end_point in $END_POINTS; do
#                                 len=$(echo $end_point | grep "http" | wc -c)
#                                 mkdir "scriptsresponse/$x/" >/dev/null 2>&1
#                                 URL=$end_point
#                                 if [ $len == 0 ]; then
#                                         URL="https://$x$end_point"
#                                 fi
#                                 file=$(basename $end_point)
#                                 curl -X GET $URL -L >"scriptsresponse/$x/$file"
#                                 echo $URL >>"scripts/$x"
#                         done
#                 done
#         }

#         endpoints() {
#                 echo "Gathering Endpoints"
#                 for domain in $(ls scriptsresponse); do
#                         #looping through files in each domain
#                         mkdir endpoints/$domain
#                         for file in $(ls scriptsresponse/$domain); do
#                                 ruby ~/tools/relative-url-extractor/extract.rb scriptsresponse/$domain/$file >>endpoints/$domain/$file
#                         done
#                 done

#         }
#         response
#         jsfinder
#         endpoints
# }
# jsep
# cat endpoints/*/* | sort -u | tee -a endpoints.txt


echo "${GREEN} ######################################################### ${RESET}"
echo "${GREEN} #                            FFUF                       # ${RESET}"
echo "${GREEN} ######################################################### ${RESET}"

for i in $(cat alive.txt); do ffuf -u $i/FUZZ -w ~/tools/dirsearch/db/dicc.txt -mc 200 -t 60; done | tee -a ffuf_op.txt
