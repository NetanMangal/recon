#!/bin/bash

source ~/.bash_profile

RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
BLUE=$(tput setaf 4)
RESET=$(tput sgr0)

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

sources='alive.txt alive2.txt all.txt amass_ips.txt corsy_op.txt data_output dns_op.txt massdns.raw naabu_portscan.txt nmap_op nmap_scan.txt nuclei_op op.txt output.txt smuggler_op.txt'

echo "${GREEN} ######################################################### ${RESET}"
echo "${GREEN} #                         $domain                    # ${RESET}"
echo "${GREEN} ######################################################### ${RESET}"

for item in $sources; do
    if [[ $(ls -lah | awk '{print $NF}' | grep -E "^$item\$") != "$item" ]]; then
        echo "${RED} # $item not found # ${RESET}"
    fi
done
