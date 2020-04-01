#!/usr/bin/sh
#
#
# get_public_ip.sh - Script to lookup public IP address and map
#                    private IP, server name and other bits from Control
#
#
# Script will be fed like:
# get_public_ip.sh Datacenter Public_IP SRX_username SRX_password SRX_EDGE SRX_CORE Control_user Control_passwd VPX_username VPX_password VPX_RNAT
# Example:
# get_public_ip.sh XY1 1.2.3.4 root Password123 10.1.1.1 10.1.2.1 SomeUserNameHere Password456 123.123.123.1 nsroot Password789
#

####################
# SECTION BEGIN: Setup
#

# Set $DEBUG to true if you are debugging and want to keep the output directory contents.
#
DEBUG=true

# Set variables to collect output and make the output directory.
#
OUTDIR=/tmp/get_ip.$$
EDGEOUTFILE=/tmp/get_ip.$$/from_edge
EDGEPOLICYOUTFILE=/tmp/get_ip.$$/from_edge_policy
COREOUTFILE=/tmp/get_ip.$$/from_core
NETOUTFILE=/tmp/get_ip.$$/from_control_networks
SERVERLISTOUTFILE=/tmp/get_ip.$$/from_control_servers_list
SERVEROUTFILE=/tmp/get_ip.$$/from_control_server
VPXOUTFILE=/tmp/get_ip.$$/from_shared_vpx
mkdir -p ${OUTDIR}

# Process command line arguments and set some variables.
#
DC=${1}
PUBIPRAW=${2}
SRXUSER=${3}
SRXPASS=${4}
SRXEDGE=${5}
SRXCORE=${6}
CTRLUSER=${7}
CTRLPASS=${8}
VPXUSER=${9}
VPXPASS=${10}
VPXRNAT=${11}
SRXSSHPASS="sshpass -p ${SRXPASS} ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
VPXSSHPASS="sshpass -p ${VPXPASS} ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

#
# SECTION END: End of setup section.
####################


####################
# SECTION BEGIN: Define functions
#

# Function to clean things up and exit.  Base the exit status on supplied value.
#
cleanup_and_exit()
{
   EXITSTATUS=${1}

   # If you are debugging this script, do not remove $OUTPUTDIR.
   #
   if [ ${DEBUG} = "false" ]; then
      rm -r ${OUTDIR}
   fi

   exit ${EXITSTATUS}
}

# Function to lookup the account alias from the core SRX.
#
get_account_alias()
{
   GATEWAY=`echo ${PRIVATEIP} | cut -d"." -f-3`.1

   ${SRXSSHPASS} ${SRXUSER}@${SRXCORE} "cli -c \"show configuration | display set | match ${GATEWAY}\"" > ${COREOUTFILE} 2>/dev/null
   RETH=`grep unit ${COREOUTFILE} | cut -d" " -f3`.`grep unit ${COREOUTFILE} | cut -d" " -f5`

   ${SRXSSHPASS} ${SRXUSER}@${SRXCORE} "cli -c \"show interfaces ${RETH} brief\"" >> ${COREOUTFILE} 2>/dev/null
   ACCOUNTALIAS=`grep "Security: Zone: " ${COREOUTFILE} | awk '{print $3}' | tr '[a-z]' '[A-Z]'`
   if [ ${ACCOUNTALIAS:-"BoGuS"} = "BoGuS" ]; then
      echo "Account Alias: Not Found"
      echo ""
      echo "ERROR: Unable to continue as account alias could not be found on SRX Core."
      cleanup_and_exit 1
   fi
   echo "Account Alias: ${ACCOUNTALIAS}"
}

# Function to get info about the server from Control
#
get_server_info()
{
   # Get bearer token for Control lookups and get a list of networks.
   #
   BTOKEN=`curl --silent -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d "{\"username\":\"${CTRLUSER}\",\"password\":\"${CTRLPASS}\"}" "https://api.ctl.io/v2/authentication/login"  | jq ".bearerToken" | sed 's/"//g'`

   MYCURL="curl --silent -X GET -H \"Content-Type: application/json\" -H \"Accept: application/json\""

   ${MYCURL} -H "Authorization: Bearer ${BTOKEN}" "https://api.ctl.io/v2-experimental/networks/${ACCOUNTALIAS}/${DC}" | jq "." > ${NETOUTFILE}
   NETWORKID=`jq ".[] | select(.gateway == \"${GATEWAY}\") | .id" ${NETOUTFILE} | sed 's/"//g'`
   if [ ${NETWORKID:-"none"} = "none" ]; then
      echo ""
      echo "ERROR: Unable to continue as I could not find the private network in Control under ${ACCOUNTALIAS}."
      cleanup_and_exit 1
   fi

   # Find the server in Control
   #
   ${MYCURL} -H "Authorization: Bearer ${BTOKEN}" "https://api.ctl.io/v2-experimental/networks/${ACCOUNTALIAS}/${DC}/${NETWORKID}?ipAddresses=claimed" > ${SERVERLISTOUTFILE}
   SERVERNAME=`jq ".ipAddresses[] | select(.address == \"${PRIVATEIP}\") | .server" ${SERVERLISTOUTFILE} | sed 's/"//g'`
   if [ ${SERVERNAME:-"BoGuS"} = "BoGuS" ]; then
      echo "  Server Name: Server not found in Control"
      echo "  Description:"
      echo "      OS Type:"
      echo "  Power State:"
      echo ""
   else
      # Find the description, OS type and powerstate.
      #
      ${MYCURL} -H "Authorization: Bearer ${BTOKEN}" "https://api.ctl.io/v2/servers/${ACCOUNTALIAS}/${SERVERNAME}" | jq . > ${SERVEROUTFILE}
      DESCRIPTION=`jq ".description" ${SERVEROUTFILE} | sed 's/"//g'`
      OSTYPE=`jq ".osType" ${SERVEROUTFILE} | sed 's/"//g'`
      POWERSTATE=`jq ".details.powerState" ${SERVEROUTFILE} | sed 's/"//g'`

      echo "  Server Name: ${SERVERNAME}"
      echo "  Description: ${DESCRIPTION}"
      echo "      OS Type: ${OSTYPE}"
      echo "  Power State: ${POWERSTATE}"
      echo ""
   fi
}

#
# SECTION END: Define functions
####################


####################
# SECTION BEGIN: Check to make sure you're getting a proper IP address.
#

# Slack appears to think some malformed public IP addreses are telephone numbers.  If you
# see "tel:", strip if off.
#
echo ${PUBIPRAW} | grep "tel" > /dev/null 2>&1
if [ ${?} -eq 0 ]; then
 PUBIPRAW=`echo ${PUBIPRAW} | sed -e 's/tel%3A//'`
fi

# Check to make sure it is a valid IP address.
# Ensure it is 4 octets of 1-3 numbers, separated by periods.
#
echo ${PUBIPRAW} |  grep -E -o "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" > /dev/null 2>&1
if [ ${?} -ne 0 ]; then
   echo "ERROR: ${PUBIPRAW} does not appear to be a valid public IP address."
   cleanup_and_exit 1
fi

# Check out each octet in $PUBIPRAW to make sure it is valid.
# If valid, assemble into a new variable named $PUBLICIP.
#
for OCTET in 1 2 3 4
do
   # Grab the octet in question.
   #
   OCTETVALRAW=`echo ${PUBIPRAW} | cut -d"." -f${OCTET}`

   # Convert to base 10 to drop any leading zeros in the octet.
   # IE: 08 becomes 8
   #
   OCTETVAL=$((10#${OCTETVALRAW}))

   if [ ${OCTETVAL} -gt 255 ]; then
      echo "ERROR: ${PUBIPRAW} does not appear to be a valid public IP address."
      cleanup_and_exit 1
   fi

   # If you're looking at the first octet, make sure it is not a zero, and not a 10.x.x.x,
   # 192.x.x.x or 172.x.x.x address.
   #
   if [ ${OCTET} -eq 1 ]; then
      if [  ${OCTETVAL} -eq 0 -o ${OCTETVAL} -eq 10 -o ${OCTETVAL} -eq 192 -o ${OCTETVAL} -eq 172 ]; then
         echo "ERROR: ${PUBIPRAW} does not appear to be a valid public IP address."
         cleanup_and_exit 1
      else
         PUBLICIP="${OCTETVAL}"
      fi
   else
      PUBLICIP="${PUBLICIP}.${OCTETVAL}"
   fi

done

#
# SECTION END: End of IP address checking section.
####################


####################
# SECTION BEGIN: Look up the public IP on the edge and get info about its mapping.
#

# Login to the edge and lookup the public IP.
#
${SRXSSHPASS} ${SRXUSER}@${SRXEDGE} "cli -c \"show configuration | display set | match ${PUBLICIP}/32\"" > ${EDGEOUTFILE} 2>/dev/null


# Find out the rule name from the output received.
#
RULE=`grep ${PUBLICIP} ${EDGEOUTFILE} | grep " static-nat " | awk '{print $8}'`

if [ ${RULE:-"NOTFOUND"} != "NOTFOUND" ]; then

   # Obtain the private IP address.
   #
   ${SRXSSHPASS} ${SRXUSER}@${SRXEDGE} "cli -c \"show configuration | display set | match rule\ ${RULE}\ then\ static-nat\ prefix\ \"" >> ${EDGEOUTFILE} 2>/dev/null
   PRIVATEIP=`grep " ${RULE} then static-nat prefix " ${EDGEOUTFILE} | awk '{print $12}' | cut -d"/" -f1`

   # Obtain the policy name.
   #
   ${SRXSSHPASS} ${SRXUSER}@${SRXEDGE} "cli -c \"show configuration | display set | match ${PRIVATEIP}/32 | match from-zone\ untrust\ to-zone\ trust\ \"" >> ${EDGEOUTFILE} 2>/dev/null
   POLICY=`grep ${PRIVATEIP} ${EDGEOUTFILE} | grep "from-zone untrust to-zone trust policy " | awk '{print $9}'`

   # Obtain info about the policy itself
   #
   ${SRXSSHPASS} ${SRXUSER}@${SRXEDGE} "cli -c \"show configuration | display set | match from-zone\ untrust\ to-zone\ trust\ policy\ ${POLICY}\ \"" > ${EDGEPOLICYOUTFILE} 2>/dev/null

   # Get a listing of any source IP restrictions.
   #
   for ALLOW in `grep source-address ${EDGEPOLICYOUTFILE} | cut -d" " -f12`
   do
      ALLOWFROM="${ALLOWFROM} ${ALLOW}"
   done

   # Get a list of opened ports.
   #
   for APP in `grep application ${EDGEPOLICYOUTFILE} |  cut -d" " -f12`
   do
      echo ${APP} | egrep "tcp|udp" > /dev/null 2>&1
      if [ ${?} -eq 0 ]; then
         APP=`echo ${APP} | sed -e 's/_/:/' -e 's/_/-/'`
      fi
      PORTS="${PORTS} ${APP}"
   done

   # Report what you know about the static NAT mapping.
   #
   echo "${PUBLICIP} is a static NAT on the ${DC} Edge SRX."
   echo ""
   echo "    Public IP: ${PUBLICIP}"
   echo "   Private IP: ${PRIVATEIP}"
   echo "   Allow from:${ALLOWFROM}"
   echo "      Port(s):${PORTS}"

   # Lookup the Account alias and then server find from Control.
   #
   get_account_alias
   get_server_info
   echo "Please note these may not be the only IP addresses listed for the server."

else
   # Check to see if the public IP address is a VIP on the shared VPX LB.
   #
   ${VPXSSHPASS} ${VPXUSER}@${VPXRNAT} "show lb vserver | grep \"(${PUBLICIP}:\"" > ${VPXOUTFILE} 2>/dev/null

   grep "(${PUBLICIP}:" ${VPXOUTFILE} > /dev/null 2>&1
   if [ ${?} -eq 0 ]; then
      # Found the IP
      #
      echo "${PUBLICIP} is a VIP on the ${DC} shared VPX load balancer."
      echo ""
      echo ""
      for VSERVER in `grep "(${PUBLICIP}:" ${VPXOUTFILE} | awk '{print $2}'`
      do
         LBPORT=`echo ${VSERVER} | cut -d: -f2`
         echo "===> LB Virtual Server IP (VIP): ${PUBLICIP}  Port: ${LBPORT}"
         echo ""
         ${VPXSSHPASS} ${VPXUSER}@${VPXRNAT} "show lb vserver ${VSERVER} | grep \"${VSERVER} (10.\"" > ${VPXOUTFILE}_${LBPORT} 2>/dev/null
         for PRIVATEIP in `grep ${VSERVER} ${VPXOUTFILE}_${LBPORT} | cut -d"(" -f2 | cut -d":" -f1`
         do
            POOLPORT=`grep ${PRIVATEIP} ${VPXOUTFILE}_${LBPORT} | cut -d":" -f3 | cut -d")" -f1`
            echo "    Member IP: ${PRIVATEIP} port${POOLPORT}"
            get_account_alias
            get_server_info
         done
      echo ""
      done
      cleanup_and_exit 0
   else
      # If you get to this point, the public IP is not a static NAT and it is
      # not a shared LB VIP IP.
      #

      # Check to see if the public IP is the OpenVPN VIP.
      #
      grep ${PUBLICIP} ${EDGEOUTFILE} | grep openvpn-vip > /dev/null 2>&1
      if [ ${?} -eq 0 ]; then
         echo "${PUBLICIP} is the shared OpenVPN NAT IP address in the ${DC} datacenter."
         cleanup_and_exit 0

      else
         # Check to see if the public IP is the NAT IP for the datacenter.
         #
         ${SRXSSHPASS} ${SRXUSER}@${SRXEDGE} "cli -c \"show interfaces reth0.0 | match Local\"" > ${EDGEOUTFILE} 2>/dev/null
         if [ ${PUBLICIP} = "grep Local ${EDGEOUTFILE} | awk '{print $4}' | cut -d"," -f1" ]; then
            echo "${PUBLICIP} is the shared NAT IP address for the ${DC} datacenter."
            cleanup_and_exit 0

         else
            # Check to see if the public IP is the VPN endpoint for the datacenter.
            #
            ${SRXSSHPASS} ${SRXUSER}@${SRXCORE} "cli -c \"show interfaces reth3.998 | match Local\"" > ${COREOUTFILE} 2>/dev/null
            if [ ${PUBLICIP} = "grep Local ${COREOUTFILE} | awk '{print $4}' | cut -d"," -f1" ]; then
               echo "${PUBLICIP} is the IP address for the VPN endpoint in the ${DC} datacenter."
               cleanup_and_exit 0
            else

               # Did not find the IP on the shared VPX.  At this point, Alice has
               # exhausted all possibilities. <insert sad trombone>
               #
               echo "I'm sorry but I am not able to find ${PUBLICIP} in ${DC}."
               echo "Please double-check the IP address and datacenter and try again."
               echo "If they are correct, you will need to investigate this IP address manually."
               echo "If it is pingable, it is possible that the public IP address might be assigned"
               echo "to an LBaaS pool or a VFW static NAT.  Please check with those teams as well."
               cleanup_and_exit 1
            fi
         fi
      fi
   fi

   cleanup_and_exit 0
fi

#
# SECTION END: Lookup public IP on Edge
####################


# All done.
#
cleanup_and_exit 0
