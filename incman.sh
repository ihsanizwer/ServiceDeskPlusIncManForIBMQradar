#!/usr/bin/bash
clear
cat header
echo ""
rawinc=`curl -X GET -s -k -u admin:Password123 https://10.10.20.101/api/siem/offenses/{$1}`
echo -e "Incident number = `echo $rawinc | jq '."id"'` \n"
echo -e "Incident description = `echo $rawinc | jq '."description"'` \n"
echo -e "Magnitude = `echo $rawinc | jq '."magnitude"'` \n"

echo -e "Source IP Addresses :\n"
echo $rawinc | jq '."source_address_ids"' | jq -c '.[]' | while read object
do
curl -X GET -s -k -u admin:Password123 https://10.10.20.101/api/siem/source_addresses/${object}| jq -c '."source_ip"'
done
echo ""

echo -e "Destination IP Addresses :\n"
echo $rawinc | jq '."local_destination_address_ids"' | jq -c '.[]' | while read object2
do
curl -X GET -s -k -u admin:Password123 https://10.10.20.101/api/siem/local_destination_addresses/${object2} | jq -c '."local_destination_ip"'
done

echo ""
echo -e "Raw offense details :\n $rawinc"

xmlpar="<operation><details><requester>Administrator</requester><subject>`echo $rawinc | jq '."description"'`</subject><description>${rawinc}</description><callbackURL>http://10.10.1.132:8008/CustomReportHandler.do</callbackURL><requesttemplate>Qradar Security Incident</requesttemplate><technician>Howard Stern</technician><status>open</status></details></operation>"

subject=`echo $rawinc | jq '."description"'`

techniciankey=6ED545BB-F6AD-4A52-B728-562D8F37BE14

curl -X POST 'http://10.10.1.132:8008/sdpapi/request/' -d OPERATION_NAME=ADD_REQUEST -d TECHNICIAN_KEY=${techniciankey} -d INPUT_DATA="<Operation><Details><parameter><name>requester</name><value>administrator</value></parameter><parameter><name>subject</name><value>${subject}</value></parameter><parameter><name>description</name><value>${description}</value></parameter><parameter><name>callbackURL</name><value>http://10.10.1.132:8008/CustomReportHandler.do</value></parameter><parameter><name>requesttemplate</name><value>Qradar Security Incident</value></parameter><parameter><name>priority</name><value>High</value></parameter><parameter><name>group</name><value>Network</value></parameter><parameter><name>technician</name><value>Howard Stern</value></parameter><parameter><name>status</name><value>Open</value></parameter></Details></Operation>"