#!/bin/bash

# Set remote path to latest DNSFilter domains list.
DNSFILTER_GIT="https://raw.githubusercontent.com/DNSFilter/topdomains/main"
LATEST_PATH="latest.csv"
OUTPUT_PATH="DNSFilter_latest.csv"

# Obtain latest DNSFilter list.
latest_value=$(curl "$DNSFILTER_GIT/$LATEST_PATH")
echo "INFO: Obtained redirect to latest data file at: $latest_value"

# Construct path to latest data file and pull it.
latest_data_path="$DNSFILTER_GIT/$latest_value"
wget -O $OUTPUT_PATH $latest_data_path
res=$?
if test $res -eq 0
then
	echo "INFO: Downloaded domain ranking data from: $latest_data_path"
	exit 0
else
	echo "ERROR: Failed to download domain ranking data! Wget exit code: $res"
	exit $res
fi
