#!/bin/bash

# Create target directory if it does not exist yet.
mkdir -p /tmp/drukwerk

# Copy all mail messages from the spam pot drukwerk.sec.nl.
scp -P 2222 -r gijs@drukwerk.sec.nl:/var/spamsinkd/log/*/mailstore/* /tmp/drukwerk/

# Execute preparation script for the analyzer.
python3 /opt/spam-analyzer/drukwerk.py

# Remove files from target directory to avoid clutter.
rm -r /tmp/drukwerk/*
