import sys
import os
import re
import json
import argparse
from time import strftime, localtime
from datetime import datetime
from dateutil.relativedelta import relativedelta

# Creation date regexes.
creation_date_regexes = [
	( "[cC]reated: ([12][0-9]{3}-[01][0-9]-[0123][0-9])T?\s?", '%Y-%m-%d', 1 ),
	( "[cC]reat(e|ion) [dD]ate: ([12][0-9]{3}-[01][0-9]-[0123][0-9])T", '%Y-%m-%d', 2 ),
	( "Registered: ([12][0-9]{3}-[01][0-9]-[0123][0-9])", '%Y-%m-%d', 1 )
]

# Attempts to grep creation date from whois data if creation_date is not present.
def grep_creation_date(whois):
	# 'created: <date>\n is a common one, so let's try that first and see if it yields a valid date stamp.
	creation_date = None
	for regex in creation_date_regexes:
		matches = re.search(regex[0], whois)
		if matches:
			creation_date = datetime.strptime(matches.group(regex[2]), regex[1])
			print(creation_date)
			break

	# Return timestamp converted from date if valid.
	return creation_date.timestamp() if creation_date else None

# Analyzes JSON file containing analysis results from Virustotal for a domain name.
def analyze_json_file(path, require_aaaa):
	with open(path, 'r') as input_file:
		# Read JSON data from file.
		buffer = input_file.read()
		if len(buffer) == 0:
			return False
		json_buffer = json.loads(buffer)
		if len(json_buffer) < 1:
			print("miauw")
			exit(1)
		json_data = json_buffer[0]
		domain = json_data["_id"]

		# See if any information about last DNS records is available. If not, we will drop the result immediately.
		if "last_dns_records" not in json_data:
			return False

		# Check for domain names that had a TLS certificate.
		if "last_https_certificate" not in json_data:
			return False

		# Discard any domain not having a popularity rank, see what we are left with.
		if "popularity_ranks" not in json_data:
			return False
		popularity_ranks = json_data["popularity_ranks"]

		# Obtain the creation date of the domain from the result object, if present.
		if "creation_date" in json_data:
			creation_date = json_data["creation_date"]
		else:
			# Try to obtain creation date from whois data in result object.
			if "whois" not in json_data:
				return False

			# Grep creation date from whois string.
			creation_date = grep_creation_date(json_data["whois"])
			if creation_date is None:
				return False

		# See if the domain has been registered for at least two years straight.
		two_years = (datetime.today() - relativedelta(years=2)).timestamp()
		if creation_date > two_years:
			return False

		# Check whether the domain name has had an MX and SOA record in its last records.
		last_dns_records = json_data["last_dns_records"]
		found_mx = False
		found_soa = False
		found_aaaa = False
		for record in last_dns_records:
			if record["type"] == "MX":
				found_mx= True
			elif record["type"] == "SOA":
				found_soa = True
			elif require_aaaa and record["type"] == "AAAA":
				found_aaaa = True

		# We filter out any domain names not having had any MX and SOA records in their last state.
		if not found_mx or not found_soa:
			return False

		# If an AAAA record is required, see if we found one.
		if require_aaaa and not found_aaaa:
			return False

		# If the domain was in the Alexa, Cisco Umbrella or Statvoo popularity ranks, the domain has potentially good quality for attracting spam.
		umbrella_rank = 0xFFFFFFFF
		alexa_rank = 0xFFFFFFFF
		statvoo_rank = 0xFFFFFFFF
		if "Cisco Umbrella" in popularity_ranks:
			umbrella_rank = popularity_ranks["Cisco Umbrella"]["rank"]
		elif "Alexa" in popularity_ranks:
			alexa_rank = popularity_ranks["Alexa"]["rank"]
		elif "Statvoo" in popularity_ranks:
			statvoo_rank = popularity_ranks["Statvoo"]["rank"]

		# Check when the certificate for this domain is not from too long ago.
		last_https_certificate_date = json_data["last_https_certificate_date"]

		# Still here, so this domain is potentially interesting.
		return (domain, creation_date, last_https_certificate_date, umbrella_rank, alexa_rank, statvoo_rank)

if __name__ == "__main__":
	# Parse command line arguments.
	parser = argparse.ArgumentParser(description="Virustotal domain lookup results analyzer")
	parser.add_argument("-s", "--sort-column", help="Sort by popularity ranking (alexa,umbrella,statvoo) or creation date", required=True)
	parser.add_argument("-n", "--top", type=int, default=10, help="Top N domain names to display (default = 10)")
	parser.add_argument("root_directory", help="Root directory to look for JSON files")
	args = parser.parse_args()

	# Check sorting column.
	sort_arg = str(args.sort_column).casefold()
	if sort_arg != "alexa" and sort_arg != "umbrella" and sort_arg != "statvoo" and sort_arg != "creation_date":
		print("ERROR: Sort column can be either 'alexa', 'umbrella', 'statvoo' or 'creation_date'!")
		exit(1)

	# Iterate over all files in root directory.
	potential_domains = []
	num_total = 0
	i = 1
	for path in os.listdir(args.root_directory):
		# Print progress.
		print("\rFiles processed: %i" % i, end="")
		i += 1

		# Check if file matches our criteria.
		full_path = os.path.join(args.root_directory, path)
		if os.path.isfile(full_path) and path.endswith(".json"):
			# Analyze JSON file.
			res = analyze_json_file(full_path, True)
			num_total += 1
			if res != False:
				potential_domains.append(res)

	# Sort potential domains by the Cisco Umbrealla rank or Alexa rank, and print table output.
	if sort_arg == "umbrella":
		potential_domains.sort(key=lambda a: a[3])
	elif sort_arg == "alexa":
		potential_domains.sort(key=lambda a: a[4])
	elif sort_arg == "statvoo":
		potential_domains.sort(key=lambda a: a[5])
	elif sort_arg == "creation_date":
		potential_domains.sort(key=lambda a: a[1])
	print("#,domain,creation_date,last_https_certificate_date,umbrella,alexa,statvoo")

	# Create and print summary.
	top = min(args.top, len(potential_domains))
	for i in range(0, top):
		entry = potential_domains[i]
		umbrella_str = "N/A"
		if entry[3] != 0xFFFFFFFF:
			umbrella_str = str(entry[3])
		alexa_str = "N/A"
		if entry[4] != 0xFFFFFFFF:
			alexa_str = str(entry[4])
		statvoo_str = "N/A"
		if entry[5] != 0xFFFFFFFF:
			statvoo_str = str(entry[5])
		creation_date_str = "Unknown" if entry[1] == 0 else strftime('%Y', localtime(entry[1]))
		print("%i,%s,%s,%s,%s,%s,%s" % (i, entry[0], creation_date_str, strftime('%Y-%m-%d', localtime(entry[2])), umbrella_str, alexa_str, statvoo_str))
	print("INFO: Potentially interesting domains: %i/%i" % (len(potential_domains), num_total))
