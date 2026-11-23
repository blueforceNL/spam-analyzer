# ----------------------------------------------------------|
# Spam trap analyzer main component, polls for new incoming |
# mail and performs initial analysis on it.                 |
# ----------------------------------------------------------|

import os
import psutil
import shutil
import sys
import git
import csv
import time
import base64
import argparse
import logging
import hashlib
import datetime
import subprocess
import mysql.connector
import encodings
import urllib.request
import json
import codecs
from bs4 import BeautifulSoup
from systemd import journal
from configparser import ConfigParser
from analyzer_config import load_or_create_config
from mail_analysis import analyze_mail_message

# Filename of the script that obtains the latest DNSFilter domain ranking data.
DNSFILTER_PULL_LATEST_SCRIPT_FILENAME = "analysis/get_dnsfilter_latest.sh"

# ----------------------------------------------------------|
# Database functions.                                       |
# ----------------------------------------------------------|

# Executes a mutation query (INSERT, UPDATE, etc) to the MySQL database server. Requires to be parameterized for SQL injection protection.
def execute_mutation_sql_query(db, q, params):
	cursorObject = db.cursor()
	cursorObject.execute(q, params)
	db.commit()
	return cursorObject.lastrowid

# Executes a SELECT query that returns results. Also a parameterized function to safeguard against SQL injection.
def execute_select_sql_query(db, q, params):
	cursorObject = db.cursor(buffered=True)
	cursorObject.execute(q, params)
	db.commit()
	return cursorObject.fetchall()

# -----------------------------------------------------------

# Inserts an indicator into the enricher queue if it does not exist there already.
# This check includes the inactive queue, because the IP might already be there waiting for processing too.
def enqueue_indicator_for_enricher(database, indicator, mail_id):
	# Query the primary queue first to see if the indicator is already queued.
	queue_entries_result = execute_select_sql_query(database, "SELECT id FROM enricher_queue WHERE checksum = CRC32(%s)", (indicator,))
	if len(queue_entries_result) > 0:
		return

	# Query the inactive entries queue as well to see if the indicator was already queued before a longer time ago.
	inactive_entries_result = execute_select_sql_query(database, "SELECT id FROM inactive_enricher_queue WHERE checksum = CRC32(%s)", (indicator,))
	if len(inactive_entries_result) > 0:
		return

	# Still here, so the indicator was not found, so insert it into the primary queue.
	query = "INSERT INTO enricher_queue (added,indicator,checksum,mail_id,enrichers) VALUES (NOW(),%s,CRC32(%s),%s,'*')"
	execute_mutation_sql_query(database, query, (indicator, indicator, mail_id))

# Obtains version number from the number of commits in the local Git repo.
def obtain_version_number():
	try:
		repo = git.Repo(".")
		version = int(repo.git.rev_list('--count', 'HEAD'))
		logger.info("Obtained version number from local Git repository: %i" % version)
	except git.exc.InvalidGitRepositoryError:
		logger.error("Could not parse working directory as Git repository to obtain version number!")
		logger.error("Setting version = 0")
		version = 0
	return version

# Attempt connection to the MySQL database server.
def connect_mysql_database(server, dbname, user, passwd):
	try:
		database = mysql.connector.connect(host=analyzer_config["database_addr"], user=analyzer_config["database_user"],
			passwd=analyzer_config["database_passwd"], database=analyzer_config["database_name"], connect_timeout=10)
	except mysql.connector.Error:
		return None

	# Check and print connection info.
	return database if database.is_connected() else None

# Parses HTML from an email and extracts the text, currently for debug purposes.
def bs_extract_text_from_html(html):
	# Parse the HTML with BeautifulSoup.
	soup = BeautifulSoup(html, features="html.parser")

	# Remove all script and style elements we don't want.
	for script in soup(["script", "style"]):
		script.extract()

	# Obtain the plain text from the HTML object.
	return soup.get_text()

# Purges everything from the database related to a Mail ID.
def purge_mail_message_analysis_from_database(mail_id):
	# We must start by removing any referencing foreign keys.
	try:
		# Delete entries with this mail ID from the enricher queue.
		execute_mutation_sql_query(database, "DELETE FROM enricher_queue WHERE mail_id = %s", (mail_id,))

		# Delete the mail ID from the spam classifier queue.
		execute_mutation_sql_query(database, "DELETE FROM spam_classifier_queue WHERE mail_id = %s", (mail_id,))

		# Delete any extracted BTC addresses, IP addresses or URLs.
		execute_mutation_sql_query(database, "DELETE FROM extracted_btc WHERE mail_id = %s", (mail_id,))
		execute_mutation_sql_query(database, "DELETE FROM extracted_ips WHERE mail_id = %s", (mail_id,))
		execute_mutation_sql_query(database, "DELETE FROM extracted_urls WHERE mail_id = %s", (mail_id,))

		# Delete any attachment links. We will keep the attachments as the mail is going up for re-analysis.
		execute_mutation_sql_query(database, "DELETE FROM mail_attachment_link WHERE mail_id = %s", (mail_id,))

		# Delete mail body for this mail ID.
		execute_mutation_sql_query(database, "DELETE FROM mail_message_bodies WHERE mail_id = %s", (mail_id,))

		# Delete any linked classification including loose ends like indicators if applicable.
		detection_link_result = execute_select_sql_query(database, "SELECT id FROM mail_classifications_link WHERE mail_id = %s", (mail_id,))
		for entry in detection_link_result:
			# Select all indicators linked to this detection. We want to check if any of those have more than one reference.
			classification_indicators_result = execute_select_sql_query(database, "SELECT indicator_id FROM indicator_classification_link WHERE classifications_link_id = %s", (entry[0],))

			# Remove the link to the indicator from the given mail ID. Then, only other links will appear below and we should not touch them.
			execute_mutation_sql_query(database, "DELETE FROM indicator_classification_link WHERE classifications_link_id = %s", (entry[0],))

			# Iterate over the linked indicators to see if there are any other links remaining.
			for linked_indicator in classification_indicators_result:
				# Select all indicator links with the same ID as this one, having a different classification ID.
				other_indicator_links_result = execute_select_sql_query(database, "SELECT id FROM indicator_classification_link WHERE indicator_id = %s", (linked_indicator[0],))
				if len(other_indicator_links_result) == 0:
					# No other links to this indicator exist, and therefore, we can remove the indicator from the database as well.
					execute_mutation_sql_query(database, "DELETE FROM indicators WHERE id = %s", (linked_indicator[0],))

			# Delete attributes if any are linked to this detection.
			execute_mutation_sql_query(database, "DELETE FROM linked_attributes WHERE classifications_link_id = %s", (entry[0],))

			# Finally, remove the classification from the database.
			execute_mutation_sql_query(database, "DELETE FROM mail_classifications_link WHERE id = %s", (entry[0],))

		# Finally, delete the mail from the analyzed_mail table. After this, the purging is complete and re-analysis is good to go.
		execute_mutation_sql_query(database, "DELETE FROM analyzed_mail WHERE id = %s", (mail_id,))
	except Exception as e:
		logger.warning("Exception occurred when purging all related to a mail in the database: %s" % str(e))

# ----------------------------------------------------------------------------------|
# Some mails have exotic encodings, and we will have to map some from weird aliases.|
# ----------------------------------------------------------------------------------|

def exotic_codec_mapper(codec_name):
	# Normalize characters first.
	codec_name = codec_name.replace('_', '-').lower()

	# Perform lookup based on our observations.
	if codec_name == "cp-850":
		return codecs.lookup("cp850")
	elif codec_name == "windows-874":
		return codecs.lookup("cp874")

	# Found nothing.
	return None

# ----------------------------------------------------------|
# Main analyzer component code                              |
# ----------------------------------------------------------|

# Allow single-mail debugging by checking for a filename argument. If a file is specified, we just analyze the single mail file and exit.
parser = argparse.ArgumentParser(description='Spam mail analyzer')
parser.add_argument('filename', nargs='?')
parser.add_argument('-s', action='store_true', dest='store_attachments', help='Store attachments to disk, only in debug mode')
parser.add_argument('-v', action='store_true', dest='verbose', help='Verbose mode, print mail message body in debug mode')
parser.add_argument('-d', action='store_true', dest='decode_html', help='Decode HTML email body, only in debug mode')
args = parser.parse_args()

# We have to hack an alias for the broken encoding reference in the encodings table.
codecs.register(exotic_codec_mapper)

# Do initial tasks for starting the analyzer. We initialize a logger that targets systemd.
logger = logging.getLogger("spam-analyzer")
journald_handler = journal.JournaldLogHandler()
journald_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))

# Test whether debug mode is activated.
debug = False
if args.filename:
	# Get filename from second argument.
	if os.path.isfile(args.filename):
		debug = True
		logger.setLevel(logging.DEBUG)
		stdout_handler = logging.StreamHandler(sys.stdout)
		stdout_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
		logger.addHandler(stdout_handler)
		logger.info("Running in single-file mode for debugging! Database connection turned off.")
		if args.verbose:
			logger.info("Verbose mode enabled.")
	else:
		logger.error("First argument: %s must be a filename but file does not exist! Exiting." % sys.argv[1])
		exit(1)

# Still here, so running in service mode. Set journald handler.
logger.setLevel(logging.INFO)
logger.addHandler(journald_handler)

# Create or load the configuration.
try:
	config_object = load_or_create_config()
	analyzer_config = config_object["ANALYZER"]
except KeyError:
	logger.error("Could not open config file, one or more required key/value pairs are missing! Review the config file and try again.")
	exit(1)

# Start some measurements.
start_time = datetime.datetime.now()

# Obtain the version number of the analyzer from the automatically generated version file.
spam_analyzer_version = obtain_version_number()

# Run a script to pull the latest DNSFilter top domains list. We wait for the subprocess to complete before continueing.
# Do this only if debug mode is not selected.
if not debug:
	logger.info("Pulling latest DNSFilter domain rankings list...")
	subprocess.call([ 'sh', DNSFILTER_PULL_LATEST_SCRIPT_FILENAME ])

# Did we successfully pull the data to a local file? If so, open it and load DNSFilter domain ranking data.
dnsfilter_domain_rankings = set()
if os.path.exists(analyzer_config["dnsfilter_path"]) and os.path.getsize(analyzer_config["dnsfilter_path"]) > 512:
	with open(analyzer_config["dnsfilter_path"], 'r') as dnsfilter_file:
		reader = csv.reader(dnsfilter_file)
		for row in reader:
			dnsfilter_domain_rankings.add(row[1])
	logger.info("Loaded %i entries from DNSFilter domain rankings." % len(dnsfilter_domain_rankings))
else:
	logger.error("Could not load DNSfilter cache file! Did you run the spam-analyzer from the correct working directory?")
	exit(1)

# Check if reanalysis is allowed by config.
reanalysis_allowed = True if "allow_reanalysis" in analyzer_config and analyzer_config["allow_reanalysis"] == "yes" else False

# Check whether a filename is specified. If so, we enter single-mail mode for debugging.
logger.info("Spam analyzer started.")
if debug:
	# Process the next mail file in the root directory.
	logger.debug("Processing new mail file: %s" % args.filename)
	analysis_start_time = datetime.datetime.now()

	# Open the mail file for reading.
	with open(args.filename, 'rb') as mail_file:
		# Read the message file.
		mail_bytes = mail_file.read()

		# Compute MD5 hash of the mail message file.
		msg_md5 = hashlib.md5(mail_bytes).hexdigest()

		# Analyze the mail message and return the results. Since this is only run in debug mode, we want to see the exception being triggered.
		result = analyze_mail_message(mail_bytes, dnsfilter_domain_rankings, int(analyzer_config["max_number_of_urls_in_body"]))

		# Check whether the analysis result is okay or not.
		if result["ok"] == False:
			logger.error("Mail message analysis failed! OK = False.")
		else:
			# Record end time of analysis and compute number of milliseconds passed.
			analysis_end_time = datetime.datetime.now()
			delta = analysis_end_time - analysis_start_time
			analysis_milliseconds = int(delta.total_seconds() * 1000)

			# Convert mail timestamp to string.
			if result["date"] is not None:
				# The MySQL specification states TIMESTAMPS cannot be before 1970 and after 2038 so we must check this first.
				if result["date"].year < 1970 or result["date"].year > 2037:
					logger.error("Datetime in mail: %s falls outside of MySQL TIMESTAMP range! Ignoring datetime header." % result["date"].strftime("%Y-%m-%d %H:%M:%S"))
					mail_date_str = None
				else:
					mail_date_str = result["date"].strftime("%Y-%m-%d %H:%M:%S")
			else:
				mail_date_str = None

			# Truncate the subject if it is too long.
			if len(result["subject"]) > 998:
				truncated_subject = result["subject"][:998]
			else:
				truncated_subject = result["subject"]

			# Get the sender IP-address from the result.
			sender_ip = result["sender_ip"] if "sender_ip" in result else ""

			# Get mail domain.
			mail_parts = result["recipient"].split('@')
			if len(mail_parts) > 1:
				logger.info("Email domain: %s" % mail_parts[1].strip("<>"))

			# Print analysis results.
			logger.info("Date: %s, Sender IP: %s, Subject: %s" % (mail_date_str, sender_ip, truncated_subject))
			logger.info("Sender: %s, Recipient: %s, Size in bytes: %i, Body length: %i" % (result["sender"], result["recipient"], result["size"], len(result["body"])))
			attachment_count = len(result["attachments"]) if "attachments" in result else 0
			logger.info("# Attachments: %i, Malicious: %s, Analysis time: %i ms" % (attachment_count, "yes" if result["potentially_malicious"] else "no", analysis_milliseconds))
			att_i = 1

			# Check whether the message was bounced or not. We print this information and the original headers if requested.
			if result["bounced"] and "bounced_subject" in result:
				# Truncate the bounced subject if it is too long.
				if len(result["bounced_subject"]) > 998:
					truncated_bounced_subject = result["bounced_subject"][:998]
				else:
					truncated_bounced_subject = result["bounced_subject"]

				logger.info("Message was bounced for being undeliverable. Original subject (guess): %s" % truncated_bounced_subject)
			else:
				truncated_bounced_subject = None

			# Print message body if requested.
			if args.verbose:
				if args.decode_html:
					logger.info("Message body (text parsed from HTML): %s" % bs_extract_text_from_html(base64.b64decode(result["body"])))
				else:
					logger.info("Message body (decoded): %s" % base64.b64decode(result["body"]))

			# Print basic information about attachments and their mime type.
			if "attachments" in result:
				for att in result["attachments"]:
					logger.info("Attachment #%i -> Filename: %s, MIME-type: %s, Size in bytes: %i" % (att_i, att["filename"] if "filename" in att else "", att["mime_type"], att["size"]))
					att_i += 1
					if args.store_attachments:
						logger.info("--> Dumped attachment to file: %s" % att["filename"])

						# If requested, write the attachment into a file in the current working directory, given by filename specified in the mail.
						# This option is only available io manual analysis mode, specifying a single mail message file.
						with open(att["filename"], 'wb') as attachment_file:
							attachment_file.write(att["payload"])

			# Print extracted URLs.
			if "extracted_urls" in result:
				for url in result["extracted_urls"]:
					logger.info("Extracted URL: %s" % url)
				total_urls = result["total_scanned_urls"] if "total_scanned_urls" in result else 0
				logger.info("Found %i URLs for analysis (%i URLs found in total, but filtered)." % (len(result["extracted_urls"]), total_urls))

			# Print extracted BTC addresses.
			if "extracted_btc" in result:
				for btc in result["extracted_btc"]:
					logger.info("Extracted BTC address: %s" % btc)

			# Print extracted IP-addresses if any.
			if "extracted_ips" in result:
				for ip in result["extracted_ips"]:
					logger.info("Extracted IP address: %s" % ip)

		# Print final message.
		logger.info("Analysis completed!")
else:
	# Create connection to MySQL database.
	logger.info("Connecting to MySQL database server at: %s" % analyzer_config["database_addr"])
	database = connect_mysql_database(analyzer_config["database_addr"], analyzer_config["database_name"], analyzer_config["database_user"], analyzer_config["database_passwd"])
	if database is not None:
		logger.info("Successfully connected to MySQL database at %s!" % analyzer_config["database_addr"])
	else:
		logger.error("Failed to connect to MySQL server at: %s!" % analyzer_config["database_addr"])
		exit(1)

	# Register new run in the database before starting.
	timestamp_string = start_time.strftime("%Y-%m-%d %H:%M:%S")
	execute_mutation_sql_query(database, "INSERT INTO analyzer_runs (timestamp,version) VALUES (%s,%s)", (timestamp_string, spam_analyzer_version))

	# Track some statistics for telemetry purposes. The counters are reset after the interval passed.
	telemetry_interval = int(analyzer_config["telemetry_interval_seconds"])
	telemetry_interval_start = 0
	telemetry_interval_end = 0
	total_mails_processed = 0
	total_malicious_mails = 0
	total_mails_failed = 0
	total_analysis_times = 0
	max_analysis_time = 0

	# Create list of configured root directories and test whether they all exist.
	mail_root_dirs = []
	for dir in analyzer_config["mail_root"].split(','):
		if not os.path.exists(dir):
			logger.error("Configured root directory: %s does not exist or is not readable!" % dir)
			logger.error("Cannot continue initialization! Exiting.")
			exit(1)

		# Store this directory, it is valid.
		mail_root_dirs.append(dir)
		logger.info("Analyzer will process mail in root directory: %s" % dir)

	# Start main loop, watching for new incoming mail.
	while True:
		# Process next emails in line.
		try:
			# Update the interval timer if necessary.
			if telemetry_interval_start == 0:
				telemetry_interval_start = datetime.datetime.now()
				telemetry_interval_end = telemetry_interval_start + datetime.timedelta(seconds=telemetry_interval)

			# Iterate through all configured root directories.
			for root_dir in mail_root_dirs:
				# Obtain list of new mail files in the current root directory.
				mail_root_files = os.listdir(root_dir)
				for m in mail_root_files:
					# Check whether the current file matches the pattern we expect and is not a directory.
					absolute_filename = os.path.join(root_dir, m)
					if not os.path.isfile(absolute_filename):
						continue

					# Process the next mail file in the root directory.
					logger.info("Processing new mail file: %s" % m)

					# Record start time to provide statistics later.
					analysis_start_time = datetime.datetime.now()
					ast_string = analysis_start_time.strftime("%Y-%m-%d %H:%M:%S")

					# Open the mail file for reading.
					with open(absolute_filename, 'rb') as mail_file:
						# Read the message file.
						mail_bytes = mail_file.read()

						# Compute MD5 hash of the mail message file.
						msg_md5 = hashlib.md5(mail_bytes).hexdigest()

						# Check if reanalysis is allowed. If so, we will not have to perform the MD5 check.
						if not reanalysis_allowed:
							# Query the analyzed mail table to see if the MD5 checksum is already stored there.
							checksum_result = execute_select_sql_query(database, "SELECT id FROM analyzed_mail WHERE md5_hash = X%s", (msg_md5,))
							if len(checksum_result) > 0:
								logger.info("Message file: %s has already been analyzed. Skipping and removing the message." % m)
								os.remove(absolute_filename)
								continue

						# Analyze the mail message and return the results.
						try:
							result = analyze_mail_message(mail_bytes, dnsfilter_domain_rankings, int(analyzer_config["max_number_of_urls_in_body"]))
						except Exception as e:
							logger.error("An error occurred processing %s. Message: %s" % (m, str(e)))
							result = { "ok" : False }

					# Analyze the result.
					total_mails_processed += 1
					if not result["ok"]:
						# Analysis failed, so move the mail message file to the faild analysis directory for further inspection.
						total_mails_failed += 1
						shutil.move(absolute_filename, os.path.join(analyzer_config["failed_analysis_dir"], m))
						logger.warning("Failed to process %s, moved to failed analysis directory." % m)
					else:
						# Record end time of analysis and compute number of milliseconds passed.
						analysis_end_time = datetime.datetime.now()
						delta = analysis_end_time - analysis_start_time
						analysis_milliseconds = int(delta.total_seconds() * 1000)
						max_analysis_time = max(max_analysis_time, analysis_milliseconds)
						total_analysis_times += analysis_milliseconds

						# Convert mail timestamp to string for database insertion.
						if result["date"] is not None:
							# The MySQL specification states TIMESTAMPS cannot be before 1970 and after 2038 so we must check this first.
							if result["date"].year < 1970 or result["date"].year > 2037:
								logger.error("Datetime in mail: %s falls outside of MySQL TIMESTAMP range! Ignoring datetime header." % result["date"].strftime("%Y-%m-%d %H:%M:%S"))
								mail_date_str = None
							else:
								mail_date_str = result["date"].strftime("%Y-%m-%d %H:%M:%S")
						else:
							mail_date_str = None

						# Truncate the subject if it is too long.
						if len(result["subject"]) > 998:
							truncated_subject = result["subject"][:998]
						else:

							truncated_subject = result["subject"]

						# Get the sender IP-address from the result.
						sender_ip = result["sender_ip"] if "sender_ip" in result else None

						# Check whether the message was bounced or not. We print this information and the original headers if requested.
						if result["bounced"] and "bounced_subject" in result:
							# Truncate the bounced subject if it is too long.
							if len(result["bounced_subject"]) > 998:
								truncated_bounced_subject = result["bounced_subject"][:998]
							else:
								truncated_bounced_subject = result["bounced_subject"]
						else:
							truncated_bounced_subject = None

						# I don't think this will ever be necessary but just to prevent crashing, truncate the filename to the database field length constraint.
						# All mail filenames have a fixed format given by Postfix so this should never happen anyway.
						mail_filename = m
						if len(mail_filename) > 48:
							logger.error("Filename exceeds database constraint of 48 characters, so truncating filename for inserting.")
							mail_filename = m[:48]

						# Insert row into the mail analysis table for this mail.
						attachment_count = len(result["attachments"]) if "attachments" in result else 0
						total_urls = result["total_scanned_urls"] if "total_scanned_urls" in result else 0

						# Get the domain from the recipient address and update the counters in the database.
						mail_parts = result["recipient"].split('@')
						domain_id = None
						mail_domain = None
						if len(mail_parts) >= 2:
							# Strip some common auxiliary characters from the domain, just in case.
							mail_domain = mail_parts[1].strip("<>")

							# Get current statistics for sinkholed domain.
							domain_stats = execute_select_sql_query(database, "SELECT id,incoming_mails,malicious_mails FROM domains WHERE domain = %s", (mail_domain,))
							if len(domain_stats) == 1:
								# Set incremented counters in the database.
								current_stats = domain_stats[0]
								domain_id = current_stats[0]
								current_incoming = current_stats[1]
								current_malicious = current_stats[2]
							elif len(domain_stats) == 0:
								# Domain for this sender is not yet in the domains table, so insert it.
								query = "INSERT INTO domains (domain,sinkholed,added,incoming_mails,malicious_mails) VALUES (%s,%s,%s,%s,%s)"
								domain_id = execute_mutation_sql_query(database, query, (mail_domain, 0, ast_string, 0, 0))
								current_incoming = 0
								current_malicious = 0
								logger.info("New incoming meil processed for non-sinkholed domain: %s, added to domains table (id = %i). Set country manually." % (mail_domain, domain_id))
							else:
								logger.warning("Obtained %i rows from domains query while 0 or 1 was expected! Sender email: %s" % (len(domain_stats), result["recipient"]))
						else:
							logger.warning("Invalid email address detected in recipient field: %s in file: %s (statistics not updated)." % (result["recipient"], m))

						# Query the analyzed mail table to see whether this mail was already analyzed. We have a unique constraint on the filename to counter duplicates.
						# If the mail already exists in the database, we do want to re-analyze it and therefore, we have to purge everything related to this mail from the database.
						analyzed_mail_entry = execute_select_sql_query(database, "SELECT id FROM analyzed_mail WHERE filename = %s", (mail_filename,))
						if len(analyzed_mail_entry) > 0:
							# Check whether reanalysis is allowed by configuration.
							if reanalysis_allowed:
								# Save the existing mail ID, as we will have to delete everything related to this.
								analyzed_mail_row = analyzed_mail_entry[0]
								existing_mail_id = analyzed_mail_row[0]

								# Purge the mail message and all its analyses from the database.
								logger.info("Mail message filename was found in the database! Purging existing data to allow re-analysis.")
								purge_mail_message_analysis_from_database(existing_mail_id)
							else:
								logger.warning("Message filename was found in the database but re-analysis is not allowed. Skipping and removing.")
								os.remove(absolute_filename)
								continue

						# The recipient, or list of recipients, has a fixed maximum size in the databas too.
						# Truncate it right here.
						if len(result["recipient"]) > 128:
							truncated_recipient = result["recipient"][:128]
						else:
							truncated_recipient = result["recipient"]

						# The sender may also be too long so we will have to truncate that one too.
						if len(result["sender"]) > 320:
							truncated_sender = result["sender"][:320]
						else:
							truncated_sender = result["sender"]

						# We catch the exception thrown here if any, because the analyzed_mail table has a unique constraint on filename to counter duplicate entries.
						# After purging everything from the database, this should not happen anymore, but we will keep the check in case I made a mistake above.
						try:
							query = "INSERT INTO analyzed_mail (timestamp,filename,md5_hash,potentially_malicious,sender,recipient,subject,bounced_subject,mail_timestamp,size,num_attachments,body_length,analysis_time,domain_id,total_scanned_urls,sender_ip) VALUES (%s,%s,X%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,INET_ATON(%s))"
							inserted_mail_id = execute_mutation_sql_query(database, query, (ast_string, mail_filename, msg_md5, 1 if result["potentially_malicious"] else 0, truncated_sender, truncated_recipient, truncated_subject, truncated_bounced_subject, mail_date_str, result["size"], attachment_count, result["body_length"], analysis_milliseconds, domain_id, total_urls, sender_ip))
						except Exception as e:
							# Analysis failed, so move the mail message file to the faild analysis directory for further inspection.
							total_mails_failed += 1
							shutil.move(absolute_filename, os.path.join(analyzer_config["failed_analysis_dir"], m))
							logger.warning("Exception occurred when inserting mail into database: %s" % str(e))
							logger.warning("Failed to process %s, moved to failed analysis directory." % m)
							continue

						# Mail message metadata was successfully inserted into the database and a new domain was successfully inserted as well.
						# Now we can safely update the domain stats, but only if domain detection succeeded.
						if domain_id and mail_domain:
							inc_mails = current_incoming + 1
							mal_inc = 1 if result["potentially_malicious"] else 0
							mal_mails = current_malicious + mal_inc
							update_query = "UPDATE domains SET incoming_mails = %s,malicious_mails = %s WHERE domain = %s"
							execute_mutation_sql_query(database, update_query, (inc_mails, mal_mails, mail_domain))
						else:
							logger.warning("Receiver domain detection failed! Not updating counters. Message file: %s" % m)

						# Analyze all results in case the mail is potentially malicious.
						if result["potentially_malicious"]:
							total_malicious_mails += 1
							url_count = len(result["extracted_urls"]) if "extracted_urls" in result else 0
							btc_count = len(result["extracted_btc"]) if "extracted_btc" in result else 0
							logger.debug("Mail message: %s is flagged as potentially malicious! (%i URLs (%i total scanned), %i BTC addresses, %i attachments)" % (m, url_count, total_urls, btc_count, attachment_count))

							# Insert the mail message body into the database, in encoded form.
							if "body" in result:
								query = "INSERT INTO mail_message_bodies (mail_id,encoded_body) VALUES (%s,%s)"
								execute_mutation_sql_query(database, query, (inserted_mail_id, result["body"]))

							# If the sender IP-address is non-NULL, enqueue it for the enricher.
							if sender_ip:
								enqueue_indicator_for_enricher(database, sender_ip, inserted_mail_id)

							# Insert extracted URLs into database and link it to the main analysis row.
							if "extracted_urls" in result:
								query = "INSERT INTO extracted_urls (mail_id,url) VALUES (%s,%s)"
								for url in result["extracted_urls"]:
									# The URL field is only 2000 characters long in the database and this should be more than enough.
									# Turns out we did trigger an exception and this broke everything. So we truncate the URL
									# explicitly to 2000 characters.
									truncated_url = url
									if len(url) >= 2000:
										truncated_url = url[:1999] # To be safe, because I think MySQL counts NULL terminator as well.
									execute_mutation_sql_query(database, query, (inserted_mail_id, truncated_url))

							# Print extracted BTC addresses.
							if "extracted_btc" in result:
								query = "INSERT INTO extracted_btc (mail_id,btc) VALUES (%s,%s)"
								for btc in result["extracted_btc"]:
									execute_mutation_sql_query(database, query, (inserted_mail_id, btc))

							# Print extracted IP-addresses if any.
							if "extracted_ips" in result:
								for ip in result["extracted_ips"]:
									# Insert IP-address into database table for extracted IP-addresses.
									query = "INSERT INTO extracted_ips (mail_id,ip_address) VALUES (%s,INET_ATON(%s))"
									execute_mutation_sql_query(database, query, (inserted_mail_id, ip))

									# Schedule enrichment for the given IP address by inserting an entry with enrichers '*' into the enricher queue.
									enqueue_indicator_for_enricher(database, ip, inserted_mail_id)

							# Check the attachments in the result object and add them to the database if the mail is flagged as potentially malicious.
							if "attachments" in result:
								# Create directory with the message filename in the attachments directory. We will extract the attachments in there for the spam-classifier to work with.
								attachments_dir = os.path.join(analyzer_config["attachments_dir"], m)
								os.makedirs(attachments_dir, exist_ok=True)

								# Iterate over all attachments in the analysis result.
								attachment_counter = 1
								for attach_obj in result["attachments"]:
									# Get truncated filename if it is too long.
									attachment_filename = attach_obj["filename"] if "filename" in attach_obj else None
									if attachment_filename and len(attachment_filename) > 78:
										attachment_filename = attach_obj["filename"][:79]

									# Get the MIME type string and find it in the database.
									mime_type_res = execute_select_sql_query(database, "SELECT id FROM mime_types WHERE description = %s", (attach_obj["mime_type"],))
									if len(mime_type_res) == 1:
										mime_type_first_row = mime_type_res[0]
										mime_type_id = mime_type_first_row[0]
									else:
										# MIME type description not found, so not yet inserted into database. Let's do that now.
										query = "INSERT INTO mime_types (description) VALUES (%s)"
										mime_type_id = execute_mutation_sql_query(database, query, (attach_obj["mime_type"],)) # Weird stuff, if we leave the trailing comma out it will throw an exception...
										logger.debug("Added new MIME type: %s to database. Attachment: %s from mail message: %s has this type." % (attach_obj["mime_type"], attachment_filename, m))

									# MIME type is either inserted into the database or the correct ID has been retrieved. Now check whether the attachment with given SHA-256 hash is already in the database or it needs to be inserted.
									attachment_res = execute_select_sql_query(database, "SELECT id FROM potentially_malicious_attachments WHERE sha256_hash = X%s", (attach_obj["sha256"],))
									if len(attachment_res) == 1:
										attachment_res_first_row = attachment_res[0]
										attachment_id = attachment_res_first_row[0]
									else:
										# Attachment is new, it needs to be inserted.
										query = "INSERT INTO potentially_malicious_attachments (sha256_hash,size,mime_type_id) VALUES (X%s,%s,%s)"
										attachment_id = execute_mutation_sql_query(database, query, (attach_obj["sha256"], attach_obj["size"], mime_type_id))
										logger.debug("Inserted new attachment: %s into the database, contained in mail message: %s." % (attach_obj["sha256"], m))

									# Write the attachments with their corresponding filenames into the newly created directory in the attachments location.
									# Attachment filename can be empty or unspecified. If so, we generate a counter-based filename on disk.
									disk_attachment_filename = attach_obj["filename"] if "filename" in attach_obj else ("%s.%i" % (m, attachment_counter))

									# Attachments can also have filenames with slashes in them, and they are forbidden on Linux filesystems. Therefore, we will
									# encode these with URL encoding and replace with: '%2F'. We also store a filename of at most 128 characters (excluding null).
									# Also remove double dot patterns, replace them with an underscore.
									disk_attachment_filename = disk_attachment_filename.replace("/", "%2F").replace("..", "_")[:127]

									# Now insert a new link between the selected or inserted attachment and the current mail message entry. We specify the filename here because the same attachment can have a different (relevant) filename in different messages.
									query = "INSERT INTO mail_attachment_link (mail_id,attachment_id,filename,filename_on_disk) VALUES (%s,%s,%s,%s)"
									execute_mutation_sql_query(database, query, (inserted_mail_id, attachment_id, attachment_filename, disk_attachment_filename))

									# Write the attachment payload to disk.
									with open(os.path.join(attachments_dir, disk_attachment_filename), 'wb') as attachment_file:
										attachment_file.write(attach_obj["payload"])

									# At this point we have an attachment. If the MIME-type is not an image, schedule an upload externally.
									query = "INSERT INTO attachment_upload_queue (attachment_id,mail_id) VALUES (%s,%s)"
									execute_mutation_sql_query(database, query, (attachment_id, inserted_mail_id))

									# Increment attachment counter.
									attachment_counter += 1

							# After the analysis, we move the mail message file to the finiahed processing directory for the spam-classifier to work on. It needs to be moved away from the 'new' mail directory so the spam-analyzer will not process it again.
							shutil.move(absolute_filename, os.path.join(analyzer_config["processing_finished_dir"], m))

							# At this point, we know the mail message contains either some questionable stuff in the body or attachments.
							# We filter down further to just mails with potentially malicious attachments and if it matches, we queue it for further analysis elsewhere.
							if attachment_count > 0:
								query = "INSERT INTO upload_queue (mail_id) VALUES (%s)"
								execute_mutation_sql_query(database, query, (inserted_mail_id,))

							# With the file moved to processing finished and the metadata all in the database, we will schedule the mail message for classification.
							# We do this by inserting a row into the classifier requests table. After that, the work of the spam-analyzer is done.
							query = "INSERT INTO spam_classifier_queue (mail_id,added) VALUES (%s,%s)"
							execute_mutation_sql_query(database, query, (inserted_mail_id,ast_string))
						else:
							# Mail message is considered non-malicious after initial analysis. We don't want to pile up data we don't need and certainly don't want to invade anybody's privacy unnecessarily.
							# Therefore, we dispose of the mail message file by deleting it from disk.
							os.remove(absolute_filename)
							logger.debug("Mail message: %s was declared non-malicious by initial analysis. Deleted file from disk." % m)

			# Check whether telemetry interval has passed.
			telemetry_now = datetime.datetime.now()
			if telemetry_now >= telemetry_interval_end:
				# Get memory usage for this spam analyzer process, in bytes.
				memory_usage = process = psutil.Process(os.getpid()).memory_info().rss

				# Get CPU usage as well.
				cpu_usage_percent = psutil.cpu_percent()

				# Get free disk space for the configured disk (where sinkhole data is stored).
				total, used, free = shutil.disk_usage("/")
				disk_usage_percent = (used / total) * 100

				# Create query for inserting next telemetry entry into the database.
				telemetry_timestamp = datetime.datetime.now()
				telemetry_timestamp_string = telemetry_timestamp.strftime("%Y-%m-%d %H:%M:%S")
				average_analysis_time = total_analysis_times / total_mails_processed if total_mails_processed > 0 else 0
				query = "INSERT INTO telemetry (timestamp,mails_processed,mails_malicious,mails_failed,max_analysis_time,average_analysis_time,cpu_percent,memory_usage,disk_usage) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
				execute_mutation_sql_query(database, query, (telemetry_timestamp_string, total_mails_processed, total_malicious_mails, total_mails_failed, max_analysis_time, average_analysis_time, cpu_usage_percent, memory_usage, disk_usage_percent))

				# Reset telemetry values for the next window.
				telemetry_interval_start = 0
				telemetry_interval_end = 0
				total_mails_processed = 0
				total_malicious_mails = 0
				total_mails_failed = 0
				total_analysis_times = 0
				max_analysis_time = 0

			# Timeout of one second to avoid hugging the CPU.
			time.sleep(1)
		except KeyboardInterrupt:
			logger.info("Received SIGINT, stopping")
			break

# Exit and print statistics.
end_time = datetime.datetime.now()
logger.info("Total runtime: %f days" % ((end_time - start_time).total_seconds() / 86400))
