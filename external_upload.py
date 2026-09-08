import os
import mysql.connector
import datetime
import requests
import time
from analyzer_config import load_or_create_config

# ----------------------------------------------------------|
# Variables such as credentials. Placed them here for now   |
# since this would be a cron job instead of a daemon.       |
# ----------------------------------------------------------|

UPLOAD_API_URL = 'FIXME'
UPLOAD_API_TOKEN = 'FIXME'

# ----------------------------------------------------------|
# Database functions.                                       |
# ----------------------------------------------------------|

# Executes a mutation query (INSERT, UPDATE, etc) to the MySQL database server.
def execute_mutation_sql_query(db, q, params):
	cursorObject = db.cursor()
	cursorObject.execute(q, params)
	db.commit()
	return cursorObject.lastrowid

# Executes a SELECT query that returns results.
def execute_select_sql_query(db, q):
	cursorObject = db.cursor(buffered=True)
	cursorObject.execute(q)
	db.commit()
	return cursorObject.fetchall()

# Attempt connection to the MySQL database server.
def connect_mysql_database(addr, username, password, dbname):
	try:
		database = mysql.connector.connect(host=addr, user=username, passwd=password, database=dbname, connect_timeout=10)
	except mysql.connector.Error:
		return None

	# Check and print connection info.
	return database if database.is_connected() else None

# -----------------------------------------------------------

# Get current date and time.
date_time = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

# Create or load the configuration.
try:
	config_object = load_or_create_config()
	analyzer_config = config_object["ANALYZER"]
except KeyError:
	logger.error("ERROR (%s): Could not open config file, one or more required key/value pairs are missing! Review the config file and try again." % date_time)
	exit(1)

# Open database connection.
database = connect_mysql_database(analyzer_config["database_addr"], analyzer_config["database_user"], analyzer_config["database_passwd"], analyzer_config["database_name"])

# Get base directory for attachments for which initial processing has finished.
attachments_dir = analyzer_config["attachments_dir"]

# Extract entries from the DropperBox queue in the database. Select at most 60 entries, which would be one per five seconds if the job runs once every five minutes.
queue_result = execute_select_sql_query(database, "SELECT attachment_upload_queue.id,analyzed_mail.filename,mail_attachment_link.filename,filename_on_disk,mime_types.description FROM attachment_upload_queue JOIN analyzed_mail ON analyzed_mail.id = attachment_upload_queue.mail_id JOIN mail_attachment_link ON mail_attachment_link.attachment_id = attachment_upload_queue.attachment_id AND mail_attachment_link.mail_id = attachment_upload_queue.mail_id JOIN potentially_malicious_attachments ON potentially_malicious_attachments.id = attachment_upload_queue.attachment_id JOIN mime_types ON mime_types.id = mime_type_id LIMIT 10")

# Check whether at least one entry is there to be uploaded. If there is nothing, we don't need to open a connection either.
if len(queue_result) > 0:
	# Process the entries in the queue for upload.
	for queue_entry in queue_result:
		# Get full path to mail file.
		entry_id = queue_entry[0]
		mail_filename = queue_entry[1]
		attachment_filename = queue_entry[2]
		attachment_filename_on_disk = queue_entry[3]
		mime_type = queue_entry[4]

		# Filter out anything that is not Windows executables.
		if mime_type != "application/x-dosexec" and mime_type != "application/octet-stream":
			print("INFO (%s): Found attachment in queue with MIME-type: %s. Skipping." % (date_time, mime_type))
			execute_mutation_sql_query(database, "DELETE FROM attachment_upload_queue WHERE id = %s", (entry_id,))
			continue

		# Constructt path to payload on disk locally.
		attachment_path = os.path.join(attachments_dir, mail_filename, attachment_filename_on_disk)

		# Test whether the file actually exists, to see if we constructed it correctly.
		if not os.path.exists(attachment_path):
			# Remove this entry from the queue.
			execute_mutation_sql_query(database, "DELETE FROM attachment_upload_queue WHERE id = %s", (entry_id,))

			date_time = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
			print("ERROR (%s): Attachment at: %s does not exist!" % (date_time, attachment_path))
			continue

		# Still here, so upload the file externally.
		try:
			with open(attachment_path, 'rb') as f_handle:
				# Perform the POST request to submit the file.
				headers = { "Authorization": UPLOAD_API_TOKEN }
				file_descriptor = { "file" : ( attachment_filename_on_disk, f_handle, mime_type ) }
				response = requests.post(UPLOAD_API_URL, files=file_descriptor, headers=headers)

				# Check the resonse code from the server.
				if response.status_code != 200:
					# When an error is encountered, we will stop processing this time.
					date_time = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
					print("ERROR (%s): Server responded with status code: %i!" % (date_time, response.status_code))
					break

				# Still here, so the entry is submitted successfully and can be removed from the queue.
				execute_mutation_sql_query(database, "DELETE FROM attachment_upload_queue WHERE id = %s", (entry_id,))
				date_time = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
				print("INFO (%s): Attachment: %s successfully uploaded!" % (date_time, attachment_filename))
		except requests.exceptions.ConnectionError:
			date_time = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
			print("ERROR (%s): Connection to %s failed! Is the endpoint reachable?" % (date_time, UPLOAD_API_URL))
			break

		# Back off, give the API endpoint some time.
		time.sleep(5)
else:
	print("INFO (%s): Nothing to do, no new entries found in spam-analyzer database." % date_time)

# Check how many entries remain in the queue.
queue_result = execute_select_sql_query(database, "SELECT COUNT(*) FROM attachment_upload_queue")
count_entry = queue_result[0]
print("INFO (%s): %i entries remaining in queue." % (date_time, count_entry[0]))
