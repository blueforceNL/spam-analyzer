import os
import urllib3
from minio import Minio
import mysql.connector
import datetime
from analyzer_config import load_or_create_config

# ----------------------------------------------------------|
# Variables such as credentials. Placed them here for now   |
# since this would be a cron job instead of a daemon.       |
# ----------------------------------------------------------|

MINIO_HOST = '<change_me>'
MINIO_ACCESS_KEY_ID = '<change_me>'
MINIO_SECRET_KEY = '<change_me>'
MINIO_BUCKET_NAME = '<change_me>'
MINIO_CERT_PATH = '/opt/spam-analyzer/minio.crt'

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

# Get base directory of mails for which initial processing has finished.
mail_base_dir = analyzer_config["processing_finished_dir"]

# Extract entries from the MinIO queue in the database. Select at most 60 entries, which would be one per five seconds if the job runs once every five minutes.
queue_result = execute_select_sql_query(database, "SELECT upload_queue.id,filename,upload_queue.mail_id FROM upload_queue JOIN analyzed_mail ON analyzed_mail.id = upload_queue.mail_id LIMIT 50")

# Check whether at least one entry is there to be uploaded. If there is nothing, we don't need to open a connection either.
if len(queue_result) > 0:
	print("INFO (%s): Connecting to MinIO..." % date_time)

	# Create custom HTTP client with path pointing to the certificates. If we don't specify the certificate explicitly it might not work well.
#	http_client = urllib3.PoolManager(cert_reqs='CERT_NONE')
	http_client = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=MINIO_CERT_PATH)

	# Open connection to the MinIO via S3.
	client = Minio(MINIO_HOST, access_key=MINIO_ACCESS_KEY_ID, secret_key=MINIO_SECRET_KEY, secure=True, http_client=http_client)

	# Process the entries in the queue for upload.
	for queue_entry in queue_result:
		# Get full path to mail file.
		filename = queue_entry[1]
		mail_path = os.path.join(mail_base_dir, filename)
		mail_id = queue_entry[2]
		entry_id = queue_entry[0]

		# Check whether the file still exists at this point.
		if not os.path.exists(mail_path):
			# Remove this entry from the queue.
			execute_mutation_sql_query(database, "DELETE FROM upload_queue WHERE id = %s", (entry_id,))

			# Print a nice friendly message about this situation.
			print("INFO (%s): Message file: %s for mail ID: %i does not exist anymore, so nothing to do here." % (date_time, mail_path, mail_id))
			continue

		# Upload the file referenced in the queue into the specified bucket. From there it will be taken by AssemblyLine.
		# We just assume the bucket is there because we are not allowed to read.
		try:
			result = client.fput_object(MINIO_BUCKET_NAME, filename, mail_path)
			print("INFO (%s): Mail ID: %i, created object: %s, etag: %s, version-id: %s" % (date_time, mail_id, result.object_name, result.etag, result.version_id))

			# Delete this entry from the queue.
			execute_mutation_sql_query(database, "DELETE FROM upload_queue WHERE id = %s", (entry_id,))

			# Update the analyzed mail table and flag this mail ID as processed.
			execute_mutation_sql_query(database, "UPDATE analyzed_mail SET upload_processed = 1 WHERE id = %s", (mail_id,))
		except urllib3.exceptions.MaxRetryError:
			print("ERROR (%s): SSL certificate verification error! Has the certificate changed?" % date_time)
			exit(1)
else:
	print("INFO (%s): Nothing to do, no new entries found in spam-analyzer database." % date_time)
