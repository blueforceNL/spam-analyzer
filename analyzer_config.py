# ----------------------------------------------------------|
# Configuration file logic for spam analyzer                |
# ----------------------------------------------------------|

from configparser import ConfigParser
import os

CONFIG_PATH = "/etc/spam-analyzer"
DEFAULT_MAIL_ROOT = "/sinkhole/new"
DEFAULT_DB_ADDR = "localhost"
DEFAULT_DB_NAME = "spam_analyzer"
DEFAULT_DB_USER = "spam-analyzer"
DEFAULT_DB_PWD = "ChangeMe"
PROCESSING_FINISHED_DIR = "/sinkhole/processing_finished"
PROCESSING_FAILED_DIR = "/sinkhole/analysis_failed"
ATTACHMENTS_DIR = "/sinkhole/attachments"
DEFAULT_TELEMETRY_INTERVAL_SECONDS = 60
DEFAULT_DNSFILTER_PATH = "DNSFilter_latest.csv"
DEFAULT_MAXIMUM_NUMBER_OF_URLS = 16
DEFAULT_ALLOW_REANALYSIS = "yes"

# Reads configuration file from the config directory.
def load_configuration_file(path):
	config_object = ConfigParser()
	config_object.read(path)
	return config_object

# Creates a new default configuration.
def create_default_configuration(path):
	# Create default configuration.
	config_object = ConfigParser()
	config_object["ANALYZER"] = {
		"mail_root" : DEFAULT_MAIL_ROOT,
		"database_addr" : DEFAULT_DB_ADDR,
		"database_name" : DEFAULT_DB_NAME,
		"database_user" : DEFAULT_DB_USER,
		"database_passwd" : DEFAULT_DB_PWD,
		"processing_finished_dir" : PROCESSING_FINISHED_DIR,
		"failed_analysis_dir" : PROCESSING_FAILED_DIR,
		"attachments_dir" : ATTACHMENTS_DIR,
		"telemetry_interval_seconds" : DEFAULT_TELEMETRY_INTERVAL_SECONDS,
		"dnsfilter_path" : DEFAULT_DNSFILTER_PATH,
		"max_number_of_urls_in_body" : DEFAULT_MAXIMUM_NUMBER_OF_URLS,
		"allow_reanalysis" : DEFAULT_ALLOW_REANALYSIS
	}

	# Write default configuration to the config directory.
	with open(path, 'w') as config_file:
		config_object.write(config_file)

	return config_object

# Gets the configuration, newly created default or loaded from disk.
def load_or_create_config():
	# Create subdirectory for the configuration if it doesn't exist.
	os.makedirs(CONFIG_PATH, exist_ok=True)

	# Load configuration file from /etc/spam-analyzer/analyzer.comf. If it doesn't exist, create a new default one.
	conf_path = os.path.join(CONFIG_PATH, "analyzer.conf")
	if os.path.exists(conf_path):
		config_object = load_configuration_file(conf_path)
	else:
		# Create default configuration.
		config_object = create_default_configuration(conf_path)

	# Get analyzer object from config.
	analyzer_config = config_object["ANALYZER"]

	# Check whether the analysis failed directory exists, and create if it does not.
	os.makedirs(analyzer_config["failed_analysis_dir"], exist_ok=True)

	# Check whether the processing finished directory exists, and create if it does not.
	os.makedirs(analyzer_config["processing_finished_dir"], exist_ok=True)

	# Check whether the attachments directory exists, and create if it does not.
	os.makedirs(analyzer_config["attachments_dir"], exist_ok=True)

	# Finally, return the config object to the caller.
	return config_object
