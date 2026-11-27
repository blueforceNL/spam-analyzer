# ---------------------------------------------------|
# Database construction file for spam trap software. |
# Create the database before running the tools.      |
# ---------------------------------------------------|

# Create table for tracking analyzer runs, when, which version etc.
CREATE TABLE analyzer_runs(
	id INT NOT NULL AUTO_INCREMENT,
	timestamp TIMESTAMP NOT NULL,
	version INT NOT NULL,
	PRIMARY KEY(id)
);

# Stores branch names to identify possible branch-specific spam.
CREATE TABLE branches(
	id INT NOT NULL,
	name VARCHAR(64),
	PRIMARY KEY(id),
	UNIQUE(name)
);

# Add branches here before referencing them from domain inserts.
INSERT INTO branches(id,name) VALUES (1,"Unknown");
INSERT INTO branches(id,name) VALUES (2,"Retail");
INSERT INTO branches(id,name) VALUES (3,"Industry");
INSERT INTO branches(id,name) VALUES (4,"Logistics");
INSERT INTO branches(id,name) VALUES (5,"Healthcare");
INSERT INTO branches(id,name) VALUES (6,"Services");
INSERT INTO branches(id,name) VALUES (7,"News");
INSERT INTO branches(id,name) VALUES (8,"Hospitality");

# Stores countries for linking to domain names, allowing us to more easily show statistics per supposed country.
CREATE TABLE countries(
	id INT NOT NULL,
	name VARCHAR(48) NOT NULL,
	tld VARCHAR(16) NOT NULL,
	PRIMARY KEY(id)
);

# Add countries for linking to domains.
INSERT INTO countries (id,name,tld) VALUES (1,"Netherlands",".nl");
INSERT INTO countries (id,name,tld) VALUES (2,"France",".fr");
INSERT INTO countries (id,name,tld) VALUES (3,"Sweden",".se");

# Keeps track of all API keys allowed in the spam analyzer API.
CREATE TABLE api_keys(
	id INT NOT NULL AUTO_INCREMENT,
	api_key VARCHAR(64),
	description TEXT,
	contact TEXT,
	PRIMARY KEY(id),
	UNIQUE(api_key)
);

# The API interface allows external tools like threat intelligence platforms to pull information from the database.
# We must do this statefully in order to maintain efficiency and therefore, we have to keep a state.
# This state determines when new entries are inserted so a new pull at the API does not return old stuff.
# We only want to return incrementally. Since every row in this table represents a log entry of somebody calling
# a tracked API endpoint, we store some additional information about the connection as well.
CREATE TABLE api_state(
	id INT NOT NULL AUTO_INCREMENT,
	state INT UNSIGNED NOT NULL,
	created TIMESTAMP NOT NULL,
	PRIMARY KEY(id),
	UNIQUE(state)
);

# Insert first state, as we must have one to reference in other tables.
INSERT INTO api_state (state,created) VALUES (1,NOW());

# Create a table that links the API (system) state to the API-key-based states. Every API key pulls at its own pace.
CREATE TABLE api_state_key_link(
	id INT NOT NULL AUTO_INCREMENT,
	api_state_id INT NOT NULL,
	api_key_id INT NOT NULL,
	src_ip INT UNSIGNED,
	user_agent TEXT,
	url TEXT,
	prev_state_id INT,
	PRIMARY KEY(id),
	FOREIGN KEY(api_key_id) REFERENCES api_keys(id),
	FOREIGN KEY(api_state_id) REFERENCES api_state(id),
	FOREIGN KEY(prev_state_id) REFERENCES api_state(id)
);

# Keeps track of the number of queries performed per API key per day.
CREATE TABLE api_key_requests_log(
	id INT NOT NULL AUTO_INCREMENT,
	api_key_id INT NOT NULL,
	tracked_date DATETIME,
	requests INT UNSIGNED,
	PRIMARY KEY(id),
	FOREIGN KEY(api_key_id) REFERENCES api_keys(id)
);

# Stores a list of domains for which we have seen incoming mail. Add sinkholed domains using INSERT statements below.
# Non-sinkholed domains for which we did receive mail are inserted or updated upon processing.
CREATE TABLE domains(
	id INT NOT NULL AUTO_INCREMENT,
	domain VARCHAR(64) NOT NULL,
	sinkholed TINYINT NOT NULL,
	added TIMESTAMP NOT NULL,
	removed TIMESTAMP,
	country_id INT,
	branch_id INT,
	incoming_mails INT NOT NULL,
	malicious_mails INT NOT NULL,
	PRIMARY KEY(id),
	FOREIGN KEY(branch_id) REFERENCES branches(id),
	UNIQUE(domain)
);

# Add sinkholed domains, by setting 'sinkholed' to 1. Since this list doesn't change often we keep it in the Git repository.
# INSERT INTO domains (domain,sinkholed,added,country_id,branch_id,incoming_mails,malicious_mails) VALUES ("example.com",1,"2026-07-21",1,3,0,0);

# Stores an entry for every mail analyzed.
CREATE TABLE analyzed_mail(
	id INT NOT NULL AUTO_INCREMENT,
	timestamp TIMESTAMP NOT NULL,
	filename VARCHAR(48),
	md5_hash BINARY(16),
	potentially_malicious TINYINT,
	# Maximum length of sender is 320 characters if local and address parts are combined.
	sender VARCHAR(320),
	# Maximum length of subject defined by RFC2822 is 998 characters.
	subject VARCHAR(998),
	bounced_subject VARCHAR(998),
	recipient VARCHAR(128),
	mail_timestamp TIMESTAMP,
	size INT NOT NULL,
	num_attachments INT NOT NULL,
	body_length INT,
	analysis_time INT,
	domain_id INT,
	total_scanned_urls INT NOT NULL,
	sender_ip INT UNSIGNED,
	upload_processed TINYINT NOT NULL DEFAULT 0,
	PRIMARY KEY(id),
	FOREIGN KEY(domain_id) REFERENCES domains(id),
	UNIQUE(filename)
);

# Creates index on MD5 hash values so we can perform a quick lookup there.
CREATE INDEX mail_md5_hashes ON analyzed_mail (md5_hash);

# Stores mail bodies encoded in Base64. We store them in a separate table so we can easily delete bodies of mails that
# are not classified as malicious and therefore, we don't need to keep them.
CREATE TABLE mail_message_bodies(
	mail_id INT NOT NULL,
	encoded_body TEXT NOT NULL,
	PRIMARY KEY(mail_id),
	FOREIGN KEY(mail_id) REFERENCES analyzed_mail(id)
);

# Stores MIME-type strings. Because many attachments will share the descriptions we will not duplicate all that stuff.
CREATE TABLE mime_types(
	id INT NOT NULL AUTO_INCREMENT,
	description VARCHAR(256) NOT NULL,	# RFC 4288 says that maximum length including slash is 255.
	PRIMARY KEY(id),
	UNIQUE(description)
);

# Stores basic metadata about attachments extracted from potentially malicious mail messages.
# Note: mails not flagged as potentially malicious do not have their attachments stored!
CREATE TABLE potentially_malicious_attachments(
	id INT NOT NULL AUTO_INCREMENT,
	sha256_hash BINARY(32) NOT NULL,
	size INT NOT NULL,
	mime_type_id INT NOT NULL,
	PRIMARY KEY(id),
	FOREIGN KEY(mime_type_id) REFERENCES mime_types(id),
	UNIQUE(sha256_hash)
);

# Link table from mail messages to attachments. This is needed for optimal database normalization.
CREATE TABLE mail_attachment_link(
	id INT NOT NULL AUTO_INCREMENT,
	mail_id INT NOT NULL,
	attachment_id INT NOT NULL,
	filename VARCHAR(80),		# We truncate the filename after this length. https://community.spiceworks.com/topic/285003-max-character-length-for-email-attachment-name says it is a reasonable length.
	filename_on_disk VARCHAR(128) NOT NULL,
	PRIMARY KEY(id),
	FOREIGN KEY(mail_id) REFERENCES analyzed_mail(id),
	FOREIGN KEY(attachment_id) REFERENCES potentially_malicious_attachments(id)
);

# Stores URLs extracted from message bodies.
CREATE TABLE extracted_urls(
	id INT NOT NULL AUTO_INCREMENT,
	mail_id INT NOT NULL,
	url VARCHAR(2000) NOT NULL,	# URLs should not be longer than 2000 characters so we will keep it at that for now.
	PRIMARY KEY(id),
	FOREIGN KEY(mail_id) REFERENCES analyzed_mail(id)
);

# Stores Bitcoin addresses extracted from message bodies.
CREATE TABLE extracted_btc(
	id INT NOT NULL AUTO_INCREMENT,
	mail_id INT NOT NULL,
	btc VARCHAR(36) NOT NULL,	# Bitcoin addresses are by specification at most 35 characters and the regex enforces this.
	PRIMARY KEY(id),
	FOREIGN KEY(mail_id) REFERENCES analyzed_mail(id)
);

# Stores extracted IPv4 addresses from mail message bodies.
CREATE TABLE extracted_ips(
	id INT NOT NULL AUTO_INCREMENT,
	mail_id INT NOT NULL,
	ip_address INT UNSIGNED NOT NULL,
	PRIMARY KEY(id),
	FOREIGN KEY(mail_id) REFERENCES analyzed_mail(id)
);

# Stores telemetry entries for monitoring purposes.
CREATE TABLE telemetry(
	id INT NOT NULL AUTO_INCREMENT,
        timestamp TIMESTAMP NOT NULL,
	mails_processed INT NOT NULL,
	mails_malicious INT NOT NULL,
	mails_failed INT NOT NULL,
	max_analysis_time INT NOT NULL,
	average_analysis_time INT NOT NULL,
	cpu_percent FLOAT NOT NULL,
	memory_usage FLOAT NOT NULL,
	disk_usage FLOAT NOT NULL,
	PRIMARY KEY(id)
);

# Stores spam classifier requests: potentially malicious mails are to be scheduled for a spam classifier run.
# The spam-classifier has a wrapper scriptt that is triggered to pull the request and all analysis results
# associated to the corresponding mail message. All is converted to JSON for analysis in the spam classifier.
# When the spam classifier completes its analysis, the request is removed from this table.
CREATE TABLE spam_classifier_queue(
	id INT NOT NULL AUTO_INCREMENT,
	mail_id INT NOT NULL,
	added TIMESTAMP NOT NULL,
	PRIMARY KEY(id),
	UNIQUE(mail_id),
	FOREIGN KEY(mail_id) REFERENCES analyzed_mail(id)
);

# Stores possible classifier results, like families in which a particular mail falls.
CREATE TABLE mail_classifications(
	id INT NOT NULL AUTO_INCREMENT,
	name VARCHAR(32) NOT NULL,
	description VARCHAR(128),
	store_message_file TINYINT NOT NULL,
	PRIMARY KEY(id),
	UNIQUE(name)
);

# Implemented classifications in the classifier. They must be present in the database beforehand.
INSERT INTO mail_classifications (name,description,store_message_file) VALUES ("scam_generic","Common Bitcoin scam mails about hacked accounts or fake blackmail",0);
INSERT INTO mail_classifications (name,description,store_message_file) VALUES ("advertisement","Collection of unwanted advertisement mails, for example about viagra",0);
INSERT INTO mail_classifications (name,description,store_message_file) VALUES ("heuristic","Detection of spam mails using heuristics and scoring",0);

# Stores links between a mail message and a classifier detection.
CREATE TABLE mail_classifications_link(
	id INT NOT NULL AUTO_INCREMENT,
	mail_id INT NOT NULL,
	classification_id INT NOT NULL,
	confidence TINYINT UNSIGNED NOT NULL,
	added_state INT UNSIGNED NOT NULL,
	version INT NOT NULL,
	PRIMARY KEY(id),
	FOREIGN KEY(mail_id) REFERENCES analyzed_mail(id),
	FOREIGN KEY(classification_id) REFERENCES mail_classifications(id),
	FOREIGN KEY(added_state) REFERENCES api_state(state),
	CONSTRAINT confidence_bounds CHECK (confidence < 101)
);

# Attributes linked to a classification entry.
CREATE TABLE linked_attributes(
	id INT NOT NULL AUTO_INCREMENT,
	classifications_link_id INT NOT NULL,
	attributes JSON,
	PRIMARY KEY(id),
	FOREIGN KEY(classifications_link_id) REFERENCES mail_classifications_link(id)
);

# Stores indicator types. We need this to normalize type references in the indicators table.
CREATE TABLE indicator_types(
	id INT NOT NULL AUTO_INCREMENT,
	type VARCHAR(32),
	PRIMARY KEY(id),
	UNIQUE(type)
);

# Insert basic indicator types into the previously created table.
INSERT INTO indicator_types(type) VALUES ("domain");
INSERT INTO indicator_types(type) VALUES ("url");
INSERT INTO indicator_types(type) VALUES ("btc");
INSERT INTO indicator_types(type) VALUES ("ip");
INSERT INTO indicator_types(type) VALUES ("iban");
INSERT INTO indicator_types(type) VALUES ("phone");

# Stores indicators that can be referenced by multiple classification links.
CREATE TABLE indicators(
	id INT NOT NULL AUTO_INCREMENT,
	indicator_type_id INT NOT NULL,
	value TEXT,
	PRIMARY KEY(id),
	FOREIGN KEY(indicator_type_id) REFERENCES indicator_types(id)
);

# Links one or more indicators to a classification link.
CREATE TABLE indicator_classification_link(
	id INT NOT NULL AUTO_INCREMENT,
	classifications_link_id INT NOT NULL,
	indicator_id INT NOT NULL,
	confidence TINYINT NOT NULL,
	PRIMARY KEY(id),
	FOREIGN KEY(classifications_link_id) REFERENCES mail_classifications_link(id),
	FOREIGN KEY(indicator_id) REFERENCES indicators(id),
	CONSTRAINT indicator_confidence_bounds CHECK (confidence < 101)
);

# Represents a queue of mail files to be sent to an external application for analysis.
CREATE TABLE upload_queue(
	id INT NOT NULL AUTO_INCREMENT,
	mail_id INT NOT NULL,
	PRIMARY KEY(id),
	FOREIGN KEY(mail_id) REFERENCES analyzed_mail(id)
);

# Represents a queue of attachments to be sent to external parties.
CREATE TABLE attachment_upload_queue(
	id INT NOT NULL AUTO_INCREMENT,
	attachment_id INT NOT NULL,
	mail_id INT NOT NULL,
	PRIMARY KEY(id),
	FOREIGN KEY(attachment_id) REFERENCES potentially_malicious_attachments(id),
	FOREIGN KEY(mail_id) REFERENCES analyzed_mail(id)
);

# This table contains the queue for enrichment requests. Since determining the type of
# indicator is the responsibility of the enricher, we just add text fields here.
CREATE TABLE enricher_queue(
	id INT NOT NULL AUTO_INCREMENT,
	added TIMESTAMP NOT NULL,
	indicator TEXT NOT NULL,
	checksum INT UNSIGNED NOT NULL,
	mail_id INT, # This field may be NULL because manually added indicators will not have one associated.
	enrichers TEXT NOT NULL,
	PRIMARY KEY(id),
	FOREIGN KEY(mail_id) REFERENCES analyzed_mail(id)
);

# Creates index on checksum so we can perform a quick lookup there.
ALTER TABLE enricher_queue ADD INDEX (checksum);

# This table contains inactive queue entries. When the quota for a specific enricher is used for the day, the
# enricher will loop the mnain queue forever and places inactive entries at the back of the queue until it reaches
# them again. This situation will give unnecessary overhead at scale and therefore, we place inactive entries in
# the inactive queue. Once the quota has been reset for the day, the enricher will move back the top 'quota' entries
# to the primary queue for processing.
CREATE TABLE inactive_enricher_queue(
	id INT NOT NULL AUTO_INCREMENT,
	added TIMESTAMP NOT NULL,
	indicator TEXT NOT NULL,
	checksum INT UNSIGNED NOT NULL,
	mail_id INT, # This field may be NULL because manually added indicators will not have one associated.
	enrichers TEXT NOT NULL,
	PRIMARY KEY(id),
	FOREIGN KEY(mail_id) REFERENCES analyzed_mail(id)
);

# Creates index on checksum so we can perform a quick lookup there.
ALTER TABLE inactive_enricher_queue ADD INDEX (checksum);

# Table that stores up-to-date quotas and other metadata for enrichment sources.
# This table is updated on every request performed.
CREATE TABLE enricher_state(
	id INT NOT NULL AUTO_INCREMENT,
	name VARCHAR(64) NOT NULL,
	quota INT NOT NULL,
	last_request TIMESTAMP,
	status_code INT,
	last_quota_reset TIMESTAMP,
	PRIMARY KEY(id),
	UNIQUE(name)
);

# Table to store VPNAPI.io enrichment results.
CREATE TABLE vpnapi(
	id INT NOT NULL AUTO_INCREMENT,
	response_time TIMESTAMP NOT NULL,
	ip_address INT UNSIGNED NOT NULL,
	vpn TINYINT NOT NULL,
	proxy TINYINT NOT NULL,
	tor TINYINT NOT NULL,
	relay TINYINT NOT NULL,
	city VARCHAR(64),
	region VARCHAR(64),
	country VARCHAR(64),
	continent VARCHAR(64),
	region_code VARCHAR(4),
	country_code VARCHAR(4),
	continent_code VARCHAR(4),
	latitude FLOAT,
	longitude FLOAT,
	time_zone VARCHAR(64),
	locale_code VARCHAR(4),
	metro_code VARCHAR(4),
	is_in_european_union TINYINT,
	network VARCHAR(20),
	asn VARCHAR(16),
	as_org TEXT,
	PRIMARY KEY(id)
);

# Creates index on IP address so we can perform a quick lookup there.
ALTER TABLE vpnapi ADD INDEX (ip_address);

# Table to store IPIntel enrichment results.
CREATE TABLE ipintel(
	id INT NOT NULL AUTO_INCREMENT,
	response_time TIMESTAMP NOT NULL,
	ip_address INT UNSIGNED NOT NULL,
	value FLOAT NOT NULL,
	PRIMARY KEY(id)
);

# Creates index on IP address so we can perform a quick lookup there.
ALTER TABLE ipintel ADD INDEX (ip_address);

# Table to store IP2Proxy enrichment results.
CREATE TABLE ip2proxy(
	id INT NOT NULL AUTO_INCREMENT,
	response_time TIMESTAMP NOT NULL,
	ip_address INT UNSIGNED NOT NULL,
	proxy_type VARCHAR(8),
	country_code VARCHAR(4),
	country_name VARCHAR(128),
	PRIMARY KEY(id)
);

# Creates index on IP address so we can perform a quick lookup there.
ALTER TABLE ip2proxy ADD INDEX (ip_address);
