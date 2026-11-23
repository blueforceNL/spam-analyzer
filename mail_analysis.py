# ----------------------------------------------------------|
# Mail analysis component, procedures to parse messages.    |
# ----------------------------------------------------------|

import email
import magic
import re
import tldextract
import hashlib
import base64
import ipaddress
from urllib.parse import urlparse

# The mail headers normally include a charset but this may either not be available in Python, or not work for some reason.
# Therefore, we define a default fallback charset which we will use in case the specified one fails.
DEFAULT_BODY_CHARSET = "latin-1"

# A list of mime types for attachments we will filter regardless of any specific content.
potentially_malicious_mime_types = [
	"application/msword",
	"application/vnd.ms-excel",
	"application/vnd.ms-excel.addin.macroEnabled.12",
	"application/vnd.ms-excel.sheet.binary.macroEnabled.12",
	"application/vnd.ms-excel.sheet.macroEnabled.12",
	"application/vnd.ms-excel.template.macroEnabled.12",
	"application/vnd.ms-fontobject",
	"application/vnd.ms-powerpoint",
	"application/vnd.ms-powerpoint.addin.macroEnabled.12",
	"application/vnd.ms-powerpoint.presentation.macroEnabled.12",
	"application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
	"application/vnd.ms-powerpoint.template.macroEnabled.12",
	"application/vnd.ms-word.document.macroEnabled.12",
	"application/vnd.ms-word.template.macroEnabled.12",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation",
	"application/vnd.openxmlformats-officedocument.presentationml.template",
	"application/vnd.openxmlformats-officedocument.presentationml.slideshow",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.template",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.template",
	"application/vnd.ms-htmlhelp",
	"application/vnd.rar",
	"application/vnd.visio",
	"application/x-dosexec",
	"application/x-sh",
	"application/zip",
	"application/x-rar-compressed",
	"application/octet-stream",
	"application/onenote",
	"application/pdf",
	"application/x-msdownload",
	"application/javascript",
	"application/x-iso9660-image",
	"application/x-ms-shortcut",
	"text/x-script.python",
	"text/x-shellscript",
	"text/javascript",
	"text/html",
]

# Analyzes an attachment in an incoming email and returns the analysis result dictionary.
def analyze_attachment(attachment_bytes):
	# Use the magic library to identify the attachment file type and see if we want to process it further.
	mime_type = magic.from_buffer(attachment_bytes, mime=True)

	# Create initial result object and set mime type.
	result = {}
	result["mime_type"] = mime_type

	# Compute SHA256 hash of attachment and store it in the result.
	result["sha256"] = hashlib.sha256(attachment_bytes).hexdigest()

	# Check whether the MIME type of the attachment is one that we consider potentially malicious and want to analyze further.
	if mime_type in potentially_malicious_mime_types:
		# Files in the potentially malicious mime types list are always submitted for analysis in the sandbox.
		result["requires_analysis"] = True
	else:
		# MIME type is not one of the specified, so we flag the attachment as it does not need any further analysis.
		result["requires_analysis"] = False

	return result

# Scans message body for Bitcoin addresses in conjunction with Bitcoin or BTC being mentioned.
def scan_body_for_btc_addrs(body):
	# First check whether BTC or Bitcoin is mentioned (case-insensitive).
	btc_addresses = set()
	canonicalized_body = str(body).lower()
	if ("btc" in canonicalized_body or "bitcoin" in canonicalized_body) and (" wallet" in canonicalized_body or " address" in canonicalized_body):
		# Scan for Bitcoin addresses using regex from: https://stackoverflow.com/questions/21683680/regex-to-match-bitcoin-addresses.
		btc_regex = r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"
		matches = re.findall(btc_regex, body)

		# Iterate over the matches we have.
		for btc in matches:
			# Filter out accidental Base64 matches with padding at the end.
			if not btc.endswith("="):
				btc_addresses.add(btc)

	return btc_addresses

# Scans message body for URLs.
def scan_body_for_urls(body, dnsfilter_domain_rankings):
	# Scan for URLs in the message body (only returns URLs prefixed with http or https.
	url_regex = r"\b((?:https?://)(?:(?:www\.)?(?:[\da-z\.-]+)\.(?:[a-z]{2,6})|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))(?::[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?(?:/[\w\.-]*)*/?)\b"
	matches = re.findall(url_regex, body)

	# Look up all matches in the DNSFilter domain ranking and filter out any URLs having a domain that is on the list.
	filtered_matches = set()
	total_urls = 0
	for url in matches:
		# Extract the domain from the URL.
		obj = urlparse(url)
		tld_obj = tldextract.extract(obj.netloc)
		sld = '.'.join([tld_obj.domain, tld_obj.suffix])

		# Test whether the URL actually contains a path. If not, the probability of it being malicious is very low.
		if len(obj.path) > 0:
			# Look up the parsed domain name on the DNSFilter domain ranking and filter it out from the matches if found.
			if sld not in dnsfilter_domain_rankings:
				# Passed filtering, add the URL to the database.
				filtered_matches.add(url)

		# Track the total number URLs as well.
		total_urls += 1

	return (filtered_matches, total_urls)

# Scans a given string for IPv4 addresses.
def scan_body_for_ipv4_addresses(body):
	# Get all IPv4 addresses from the body.
	ipv4_regex = r"[12]?[0-9]{1,2}\.[12]?[0-9]{1,2}\.[12]?[0-9]{1,2}\.[12]?[0-9]{1,2}"
	matches = re.findall(ipv4_regex, body)

	# Iterate over the matches and filter out everything that is a private IP-address.
	filtered_matches = set()
	for ip in matches:
		try:
			# Parse IP-address using subnetting library.
			ip_addr = ipaddress.ip_address(ip)

			# Test whether this IP-address is in a private network, e.g. irrelevant for us.
			if ip_addr.is_private or ip_addr.is_link_local or ip_addr.is_unspecified or ip_addr.is_multicast or ip_addr.is_reserved or ip_addr.is_loopback:
				continue

			# Still here, so we will save this address in the output.
			filtered_matches.add(ip)
		except ValueError:
			continue

	# Return filtered list of matches, but converted to a list. This way we have a nicely deduplicated list.
	return list(filtered_matches)

# Utility function to parse Content-Type and get properties.
def parse_content_type(content_type):
	# We return a dictionary containing the parsed properties.
	content_type_props = {}

	# Strip any irrelevant characters from the Content-Type to avoid parsing problems.
	stripped_content_type = content_type.replace('"', '').replace('\n', '').replace(' ', '').replace('\t', '')
	ct_fields = stripped_content_type.split(';')
	for field in ct_fields:
		# Check if the field can be split even further using '='.
		if '=' in field:
			k_v = field.split('=')
			if len(k_v) == 2:
				content_type_props[k_v[0].lower()] = k_v[1].lower()
		elif len(field.split('/')) == 2:
			content_type_props["mime_type"] = field.lower()
	return content_type_props if len(content_type_props) > 0 else None

# Detects a bounced mail message based on its subject.
def is_bounced_undeliverable(subject):
	lower_subject = str(subject).lower()
	return True if (lower_subject.startswith("undeliverable:") or lower_subject.startswith("undelivered") or lower_subject.startswith("mail delivery failed")
		or lower_subject.startswith("returned mail:") or lower_subject == "delivery status notification (failure)"
		or lower_subject == "failure notice" or lower_subject.startswith("delivery failure") or lower_subject == ""
		or lower_subject == "successful mail delivery report" or lower_subject.startswith("delivery Notification:")
		or lower_subject == "delivery failure notification" or lower_subject == "permanent error") else False

# Decodes a mail message body or body part.
def decode_message_body_part(part, charset):
	# Decode and extract the payload from the part. If we encounter an empty part, we can ignore the contents.
	body_part_raw = part.get_payload(decode=True)
	if body_part_raw is None:
		return None

 	# Get decoded payload and convert.
	try:
		return (body_part_raw, body_part_raw.decode(charset))
	except (UnicodeDecodeError, LookupError):
		# We encountered an unknown encoding in the mail headers. Try to decode it in default 8-bit or fail if it doesn't work.
		try:
			return (body_part_raw, body_part_raw.decode(DEFAULT_BODY_CHARSET)) # Latin-1 works in more cases than UTF-8 does!
		except (UnicodeDecodeError, LookupError):
			return None

# Parses a multipart email message. We can do this recursively because a multipart message might contains another multipart message.
def parse_multipart_message(message, bounced):
	attachments = []
	message_body = ""
	raw_message_body = bytearray()
	bounced_subject = None
	contains_html = False
	for part in message.walk():
		# Check whether this part is an attachment or not.
		ctype = part.get_content_type()
		cdispo = str(part.get('Content-Disposition'))
		if 'attachment' in cdispo:
			# Get the attachment file as bytes for analysis.
			attachment_bytes = part.get_payload(decode=True)

			# Perform initial analysis on attachment to decide whether it is malicious.
			if attachment_bytes is None:
				continue
			attachment_result = analyze_attachment(attachment_bytes)

			# Add some basic metadata to the attachment.
			attachment_result["size"] = len(attachment_bytes)
			attachment_result["payload"] = attachment_bytes

			# Store the attachment filename if specified.
			attachment_filename = part.get_filename()
			if attachment_filename is not None:
				attachment_result["filename"] = str(email.header.make_header(email.header.decode_header(attachment_filename)))

			# Add processed attachment information to result object.
			attachments.append(attachment_result)
		else:
			# For now we will construct the body from multipart a message by concatenating all text/plain and text/html parts (decoded).
			# Inline pictures will be skipped for now, but FIXME for later is to see how we should do this right.
			content_type = str(part.get("Content-Type"))
			content_type_props = parse_content_type(content_type)
			if content_type_props is not None and "mime_type" in content_type_props:
				if content_type_props["mime_type"] == "text/plain" or content_type_props["mime_type"] == "text/html":
					# Obtain charset from content type if applicable.
					charset = "utf-8"
					if "charset" in content_type_props:
						charset = content_type_props["charset"]

					# Decode the message body part.
					decoded_part = decode_message_body_part(part, charset)
					if decoded_part is None:
						# Failed to decode, return a parse failure for further investigation.
						return False

					# Append the decoded payload to the (raw) message body.
					raw_message_body.extend(decoded_part[0])
					message_body += decoded_part[1]

					# Keep track of any HTML parts in the body.
					if content_type_props["mime_type"] == "text/html":
						contains_html = True
				elif content_type_props["mime_type"] == "message/rfc822":
					# A message is attached. If the subject of the parent mail indicates a bounced one, we will extract the subject from this mail and store it as well.
					if bounced:
						orig_subject_matches = re.findall(r'\n[sS]ubject: (.*?)\r?\n', str(part))
						if len(orig_subject_matches) > 0:
							bounced_subject = orig_subject_matches[0]

				elif content_type_props["mime_type"][:5] == "text":
					# Unknown but plaintext body part, let's investigate this further if it happens.
					return False

	# Successfully came to the end of the analysis, so we will return all that came out here in a tuple.
	return (message_body, raw_message_body, attachments, bounced_subject, contains_html)

# Main mail analysis function.
def analyze_mail_message(msg_bytes, dnsfilter_domain_rankings, total_num_url_threshold):
	# Parse mail message from input bytes.
	message = email.message_from_bytes(msg_bytes)

	# Get content type for the message body. If there are non-ascii characters in any header, we need to know the charset to decode successfully.
	message_content_type = str(message.get("Content-Type"))
	message_content_type_props = parse_content_type(message_content_type)
	message_charset = "utf-8"
	if message_content_type_props is not None:
		# Obtain charset from content type if applicable.
		if "charset" in message_content_type_props:
			message_charset = message_content_type_props["charset"]

	# Create result object with basic metadata and store the recipient of the mail.
	# We start with the verdict benign, and try to prove otherwise.
	result = {}
	result["size"] = len(msg_bytes)
	result["potentially_malicious"] = False

	# Check whether the X-Original-To actually contains a value because if it is None, this will crash the analyzer.
	if message["X-Original-To"]:
		result["recipient"] = str(email.header.make_header(email.header.decode_header(message["X-Original-To"])))
	elif message["To"]:
		# In the rare case that the X-Original-To does not exist, lets just try the 'To' header instead.
		result["recipient"] = str(email.header.make_header(email.header.decode_header(message["To"])))
	else:
		# Safe in the rare case that this should happen.
		result["recipient"] = ""

	# Attempt to extract the IPv4 address of the sender. Only IPv4 because the spam trap does not support IPv6.
	if "Received" in message:
		sender_line = message["Received"].split(',')
		if len(sender_line) > 0:
			matches = re.search("((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", sender_line[0])
			if matches:
				# Extract the match from the received line.
				sender_ip = matches.group(0)

				# Test whether this is actually a valid IP-address by loading it into an ipaddress object.
				try:
					addr = ipaddress.ip_address(sender_ip)
					result["sender_ip"] = str(addr)
				except:
					# The sender IP address would be nice but it is not mandatory. Just pass if the extraction and validation fails.
					pass

	# Obtain the sender of the mail. if the 'From' header is not present, use the 'Return-Path' instead.
	if "From" in message:
		result["sender"] = str(email.header.make_header(email.header.decode_header(message["From"])))
	elif "X-Mail-From" in message:
		result["sender"] = str(email.header.make_header(email.header.decode_header(message["X-Mail-From"])))
	elif "Return-Path" in message:
		result["sender"] = str(email.header.make_header(email.header.decode_header(message["Return-Path"])))
	else:
		# No information pertaining to the potential sender email address could be found.
		# Not sure what breaks if the sender isn't present in the output so keep it empty for now.
		result["sender"] = ""

	# Parse and decode subject header, which is sometimes missing or contains non-ascii characters.
	if message["Subject"] is not None:
		# First extract the subject and encoding. Most of the time it will work just fine, but every now and then an invalid UTF-8
		# subject will come by and the mail will fail to parse. In this case, we will catch the exception and use ISO-8859-1 instead.
		# Might not yield the right results for the subject, but it will make sure we will get all other information in the mail stored.
		subj = email.header.decode_header(message["Subject"])
		try:
			result["subject"] = str(email.header.make_header(subj))
		except UnicodeDecodeError:
			subj[0] = (subj[0][0], "iso-8859-1")
			result["subject"] = str(email.header.make_header(subj))
	else:
		result["subject"] = ""

	# Parse the date if possible: mail clients are free to do whatever they want with this field so if it is incorrect, we will ignore it.
	try:
		result["date"] = email.utils.parsedate_to_datetime(message["Date"])
	except (ValueError, TypeError):
		result["date"] = None

	# Try to detect whether the mail is bounced for being undeliverable. We have much useful information in those mails but the subject
	# and other primary mail headers cannot be used as the useful stuff resides in the original mail in the body.
	result["bounced"] = True if is_bounced_undeliverable(message["Subject"]) else False

	# Walk the mail content, if multipart, all parts.
	attachments = []
	message_body = ""
	raw_message_body = bytearray()
	if message.is_multipart():
		# Parse the multipart message.
		multipart_result = parse_multipart_message(message, result["bounced"])
		if multipart_result == False:
			# Something that shouldn't go wrong went wrong. We need to investigate further.
			result["ok"] = False
			return result

		# Append the mail-wide results with the ones from this analysis.
		message_body += multipart_result[0]
		raw_message_body.extend(multipart_result[1])
		attachments.extend(multipart_result[2])

		# Set the HTML flag if applicable.
		result["body_contains_html"] = True if multipart_result[4] else False

		# If the mail was bounced, we store the bounced subject.
		if result["bounced"] and multipart_result[3]:
			result["bounced_subject"] = multipart_result[3]
	else:
		# Get content type and check whether it is HTML or plain.
		content_type = str(message.get("Content-Type"))
		content_type_props = parse_content_type(content_type)

		# The content type parse result might be None, so we have to check for this too.
		if content_type_props and "mime_type" in content_type_props and content_type_props["mime_type"] == "text/html":
			result["body_contains_html"] = True
		else:
			result["body_contains_html"] = False

		# Decode and extract the payload from the message. If we encounter an empty message, we can ignore the contents.
		body_raw = message.get_payload(decode=True)
		if body_raw:
			# Get decoded payload and convert.
			try:
				decoded_msg = body_raw.decode(message_charset)
			except (UnicodeDecodeError, LookupError):
				# We encountered an unknown encoding in the mail headers. Try to decode it in default 8-bit or fail if it doesn't work.
				try:
					decoded_msg = body_raw.decode(DEFAULT_BODY_CHARSET)
				except (UnicodeDecodeError, LookupError):
					# Failed to decode, return a parse failure for further investigation.
					result["ok"] = False
					return result

			# Append the decoded payload to the (raw) message body.
			raw_message_body.extend(body_raw)
			message_body += decoded_msg

	# If the message was detected as bounced but no subject has been found so far, it means the subject header probably resides somewere in the body.
	if result["bounced"] and "bounced_subject" not in result:
		# The message is bounced so we will try to detect the original subject of the message. This might be relevant for classification.
		# We pick the first match from the list. We will see if this will do.
		orig_subject_matches = re.findall(r'\n[sS]ubject: (.*?)\r?\n', message_body)
		if len(orig_subject_matches) > 0:
			result["bounced_subject"] = orig_subject_matches[0]

	# The database will store up to 2^16-1 characters which includes the encoding. We don't need the full body anyway in most cases
	# so we will truncate the body up till 2/3 of 2^16-1. After encoding it will fit in the database. We cap the limit to 49149 chars
	# which results in 65532 characters after encoding. One byte more will get us 3 extra bytes of padding.
	final_message_body = raw_message_body
	if len(final_message_body) > 49149:
		final_message_body = raw_message_body[:49149]

	# Store the message body and basic metadata on it. In the end, we will store the mail body in a different table in the database.
	# That way, we can easily drop the body of mail messages that are not classified as malicious.
	result["body"] = base64.b64encode(final_message_body)
	result["body_length"] = len(message_body)

	# Scan the message body for URLs we might want to use as indicators later.
	url_match_results = scan_body_for_urls(message_body, dnsfilter_domain_rankings)
	url_matches = url_match_results[0]
	result["total_scanned_urls"] = url_match_results[1]
	if len(url_matches) > 0:
		# Store extracted URLs in the result object.
		result["extracted_urls"] = url_matches

		# If we manage to extract URLs for which the domain is not in the rankings, we would like to analyze it further and therefore mark it as potentially malicious.
		# To avoid clogging the database with advertisement garbage we cap the number of URLs currently allowed to be found before ditching the mail.
		if result["total_scanned_urls"] < total_num_url_threshold:
			result["potentially_malicious"] = True

	# Scan the message body for BTC addresses in conjunction with textual occurrence of Bitcoin or BTC.
	btc_matches = scan_body_for_btc_addrs(message_body)
	if len(btc_matches) > 0:
		result["extracted_btc"] = btc_matches

		# Bitcoin addresses would make the mail at least slightly suspicious.
		result["potentially_malicious"] = True

	# Scan the message body for IP-addresses.
	result["extracted_ips"] = scan_body_for_ipv4_addresses(message_body)

	# Add attachment metadata to final results. If at least one of the attachments is flagged for further analysis it means we will store the mail message and all
	# of its attachments for this analysis. We need the full view in case it is flagged as malicious by the spam-classifier. To do so, we flag this mail analysis
	# result as potentially malicious.
	if len(attachments) > 0:
		result["attachments"] = attachments
		for attachment in attachments:
			if attachment["requires_analysis"]:
				result["potentially_malicious"] = True
				break

	# Finally, decide whether mail is malicious or not and set the status to ok.
	result["ok"] = True
	return result
