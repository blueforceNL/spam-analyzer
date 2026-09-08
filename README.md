# Spam Analyzer

This repository contains the spam-analyzer. This component runs as a service on the spam trap and it collects and parses new mail message files stored locally by Postfix. The spam analyzer
extracts metadata from those mail messages and stores it locally in the MySQL database.

## Installing

```bash
apt-get install libmagic1 python3-pip python3-magic python3-psutil python3-tldextract libsystemd-dev python3-systemd
```

Clone the spam-analyzer Git repository and move the directory into /opt/, from where we will run it as a daemonized application. Also change the permissions from presumably root to sinkhole, the user that will run the software.
```
git clone git@github.com:blueforceNL/spam-analyzer.git
mv spam-analyzer /opt/
chown -R sinkhole:sinkhole /opt/spam-analyzer
```

Copy the systemd script from the repository into /etc/systemd/system/ to allow systemd to run the spam-analyzer as a daemon and tell systemd that the service is there.

```
cp /opt/spam-analyzer/etc/spam-analyzer.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable spam-analyzer
```

Create the config directory in /etc and copy the sample configuration there. You can also run the spam-analyzer once to have the sample configuration created.

```
mkdir /etc/spam-analyzer
cp /opt/spam-analyzer/etc/analyzer.conf.sample /etc/spam-analyzer
```

Now fill in the configuration below. Most is already correct, but the database password needs to be inserted.

```
mail_root = /sinkhole/new
database_addr = localhost
database_name = spam_analyzer
database_user = spam-analyzer
database_passwd = <change this>
failed_analysis_dir = /sinkhole/analysis_failed
processing_finished_dir = /sinkhole/processing_finished
attachments_dir = /sinkhole/attachments
telemetry_interval_seconds = 60
dnsfilter_path = DNSFilter_latest.csv
max_number_of_urls_in_body = 16
```

Create the spam-analyzer database schema with the database.sql file in the Git repository. Use the MySQL root password to log in and import the SQL database.

```
cd /opt/spam-analyzer
mysql -u root -p spam_analyzer < database.sql
```

Now we are ready to start the spam-analyzer service and check whether all is right. :)

```
systemctl start spam-analyzer
systemctl status spam-analyzer
```

## Debugging

By default, the spam-analyzer runs in production in which it is controlled by systemd. However, when a mail message could not be parsed and throws an error,
we need to examine this file closely. To do so, the spam analyzer has a debug mode that can be activated by supplying the path to the mail message as argument.

```
python3 /opt/spam-analyzer/spam_analyzer.py /sinkhole/new/<message_file_name> -v
```

If the verbose _-v_ swith is supplied, the spam-analyzer will print more output, including the body of the mail.
