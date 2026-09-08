import os
import glob
import shutil

ROOT_DIR = "/tmp/drukwerk"
TARGET_DIR = "/sinkhole/drukwerk"

# Iterate through the root directory recursively to identify all files.
query = os.path.join(ROOT_DIR, '**/*')
i = 0
for filename in glob.glob(query, recursive = True):
	# Skip everything that is not a file.
	if not os.path.isfile(filename):
		continue

	# Create renamed filename.
	i += 1
	renamed = os.path.join(TARGET_DIR, "drukwerk.%i" % i)

	# Move the file to the spam-analyzer root directory for processing.
	shutil.move(filename, renamed)
	print("INFO: Renamed %s to %s" % (filename, renamed))
