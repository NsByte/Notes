import hashlib
import sys

filepath=str(sys.argv[1])
with open(filepath) as fp:
   line = fp.readline()
   while line:
		regel = format(line.strip())
		line = fp.readline()
		digest = hashlib.md5(regel.encode(utf-8)).hexdigest() # 16 byte binary
		print digest
