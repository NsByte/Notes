import sys

cracked_input=sys.argv[1]
hash_list=sys.argv[2]
sort=sys.argv[3]

with open(cracked_input) as f:
	content_cracked = f.read().splitlines()
with open(hash_list) as f:
	content_hash = f.read().splitlines()

for line in content_cracked:
	array = line.split(':')
	c_hash = str(array[0])
	c_found= str(array[1])
	for line in content_hash:
		username = line.split()[0]
		for word in line.split():
			if sort == str(1):
				if str(word) == c_hash:
					print str(username) + ":" + str(c_found) 
			if sort == str(2):
				if str(word) == c_hash:
					print str(username) + "&password=" + str(c_found) 
			else:
				if str(word) == c_hash:
					print str(c_found) + ":" + str(username) 