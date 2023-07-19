import sys


text=sys.argv[1]

from shodan import Shodan
api = Shodan('<INSERT API KEY>')

for banner in api.search_cursor('http.title:text'):
	print(banner)
