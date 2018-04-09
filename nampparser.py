from libnmap.parser import NmapParser
nmap_report = NmapParser.parse_fromfile(r'/root/Desktop/mega38224')
for i in nmap_report.hosts:
	port = []
	for j in i.get_open_ports():
		port.append(str(j[0]))
	print(i.address,",".join(port))
