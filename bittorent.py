from signal import signal,SIGPIPE,SIG_DFL
signal(SIGPIPE,SIG_DFL)
from bencoding import bdecode,bencode
import socket
import binascii
from urllib.parse import urlparse
from socket import gethostbyname
import struct
import random
import hashlib
import requests
import time
import sys
import threading
import progressbar
global BLOCK
BLOCK = 16384 #2^14 bytes (sub piece of piece)
global piece
def initialisation():
	global trackers
	trackers = []
	global files
	global torrent_file
	global peer_id
	global download_file
	peer_id ="-AZ1910-aklmnopqtrsw"
	files = []
	torrent_file = sys.argv[1]
	download_file = sys.argv[2]

def torrent_decode():
	f = open(torrent_file, "rb")
	meta_info = f.read()
	torrent = bdecode(meta_info)
	global tracker
	tracker = []
	if b'announce' in torrent:
		t = torrent[b'announce'].decode()
		tracker.append(t)
	if b'creation date' in torrent:
		date = torrent[b'creation date']
	if b'announce-list' in torrent:
		for i in torrent[b'announce-list']:
			tracker.append(i[0].decode())
	info = dict(torrent[b'info'])
	#print(tracker)
	global piece_length
	piece_length = torrent[b'info'][b'piece length']
	file_name = torrent[b'info'][b'name'].decode()
	global file_length
	file_length = 0
	if b'length' in info:
		file_length = torrent[b'info'][b'length']
	if b'comment' in torrent:
		comment = torrent[b'comment'].decode()
	global pieces
	pieces = torrent[b'info'][b'pieces']
	global pieces_no
	pieces_no = 0
	global extra_piece
	extra_piece = 0
	if(file_length > 0):
		pieces_no = file_length // piece_length
		#extra piece
		if(file_length % piece_length != 0):
			extra_piece = file_length % piece_length
			pieces_no = pieces_no + 1
			#print(file_length,piece_length,pieces_no)
	else:
		pieces_no = len(pieces) // 20
		if(len(pieces) % 20 != 0):
			pieces_no = pieces_no + 1
			extra_piece = 0
		file_length = pieces_no * piece_length
			
	sha1 = hashlib.sha1()
	sha1.update(bencode(info))
	global info_hash
	info_hash = sha1.digest()
	#print(info_hash)
	global bar
	global n
	n = file_length// BLOCK
	widgets = [' [',progressbar.Timer(format= 'elapsed time: %(elapsed)s'),'] ',progressbar.Bar('*'),' (',progressbar.ETA(), ') ',]
	bar = progressbar.ProgressBar(max_value=n,widgets=widgets).start()
	piece_info()
	which_tracker()

def piece_info():
	global piece_list
	piece_list = []
	begin = 0
	for i in range(pieces_no):
		begin = begin
		end = begin + 20
		piece = {"piece_no":0,"present":0,"piece_length":0,"blocks":0,"hash":"","data":b"","blocks_present":[]}
		piece["piece_no"] = i
		piece["hash"] = pieces[begin:end]
		begin = begin + 20
		piece_list.append(piece)
		if(i < pieces_no -1):
			piece["piece_length"] = piece_length
		else:
			piece["piece_length"] = extra_piece
		blocks_no = block(piece["piece_length"])
		piece["blocks"] = blocks_no
		
		
		
		
		
def which_tracker():
	thrd_list = []
	if(len(tracker) == 1):
		if(tracker[0][0:4] == 'http'):
			print("connecting to tracker")
			p = http_tracker_request(tracker[0])
			while(p == 'No'):
				p = http_tracker_request(tracker[0])
			http_tracker_request(tracker[0])		
		else:
			p = udp_tracker_request(tracker[0])
			while(p == 'No'):
				p = udp_tracker_request(tracker[0])

		
	elif(len(tracker) >1):
		for trk in tracker:
			#print("ok")
			if(trk[0:4] == 'http'):
				http_tracker_request(trk)
			else:
				udp_tracker_request(trk)
def http_tracker_request(trk):
	#tracker typically listen on 6881 to 6889
	#compact = 1 cient want peers with 6 bytes
	#6 =4 bytes are ip and next 2 bytes are port(network byte order)(no peer_id when compact = 1)
	#print("in http")
	peer = []
	query = {'info_hash':info_hash,
		'peer_id':peer_id,
		'uploaded':0,
		'downloaded':0,
		'event':'started',
		'left':file_length,
		'port':6881,
		'compact':1
		}
		
	try:
		response = requests.get(trk, params = query, timeout = 5)
		response = bdecode(response.content)
		#print("peers",response[b'peers'])
		peer_list = response[b"peers"]
		length = len(peer_list)
		l = 0
		#print(length)
		while(l < length):
			peers = {"peers address":[],"peers bitfield":[],"handshake":0}
			ip = socket.inet_ntoa(peer_list[:4])
			port = struct.unpack("!H",peer_list[4:6])
			peer_list = peer_list[6:]
			l = l + 6
			peers["peers address"].append((ip,port[0]))
			peer.append(peers)
		#print("http peers:",peer)
	except:
		return 'No'
	print("connetion done with tracker......")
	#print(peer)
	peer_thread(peer)


#8 byte connection_id
#4 byte action
#4 byte transaction_id	
def udp_tracker_request(trk):
	#print("in udp")
	connection_id = 0x41727101980
	action = 0
	transaction_id = int(random.randrange(0,255))
	query = struct.pack("!qll",connection_id,action,transaction_id)
	global parse
	parse = urlparse(trk)
	peer = []
	global udp_ip
	try:
		udp_ip = gethostbyname(parse.hostname)
	except:
		print("hostname no resolve")
	try:
		#print("sending")
		sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		sock.settimeout(10)
		sock.sendto(query,(udp_ip,parse.port))
		reply,addr = sock.recvfrom(1024)
	except:
		return False
	if(len(reply) < 16):
		print("Invalid response")
	#4 byte connection_id
	#4 byte transaction_id
	#8 byte connection_id(from tracker)
	#print(reply)
	action,transaction_id,connection_id = struct.unpack("!iiq",reply)
	if(action == 0):
		msg = udp_announce(connection_id)
		#print(connection_id)
		sock.settimeout(5)
		try:
			sock.sendto(msg,(udp_ip,parse.port))
			#print("sending")
			reply,addr = sock.recvfrom(2098)
			#print("reply of tracker:",reply,len(reply))
			#print("connection done udp")
		except:
			return 'No'
	udp_announce_response(reply)
	
	
	
	
def udp_announce(connection_id):
	#print(connection_id)
	action = 1
	transaction_id = int(random.randrange(0,255))
	#print(transaction_id)
	download = 0
	left = file_length
	uploaded = 0
	event = 2
	ip = 0
	key = 0
	numwant = -1
	port = 6881
	msg = struct.pack("!qii",connection_id,action,transaction_id)
	msg = msg + info_hash
	msg = msg + struct.pack("!qqqiiiiH",download,left,uploaded,event,ip,key,numwant,port)
	msg = msg + (peer_id).encode()
	return msg

def udp_announce_response(reply):
	action,transaction_id,interval,leechers,seeders = struct.unpack("!iiiii",reply[0:20])
	#print(action,transaction_id,interval,leechers,seeders)
	udp_peers_list = []
	if(action == 1):
		reply = reply[20:]
		length = len(reply)
		#print(length)
		l = 0
		while(l < length):
			ip = socket.inet_ntoa(reply[0:4])
			port = struct.unpack("!H",reply[4:6])
			peers = {"peers address":[],"peers bitfield":[],"handshake":0}
			reply = reply[6:]
			l = l + 6
			port = port[0]
			peers["peers address"].append((ip,port))
			udp_peers_list.append(peers)
		#print(udp_peers_list)
	peer_thread(udp_peers_list)

#peer state
#handshake msg <pstrlen><pstr><reserved><info_hash><peer_id> len= (49+len(pstr))
def handshake_request():
	#peer wire protocol(TCP) Version 1.0 bittorent protocol
	pstr = "BitTorrent protocol"
	pstrlen = chr(len(pstr))
	reserved = '\x00\x00\x00\x00\x00\x00\x00\x00'
	msg = pstrlen+pstr+reserved
	msg = msg.encode()
	msg = msg +info_hash
	msg = msg + (peer_id).encode()
	return msg

def peer_connection(i):
	#print("in connection peer")
	sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	try:
		sock.settimeout(15)
		#print("connecting topeer")
		sock.connect(i["peers address"][0])
		#print("connection with peer done")
	except:
		return
	msg = handshake_request()
	#print(msg)
	#print("conection done")
	try:
		sock.sendall(msg)
		#print("sending")
		reply1 = sock.recv(3000)
		time.sleep(10)
		reply2 = sock.recv(3000)
		reply = reply1+reply2
	except:
		print("No response from peer")
		return
	if(len(reply) > 0 and len(reply) > 68):
		#print(reply)
		connection,array_bin = handshake_decode(reply)
	else:
		return
	if(len(array_bin) > 0):
		if(connection == 0):
			try:
				intsed = interested()
				sock.settimeout(10)
				sock.send(intsed)
				reply = sock.recv(1024)
				#print("2",reply,len(reply))
			except:
				print("oops no hanshake")
				return
		i["peers bitfield"] = i["peers bitfield"] + array_bin
		i["handshake"] = 1
		#print(i["handshake"])
		begin = 0
		p = b''
		if(i["handshake"] == 1):
			#print(len(piece_list))
			for j in range(len(piece_list)):
				if(piece_list[j]["present"] != 1):
					l = i["peers bitfield"]
					if(j < len(l)):
						if(l[j] == '1'):
							piece_list[j]['present'] = 1
							for k in range(block(piece_list[j]["piece_length"])):
								req = request_block(j,k*BLOCK)
								sock.sendall(req)
								#print("requested")
								try:
									time.sleep(10)
									reply = sock.recv(16397)
									#print("Get reply")
									rep_msg = piece(reply)
									if(rep_msg[0]):
										p = p +rep_msg[1]
										piece_list[j]["blocks_present"].append(1)
										bar.update(1)
										#exit(0)
									else:
										piece_list[j]["blocks_present"].append(0)
								except:
									pass
							piece_list[j]["data"] = piece_list[j]["data"] + p
						'''sha1 = hashlib.sha1()
						inf = sha1.update(p)
						print(inf.digest())'''
						#print(piece_list)
def peer_thread(peer):
	t_list = []
	#print(peer)
	#peer_connection(peer[0])
	#print("Inpeers")
	for i in peer:
		t = threading.Thread(target = peer_connection,args = [i])
		t_list.append(t)
		t.start()
	for t in t_list:
		t.join()
	
def handshake_decode(reply):
	if(reply[28:48] == info_hash):
		if(len(reply)>68):
			ar = [0]*10000
			reply = reply[68:]
			#print(reply)
			len_prefix = struct.unpack("!I",reply[0:4])
			msg_id = struct.unpack("!b",reply[4:5])
			msg_id = msg_id[0]
			len_prefix = len_prefix[0]
			#print("in handshake___")
			if(len_prefix == 1 and msg_id == 1):
				have_msg = reply[5:]
				if(len(have_msg) > 0):
					#print("in hve msges")
					len_prefix = struct.unpack("!I",have_msg[0:4])
					msg_id = struct.unpack("!b",have_msg[4:5])
					msg_id = msg_id[0]
					len_prefix = len_prefix[0]
					if(len_prefix == 5 and msg_id == 4):
						hv_msg = have_msg[9:]
						#print(hv_msg)
						if(len(hv_msg) > 0):
							con,ar = handshake_decode(hv_msg) 
							#ar[msg] = 1
							return con,ar
						else:
							msg = have(have_msg)
							ar[msg[0]] = 1
							#print("index",msg)
							return 1,ar
				#print("interested")
				return 1,[]
			if(msg_id == 5):
				#print("in bitfield")
				bitfield_length = len_prefix -1
				have_msg = reply[bitfield_length+5:]
				#print(have_msg)
				reply = reply[5:bitfield_length+5]
				reply = binascii.hexlify(reply)
				reply = reply.decode()
				array_bin = bin(int(reply,16)).zfill(8)
				ar = [o for o in array_bin[2:]]
				if(len(have_msg) > 0):
					len_prefix = struct.unpack("!I",have_msg[0:4])
					msg_id = struct.unpack("!b",have_msg[4:5])
					msg_id = msg_id[0]
					len_prefix = len_prefix[0]
					if(len_prefix == 1 and msg_id == 1):
						#print("unchoke")
						return 1,ar
				return 0,ar
			if(msg_id == 1 and len_prefix == 0):
				return 0,[]
			if(msg_id == 1 and len_prefix == 3):
				return 0,[]
			return 0,ar


def have(msg):
	index = struct.unpack("!i",msg[0:4])
	return index[0]
def interested():
	msg_id = 2
	l = 1
	msg = struct.pack('!ib',l,msg_id)
	return msg

def not_interested():
	msg_id = 3
	l = 1
	msg = struct.pack('!ib',l,msg_id)
	return msg

def reply_unchoked(res):
	len_prefix = struct.unpack("!I",res[0:4])
	msg_id = struct.unpack("!b",res[4:5])
	if(len_prefix[0] == 1 and msg_id[0] ==1):
		return True

def block(piece_lengths):
	no_of_blocks = piece_lengths // BLOCK
	if(piece_lengths % BLOCK != 0):
		last_piece = piece_lengths % BLOCK
		no_of_blocks = no_of_blocks + 1
	return no_of_blocks
		
def request_block(index,begin):
	#print(begin)
	l = 13
	msg_id = 6
	index = index
	begin = begin
	length = BLOCK
	#print(length)
	msg = struct.pack("!ibiii",l,msg_id,index,begin,length)
	return msg

def piece(piece):
	l,msg_id,index,begin = struct.unpack("!lbll",piece[0:13])
	if(msg_id == 7 and len(piece[13:]) == BLOCK):
		#print(msg_id,begin)
		return True,piece[13:]
	else:
		return False,piece
	
def writefile():
	f = open(download_file,"a")
	for i in piece_list:
		f.write(i["data"].decode())
	f.close()
		
		
	
if __name__ == "__main__":
	initialisation()
	'''widgets = [' [',progressbar.Timer(format= 'elapsed time: %(elapsed)s'),'] ',progressbar.Bar('*'),' (',progressbar.ETA(), ') ',]
	bar = progressbar.ProgressBar(max_value=102304,widgets=widgets).start()'''
	torrent_decode()
	writefile()


