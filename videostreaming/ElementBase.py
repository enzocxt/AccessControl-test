import pygst
pygst.require("0.10")
import gst
import gobject

import os, math, Queue, threading, struct, traceback, time, datetime

import pyccn
import utils

from encrypt import AESCipher

__all__ = ["CCNPacketizer", "CCNDepacketizer"]

# encryption flag
encrypt_flag = True

DataKey_enc = None
DataKey_dec = None

# offset, element count
packet_hdr = "!HB" #@ unsigned short & unsigned char
packet_hdr_len = struct.calcsize(packet_hdr) #@ calculate the length = 3

# size, timestamp, duration
segment_hdr = "!IQQ" #@ unsigned int & unsigned long long 
segment_hdr_len = struct.calcsize(segment_hdr)	# length = 20

CMD_SEEK = 1

def debug(cls, text):
	print "%s: %s" % (cls.__class__.__name__, text)

class DataSegmenter(object):
	def __init__(self, callback, max_size = None):
		print "@ running in ElementBase.DataSegmenter.__init__()"
		global packet_hdr_len

		self._callback = callback
		self._max_size = None if max_size is None else max_size - packet_hdr_len

		self._packet_content = bytearray() #@ create a bytearray
		self._packet_elements = 0
		self._packet_element_off = 0
		self._packet_lost = False

	@staticmethod
	def buffer2segment(buffer):
		print "@ running in ElementBase.DataSegmenter.buffer2segment()"
		"""
		Converts a single buffer into segment
		(with all necessary information to restore it)
		"""

		global segment_hdr

		#@ maybe we can encrypt buffer.data here!!!
		print "@@@ length of buffer is %d" % buffer.size
		return struct.pack(segment_hdr, buffer.size, buffer.timestamp, \
				buffer.duration) + buffer.data

	@staticmethod
	def segment2buffer(segment, offset):
		print "@ running in ElementBase.DataSegmenter.segment2buffer()"
		"""
		Converts a segment into buffer. It is capable of working on incomplete
		segments, returns buffer and offset for next segment.
		If not enough data is available it returns None and the supplied offset
		"""
		global segment_hdr, segment_hdr_len
		
		print "@@@ length of segment is %d" % len(segment)

		if len(segment) - offset < segment_hdr_len:
			return None, offset

		header = bytes(segment[offset:offset + segment_hdr_len])
		size, timestamp, duration = struct.unpack(segment_hdr, header)
		start = offset + segment_hdr_len
		end = start + size
		print "@@@ offset is %d" % offset
		print "@@@ size is %d" % size
		print "@@@ size is %s" % bin(size) 
		print "@@@ end is %d" % end
		print "@@@ timestamp is %s" % timestamp
		print "@@@ duration is %s" % duration

		if end > len(segment):
			return None, offset

		#@ buffers are usually created with the constructor gst.Buffer()
		buf = gst.Buffer(bytes(segment[start:end]))
		buf.timestamp, buf.duration = timestamp, duration

		return buf, end

	def process_buffer(self, buffer, start_fresh = False, flush = False):
		print "@ running in ElementBase.DataSegmenter.process_buffer()"
		assert self._max_size, "You can't use process_buffer without \
				defining max_size"

		if start_fresh and len(self._packet_content) > 0:
			print "@ perform_send_callback(1)"
			self.perform_send_callback()

		element = self.buffer2segment(buffer)
		self._packet_content.extend(element)
		self._packet_elements += 1
		
		print "@@@ length of _packet_content is %d" % len(self._packet_content)
		print "@@@ self._max_size is %d" % self._max_size
		nochunks = int(math.ceil(len(self._packet_content) \
				/ float(self._max_size)))
		print "@@@ nochunks = %d" % nochunks
		
		while nochunks >= 2:
			packet_size = min(self._max_size, len(self._packet_content))
			nochunks -= 1
			print "@ perform_send_callback(2)"
			self.perform_send_callback(packet_size)
		assert(nochunks == 1)

		if len(self._packet_content) == self._max_size or flush:
			print "@ perform_send_callback(3)"
			self.perform_send_callback()

	def perform_send_callback(self, size = None):
		print "@ running in ElementBase.DataSegmenter.perform_send_callback()"
		if size is None:
			size = len(self._packet_content)

		offset = 0 if self._packet_elements == 0 else self._packet_element_off
		print "@@@ offset = %d" % offset
		header = struct.pack(packet_hdr, offset, self._packet_elements)
		print "@@@ _packet_elements is %d" % self._packet_elements
		#print "@@@ header is %s" % header
		#@ type of header is str.

		self._callback(header + bytes(self._packet_content[:size]))
		self._packet_content = self._packet_content[size:]
		self._packet_element_off = len(self._packet_content)
		self._packet_elements = 0

	def packet_lost(self):
		print "@ running in ElementBase.DataSegmenter.packet_lost()"
		self._packet_lost = True
		self._packet_content = bytearray()
		self._packet_elements = 0

	def process_packet(self, timestamp, packet):
		print "@ running in ElementBase.DataSegmenter.process_packet()"
		global packet_hdr, packet_hdr_len

		header = packet[:packet_hdr_len]
		offset, count = struct.unpack(packet_hdr, header)
		print "@@@ offset is %d" % offset
		print "@@@ count is %d" % count

		#skip packets that don't have beginning (offset is meaningless)
		if self._packet_lost and count == 0:
			assert self._packet_elements == 0 and len(self._packet_content) == 0
			return

		#for continuation assume offset is 0 (use data we already received)
		if not self._packet_lost or len(self._packet_content) > 0:
			print "@@@ offset = 0"
			offset = 0

		if self._packet_lost:
			self._packet_lost = False
			discont = True
		else:
			discont = False

		offset += packet_hdr_len
		print "@@@ offset is %d" % offset
		#@ the real content is here
		self._packet_content.extend(packet[offset:])
		self._packet_elements += count
		print "@@@ _packet_elements is %d" % self._packet_elements

		off = 0
		while self._packet_elements > 0:
			print "@ segment2buffer(self._packet_content, off)"
			buf, off = self.segment2buffer(self._packet_content, off)
			print "@@@ off is %d" % off

			if buf is None:
				break

			if discont:
				discont = False
				buf.flag_set(gst.BUFFER_FLAG_DISCONT)

			self._callback(timestamp, buf)
			self._packet_elements -= 1
			print "@@@ _packet_elements %d" % self._packet_elements
		#assert (left > 0 and self._packet_elements == 1) or self._packet_elements == 0, "left = %d, packet_elements = %d" % (left, self._packet_elements)
		assert self._packet_elements <= 1, "packet_elements %d" % self._packet_elements

		self._packet_content = self._packet_content[off:]

class CCNPacketizer(object):
	def __init__(self, publisher, uri):
		print "@ running in ElementBase.CCNPacketizer.__init__"
		freshness = 30 * 60

		self._chunk_size = 3900
		self._segment = 0
		self._caps = None

		self.publisher = publisher

		self._basename = pyccn.Name(uri)
		self._name_segments = self._basename.append("segments")
		self._name_frames = self._basename.append("index")
		self._name_key = self._basename.append("key")

		self._key = pyccn.CCN.getDefaultKey()
		self._signed_info = pyccn.SignedInfo(self._key.publicKeyID, pyccn.KeyLocator(self._name_key), freshness = freshness)
		self._signed_info_frames = pyccn.SignedInfo(self._key.publicKeyID, pyccn.KeyLocator(self._name_key), freshness = 1)

		# key for encrypting content
#		self._dataKey_flag = False # if True, data key has been published
#		self._data_key = os.urandom(16)
		self._data_key = '123456789asdfghj'
#		self._name_of_dataKey = self._basename.append('DataKey')

		#@ self._segmenter initials the DataSegmenter(self, _callback,) 
		#@ _callback is initialed by self.send_data.
		self._segmenter = DataSegmenter(self.send_data, self._chunk_size)

		signed_info = pyccn.SignedInfo(self._key.publicKeyID, pyccn.KeyLocator(self._key), freshness = freshness)
		co = pyccn.ContentObject(self._name_key, self._key.publicToDER(), signed_info)
		co.sign(self._key)
		self.publisher.put(co)

	def set_caps(self, caps):
		print "@ running in ElementBase.CCNPacketizer.set_caps()"
		if not self._caps:
			self._caps = caps

			packet = self.prepare_stream_info_packet(caps)
			self.publisher.put(packet)

			self.post_set_caps(caps)

	def post_set_caps(self, caps):
		pass

	def prepare_stream_info_packet(self, caps):
		print "@ running in ElementBase.CCNPacketizer.prepare_stream_info_packet()"
		name = self._basename.append("stream_info")

		# Make sure the timestamp is regenerated
		self._signed_info.ccn_data_dirty = True
		co = pyccn.ContentObject(name, self._caps, self._signed_info)
		co.sign(self._key)

		return co
	
	def publish_data_key(self):
		print "@@@ running in ElementBase.CCNPacketizer.publish_data_key()"
		dataKey = self.prepare_data_key_packet()
		self.publisher.put(dataKey)
	
	def prepare_data_key_packet(self):
		print "@@@ running in ElementBase.CCNPacketizer.prepare_data_key_packet()"
		self._signed_info.ccn_data_dirty = True

		co = pyccn.ContentObject(self._name_of_dataKey, self._data_key, self._signed_info)
		co.sign(self._key)

		return co

	def prepare_frame_packet(self, frame, segment):
		print "@ running in ElementBase.CCNPacketizer.prepare_frame_packet()"
		name = self._name_frames.append(frame)

		# Make sure the timestamp is regenerated
		self._signed_info_frames.ccn_data_dirty = True
		print "@ segment is %s" % segment
		co = pyccn.ContentObject(name, segment, self._signed_info_frames)
		co.sign(self._key)

		return co

	def send_data(self, packet):
		#@ create a contentobject, the content is packet
		#@ the type of packet is 'str'
		print "@ running in ElementBase.CCNPacketizer.send_data()."
		name = self._name_segments.appendSegment(self._segment)
		self._segment += 1

		# Make sure the timestamp is regenerated
		self._signed_info.ccn_data_dirty = True
		if encrypt_flag:
			print "@@@ the encryption is here!!!"
			# if need encryption, publish data key
#			if self._dataKey_flag == False:
#				self.publish_data_key()
#				self._dataKey_flag = True
			# aes = AESCipher('123456789asdfghj') 
			aes = AESCipher(self._data_key)
			# print "@@@ data key length is: %d" % len(self._data_key)
			enc_packet = aes.encrypt(str(packet))
			co = pyccn.ContentObject(name, enc_packet, self._signed_info)
			# print "@@@ length of packet is %d" % len(packet)
			# print "@@@ length of enc_packet is %d" % len(enc_packet)
		else:
			print "@@@ no encrytpion!!!"
			co = pyccn.ContentObject(name, packet, self._signed_info)
		co.sign(self._key)
		self.publisher.put(co)

	def pre_process_buffer(self, buffer):
		return True, True

	def process_buffer(self, buffer):
		print "@ running in ElementBase.CCNPacketizer.process_buffer()."
		#@ print "@ running result = .."
		result = self.pre_process_buffer(buffer)
		#@ print "@ running in ElementBase.CCNPacketizer._segmenter.process_buffer()"
		self._segmenter.process_buffer(buffer, start_fresh = result[0],
				flush = result[1])

class CCNDepacketizer(pyccn.Closure):
	def __init__(self, uri, window = 1, retries = 1):
		print "@ running in ElementBase.CCNDepacketizer.__init__"
		# size of the pipeline
		self.window = window

		# how many times to retry request
		self.interest_retries = retries

		# maximum number of buffers we can hold in memory waiting to be processed
		self.queue = None

		# publisher's id
		self.publisher_id = None

		# duration of the stream (in nanoseconds)
		self.duration_ns = None

		# interest timeout
		self.interest_lifetime = None

		# whether fetching thread is running
		self._running = False

		# caps of the stream
		self._caps = None

		# timestamp of the remote machine
		self._start_time = None
		self._seek_segment = None
		self._duration_last = None
		self._cmd_q = Queue.Queue(2)

		self._handle = pyccn.CCN()
		self._get_handle = pyccn.CCN()

		self._uri = pyccn.Name(uri) # @base uri
		self._name_segments = self._uri + 'segments'
		self._name_frames = self._uri + 'index'

		# key for decrypting content
		self._data_key = None
#		self._name_of_dataKey = self._uri.append('DataKey')
		self._name_of_dataKey = pyccn.Name('/test/VideoSite/Movie/DataKey')
		self._dataKey_flag = False

		# aes for decryption
		self.aes = None
		
		self.fileHandle = open('/home/enzo/CCNx/ndnvideo-test/decryption_time_record/Part_Of_Me.txt', 'w')

		self._pipeline = None
		self._segmenter = DataSegmenter(self.push_data)
		#@ here initial push_data to the _callback in DataSegmenter

		self._stats = {
			'srtt': 0.6,
			'rttvar': 0.15 \
		}

		self._stats_retries = 0
		self._stats_drops = 0

		self._tmp_retry_requests = {}

		DurationChecker = type('DurationChecker', (pyccn.Closure,),
			dict(upcall = self.duration_process_result))
		self._duration_callback = DurationChecker()

	def fetch_stream_info(self):
		print "@ running in ElementBase.CCNDepacketizer.fetch_stream_info()"
		name = self._uri.append('stream_info')
		debug(self, "Fetching stream_info from %s ..." % name)

		print "@@@ publisherPublicKeyDigest is %s" % self.publisher_id
		co = self._get_handle.get(name, pyccn.Interest(publisherPublicKeyDigest = self.publisher_id))
		#@ _get_handle is a CCN handle.
		#@ fetch co by handle.get()
		if not co:
			debug(self, "Unable to fetch %s" % name)
			exit(10)

		ts = co.signedInfo.py_timestamp
		debug(self, "Got timestamp: %s %f" % (time.ctime(ts), ts))
		self._start_time = ts
		self._caps = gst.caps_from_string(co.content)
		debug(self, "Stream caps: %s" % self._caps)

		self.post_fetch_stream_info(self._caps)

		if self._start_time is None:
			self.fetch_start_time()

	def fetch_start_time(self):
		print "@ running in ElementBase.CCNDepacketizer.fetch_start_time()"
		name = self._name_segments.appendSegment(0)
		#@ fetch content object
		co = self._get_handle.get(name, pyccn.Interest(publisherPublicKeyDigest = self.publisher_id))
		if not co:
			debug(self, "Unable to fetch %s" % name)
			exit(10)

		ts = co.signedInfo.py_timestamp
		debug(self, "Got timestamp: %s %f" % (time.ctime(ts), ts))
		self._start_time = ts

	def post_fetch_stream_info(self, caps):
		pass

	def get_caps(self):
		print "@ running in ElementBase.CCNDepacketizer.get_caps()"
		if not self._caps:
			self.fetch_stream_info()

		return self._caps

	def start(self):
		print "@ running in ElementBase.CCNDepacketizer.start()"
		# maximum number of buffers we can hold in memory waiting to be processed
		self.queue = Queue.Queue(self.window * 2)
		self._pipeline = utils.PipelineFetch(self.window, self.issue_interest,
				self.process_response)

		self._receiver_thread = threading.Thread(target = self.run)
		self._running = True
		self._receiver_thread.start()

	def stop(self):
		print "@ running in ElementBase.CCNDepacketizer.stop()"
		self._running = False
		self.finish_ccn_loop()
		debug(self, "Waiting for ccn to shutdown ...")
		self._receiver_thread.join()
		debug(self, "Thread was shut down.")

	def finish_ccn_loop(self):
		print "@ running in ElementBase.CCNDepacketizer.finish_ccn_loop()"
		self._handle.setRunTimeout(0)

	def seek(self, ns):
		print "@ running in ElementBase.CCNDepacketizer.seek()"
		self._cmd_q.put([CMD_SEEK, ns])
		self.finish_ccn_loop()

	def check_duration_initial(self):
		print "@ running in ElementBase.CCNDepacketizer.check_duration_initial()"
		global packet_hdr, packethdr_len, segment_hdr, segment_hdr_len

		last_duration, duration = 0, 0

		interest = pyccn.Interest(publisherPublicKeyDigest = self.publisher_id,
			childSelector = 1, answerOriginKind = pyccn.AOK_DEFAULT)

		exclude = interest.exclude = pyccn.ExclusionFilter()

		while True:
			t_start = time.time()
			co = self._get_handle.get(self._name_frames, interest, 4200)
			t_end = time.time()

			if co is None:
#				break
				continue

#			packet = co.content
#			header = packet[:packet_hdr_len]
#			offset, count = struct.unpack(packet_hdr, header)
#			if count == 0 or len(packet) < packet_hdr_len + offset + segment_hdr_len:
#				continue
#
#			offset += packet_hdr_len
#			header = packet[offset:offset + segment_hdr_len]
#			duration = struct.unpack(segment_hdr, header)[1]

			name = co.name[-1:]
			duration = pyccn.Name.seg2num(co.name[-1])
			duration_s = duration / float(gst.SECOND)

			#t_packet = co.signedInfo.py_timestamp
			rtt = t_end - t_start
			#t_diff = t_start - t_packet

			print "Duration:", datetime.timedelta(seconds = duration_s)
			print "Duration diff:", duration_s - last_duration
			print "Rtt:", rtt
			print "Rtt diff", duration_s - last_duration - rtt
			#print "Packet timestamp:", time.ctime(t_packet)
			#print "Time difference:", datetime.timedelta(seconds = t_diff), t_diff

			if duration_s - last_duration - rtt < 0.001:
				break

			print "Excluding %r" % name
			exclude.reset()
			exclude.add_any()
			exclude.add_name(name)

			last_duration = duration_s

		return duration

#
# Bellow methods are called by thread
#

	def run(self):
		print "@ running in ElementBase.CCNDepacketizer.run()"
		debug(self, "Running ccn loop")

		while self._running:
			self.check_duration()
			self._handle.run(10000)
			self.process_commands()

		debug(self, "Finished running ccn loop")

	def process_commands(self):
		print "@ running in ElementBase.CCNDepacketizer.process_commands()"
		try:
			if self._cmd_q.empty():
				return
			cmd = self._cmd_q.get_nowait()
		except Queue.Empty:
			return

		if cmd[0] == CMD_SEEK:
			if cmd[1] == 0:
				tc, segment = 0, 0 #streaming always starts from segment 0
			else:
				tc, segment = self.fetch_seek_query(cmd[1])
			debug(self, "Seeking to segment %d [%s]" % (segment, tc))
			self._seek_segment = True
			self._segmenter.packet_lost()
			self._pipeline.reset(segment)
			self._cmd_q.task_done()
		else:
			raise Exception, "Unknown command: %d" % cmd

	def fetch_seek_query(self, ns):
		print "@ running in ElementBase.CCNDepacketizer.fetch_seek_query()"
		index = self.ts2index_add_1(ns)

		#debug(self, "Fetching segment number before %s" % index)

		interest = pyccn.Interest(publisherPublicKeyDigest = self.publisher_id,
			childSelector = 1, answerOriginKind = pyccn.AOK_NONE)
		interest.exclude = pyccn.ExclusionFilter()
		interest.exclude.add_name(pyccn.Name([index]))
		interest.exclude.add_any()

		#debug(self, "Sending interest to %s" % self._name_frames)
		#debug(self, "Exclusion list %s" % interest.exclude)
		while True:
			co = self._get_handle.get(self._name_frames, interest)
			if co:
				break
			debug(self, "Timeout while seeking %d, retrying ..." % (ns))
		debug(self, "Got segment: %s" % co.content)

		index = co.name[-1]
		segment = int(co.content)

		return (self.index2ts(index), segment)

	def duration_process_result(self, kind, info):
		print "@ running in ElementBase.CCNDepacketizer.duration_process_result()"
		if kind == pyccn.UPCALL_FINAL:
			return pyccn.RESULT_OK

		if kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
			return pyccn.RESULT_VERIFY

		if kind != pyccn.UPCALL_CONTENT and kind != pyccn.UPCALL_INTEREST_TIMED_OUT:
			return pyccn.RESULT_ERR

		if kind == pyccn.UPCALL_CONTENT:
			self._duration_last = info.ContentObject.name[-1]
		else:
			debug(self, "No response received for duration request")
			self._duration_last = None

		if self._duration_last:
			self.duration_ns = self.index2ts(self._duration_last)
		else:
			self.duration_ns = 0

		return pyccn.RESULT_OK

	def check_duration(self):
		print "@ running in ElementBase.CCNDepacketizer.check_duration()"
		interest = pyccn.Interest(publisherPublicKeyDigest = self.publisher_id, childSelector = 1)

		if self._duration_last:
			interest.exclude = pyccn.ExclusionFilter()
			interest.exclude.add_any()
			interest.exclude.add_name(pyccn.Name([self._duration_last]))

		self._handle.expressInterest(self._name_frames, self._duration_callback, interest)

	def issue_interest(self, segment):
		print "@ running in ElementBase.CCNDepacketizer.issue_interest()"
		name = self._name_segments.appendSegment(segment)

		#debug(self, "Issuing an interest for: %s" % name)
		self.interest_lifetime = min(2.0, self._stats['srtt'] + 3 * self._stats['rttvar'])
		self._tmp_retry_requests[str(name[-1])] = (self.interest_retries, time.time(), self.interest_lifetime)

		interest = pyccn.Interest(publisherPublicKeyDigest = self.publisher_id, interestLifetime = self.interest_lifetime)
		self._handle.expressInterest(name, self, interest)

		return True
	
	def get_data_key(self):
		print "@@@ running in ElementBase.CCNDepacketizer.get_data_key()"
		debug(self, "Fetching data key from %s ..." % self._name_of_dataKey)
		co = self._get_handle.get(self._name_of_dataKey, pyccn.Interest(publisherPublicKeyDigest = self.publisher_id))
		if not co:
			debug(self, "Unable to fetch %s" % self._name_of_dataKey)
			exit(10)

		self._data_key = co.content
		# print "@@@ length of self._data_key is : %d" % len(self._data_key)
		# print "@@@ type of self._data_key is : %s" % type(self._data_key)
		return self._data_key

	def process_response(self, co):
		print "@ running in ElementBase.CCNDepacketizer.process_response()"
		if not co:
			self._segmenter.packet_lost()
			return

		timestamp = co.signedInfo.py_timestamp

		if encrypt_flag:
			print "@@@ decryption is here!!!"
			if self._dataKey_flag == False:
				self._data_key = self.get_data_key()
				print "@@@ data key is : %s" % self._data_key
				self._dataKey_flag = True

			# print "@@@ length of self._data_key is : %d" % len(self._data_key)
			# print "@@@ length of co.content is %d" % len(co.content)
			# aes = AESCipher('123456789asdfghj')	
			if self.aes == None:
				self.aes = AESCipher(self._data_key)
			
#			time_start = time.time()
			dec_content = self.aes.decrypt(co.content) 
			#time_start = time.time()
			#for i in range(1000):
			#	dec_content_sample = self.aes.decrypt(co.content)
#			time_stop = time.time()
#			dec_time = time_stop - time_start
#			self.fileHandle.write('%0.9f\n' % ( dec_time))
			# print "@@@ length of dec_content is %d" % len(dec_content)
			self._segmenter.process_packet(timestamp, dec_content)
		else:
			print "@@@ no decryption!!!"
			# print "@@@ length of co.content is %d" % len(co.content)
			self._segmenter.process_packet(timestamp, co.content)

	def push_data(self, timestamp, buf):
		print "@ running in ElementBase.CCNDepacketizer.push_data()"
		status = 0

		# Marking jump due to seeking
		if self._seek_segment == True:
			debug(self, "Marking as discontinued")
			status = CMD_SEEK
			self._seek_segment = None

		while True:
			try:
				self.queue.put((status, timestamp, buf), True, 1)
				break
			except Queue.Full:
				if not self._running:
					break

	def upcall(self, kind, info):
		print "@ running in ElementBase.CCNDepacketizer.upcall()"
		if not self._running:
			return pyccn.RESULT_OK

		elif kind == pyccn.UPCALL_FINAL:
			return pyccn.RESULT_OK

		elif kind == pyccn.UPCALL_CONTENT:
			name = str(info.Interest.name[-1])
			if name in self._tmp_retry_requests:
				n_rtt = time.time() - self._tmp_retry_requests[name][1]

				difference = n_rtt - self._stats['srtt']
				self._stats['srtt'] += 1 / 32.0 * difference
				self._stats['rttvar'] += 1 / 16.0 * (abs(difference) - self._stats['rttvar'])
				del self._tmp_retry_requests[name]
			else:
				debug(self, "Got ContentObject but I'm missing RTT record")

			#self.interest_lifetime = self._stats['srtt'] + 3 * math.sqrt(self._stats['rttvar'])
			#print "Roundtrip:", n_rtt, self.interest_lifetime, self.interest_lifetime - n_rtt

			self._pipeline.put(pyccn.Name.seg2num(info.ContentObject.name[-1]),
							info.ContentObject)
			return pyccn.RESULT_OK

		elif kind == pyccn.UPCALL_INTEREST_TIMED_OUT:
			name = str(info.Interest.name[-1])
			req = self._tmp_retry_requests[name]

			difference = req[2] - self._stats['srtt']
			self._stats['srtt'] += 1 / 32.0 * difference
			self._stats['rttvar'] += 1 / 16.0 * (abs(difference) - self._stats['rttvar'])

			if req[0] > 0:
				self._stats_retries += 1
				self._tmp_retry_requests[name] = (req[0] - 1, time.time(), req[2])
				return pyccn.RESULT_REEXPRESS

			self._stats_drops += 1
			del self._tmp_retry_requests[name]
			self._pipeline.timeout(pyccn.Name.seg2num(info.Interest.name[-1]))
			return pyccn.RESULT_OK

		elif kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
			debug(self, "%s arrived unverified, fetching the key" % info.ContentObject.name)
			return pyccn.RESULT_VERIFY

		debug(self, "Got unknown kind: %d" % kind)

		return pyccn.RESULT_ERR

	def get_status(self):
		print "@ running in ElementBase.CCNDepacketizer.get_status()"
		return "PSize: %d/%d Segment: %d Timeout: %.3f (%.3f, %.3f) Retries: %d Drops: %d Duration: %ds" \
			% (self._pipeline.get_pipeline_size(), self._pipeline.window,
			self._pipeline.get_position(), self.interest_lifetime or - 1,
			self._stats['srtt'], self._stats['rttvar'], self._stats_retries,
			self._stats_drops,
			self.duration_ns / gst.SECOND if self.duration_ns else 1.0)

	def ts2index(self, ts):
		return pyccn.Name.num2seg(ts)

	def ts2index_add_1(self, ts):
		return self.ts2index(ts + 1)

	def index2ts(self, index):
		return pyccn.Name.seg2num(index)

class CCNElementSrc(gst.BaseSrc):
	__gsttemplates__ = (
		gst.PadTemplate("src",
			gst.PAD_SRC,
			gst.PAD_ALWAYS,
			gst.caps_new_any()),
		)

	def __init__(self):
		print "@ running in ElementBase.CCNElementSrc.__init__"
		gst.BaseSrc.__init__(self)
		self.depacketizer = None
		self.set_format(gst.FORMAT_TIME)
		self.seek_in_progress = None
		self._no_locking = False

	def do_get_caps(self):
		print "@ running in ElementBase.CCNElementSrc.do_get_caps()"
		debug(self, "Called do_get_caps")
		if self.depacketizer:
			return self.depacketizer.get_caps()
		return None

	def do_start(self):
		print "@ running in ElementBase.CCNElementSrc.do_start()"
		debug(self, "Called start")
		self.depacketizer.start()
		return True

	def do_stop(self):
		print "@ running in ElementBase.CCNElementSrc.do_stop()"
		debug(self, "Called stop")
		self.depacketizer.stop()
		return True

	def do_is_seekable(self):
		debug(self, "is seekable")
		return True

#	def do_event(self, event):
#		if event.type == gst.EVENT_QOS:
#			print "QOS: proportion: %f diff: %d timestamp: %d" % event.parse_qos()
#		else:
#			print "Got event %s" % event.type
#		return gst.BaseSrc.do_event(self, event)

	def do_create(self, offset, size):
		print "@ running in ElementBase.CCNElementSrc.do_create()"
		if self._no_locking:
			return gst.FLOW_WRONG_STATE, None

		#debug(self, "Offset: %d, Size: %d" % (offset, size))
		try:
			while True:
				try:
					status, timestamp, buffer = self.depacketizer.queue.get(True, 5)
					#print "%d %d %d %s" % (buffer.timestamp, buffer.duration, buffer.flags, buffer.caps)
				except Queue.Empty:
					if self._no_locking:
						return gst.FLOW_WRONG_STATE, None
					else:
						debug(self, "Starving for data")
						continue

				if self._no_locking:
					self.depacketizer.queue.task_done()
					return gst.FLOW_WRONG_STATE, None

				if self.seek_in_progress is not None:
					if status != CMD_SEEK:
						debug(self, "Skipping prefetched junk ...")
						self.depacketizer.queue.task_done()
						continue

					debug(self, "Pushing seek'd buffer")
					event = gst.event_new_new_segment(False, 1.0, gst.FORMAT_TIME,
					                                  self.seek_in_progress, -1,
					                                  self.seek_in_progress)
					r = self.get_static_pad("src").push_event(event)
					debug(self, "Result of announcement of the new segment: %s" % r)

					self.seek_in_progress = None
					buffer.flag_set(gst.BUFFER_FLAG_DISCONT)

				self.depacketizer.queue.task_done()
				return gst.FLOW_OK, buffer
		except:
			traceback.print_exc()
			return gst.FLOW_ERROR, None

	def do_do_seek(self, segment):
		print "@ running in ElementBase.CCNElementSrc.do_do_seek()"
		debug(self, "Asked to seek to %d" % segment.start)
		self.seek_in_progress = segment.start
		self.depacketizer.seek(segment.start)
		return True

	def do_query(self, query):
		print "@ running in ElementBase.CCNElementSrc.do_query()"
		if query.type != gst.QUERY_DURATION:
			return gst.BaseSrc.do_query(self, query)

		duration = self.depacketizer.duration_ns

		if not duration:
			return True

		query.set_duration(gst.FORMAT_TIME, duration)

		#debug(self, "Returning %s %d" % (query.parse_duration()))

		return True

	def do_check_get_range(self):
		print "@ running in ElementBase.CCNElementSrc.do_check_get_range()"
		debug(self, "get range")
		return False

	def do_unlock(self):
		print "@ running in ElementBase.CCNElementSrc.do_unlock()"
		debug(self, "Unlock!!!")
		self._no_locking = True
		return True

	def do_unlock_stop(self):
		print "@ running in ElementBase.CCNElementSrc.do_unlock_stop()"
		debug(self, "Stop unlocking!!!")
		self._no_locking = False
		return True

	def query_duration(self):
		print "@ running in ElementBase.CCNElementSrc.query_duration()"
		debug(self, "Querying duration")
		return self.depacketizer.check_duration_initial()

	def get_status(self):
		print "@ running in ElementBase.CCNElementSrc.get_status()"
		return self.depacketizer.get_status()

#	def do_change_state(self, transition):
#		print "CHANGE IS INEVITABLE!"
#		print transition
#		res = gst.BaseSrc.do_change_state(self, transition)
#		print res
#		return gst.STATE_CHANGE_SUCCESS
