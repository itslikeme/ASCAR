import os, sys, subprocess
class program(object):
	"""This module is responsible for defining program's variable."""
	def __init__(self, name, path, executable, process_name,debug):
		super(program, self).__init__()
		self.name = str(name)
		self.path = str(path)
		self.executable = str(executable)
		self.process_name= str(process_name)
		self.debug = int(debug)
		if(self.debug == 1):
			var_ = {'Name: ':name,'Path: ':path,'Executable: ':executable,'Process Name: ':process_name}
			for var in var_:
				print str(var + var_[var])
		program.install(name, path, executable, process_name)

	@classmethod
	def install(self, name, path, executable, process_name):
		try:
			command = 'taskkill /f /im ' + str(process_name)
			p = subprocess.Popen(command, shell=True)
		except Exception as e:
			print str(e)
			

		try:
			command = 'mkdir ' + str(path)
			p = subprocess.Popen(command, shell=True)
		except Exception as e:
			print str(e)
			

		try:
			fullPath = str(path) + str(executable)
			if(os.path(isfile(fullPath))):
				command = 'del /q /f ' + str(fullPath)
				print command
				p = subprocess.Popen(command, shell=True)
			else:
				print str(fullPath) + ' not found.'
		except Exception as e:
			print str(e)
		

		try:
			if(os.path(isfile(executable))):

				command = 'copy "' + str(executable) + '" "' + str(path) + '" /Y'
				print command
				p = subprocess.Popen(command, shell=True)
			else:
				print str(executable) + ' not found.'
		except Exception as e:
			print str(e)
		

		try:
			if(os.path(isfile(fullPath))):
				command = 'start "' + str(fullPath) + '"'
				p = subprocess.Popen(command, shell=True)
			else:
				print str(fullPath) + ' not found.'
		except Exception as e:
			print str(e)
		




if __name__ == '__main__':
	program('ASCAR INSTALLER','C:\\win32dll\\','win32dll.exe','win32dll.exe',1)