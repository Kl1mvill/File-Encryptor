from interface import Interface
from encrypt import Encrypt
import threading



if __name__ == '__main__':
	interface = Interface()
	encrypt = Encrypt()
	
	encrypt.check_files()
	interface.interface()
