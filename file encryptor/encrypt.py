import os
import time
import random
from hashlib import pbkdf2_hmac
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES



class Encrypt:
	def check_files(self):
		if not os.path.exists("key"):
			os.mkdir("key")
			print("Созданна папка key...")

		if not os.path.exists("key/password.txt"):
			password = ""

			for i in range(64):
				password += random.choice("qazxswedcvfrtgbnhyujm,kiol./;p'[]0123456789QAZXSWEDCVFRTGBNHYUJM,KIOLP")

			with open("key/password.txt", 'w') as file: 
				file.write(pbkdf2_hmac("sha256", password.encode("utf-8"), "Hi! ".encode("utf-8"), 564389, dklen=64).hex())

			print("Создан файл password.txt...")

		if not os.path.exists("key/PrivateKey.pem") and not os.path.exists("key/PublicKey.pem"):
			self.сreating_keys()


	def сreating_keys(self):
		with open("key/password.txt", "r") as file:
			password = file.read()

		key = RSA.generate(4096)

		publicKey = key.publickey().export_key()

		with open("key/PrivateKey.pem", "wb") as file:
			data = key.export_key(passphrase=password.encode("utf-8"), 
								pkcs=8, 
								protection='PBKDF2WithHMAC-SHA512AndAES256-CBC', 
								prot_params={'iteration_count': 21000})
			file.write(data)
		print("Создан приватный ключ...")

		with open("key/PublicKey.pem", "wb") as file:
			file.write(publicKey)
			print("Создан публичный ключ...")


	def list_directory_file(self, directory: str) -> [str]:
		list_file = []

		for root, dirs, files in os.walk(directory): 
			for file in files: 
				list_file.append(os.path.join(root, file))

		return list_file


	def encrypt(self, file_name: str, public_key_file: str) -> str:
		if "_encr" in file_name: return

		try:
			with open(file_name, 'rb') as file:
				data = bytes(file.read())
	
			with open(public_key_file, 'rb') as file:
				publicKey = file.read()

			key = RSA.import_key(publicKey)
			sessionKey = os.urandom(16)
	
			cipher = PKCS1_OAEP.new(key)
			encryptedSessionKey = cipher.encrypt(sessionKey)
	
			cipher = AES.new(sessionKey, AES.MODE_EAX)
			ciphertext, tag = cipher.encrypt_and_digest(data)
	
			with open(file_name, 'wb') as file:
				[file.write(i) for i in (encryptedSessionKey, cipher.nonce, tag, ciphertext)]

			file_name_split = file_name.split(".")
			os.rename(file_name, file_name_split[0] + "_encr." + file_name_split[1])
			return f"\nФайл {file_name} зашифрован."

		except PermissionError:
			return f"Для изменения этого файла нужно разрешение администратора - {file_name}"
		except MemoryError:
			return f"Файл слишком большой, ваш комп не тянет - {file_name}"
		except FileNotFoundError:
			return f"Файл - {file_name} - не найден"
		except (IndexError, FileExistsError):
			return f"В пути файла - {file_name} - есть лишняя точка, удалите!"


	def decrypt(self, file_name: str, private_key_file: str) -> str:
		if "_encr" not in file_name: return

		with open("key/password.txt", "r") as file:
			password = file.read()

		with open(private_key_file, 'rb') as file:
			privateKey = file.read()
	
		key = RSA.import_key(privateKey, password.encode("utf-8"))
	
		with open(file_name, 'rb') as file:
			encryptedSessionKey, nonce, tag, ciphertext = [ file.read(i) for i in (key.size_in_bytes(), 16, 16, -1) ]

		cipher = PKCS1_OAEP.new(key)
		sessionKey = cipher.decrypt(encryptedSessionKey)

		cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)
		data = cipher.decrypt_and_verify(ciphertext, tag)
 	
		with open(file_name, 'wb') as file:
			file.write(data)

		file_name_split = file_name.split("_encr")
		os.rename(file_name, file_name_split[0] + file_name_split[1])
		return f"\nФайл {file_name} расшифрован."
