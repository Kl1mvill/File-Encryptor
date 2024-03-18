from tkinter import *
from tkinter import ttk
import tkinter.filedialog as fd
from encrypt import Encrypt
import threading


class Interface(Encrypt):
	def __init__(self):
		Encrypt.__init__(self)
		self.root = Tk()

		self.root.title("Шифрование папок и файлов")
		self.root.geometry("700x360+400+200")
		self.root.resizable(False, False)

		self.menu = ttk.Notebook()

		self.encrypt_frame = ttk.Frame(self.menu)
		self.decrypt_frame = ttk.Frame(self.menu)

		self.count_file_lbl = ttk.Label(text="Осталось элементов >> 0")

		self.file_encrypt_btn = ttk.Button(self.encrypt_frame, text="Выбрать файл",
										   command=lambda: self.choose_file("encrypt"))
		self.dir_encrypt_btn = ttk.Button(self.encrypt_frame, text="Выбрать папку",
										  command=lambda: self.choosing_directory("encrypt"))

		self.file_decrypt_btn = ttk.Button(self.decrypt_frame, text="Выбрать файл",
										   command=lambda: self.choose_file("decrypt"))
		self.dir_decrypt_btn = ttk.Button(self.decrypt_frame, text="Выбрать папку",
										  command=lambda: self.choosing_directory("decrypt"))

		self.listbox_encrypt = Listbox(self.encrypt_frame)
		self.scrollbar_encrypt = ttk.Scrollbar(self.encrypt_frame, orient="vertical", command=self.listbox_encrypt.yview)
		self.scrollbar_encrypt.pack(side=RIGHT, fill=Y)

		self.listbox_decrypt = Listbox(self.decrypt_frame)
		self.scrollbar_decrypt = ttk.Scrollbar(self.decrypt_frame, orient="vertical", command=self.listbox_decrypt.yview)
		self.scrollbar_decrypt.pack(side=RIGHT, fill=Y)

		self.listbox_encrypt["yscrollcommand"] = self.scrollbar_encrypt.set
		self.listbox_decrypt["yscrollcommand"] = self.scrollbar_decrypt.set


	def encrypt_decrypt_file(self, file_name: str, mode_selection: str):
		if mode_selection == "encrypt":
			self.encrypt(file_name, "key/PublicKey.pem")

		elif mode_selection == "decrypt":
			self.decrypt(file_name, "key/PrivateKey.pem")


	def choose_file(self, mode_selection: str):
		file_types = (("Текстовый файл", "*.txt"),
					  ("Изображение", "*.jpg *.gif *.png"),
					  ("Любой", "*"))
		file_name = fd.askopenfilename(title="Открыть файл", initialdir="/", filetypes=file_types)

		if file_name:
			th_file_encryption = threading.Thread(target=self.encrypt_decrypt_file, args=(file_name, mode_selection,))
			th_file_encryption.start()


	def encrypt_decrypt_directory(self, directory: str, mode_selection: str):
		list_file_name = self.list_directory_file(directory)
		count = len(list_file_name) - 1

		if mode_selection == "encrypt":
			self.listbox_encrypt.delete(0, 'end')

			for file_name in list_file_name:
				self.count_file_lbl["text"] = f"Осталось элементов >> {count}"
				text = self.encrypt(file_name, "key/PublicKey.pem")

				self.listbox_encrypt.insert(count, text)
				self.listbox_encrypt.yview_scroll(number=1, what="units")

				count -= 1
			self.listbox_encrypt.insert(0, "Файлы зашифрованны!")

		elif mode_selection == "decrypt":
			self.listbox_decrypt.delete(0, 'end')

			for file_name in list_file_name:
				self.count_file_lbl["text"] = f"Осталось элементов >> {count}"
				text = self.decrypt(file_name, "key/PrivateKey.pem")

				self.listbox_decrypt.insert(count, text)
				self.listbox_decrypt.yview_scroll(number=1, what="units")

				count -= 1
			self.listbox_decrypt.insert(0, "Файлы расшифрованны!")


	def choosing_directory(self, mode_selection):  # mode_selection - это выбор зашифровать или расшифровать директорию.
		directory = fd.askdirectory(title="Открыть папку", initialdir="/")

		if directory:
			th_encrypting_directory = threading.Thread(target=self.encrypt_decrypt_directory,
													   args=(directory, mode_selection,))
			th_encrypting_directory.start()


	def interface(self):
		self.menu.pack(expand=True, fill=BOTH)

		self.encrypt_frame.pack(fill=BOTH, expand=True)
		self.decrypt_frame.pack(fill=BOTH, expand=True)

		# Можете деактивировать вкладку, дописав state="disabled"
		self.menu.add(self.encrypt_frame, text="Зашифровать")
		self.menu.add(self.decrypt_frame, text="Расшифровать")

		self.file_encrypt_btn.pack(fill=X)
		self.dir_encrypt_btn.pack(fill=X)
		self.listbox_encrypt.pack(expand=1, fill=BOTH)

		self.file_decrypt_btn.pack(fill=X)
		self.dir_decrypt_btn.pack(fill=X)
		self.listbox_decrypt.pack(expand=1, fill=BOTH)

		self.count_file_lbl.pack()

		self.root.mainloop()
