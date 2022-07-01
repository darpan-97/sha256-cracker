from pwn import *
import sys
from termcolor import colored

if len(sys.argv) != 3:
	print("\nUSAGE:\nsha256.py [sha256 hash value] [wordlist file]\n")
	exit()

else : 
	wanted_hash = sys.argv[1]
	password_file = sys.argv[2]
	attempts = 0

	with log.progress("Cracking: {}!\n".format(wanted_hash)) as H:
		with open(password_file, "r", encoding='latin-1') as password_list:
			for password in password_list:
				password = password.strip("\n").encode('latin-1')
				password_hash = sha256sumhex(password)
				H.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
				if password_hash == wanted_hash:
					print(colored("Cracked Password :" + password.decode('latin-1'), 'white', 'on_blue').center(45 ,"="))
					H.success("Total attempts {}\n\n".format(attempts))
					exit()
				attempts += 1
			H.failure("Password hash not found")

