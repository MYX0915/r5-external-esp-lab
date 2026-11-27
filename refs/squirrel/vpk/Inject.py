# importing the modules
import os
import shutil
import time

# Providing the folder path
cheat = 'PATH_TO_WHERE_THE_FOLDER_THAT_CHEATSFOLDER_IS_STORED/CheatsFolder/'
apexfolder = 'PATH_TO_APEX_LEGENDS_FOLDER/vpk/'

deletefile = 'PATH_TO_APEX_LEGENDS_FOLDER/client_frontend.bsp.pak000_000.vpk'
deletefile2 = 'PATH_TO_APEX_LEGENDS_FOLDER/englishclient_frontend.bsp.pak000_dir.vpk'

# Fetching the list of all the files
files = os.listdir(cheat)

# define the countdown func.
def countdown(t):
    
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        time.sleep(1)
        t -= 1
      
    print("Files deleted and you can now play!")

# Clearing the terminal
os.system('clear')

print("This is an Auto Injector for apex legends linux made by Snomn :)")
print("Type Inject to inject the hax")

while True:
	code = input("> ")
	if code == 'Inject' or 'inject':
		print("Injecting...")
		
		for file_name in files:
   			shutil.copy(cheat+file_name, apexfolder+file_name)
   			
   			time.sleep(1)
		print("Injected Successfully!")
		
		time.sleep(0.5)
		# input time in seconds
		t = input("Enter the time before the files are deleted in seconds: ")
  
		# function call
		countdown(int(t))
		
		os.remove(deletefile)
		os.remove(deletefile2)
	
	exit()
