from subprocess import call
from subprocess import check_output
import subprocess
import csv
import os, sys
import re
import shutil
import time
#This program will parse memory by using the volatility framework
#It will return .txt files into a folder so you can analyze the returned data
#******************************************
def Stripper (iterator):
    for line in iterator:
        if line[:1] == 'Volatility':
            continue
        if not line.strip():
            continue
        yield line
#******************************************
def separator( str ):
    'This prints a separator.'
    sep = ('******************************************')
    print sep
    return
#******************************************
def ALL( UserEnteredFile, os_profile, kdbg_selected, commands, nbr, amount_of_plugins ):
    'This function executes ALL plugins.'
    #prepares to write netscan results to a text file
    file_ = open(selection + '.txt', 'w')
    #******************************************
    #executes commands as if entered on command line and returns results to the screen and file_
    print('The {0} plugin is processing. {1} plugins remaining...').format(commands, nbr)
    call(['vol.py', '-f', UserEnteredFile, os_profile, kdbg_selected, commands], stdout=file_)
    file_.close()
    shutil.move(selection + '.txt', dir_path)
    print
    return
#******************************************
def selected_command( UserEnteredFile, os_profile, kdbg_selected, selected_plugin ):
    'This function executes the 1 selected plugin from the menu loop.'
    #change directory to previous directory where RAM is located
    os.chdir('..')
    #prepares to write netscan results to a text file
    file_ = open(selected_plugin +  '.txt', 'w')
    #******************************************
    #executes commands as if entered on command line and returns results to the screen and file_
    print('The %s plugin is processing. Please wait...' % selected_plugin)
    call(['vol.py', '-f', UserEnteredFile, os_profile, kdbg_selected, selected_plugin], stdout=file_)
    file_.close()
    #moves the created file to the created directory
    shutil.move(selected_plugin + '.txt', dir_path)
    print
    return
#******************************************
def imageinfo( UserEnteredFile ):
    'This function executes the imageinfo plugin.'
    #change directory to newly made dir
    print('The imageinfo plugin is processing. Please wait...')
    print
    #prepares to write imageinfo results to a text file
    file_ = open('imageinfo.txt', 'w')
    #executes commands as if entered on command line and returns results to the screen and file_
    call(['vol.py', '-f', UserEnteredFile, 'imageinfo'], stdout=file_)
    file_.close()
    imageinfo_file = open('imageinfo.txt')
    content = imageinfo_file.read()
    imageinfo_file.close()
    #prints the contents of the imageinfo file to the screen
    print(content)
    #moves the imageinfo.txt file to the created directory
    shutil.move('imageinfo.txt', dir_path)
    print
    return
#******************************************
def timeliner( UserEnteredFile, os_profile, kdbg_selected ):
    #prepares to write timeliner results to a csv file
    file_ = open('timeliner.csv', 'w')
    #executes commands as if entered on command line and returns results to the screen and file_
    print('The timeliner plugin is processing. 1 plugin remaining, please wait...')
    call(['vol.py', '-f', UserEnteredFile, os_profile, kdbg_selected, 'timeliner'], stdout=file_)
    file_.close()
    #moves the timeliner.csv file to the created directory
    shutil.move('timeliner.csv', dir_path)
    print
#******************************************
#os_profile = 'blank_place_holder'
def profile_to_use( profile ):
    global os_profile
    'This function selects a profile to use.'
    if len(profile) == 0:
        profile = 'Win7SP1x64'
    else:
        os_profile = '--profile='
        os_profile += str(profile)
        print
        print('You have selected the %s profile.' % profile)
    return os_profile
#*****************************************
kdbg_selected = 'blank_place_holder'
def KDBG():
    global kdbg_selected
    #print ('Your real path is %s.' % dir_path)
    #print
    #abs_path = os.path.abspath('.')
    #print ('Your absolute path is %s.' % abs_path)
    #print
    #cwd = os.getcwd()
    #print ('Your current working directory is %s.' % cwd)
    os.chdir(dir_path)
    #cwd = os.getcwd()
    print ('Your NEW current working directory is %s.' % cwd)
    print
    imageinfo_file = open('imageinfo.txt', 'r')
    #grabs the kdbg value from the imageinfo file.
    for line in imageinfo_file:
        line = line.lstrip()
        if not line.startswith('KDBG') :
            continue
            line = line.split()
            new = line.split()[2]
            #Slices the last character from the KDBG which is the trailing "L"
            KDBG_extracted = new[:-1]
            #Concatenates the --kdbg= and the entered KDBG
            kdbg_prefix = '--kdbg='
            kdbg_prefix += str(KDBG_extracted)
            kdbg_selected = kdbg_prefix
    print
    #Tells user which KDBG was entered
    print('The %s KDBG was used.' % KDBG_extracted)
    return kdbg_selected
    print imageinfo_file
#******************************************
def imageinfo_option( answer ):
    answer_two = raw_input('Skip imageinfo processing? Enter Y or N: ')
    while True:
        if answer_two.lower() == 'n':
            imageinfo(UserEnteredFile)
            print
            profile = raw_input('Step 2. Please enter a profile to use (e.g., Win7SP1x64): ')
            profile_to_use(profile)
            break
        elif answer_two.lower() == 'y':
            print
            profile = raw_input('Step 2. Please enter a profile to use (e.g., Win7SP1x64): ')
            profile_to_use(profile)
            #Slices the last character from the KDBG which is the trailing "L"
            print
            KDBG_entered = raw_input('Enter the KDBG: ')
            KDBG_entered = KDBG_entered[:-1]
            #Tells user which KDBG was entered
            print('The %s KDBG was used.' % KDBG_entered)
            #Concatenates the --kdbg= and the entered KDBG
            kdbg_selected = '--kdbg='
            kdbg_selected += str(KDBG_entered)
            #return kdbg_selected
        else:
            print('Please enter y / n')
        return
#******************************************
def countdown():
    wait = 3
    while wait > 0 :
        time.sleep(1)
        #print '*'
        wait = wait - 1
#******************************************
#plugins used in this program
commands = [ 'netscan', 'malfind', 'pslist', 'pstree', 'dlllist', 'psxview', 'getsids', 'envars',
'verinfo', 'consoles', 'privs', 'shimcache', 'ldrmodules', 'lsadump', 'hashdump', 'hivelist', 'symlinkscan', 'mutantscan', 'filescan', 'psscan', 'uninstallinfo', 'openvpn', 'apihooks' ]
#sorts the commands list alphabetically
commands.sort()
#******************************************
#tallys the amount of plugsin run
amount_of_plugins = len(commands)
amount_of_plugins = amount_of_plugins + 1
#******************************************
#Instructions
print
print('*****Welcome to Grande-Processor*****')
print
print('This program will proceess %s volatility plugins against a single RAM image.' % amount_of_plugins)
print
print('The default profile used is Win7SP1x64.')
print
print('Execute this program in the same directory as the memory file you want to process.')
print
print('Press Ctrl-C to exit.')
print
separator('now')
print
#******************************************
#Returns the present working directory where the file is located
dir_path = os.path.dirname(os.path.realpath(__file__))
print ('Your real path is %s.' % dir_path)
print
cwd_path = os.getcwd()
print ('Your current working directory is %s.' % cwd_path)
print
#Prompts user for file to parse
while True:
    fname = raw_input('Step 1. Please enter a file to parse (e.g. memory.raw): ')
    try:
        #if len(fname) == 0:
        #    fname = '11v019sp.raw'
            #determines if the file exists in the same directory as program
            if os.path.exists(fname):
                with open(fname) as fname:
                    print
                    print ('Success! Valid file selected.')
                    break
            else:
                print('Memory File Does Not Exist - Please try again (e.g. memory.raw).')
    except IOError: #prints IOError if file does not exist
        print('Memory File Does Not Exist, Please try again.')
#******************************************
#Extracts out the user entered file name from the raw_input
def UserEnteredFileFunction(fname):
    fname = str(fname)
    line = fname
    fnameSplit = line.split()
    fnameSplit[2]
    fnameSplitSTR = str(fnameSplit[2])
    #escapes on the ' character
    finalfnameSplit = fnameSplitSTR.split("\'")
    print
    #Assign it to a variable for use
    UserEnteredFile = finalfnameSplit[1]
    return UserEnteredFile
#******************************************
def profile_second_chance():
    while True:
        answer = raw_input('Is this the profile you want to use? Enter y or n: ')
        print
        answer = answer[0]
        if answer == 'y':
            break
        elif answer == 'n':
            profile = raw_input('Step 2. Please enter a profile to use (e.g., Win7SP1x64): ')
            profile_to_use( profile )
            continue
    return
#******************************************
#loop to provide a menu for user
#selected_plugin = []
all_plugins = None
ans = True
while ans:
    print ("""
    1. All Listed Plugins
    2. apihooks
    3. consoles
    4. dlllist
    5. envars
    6. filescan
    7. getsids
    8. hashdump
    9. hivelist
    10. ldrmodules
    11. lsadump
    12. malfind
    13. mutantscan
    14. netscan
    15. openvpn
    16. privs
    17. pslist
    18. psscan
    19. pstree
    20. psxview
    21. shimcache
    22. symlinkscan
    23. uninstallinfo
    24. verinfo
    25. Exit
    """)
   #selected_plugin = []
    ans = raw_input('Select a Volatility Plugin to Execute: ')
    if ans=='1':
        commands = [ 'netscan', 'malfind', 'pslist', 'pstree', 'dlllist', 'psxview', 'getsids', 'envars',
        'verinfo', 'consoles', 'privs', 'shimcache', 'ldrmodules', 'lsadump', 'hashdump', 'hivelist', 'symlinkscan', 'mutantscan', 'filescan', 'psscan', 'uninstallinfo', 'openvpn', 'apihooks' ]
        commands.sort()
        print 'You selected All Plugins.'
        break
    elif ans=='2':
        apihooks = 'apihooks'
        selected_plugin = apihooks
        print
        print 'You selected the apihooks plugin.'
        pass
    elif ans=='3':
        consoles = 'consoles'
        selected_plugin = consoles
        #selected_plugin.append(consoles)
        print
        print 'You selected the consoles plugin.'
        break
    elif ans=='4':
        dlllist = 'dlllist'
        selected_plugin = dlllist
        print
        print 'You selected the dlllist plugin.'
        break
    elif ans=='5':
        envars = 'envars'
        selected_plugin = envars
        print
        print 'You selected the envars plugin.'
        break
    elif ans=='6':
        filescan = 'filescan'
        selected_plugin = filescan
        print
        print 'You selected the filescan plugin.'
        break
    elif ans=='7':
        getsids = 'getsids'
        selected_plugin = getsids
        print
        print 'You selected the getsids plugin.'
        break
    elif ans=='8':
        hashdump = 'hashdump'
        selected_plugin = hashdump
        print
        print 'You selected the hashdump plugin.'
        break
    elif ans=='9':
        hivelist = 'hivelist'
        selected_plugin = hivelist
        print
        print 'You selected the hivelist plugin.'
        break
    elif ans=='10':
        ldrmodules = 'ldrmodules'
        selected_plugin = ldrmodules
        print
        print 'You selected the ldrmodules plugin.'
        break
    elif ans=='11':
        lsadump = 'lsadump'
        selected_plugin = lsadump
        print
        print 'You selected the lsadump plugin.'
        break
    elif ans=='12':
        malfind = 'malfind'
        selected_plugin = malfind
        print
        print 'You selected the malfind plugin.'
        break
    elif ans=='13':
        mutantscan = 'mutantscan'
        selected_plugin = mutantscan
        print
        print 'You selected the mutantscan plugin.'
        break
    elif ans=='14':
        netscan = 'netscan'
        selected_plugin = netscan
        print
        print 'You selected the netscan plugin.'
        break
    elif ans=='15':
        openvpn = 'openvpn'
        selected_plugin = openvpn
        print
        print 'You selected the openvpn plugin.'
        break
    elif ans=='16':
        privs = 'privs'
        selected_plugin = privs
        print
        print 'You selected the privs plugin.'
        break
    elif ans=='17':
        pslist = 'pslist'
        selected_plugin = pslist
        print
        print 'You selected the pslist plugin.'
        break
    elif ans=='18':
        psscan = 'psscan'
        selected_plugin = psscan
        print
        print 'You selected the psscan plugin.'
        break
    elif ans=='19':
        pstree = 'pstree'
        selected_plugin = pstree
        print
        print 'You selected the pstree plugin.'
        break
    elif ans=='20':
        psxview = 'psxview'
        selected_plugin = psxview
        print
        print 'You selected the psxview plugin.'
        break
    elif ans=='21':
        shimcache = 'shimcache'
        selected_plugin = shimcache
        print
        print 'You selected the shimcache plugin.'
        break
    elif ans=='22':
        symlinkscan = 'symlinkscan'
        selected_plugin = symlinkscan
        print
        print 'You selected the symlinkscan plugin.'
        break
    elif ans=='23':
        uninstallinfo = 'uninstallinfo'
        selected_plugin = uninstallinfo
        print
        print 'You selected the uninstallinfo plugin.'
        break
    elif ans=='24':
        verinfo = 'verinfo'
        selected_plugin = verinfo
        print
        print 'You selected the verinfo plugin.'
        break
    elif ans=='25':
        print 'Exit.'
        sys.exit()
        break
    elif ans==' ':
        print('Unknown Option Selected! Try again.')
        continue
    break
print
separator('now')
#******************************************
#Calls UserEnteredFileFunction to extract out the user entered file name
UserEnteredFile = UserEnteredFileFunction(fname)
#Sets the absolute path to the ram image - this allows above functions to work
UserEnteredFile = os.path.abspath(UserEnteredFile)
print('Image %s selected to process.') % UserEnteredFile
print
#******************************************
#Creates a folder to store the results from the plugins
#Converts filename to string for directory creation
dir_path = str(UserEnteredFile) + '_Output_Files'
#Creates a directory to store the results
#Checks to see if the output folder already exists, if so exits program
#This keeps the user from overwriting results from previous exexution
try:
    os.mkdir(dir_path)
except Exception as e:
    print('Checking to see if directory already exists')
    print
    countdown()
    print('1. The output folder already exists in the following directory:' )
    print
    print('%s') % dir_path
    countdown()
    print
    print('2. Rename or delete the output folder and re-execute GranderParser.')
    countdown()
    print
    print ('Exiting GranderParser')
    print
    exit()
#******************************************
answer_two = None
#prompts user to skip or use the imageinfo plugin
imageinfo_option(answer_two)
#gives absolute path of RAM image
path_of_memory = os.path.abspath(UserEnteredFile)
#******************************************
cwd_path = os.getcwd()
#print ('Your current working directory is %s.' % cwd_path)
print
#******************************************
#This loop processes ALL plugins
count_down_amt = len(commands)
count_down_amt = count_down_amt + 2
try:
    for c in commands:
        selection = c
        count_down_amt -= 1
        nbr = count_down_amt
        if ans == '1':
            ALL( UserEnteredFile, os_profile, kdbg_selected, selection, nbr, amount_of_plugins)
        else:
            selected_command( UserEnteredFile, os_profile, kdbg_selected, selected_plugin )
            break
        separator('now')
        print
except KeyboardInterrupt:
    print("W: interrupt received, stopping")
#******************************************
#executes the timeliner function...this creats a .csv file
if ans == '1':
    timeliner( UserEnteredFile, os_profile, kdbg_selected )
else:
    pass
#closes the memory file that was opened
fname.close()
#******************************************
separator('now')
print
print('Your file(s) are ready.')
print
print('Browse to the %s directory to locate the file(s)S.' % cwd_path)
print
abs_path = os.path.abspath('.')
print ('Your absolute path is %s.' % abs_path)
cwd = os.getcwd()
print ('Your current working directory is %s.' % cwd)
print
print('Tip: Open all of the file(s) in Notepad++ to leverage the \'Find All in All Opened Documents\' feature.')
print
