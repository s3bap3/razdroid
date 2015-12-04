#!/usr/bin/python

#changelog
#06/11/15 Added -dp permissions types, updated -ap
#02/12/15 Added exported analysis for activities, providers, services and receivers. Added Providers (-ar) that were lost in translation. Added codes for Manifest interpretation
#03/12/15 Fixed permission issues
#04/12/15 Fixed secretcodes, special permissions and output

import sys
import signal
import os
import time
import subprocess
import re
import urllib


Path_aapt="aapt.exe"
Path_adb="adb.exe"


def signal_handler(signal, frame):
	print('=================')
	print('Execution aborted')
	print('=================')
	sys.exit(1)

def signal_exit(signal, frame):
    sys.exit(0)	

def usage ():
		print "\n\tUsage:"
		print "\t\trazroid.py -d{d,s} [Parameter]"
		print "\t\trazroid.py -d{e,g,l,p,q,u} "
		print "\t\trazroid.py -a{a,b,c,d,f i,l,m,p,q,r,s,x} [App]"
		print "\t\trazroid.py -l{l,m} [App]"
		print "\t\trazroid.py -s{a,c,m} {App} [Activity|Content Provider|Count]"
		print "\t\trazroid.py -si {Action} [App/Receiver]"
		print "\t\trazroid.py -ss {Service} {Code}"
		print "\t\trazroid.py -s{u|t} {USSD Code | Secret Code}"
		print "\t\trazroid.py -s{d|k}"
		print "\n\tDevice Enumeration"
		print "\t\t-dd\tDevice Dumpsys"
		print "\t\t-de\tDevice Environment"
		print "\t\t-du\tDevice Dumpstate"
		print "\t\t-dg\tDevice Getprop"
		print "\t\t-dl\tDevice Logcat"
		print "\t\t-dp\tDevice Permissions Types"
		print "\t\t-dq\tDevice Process List"
		print "\t\t-ds\tDevice Services"
		print "\n\tApps Enumeration"
		print "\t\t-aa\tApp Enumerate Activities"
		print "\t\t-ab\tApp Enumerate Broadcast Receiver"
		print "\t\t-ac\tApp Enumerate Content Providers"
		print "\t\t-ad\tApp Enumerate Data"
		print "\t\t-ae\tApp Enumerate Databases"
		print "\t\t-af\tApp Enumerate Features"
		print "\t\t-ai\tApp Enumerate Intents"
		print "\t\t-al\tApp Enumerate Libraries"
		print "\t\t-am\tApp Enumerate Metadata"
		print "\t\t-ap\tApp Enumerate Permissions"
		print "\t\t-aq\tApp Enumerate Dangerous Permissions"
		print "\t\t-ar\tApp Enumerate Content Resolver"
		print "\t\t-as\tApp Enumerate Services"
		print "\t\t-at\tApp Enumerate Secret Codes"
		print "\t\t-ax\tApp Enumerate Everything"
		print "\n\tListing"
		print "\t\t-lm\tDump Manifest"
		print "\t\t-ll\tList Installed Applications"
		print "\n\tExecute"
		print "\t\t-sa\tStart Activity"
		print "\t\t-sc\tAccess Content Providers"
		print "\t\t-sd\tSend Screen Touches"
		print "\t\t-si\tSend Broadcast Intent"
		print "\t\t-sk\tStart Keylogger"
		print "\t\t-sm\tStart Monkey"
		print "\t\t-ss\tStart Service"
		print "\t\t-st\tSend Secret codes"
		sys.exit()

		
def gather_apks ():
	apkdic={}
	apks = subprocess.check_output( Path_adb + ' shell pm list packages -f | awk -F ":" \'{print $2}\' | sed -e \'s/=/:/\'', shell=True)
	for line in apks.splitlines():
		(apkpath, pktname) = re.split(':',line)
		apkdic[pktname] = apkpath
	return apkdic

	
def getdevicename():
	flag = 0
	devname = ""
	try:
		output = subprocess.check_output( Path_adb + '  devices' , shell=True)
	except:
		print "\n[*] Unable to gather device information"
		sys.exit()
	for line in output.splitlines():
		if flag == 1 and line != "":
			devname = line
			break
		if "List of devices" in line:
			flag = 1
	if devname == "":
		print "\n[*] Error: Device not available"
		sys.exit()
	elif devname.split()[1] == "offline":
		print "\n[*] Error: Device offline"
		sys.exit()
	else:
		return devname.split()[0]

	
def applist(apkdic):
	print "Application List\n"
	print "%-50s %s" % ("Package","Path")
	for key in sorted(apkdic): 
		print "%-50s %s" % (key, apkdic[key])
	sys.exit()


def get_insecure_perm ():
	output = subprocess.check_output( Path_adb + ' shell pm list permissions -f | egrep "permission:|protectionLevel:" | cut -f 2 -d ":" ', shell=True)
	count = 0
	syspermissions = {}
	for line in output.split():
		count += 1
		if (count % 2 != 0):
			temp = line
		else:
			syspermissions[temp]	= line
	return syspermissions
			
def filter_permissions(outputraw):
	output=[]
	syspermissions = get_insecure_perm()
	for line in outputraw:
		try:
			if syspermissions[line] == 'dangerous' or syspermissions[line] == 'signature|system':
				output.append(line)
		except:
			pass
	return output

				
def parse_manifest (manifest):
	uses_feature = []
	uses_permission = []
	activity = []
	uses_library = []
	service = []
	receiver = []
	provider = []	
	meta_data = []
	intent_filter = []
	permissions=[]
	data = []
	cp_permission = []
	proteclevel = []
	flag=""
	parent=""
	temp_exp = ""
	
	for line in manifest.splitlines():
		if flag == "data" and "A: android" in line:
			try:
				(t1,line2,t2,t3,t4) = re.split('"',line)
			except:
				(t1,line2) = re.split('=',line)
			data.append("Data | " + parent + " | " + line2)
		if flag == "data" and "A: android" not in line:
			flag=parent	
		parent = flag
		if "E: uses-feature" in line:
			flag = "feature"
		elif "E: uses-permission" in line:
			flag = "uses_permission"
		elif "E: permission (" in line:
			flag = "permission"
		elif "android.permission" in line:
			flag = "uses_permission"
		elif "E: activity" in line:
			flag = "activity"
		elif "E: uses-library" in line:
			flag = "library"
		elif "E: service" in line:
			flag = "service"
		elif "E: receiver" in line:
			flag = "receiver"
		elif "E: provider" in line:
			flag = "provider"
		elif "E: meta-data" in line:
			flag = "meta-data"
		elif "E: action" in line:
			flag = "intent_filter"
		elif "E: category" in line:
			flag = "category"
		elif "E: data" in line:
			flag = "data"
		if "A: android:name" in line or "0x01010003" in line:
			(t1,line2,t2,t3,t4) = re.split('"',line)
			if flag == "feature":
				uses_feature.append(line2)
				flag = ""
			elif flag == "uses-permission":
				uses_permission.append(line2)
				flag = ""
			elif flag == "permission":
				permissions.append(line2)
				flag = line2
			elif flag == "activity":
				activity.append(line2)
				flag = line2
				temp_exp = "activity"
			elif flag == "uses_permission":
				uses_permission.append(line2)
				flag = line2
			elif flag == "cp-permission":
				cp_permission.append("Permission | " + parent + " | "+line2)
				flag = line2
			elif flag == "library":
				uses_library.append(line2)
				flag = line2
			elif flag == "service":
				service.append(line2)
				flag = line2
				temp_exp = "service"
			elif flag == "receiver":
				receiver.append(line2)
				flag = line2
				temp_exp = "receiver"
			elif flag == "provider":
				provider.append(line2)
				flag = line2
				temp_exp = "provider"
			elif flag == "meta-data":
				meta_data.append(line2)
				flag = "meta-data2"
			elif flag == "intent_filter" :
				intent_filter.append("Action | " + parent + " | "+line2)
				flag = parent
			elif flag == "category" :
				intent_filter.append("Category | " + parent + " | "+line2)
				flag = parent
		elif "A: android:value" in line or "A: android:resource" in line or "0x01010024" in line or "0x01010025" in line:
			try:
				(t1,line2,t2,t3,t4) = re.split('"',line)
			except:
				(t1,line2) = re.split('=',line)
			if flag == "meta-data2":
				meta_data.append(line2)
				flag = line2
		elif "A: android:permission(" in line or "0x01010006" in line:
			(t1,line2,t2,t3,t4) = re.split('"',line)
			cp_permission.append("Special Permission | " + parent + " | "+line2)
			flag = parent
		elif "A: android:readPermission" in line or "0x01010007" in line:
			(t1,line2,t2,t3,t4) = re.split('"',line)
			cp_permission.append("Read Permission | " + parent + " | "+line2)
			flag = parent
		elif "A: android:writePermission" in line or "0x01010008" in line:
			(t1,line2,t2,t3,t4) = re.split('"',line)
			cp_permission.append("Write Permission | " + parent + " | "+line2)
			flag = parent
		elif "A: android:protectionLevel" in line or "0x01010009" in line:
			(t1,t2,line2) = re.split('\)',line)
			if line2 == "0x0":
				level = "Normal"
			elif line2 == "0x1":
				level = "Dangerous"
			elif line2 == "0x2":
				level = "Signature"
			elif line2 == "0x3":
				level = "Signature or System"
			proteclevel.append("Protection Level | " + parent + " | "+level)
		elif "A: android:exported" in line or "0x01010010" in line:
			(t1,t2,line2) = re.split('\)',line)
			if line2 == "0x0":
				exported = "False"
			else:
				exported = "True"
			if temp_exp == "activity":
				temp = activity[-1]
				activity[-1] = ( temp + " "*(130-len(temp)) + "\t" + "Exported > " + exported)
			elif temp_exp == "service":
				temp = service[-1]
				service[-1] = ( temp + " "*(130-len(temp)) + "\t" + "Exported > " + exported)
			elif temp_exp == "receiver":
				temp = receiver[-1]
				receiver[-1] = ( temp + " "*(130-len(temp)) + "\t" + "Exported > " + exported)
			elif temp_exp == "provider":
				temp = provider[-1]
				provider[-1] = ( temp + " "*(130-len(temp)) + "\t" + "Exported > " + exported)
			temp_exp = ""
			
	uses_feature = list(set(uses_feature))
	uses_permission = list(set(uses_permission))
	uses_library = list(set(uses_library))
	intent_filter = list(set(intent_filter))
	permissions  = list(set(permissions))
	service  = list(set(service))
	
	return uses_feature, uses_permission, activity, uses_library, service, receiver, provider, meta_data, intent_filter, permissions , data, cp_permission, proteclevel
	
	
def printlists(list):
	if list != []:
		for line in list:
			try:
				(t1,t2,line2) = re.split(' \| ',line)
				print line2
			except:
				print line
	else:
		print "N/A"
				
def printwparents(list, newlist):
	if list != []:
		for line in list:
			print line
			for line2 in newlist:
				if "| " + line.split()[0] + " |" in line2:
					(line3,t1,line4) = re.split('\|',line2)
					print "\t" + line3 + ">" + line4
	else:
		print "N/A"


def printwparents_sc(data):
	code = 0
	secretcodes = []
	for dataline in data:
		if code == 1:
			(line3,act,line4) = re.split('\|',dataline)
			secretcodes.append("\t" + line3 + ">" + line4)
			code = 0
		if "android_secret_code" in dataline:
			code = 1
	if secretcodes != []:
		print "Action > android.provider.Telephony.SECRET_CODE" 
		printlists(secretcodes)


def touches():
	x_coord = ""
	y_coord = ""
	print "Type -1 <enter> to exit"
	while True:
		x_coord = input ("X Coord: ")
		y_coord = input ("Y Coord: ")
		if str(x_coord) == "-1" or str(y_coord) == "-1":
			break
		output = subprocess.check_output( Path_adb + ' shell input tap ' + str(x_coord) + ' ' + str(y_coord), shell=True)
		print output

				
def start_activities(action, app, activity, manifest):
	if action == "-sa" and activity != "":
		output = subprocess.check_output( Path_adb + ' shell am start -n ' + app + '/' + activity, shell=True)
		#am start -a Action(Intent) -n Apk/Activity
		print output
	elif action == "-sa" and activity == "":
		(uses_feature, uses_permission, activity, uses_library, service, receiver, provider, meta_data, intent_filter, permissions , data)=parse_manifest(manifest)
		for line in activity:
			output = subprocess.check_output( Path_adb + ' shell am start -n ' + app + '/' + line, shell=True)
			print line + "\n" + str(output.splitlines()[:3]) + "\n" 
	elif action =="-sc" and activity != "":
		output = subprocess.check_output( Path_adb + ' shell content query --uri ' + activity, shell=True)
		print activity + "\n" + output
	elif action =="-sc" and activity == "":
		temp = subprocess.check_output('unzip -p ' + directory + '/' + app + ' | strings | egrep "content://[a-zA-Z]" | sed -e "s/.*content:/content:/"', shell=True)
		for line in temp.splitlines():
			output = subprocess.check_output( Path_adb + ' shell content query --uri ' + line, shell=True)
			print line + "\n" + str(output.splitlines()[:3]) + "\n" 
	elif action =="-si" and activity != "":
		output = subprocess.check_output( Path_adb + ' shell am broadcast -a ' + app + ' -n ' + activity, shell=True)
		print app + "\n" + str(output.splitlines()[:3])
	elif action =="-si" and activity == "":
		output = subprocess.check_output( Path_adb + ' shell am broadcast -a ' + app, shell=True)
		print str(output.splitlines()[:3])
	elif action =="-ss":
		output = subprocess.check_output( Path_adb + ' shell service call ' + app + '  ' + activity, shell=True)
		print output
	elif action =="-sm":
		output = subprocess.check_output( Path_adb + ' shell monkey -p ' + app + '  ' + activity, shell=True)
		print output
	elif action =="-sk":
		output = subprocess.check_output( Path_adb + ' shell getevent -l | grep -A 2 DOWN', shell=True)
		print output
	elif action =="-sd":
		touches()
		print "Executing USSD Code\n" + urllib.quote_plus(app)
	elif action =="-st":
		output = subprocess.check_output( Path_adb + ' shell am broadcast -a android.provider.Telephony.SECRET_CODE -d android_secret_code://' + app, shell=True)
		print "Executing Secret Code\n" + output 

				
def downloadapp(apk, app):
	if not os.path.isfile (directory + '/' + app):
		print "[*] Downloading App " + app
		try:
			output = subprocess.call( Path_adb + ' pull ' + apk[1:] + ' ' + directory + '/' + app, stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT, shell=True)
		except:
			print "[*] Invalid App"
			usage()
	#else:
		#print "[*] App "+ app + " already exists"
	

def apps_enumeration (manifest, app, action, apkdic,status):
	output = []
	outputraw=[]
	(uses_feature, uses_permission, activity, uses_library, service, receiver, provider, meta_data, intent_filter, permissions , data, cp_permission, proteclevel)=parse_manifest(manifest)
	newlist= intent_filter + data + proteclevel + cp_permission
	if action == "-aa":
		if (activity != [] and status == 1) or status == 0:
			print ('\nActivities (' + app + ')\n==========')
			printlists (activity)
	elif action == "-ab":
		if (receiver != [] and status == 1) or status == 0:
			print ('\nBroadcast Receivers (' + app + ')\n===================')
			printlists (receiver)
	elif action == "-as":
		if (service != [] and status == 1) or status == 0:
			print ('\nServices (' + app + ')\n========')
			printlists (service)
	elif action == "-ad":
		if (data != [] and status == 1) or status == 0:
			print ('\nData (' + app + ')\n====')
			printlists (data)
	elif action == "-ar":
		temp = subprocess.check_output('unzip -p ' + directory + '/' + app + ' | strings | egrep "content://[a-zA-Z]" | sed -e "s/.*content:/content:/"', shell=True)
		if temp != "":
			print ('\nContent Resolver (' + app + ')\n================\n' + temp)
		else:
			print ('\nContent Resolver (' + app + ')\n================\n' + "N/A")
	elif action == "-ae":
		temp = subprocess.check_output('unzip -p ' + directory + '/' + app + ' | strings | grep "\.db.\?$" | sed -e "s/\t//"', shell=True)
		if temp != "":
			print ('\nDatabases (' + app + ')\n=========\n' + temp)
		else:
			print ('\nDatabases (' + app + ')\n=========\n' + "N/A")
	elif action == "-ap":
		if (uses_permission != [] and status == 1) or status == 0:
			print ('\nPermissions \n===========')
			print "[*] Required"
			printlists (uses_permission)
			print "[*] Exported"
			printlists (permissions)
	elif action == "-ai":
		if (intent_filter != [] and status == 1) or status == 0:
			print ('\nActions (' + app + ')\n=======')
			printlists (intent_filter)
	elif action == "-af":
		if (uses_feature != [] and status == 1) or status == 0:
			print ('\nFeatures (' + app + ')\n========')
			printlists (uses_feature)
	elif action == "-al":
		if (uses_library != [] and status == 1) or status == 0:
			print ('\nLibraries (' + app + ')\n=========')
			printlists (uses_library)
	elif action == "-am":
		if (meta_data != [] and status == 1) or status == 0:
			print ('\nMeta-Data (' + app + ')\n=========')
			printlists (meta_data)
	elif action == "-at":
		print ('\nSecret codes \n============')
		printwparents_sc (data)   
	elif action == "-ac":
		print ('\nContent Providers \n=================')
		printlists (provider)
	elif action == "-ax":
		print "\n[*] Analysis for app " + app
		if (activity != [] and status == 1) or status == 0:
			print ('\nActivities\n==========')
			printwparents (activity, newlist)
		if (receiver != [] and status == 1) or status == 0:
			print ('\nBroadcast Receivers\n===================')
			printwparents (receiver, newlist)
		if (service != [] and status == 1) or status == 0:
			print ('\nServices\n========')
			printwparents (service, newlist)
		temp = subprocess.check_output('unzip -p ' + directory + '/' + app + ' | strings | egrep "content://[a-zA-Z]" | sed -e "s/.*content:/content:/"', shell=True)
		if (temp != "" and status == 1) or status == 0:
			print ('\nContent Resolver\n================\n' + temp)
		if (uses_permission != [] and status == 1) or status == 0:
			print ('\nPermissions \n===========')
			print "[*] Required"
			printlists (uses_permission)
			print "[*] Exported"
			printwparents (permissions,newlist)
		if (uses_feature != [] and status == 1) or status == 0:
			print ('\nFeatures\n========')
			printwparents (uses_feature, newlist)
		if (provider != [] and status == 1) or status == 0:
			print ('\nContent Providers \n=================')
			printwparents (provider, newlist)
		if (uses_library != [] and status == 1) or status == 0:
			print ('\nLibraries\n=========')
			printwparents (uses_library, newlist)
		if (meta_data != [] and status == 1) or status == 0:
			print ('\nMeta-Data\n=========')
			printlists (meta_data)
		print ('\nSecret codes \n============')
		printwparents_sc (data)  
		if (status == 1):
			print "\n=================="
	elif action == "-aq":
		temp = uses_permission + permissions
		output = filter_permissions(temp)
		if (output != [] and status == 1) or status == 0:
			print ('\nDangerous Permissions (' + app + ')\n=====================')
			printlists(output)
	elif action == "-lm":
		print manifest


def device_enumeration(action, parameter):
	if action == "-dd" and parameter == "":
		output = subprocess.check_output( Path_adb + ' shell dumpsys -l', shell=True)
	elif action == "-dd" and parameter != "":
		output = subprocess.check_output( Path_adb + ' shell dumpsys ' + parameter + ' -c', shell=True)
	elif action == "-ds" and parameter == "":
		output = subprocess.check_output( Path_adb + ' shell service list', shell=True)
	elif action == "-ds" and parameter != "":
		output = subprocess.check_output( Path_adb + ' shell service call ' + parameter, shell=True)
	elif action == "-dg":
		output = subprocess.check_output( Path_adb + ' shell getprop ', shell=True)
	elif action == "-dl":
		output = subprocess.check_output( Path_adb + ' shell logcat -d ', shell=True)
	elif action == "-du":
		output = subprocess.check_output( Path_adb + ' shell dumpstate ', shell=True)
	elif action == "-dp":
		syspermissions = get_insecure_perm()
		for line in ['normal','signature','dangerous','signature|system']:
			print "\nPermission Type: " + line + '\n========'
			for key in syspermissions:
				if syspermissions[key] == line:
					print key
		#output = str(syspermissions)
		output =""
	elif action == "-dq":
		output = subprocess.check_output( Path_adb + ' shell procrank', shell=True)
	elif action == "-de":
		output = subprocess.check_output( Path_adb + ' shell printenv ', shell=True)
	else:
		print "'\n[*] Unknown Option" 
		usage()
	print "\n" + output
	
	
def getmanifest(app):
	try:
		act = subprocess.check_output( Path_aapt + ' dump xmltree ' + directory + '/'+ app + ' AndroidManifest.xml' , shell=True)
		return act
	except:
		print "[*] Error getting Manifest"
		usage()
	
	
if __name__ == "__main__":
	actionslist = ["-dd","-de","-du","-dg","-dl","-dp","-dq","-ds","-aa","-ab","-ac","-ad","-ae","-af","-ai","-al","-am","-ap","-aq","-ar","-as","-at","-ax","-lm","-ll","-sa","-sc","-sd","-si","-sk","-sm","-ss","-st","-su",'-ft']
	signal.signal(signal.SIGINT, signal_handler)
	if (len(sys.argv) != 2 and len(sys.argv) != 3 and len(sys.argv) != 4):
		usage()
	action=sys.argv[1].lower()
	if action not in actionslist:
		print '\n[*] Uknown parameter'
		usage()
	try:
		app=sys.argv[2]
	except:
		app=""
	try:
		activity=sys.argv[3]
	except:
		activity=""
	oneparam = ['-su','-si','-sa','-sc','-sm', '-st']
	twoparam = ['-ss']
	if any ( param in action for param in oneparam):
		if app == "":
			print "'\n[*] Missing argument"
			usage()
	elif any ( param in action for param in twoparam):
		if app == "" or activity == "":
			print "'\n[*] Missing argument"
			usage()
	global devicename, directory
	devicename = getdevicename()
	directory = devicename.split(':', 1)[0]
	print "\nDevice Name: " + devicename
	apkdic = gather_apks()
	if "-ll" in action:
		applist(apkdic)
	elif ("-a" in action or "-l" in action) and (app == ""):
		for key in apkdic:
			downloadapp(apkdic[key], key)
			manifest = getmanifest(key)
			apps_enumeration(manifest, key, action, apkdic,1)
	elif ("-a" in action or "-l" in action) and (app != ""):
		downloadapp(apkdic[app], app)
		manifest = getmanifest(app)
		apps_enumeration(manifest, app, action, apkdic,0)
	elif "-d" in action:
		device_enumeration(action, app)
	elif action != "-sa" and action != "-sc":
		start_activities(action, app, activity, "")
	elif "-s" in action:
		manifest = getmanifest(app)
		start_activities(action, app, activity, manifest)
	else:
		print "'\n[*] Unknown parameter" 
		usage()			
