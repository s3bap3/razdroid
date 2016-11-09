#!/usr/bin/python

#changelog
#06/11/15 Added -dp permissions types, updated -ap
#02/12/15 Added exported analysis for activities, providers, services and receivers. Added Providers (-ar) that were lost in translation. Added codes for Manifest interpretation
#03/12/15 Fixed permission issues
#04/12/15 Fixed secretcodes, special permissions and output
#22/07/16 Added support for multiple devices connected, added support for screen touches as parameters
#31/08/16 Reestructuration of the apk, in order to include more functionalities in an easier way (SQLi, Path traversal, for example)
#11/10/16 Fixed issue with exported permissions and protection level
#"normal"	The default value. A lower-risk permission that gives requesting applications access to isolated application-level features, with minimal risk to other applications, the system, or the user. The system automatically grants this type of permission to a requesting application at installation, without asking for the user's explicit approval (though the user always has the option to review these permissions before installing).
#"dangerous"	A higher-risk permission that would give a requesting application access to private user data or control over the device that can negatively impact the user. Because this type of permission introduces potential risk, the system may not automatically grant it to the requesting application. For example, any dangerous permissions requested by an application may be displayed to the user and require confirmation before proceeding, or some other approach may be taken to avoid the user automatically allowing the use of such facilities.
#"signature"	A permission that the system grants only if the requesting application is signed with the same certificate as the application that declared the permission. If the certificates match, the system automatically grants the permission without notifying the user or asking for the user's explicit approval.
#"signatureOrSystem"	A permission that the system grants only to applications that are in the Android system image or that are signed with the same certificate as the application that declared the permission. Please avoid using this option, as the signature protection level should be sufficient for most needs and works regardless of exactly where applications are installed. The "signatureOrSystem" permission is used for certain special situations where multiple vendors have applications built into a system image and need to share specific features explicitly because they are being built together.

import sys
import signal
import os
import time
import subprocess
import re
import urllib


Path_aapt="aapt.exe"
Path_adb="adb.exe"
#Leave empty unless more than one device is connected at the same time
Device_Name=""


def signal_handler(signal, frame):
	print('=================')
	print('Execution aborted')
	print('=================')
	sys.exit(1)

def signal_exit(signal, frame):
    sys.exit(0)	

def usage (action):
	if action == "":
		print "\nUsage:"
		print "\trazroid.py -d{d,s} [Service]"
		print "\trazroid.py -d{e,g,l,p,q,u} "
		print "\trazroid.py -a{a,b,c,d,f i,l,m,p,q,r,s,x} [App]"
		print "\trazroid.py -l{l,m} [App]"
		print "\trazroid.py -e{a,c,m} {App} [Activity|Content Provider|Count]"
		print "\trazroid.py -ei {Action} [App/Receiver]"
		print "\trazroid.py -es {Service} {Code}"
		print "\trazroid.py -e{u|t} {USSD Code | Secret Code}"
		print "\trazroid.py -ek"
		print "\trazroid.py -ed [Xcoord Ycoord]"
		print "\trazroid.py -s{i,p} {App} {Content Provider}"
		print "\trazroid.py -sf"
		print "\nDevice Enumeration"
		print "\t-dd\tDevice Dumpsys"
		print "\t-de\tDevice Environment"
		print "\t-du\tDevice Dumpstate"
		print "\t-dg\tDevice Getprop"
		print "\t-dl\tDevice Logcat"
		print "\t-dp\tDevice Permissions Types"
		print "\t-dq\tDevice Process List"
		print "\t-ds\tDevice Services"
		print "\nApps Enumeration"
		print "\t-aa\tApp Enumerate Activities"
		print "\t-ab\tApp Enumerate Broadcast Receiver"
		print "\t-ac\tApp Enumerate Content Providers"
		print "\t-ad\tApp Enumerate Data"
		print "\t-ae\tApp Enumerate Databases"
		print "\t-af\tApp Enumerate Features"
		print "\t-ai\tApp Enumerate Intents"
		print "\t-al\tApp Enumerate Libraries"
		print "\t-am\tApp Enumerate Metadata"
		print "\t-ap\tApp Enumerate Permissions"
		print "\t-aq\tApp Enumerate Dangerous Permissions"
		print "\t-ar\tApp Enumerate Content Resolver"
		print "\t-as\tApp Enumerate Services"
		print "\t-at\tApp Enumerate Secret Codes"
		print "\t-ax\tApp Enumerate Everything"
		print "\nListing"
		print "\t-lm\tDump Manifest"
		print "\t-ll\tList Installed Applications"
		print "\nExecute"
		print "\t-ea\tExecute Activity"
		print "\t-ec\tExecute Content Providers"
		print "\t-ed\tExecute Screen Touches"
		print "\t-ei\tExecute Broadcast Intent"
		print "\t-ek\tExecute Keylogger"
		print "\t-em\tExecute Monkey"
		print "\t-es\tExecute Service"
		print "\t-et\tExecute Secret codes"
		print "\nScan"
		print "\t-sf\tScan Insecure File Permissions"
		print "\t-si\tScan SQLi in Content providers"
		print "\t-sp\tScan Path Traversal in Content providers"
		#print "\t\t-eu\tSend USSD Service" - Not implemented yet
	elif action == '-e' :
		print "\nExecute Usage"
		print "\tSend USSD Code Usage:"
		print "\t\trazroid.py -eu {USSD Code}"
		print "\tSend Broadcast Intent"
		print "\t\trazroid.py -ei {Action} [App/Receiver]"
		print "\tStart Activity"
		print "\t\trazroid.py -ea {App} [Activity]"
		print "\tAccess Content Providers"
		print "\t\trazroid.py -ec {App} [Content Provider]"
		print "\tStart Monkey"
		print "\t\trazroid.py -em {App} [Count]"
		print "\tSend Secret codes"
		print "\t\trazroid.py -et {Secret Code}"
		print "\tStart Service"
		print "\t\trazroid.py -es {Service} {Code}"
	elif action == '-s' :
		print "\nScan Usage"
		print "\tScan Insecure File Permissions"
		print "\t\trazroid.py -sf "
		print "\tScan SQLi in Content providers"
		print "\t\trazroid.py -si {App} {Content Provider}"
		print "\tScan Path Traversal in Content providers"
		print "\t\trazroid.py -sp {App} {Content Provider}"
	elif action =='-d' :
		print "\nDevice Enumeration"
		print "\tDevice Dumpsys"
		print "\t\trazroid.py -dd [Service]"
		print "\tDevice Environment"
		print "\t\trazroid.py -de "
		print "\tDevice Dumpstate"
		print "\t\trazroid.py -du"
		print "\tDevice Getprop"
		print "\t\trazroid.py -dg"
		print "\tDevice Logcat"
		print "\t\trazroid.py -dl"
		print "\tDevice Permissions Types"
		print "\t\trazroid.py -dp"
		print "\tDevice Process List"
		print "\t\trazroid.py -dq"
		print "\tDevice Services"
		print "\t\trazroid.py -ds [Service]"
	elif action == "-a" :
		print "\nApps Enumeration"
		print "\tApp Enumerate Activities"
		print "\t\trazroid.py -aa [Application]"
		print "\tApp Enumerate Broadcast Receiver"
		print "\t\trazroid.py -ab [Application]"
		print "\tApp Enumerate Content Providers"
		print "\t\trazroid.py -ac [Application]"
		print "\tApp Enumerate Data"
		print "\t\trazroid.py -ad [Application]"
		print "\tApp Enumerate Databases"
		print "\t\trazroid.py -ae [Application]"
		print "\tApp Enumerate Features"
		print "\t\trazroid.py -af [Application]"
		print "\tApp Enumerate Intents"
		print "\t\trazroid.py -ai [Application]"
		print "\tApp Enumerate Libraries"
		print "\t\trazroid.py -al [Application]"
		print "\tApp Enumerate Metadata"
		print "\t\trazroid.py -am [Application]"
		print "\tApp Enumerate Permissions"
		print "\t\trazroid.py -ap [Application]"
		print "\tApp Enumerate Dangerous Permissions"
		print "\t\trazroid.py -aq [Application]"
		print "\tApp Enumerate Content Resolver"
		print "\t\trazroid.py -ar [Application]"
		print "\tApp Enumerate Services"
		print "\t\trazroid.py -as [Application]"
		print "\tApp Enumerate Secret Codes"
		print "\t\trazroid.py -at [Application]"
		print "\tApp Enumerate Everything"
		print "\t\trazroid.py -ax [Application]"
	sys.exit(0)

		
def gather_apks ():
	apkdic={}
	apks = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell pm list packages -f | awk -F ":" \'{print $2}\' | sed -e \'s/=/:/\'', shell=True)
	for line in apks.splitlines():
		(apkpath, pktname) = re.split(':',line)
		apkdic[pktname] = apkpath
	return apkdic

	
def getdevicename():
	if Device_Name == "":
		flag = 0
		devname = ""
		try:
			output = subprocess.check_output( Path_adb + '  devices' , shell=True)
			if output.count("device") > 2:
				print "\n[*] Error: Multiple devices connected, edit the variable \'devicename\' within this file to add the device name"
				print output[output.find('\n')+1:output.rfind('\n')]
				sys.exit(1)
		except:
			print "\n[*] Unable to gather device information"
			sys.exit(1)
		for line in output.splitlines():
			if flag == 1 and line != "":
				devname = line
				break
			if "List of devices" in line:
				flag = 1
		if devname == "":
			print "\n[*] Error: Device not available"
			sys.exit(1)
		elif devname.split()[1] == "offline":
			print "\n[*] Error: Device offline"
			sys.exit(1)
		else:
			return devname.split()[0]
	else:
		return Device_Name

	
def applist(apkdic):
	print "Application List\n"
	print "%-50s %s" % ("Package","Path")
	for key in sorted(apkdic): 
		print "%-50s %s" % (key, apkdic[key])
	sys.exit(0)


def get_insecure_perm ():
	output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell pm list permissions -f | egrep "permission:|protectionLevel:" | cut -f 2 -d ":" ', shell=True)
	count = 0
	syspermissions = {}
	for line in output.split():
		count += 1
		if (count % 2 != 0):
			temp = line
		else:
			syspermissions[temp] = line
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
	authorities = []
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
		elif "E: permission" in line:
			flag = "permission"
		elif "android.permission" in line and flag != "permission":
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
		elif "A: android:authorities(" in line or "0x01010018" in line:
			try:
				(t1,line2,t2,t3,t4) = re.split('"',line)
				authorities.append("Authorities | " + parent + " | "+line2)
				flag = parent
			except:
				pass
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
			elif line2 == "0x3" or line2 == "0x12":
				level = "Signature | System"
			else:
				print "Level " + line
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
	
	return uses_feature, uses_permission, activity, uses_library, service, receiver, provider, meta_data, intent_filter, permissions , data, cp_permission, proteclevel, authorities
	
	
def printlists(list, newlist):
	if list != []:
		for line in list:
			print line
			for line2 in newlist:
					if "| " + line.split()[0] + " |" in line2:
						(line3,t1,line4) = re.split('\|',line2)
						print "\t" + line3 + ">" + line4
	else:
		print "N/A"
		

def printlists_sc(data):
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
		printlists(secretcodes, newlist)


def touches():
	x_coord = ""
	y_coord = ""
	print "Type -1 <enter> to exit"
	while True:
		x_coord = input ("X Coord: ")
		y_coord = input ("Y Coord: ")
		if str(x_coord) == "-1" or str(y_coord) == "-1":
			break
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell input tap ' + str(x_coord) + ' ' + str(y_coord), shell=True)
		print output

				
def execute_activities(action, app, activity, manifest):
	if action == "-ea" and activity != "":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell am start -n ' + app + '/' + activity, shell=True)
		print output
	elif action == "-ea" and activity == "":
		(uses_feature, uses_permission, activity, uses_library, service, receiver, provider, meta_data, intent_filter, permissions , data)=parse_manifest(manifest)
		for line in activity:
			output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell am start -n ' + app + '/' + line, shell=True)
			print line + "\n" + str(output.splitlines()[:3]) + "\n" 
	elif action =="-ec" and activity != "":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell content query --uri ' + activity, shell=True)
		print activity + "\n" + output
	elif action =="-ec" and activity == "":
		temp = subprocess.check_output('unzip -p ' + directory + '/' + app + ' | strings | egrep "content://[a-zA-Z]" | sed -e "s/.*content:/content:/"', shell=True)
		for line in temp.splitlines():
			output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell content query --uri ' + line, shell=True)
			print line + "\n" + str(output.splitlines()[:3]) + "\n" 
	elif action =="-ei" and activity != "":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell am broadcast -a ' + app + ' -n ' + activity, shell=True)
		print app + "\n" + str(output.splitlines()[:3])
	elif action =="-ei" and activity == "":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell am broadcast -a ' + app, shell=True)
		print str(output.splitlines()[:3])
	elif action =="-es":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell service call ' + app + '  ' + activity, shell=True)
		print output
	elif action =="-em":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell monkey -p ' + app + '  ' + activity, shell=True)
		print output
	elif action =="-ek":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell getevent -l | grep -A 2 DOWN', shell=True)
		print output
	elif action =="-ed" and app == "":
			touches()
	elif action =="-ed" and app != "" and activity == "":
		print "[*] Error: Missing coordenates"	
		sys.exit(1)
	elif action =="-ed" and app != "" and activity != "":
		print "Sending touch to device, coordinates " + app + ' ' + activity
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell input tap ' + str(app) + ' ' + str(activity), shell=True)
	elif action =="-et":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell am broadcast -a android.provider.Telephony.SECRET_CODE -d android_secret_code://' + app, shell=True)
		print "Executing Secret Code\n" + output 
	elif action =="-eu":
		print "Executing USSD Code\n" + urllib.quote_plus(app)
	else:
		usage("-e")
		
		
def scan_activities(action, app, activity, manifest):
	if action =="-si" and activity != "":
		print "\n[*] Testing for SQLi"
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell "content query --uri ' + activity + ' --projection \'* FROM sqlite_master;\'"', shell=True)
		if "Error" in output:
			print "[*] Invalid permissions"
			print output.splitlines()[2].split(": ")[1]
		else:
			print output
		for line in output.splitlines():
			if "Row" in line:
				table = line.split(" ")[3].split("=")[1].split(",")[0]
				print "[*] Performing SQLi in table %s" %(table)
				output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell "content query --uri ' + activity + ' --projection \'* FROM ' + table + ';\'"', shell=True)
				print output
	elif action =="-sp" and activity != "":
		pathtraversal = ["/../etc/hosts", "/../../etc/hosts", "/../../../etc/hosts", "/../../../../etc/hosts", "/../../../../../etc/hosts", "/../../../../../../etc/hosts", "/../../../../../../../etc/hosts"]
		print "\n[*] Testing for Path Traversal"
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell content read --uri ' + activity, shell=True)
		if "Unsupported operation: read" in output:
			print "[*] Unsupported method for this Android version"
		else:
			for traversal in pathtraversal:
				output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell content read --uri ' + activity + traversal , shell=True)
				if "127.0.0.1" in output:
					print "[*] Path Travesal identified, %s%s" %(activity,traversal)
	elif action =="-sf":
		print "\n[*] Gathering files with insecure permissions"
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell ls -lR /data/ | grep -e "^.......r" ', shell=True)
		print "\n[*] Files in /data/data with read all access"
		for line in output.splitlines():
			if not "->" in line:
				print line
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell ls -lR /data/ | grep -e "^........w" ', shell=True)
		print "\n[*] Files write all access"
		for line in output.splitlines():
			print line
	else:
		usage("-s")
	

def apps_enumeration (manifest, app, action, apkdic, status):
	output = []
	outputraw=[]
	#print "[*] Analyzing app %s" %(app)
	(uses_feature, uses_permission, activity, uses_library, service, receiver, provider, meta_data, intent_filter, permissions , data, cp_permission, proteclevel, authorities)=parse_manifest(manifest)
	newlist= intent_filter + data + proteclevel + cp_permission + authorities + intent_filter
	if action == "-aa":
		if (activity != [] and status == 1) or status == 0:
			print ('\nActivities (' + app + ')\n==========')
			printlists (activity, newlist)
	elif action == "-ab":
		if (receiver != [] and status == 1) or status == 0:
			print ('\nBroadcast Receivers (' + app + ')\n===================')
			printlists (receiver, newlist)
	elif action == "-as":
		if (service != [] and status == 1) or status == 0:
			print ('\nServices (' + app + ')\n========')
			printlists (service, newlist)
	elif action == "-ad":
		if (data != [] and status == 1) or status == 0:
			print ('\nData (' + app + ')\n====')
			printlists (data, newlist)
	elif action == "-ar":
		temp = (subprocess.check_output('unzip -p ' + directory + '/' + app + ' | strings | egrep "content://[a-zA-Z]" | sed -e "s/.*content:/content:/"', shell=True)) or "N/A"
		print ('\nContent Resolver (' + app + ')\n================\n' + temp)
	elif action == "-ae":
		temp = (subprocess.check_output('unzip -p ' + directory + '/' + app + ' | strings | grep "\.db.\?$" | sed -e "s/\t//"', shell=True)) or "N/A"
		print ('\nDatabases (' + app + ')\n=========\n' + temp)
	elif action == "-ap":
		if (uses_permission != [] and status == 1) or status == 0:
			print ('\nPermissions \n===========')
			print "[*] Required"
			printlists (uses_permission, "")
			print "[*] Exported"
			printlists (permissions, newlist)
	elif action == "-ai":
		if (intent_filter != [] and status == 1) or status == 0:
			print ('\nActions (' + app + ')\n=======')
			printlists (intent_filter, newlist)
	elif action == "-af":
		if (uses_feature != [] and status == 1) or status == 0:
			print ('\nFeatures (' + app + ')\n========')
			printlists (uses_feature, newlist)
	elif action == "-al":
		if (uses_library != [] and status == 1) or status == 0:
			print ('\nLibraries (' + app + ')\n=========')
			printlists (uses_library, newlist)
	elif action == "-am":
		if (meta_data != [] and status == 1) or status == 0:
			print ('\nMeta-Data (' + app + ')\n=========')
			printlists (meta_data, "")
	elif action == "-at":
		print ('\nSecret codes \n============')
		printlists_sc (data)
	elif action == "-ac":
		print ('\nContent Providers \n=================')
		printlists (provider, newlist)
	elif action == "-ax":
		print "\n[*] Analysis for app " + app
		apps_enumeration (manifest, app, "-aa", apkdic, status)
		apps_enumeration (manifest, app, "-ab", apkdic, status)
		apps_enumeration (manifest, app, "-ac", apkdic, status)
		apps_enumeration (manifest, app, "-ad", apkdic, status)
		apps_enumeration (manifest, app, "-ae", apkdic, status)
		apps_enumeration (manifest, app, "-af", apkdic, status)
		apps_enumeration (manifest, app, "-ai", apkdic, status)
		apps_enumeration (manifest, app, "-al", apkdic, status)
		apps_enumeration (manifest, app, "-am", apkdic, status)
		apps_enumeration (manifest, app, "-ap", apkdic, status)
		apps_enumeration (manifest, app, "-aq", apkdic, status)
		apps_enumeration (manifest, app, "-ar", apkdic, status)
		apps_enumeration (manifest, app, "-as", apkdic, status)
		apps_enumeration (manifest, app, "-at", apkdic, status)
		if (status == 1):
			print "\n=================="
	elif action == "-aq":
		temp = uses_permission + permissions
		output = filter_permissions(temp)
		if (output != [] and status == 1) or status == 0:
			print ('\nDangerous Permissions (' + app + ')\n=====================')
			printlists(output, newlist)
	elif action == "-lm":
		print manifest
	else:
		usage ("-a")


def device_enumeration(action, parameter):
	if action == "-dd" and parameter == "":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell dumpsys -l', shell=True)
	elif action == "-dd" and parameter != "":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell dumpsys ' + parameter + ' -c', shell=True)
	elif action == "-ds" and parameter == "":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell service list', shell=True)
	elif action == "-ds" and parameter != "":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell service call ' + parameter, shell=True)
	elif action == "-dg":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell getprop ', shell=True)
	elif action == "-dl":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell logcat -d ', shell=True)
	elif action == "-du":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell dumpstate ', shell=True)
	elif action == "-dp":
		syspermissions = get_insecure_perm()
		for line in ['normal','signature','dangerous','signature|system']:
			print "\nPermission Type: " + line + '\n========'
			for key in syspermissions:
				if syspermissions[key] == line:
					print key
		output =""
	elif action == "-dq":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell procrank', shell=True)
	elif action == "-de":
		output = subprocess.check_output( Path_adb + ' -s ' +  devicename + ' shell printenv ', shell=True)
	else:
		print "'\n[*] Unknown Option" 
		usage("")
	print "\n" + output
	
	
def list_device(action, apkdic, app):
	if "-ll" in action:
		applist(apkdic)
	elif "-lm" in action:
		if app:
			handler(action, app, apkdic, 0)
		else:
			for key in apkdic:
				print "[*] Manifest for App %s" %(key)
				handler(action, key, apkdic, 1)
				
			
def handler(action, app, apkdic, integer):
	if not os.path.isfile (directory + '/' + app):
		#print "[*] Downloading App %s" %(app)
		output = subprocess.call( Path_adb + ' -s ' +  devicename + ' pull ' + apkdic[app][1:] + ' ' + directory + '/' + app, stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT, shell=True)
	manifest = getmanifest(app)
	apps_enumeration(manifest, app, action, apkdic, integer)
	
	
def getmanifest(app):
	try:
		act = subprocess.check_output( Path_aapt + ' dump xmltree ' + directory + '/'+ app + ' AndroidManifest.xml' , shell=True)
		return act
	except:
		print "[*] Error getting Manifest for app %s" %(app)
		sys.exit(1)
	
	
if __name__ == "__main__":
	signal.signal(signal.SIGINT, signal_handler)
	if len(sys.argv) >1:
		global devicename, directory
		devicename = getdevicename()
		directory = devicename.split(':', 1)[0]
		print "\nDevice Name: " + devicename
		if "-d" in sys.argv[1].lower():
			if len(sys.argv) > 2:
				device_enumeration(sys.argv[1], sys.argv[2])
			else:
				device_enumeration(sys.argv[1], "")
		elif "-a" in sys.argv[1].lower():
			apkdic = gather_apks()
			if len(sys.argv) > 2:
				handler(sys.argv[1], sys.argv[2], apkdic, 0)
			else:
				for key in apkdic:
					handler(sys.argv[1], key, apkdic, 1)
		elif "-l" in sys.argv[1].lower():
			apkdic = gather_apks()
			if len(sys.argv) > 2:
				list_device(sys.argv[1], apkdic, sys.argv[2])
			else:
				list_device(sys.argv[1], apkdic, "")
		elif "-e" in sys.argv[1].lower()	:
			try:
				manifest = getmanifest(sys.argv[2])
				execute_activities(sys.argv[1], sys.argv[2], sys.argv[3], manifest)
			except:
				execute_activities(sys.argv[1], "", "", "")
		elif "-s" in sys.argv[1]:
			try:
				scan_activities(sys.argv[1], sys.argv[2], sys.argv[3], "")
			except:
				scan_activities(sys.argv[1], "", "", "")
		else:
			usage("")
	else:
		usage("")
