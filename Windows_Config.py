#-*- coding=UTF-8 -*-
import subprocess
import os
import shutil
import io
import re
import time
f2 = open(r"c:\yyy(for).txt","w")
f2.close()


def get_user_sid_group():
	accontdict={}
	Group=["\"Administrators\"","\"Backup Operators\"","\"Power Users\"","\"Users\""]
	f2=open(r"c:\yyy(for).txt","a")
	for i in Group :
		catchstart=0
		commandline= "cmd.exe /c net localgroup " + i 
		readcmd=subprocess.check_output(commandline).splitlines()
		f2.write(i + "\n")
		for j in xrange(len(readcmd)-2):      #each group account
			if catchstart:
				if readcmd[j] in accontdict:
					accontdict[readcmd[j]].append(i)
				else :
					accontdict[readcmd[j]] = [i]
				f2.write("\t"+readcmd[j] + "\n")
			if "-----" in readcmd[j]:
				catchstart=1

	accontdict["*S-1-5-32-544"]=["\"Administrators\""]
	accontdict["*S-1-5-32-551"]=["\"Backup Operators\""]
	accontdict["*S-1-5-32-545"]=["\"Users\""]
	accontdict["*S-1-1-0"]=["\"Everyone\""]
	accontdict["Guest"]=["\"Guest\""]

	return accontdict

def write_to_file(item,is_pass):
	if is_pass:
		f2.write(item+" pass\n")
	else :
		f2.write(item+" fail\n")

def localuser_right(User_name,Group_Role,Group):
	is_pass=1

	for i in User_name.split(","):
		if is_pass:
			for j in Group_Role:
				Request_Group_Role = "\""+ j + "\""
				try:
					if Request_Group_Role in Group[ i.replace(" ","").rstrip() ] :
						is_pass = 1
						break
					is_pass = 0
				except :
					is_pass = 0
		else:
			break
	return is_pass
		

def patten (state,txt,Group):

	item=txt.split("=")
	if state == 1:

		if "PasswordComplexity" in item[0]:
			if int(item[1]) == 1 :
				f2.write(item[0]+"pass\n")
			else:
				f2.write(item[0]+"fail\n") 
		elif "MaximumPasswordAge" in item[0]:
			if int(item[1]) <= 90 :
				f2.write(item[0]+"pass\n")
			else:
				f2.write(item[0]+"fail\n")
		elif "MinimumPasswordLength" in item[0]:
			if int(item[1]) >= 6 :
				f2.write(item[0]+"pass\n")
			else:
				f2.write(item[0]+"fail\n")
		elif "PasswordHistorySize" in item[0]:
			if int(item[1]) >= 5 :
				f2.write(item[0]+"pass\n")
			else:
				f2.write(item[0]+"fail\n")
		elif "LockoutBadCount" in item[0]:
			if int(item[1]) <= 5 and int(item[1])!=0  :
				f2.write(item[0]+"pass\n")
			else:
				f2.write(item[0]+"fail\n")
		elif "EnableGuestAccount" in item[0]:
			if int(item[1]) ==0  :
				f2.write(item[0]+"pass =========>3-1項\n")
			else:
				f2.write(item[0]+"fail =========>3-1項\n")
		elif "LSAAnonymousNameLookup" in item[0]:
			if int(item[1]) ==0  :
				f2.write(item[0]+"pass =========>2-3項 \n")
			else:
				f2.write(item[0]+"fail =========>2-3項\n")
				
	elif state == 2:
		Audit_judgy_item=["AuditAccountLogon","AuditAccountManage","AuditLogonEvents","AuditPolicyChange","AuditSystemEvents"
		,"AuditDSAccess","AuditObjectAccess","AuditPrivilegeUse",
		]
		if "AuditProcessTracking" in item[0]:
			if int(item[1]) == 1 :
				f2.write(item[0]+"pass\n")
			else:
				f2.write(item[0]+"fail\n")

		if item[0].rstrip() in Audit_judgy_item:
			if int(item[1]) == 3 :
				f2.write(item[0]+"pass\n")
			else:
				f2.write(item[0]+"fail\n")

	elif state == 3:
		is_pass=0
		Adminrole=["SeTakeOwnershipPrivilege","SeNetworkLogonRight","SeLoadDriverPrivilege","SeSystemEnvironmentPrivilege",
		"SeSecurityPrivilege","SeIncreaseBasePriorityPrivilege","SeInteractiveLogonRight",]
		Backuprole=["SeBackupPrivilege","SeRestorePrivilege"]

		if item[0].rstrip() in Adminrole:
			is_pass=localuser_right(item[1],["Administrators"],Group)
			write_to_file(item[0],is_pass)
			print(item[0].rstrip())
		elif item[0].rstrip() in Backuprole:
			is_pass=localuser_right(item[1],["Backup Operators"],Group)
			write_to_file(item[0],is_pass)
		elif item[0].rstrip() == "SeShutdownPrivilege":
			is_pass=localuser_right(item[1],["Administrators","Backup Operators","Power Users","Users"],Group)
			write_to_file(item[0],is_pass)
		elif item[0].rstrip() == "SeSecurityPrivilege	":
			is_pass=localuser_right(item[1],["Administrators","Auditors"],Group)
			write_to_file(item[0],is_pass)


	elif state == 4:
		startoption=["RestrictAnonymous","RestrictAnonymousSAM","RestrictNullSessAccess","LimitBlankPasswordUse"]
		stopoption=["EveryoneIncludesAnonymous"]
		if "MaximumPasswordAge" in item[0]:	
			if int(item[1].split(",")[1]) <= 90:
				f2.write(item[0]+" pass\n")
			else:
				f2.write(item[0]+" fail\n")
		elif "CachedLogonsCount" in item[0]:
			if item[1].split(",")[1].rstrip() == "\"0\"":
				f2.write(item[0]+" pass\n")
			else:
				f2.write(item[0]+" fail\n")
		elif item[0].split("\\")[-1].rstrip() in startoption:
			if item[1].split(",")[1].rstrip() == "1":
				f2.write(item[0]+" pass\n")
			else:
				f2.write(item[0]+" fail\n")
		elif item[0].split("\\")[-1].rstrip() in stopoption:
			if item[1].split(",")[1].rstrip() == "0":
				f2.write(item[0]+" pass\n")
			else:
				f2.write(item[0]+" fail\n")

start_time=time.time()
group = get_user_sid_group()
subprocess.call("cmd.exe /c secedit /export /cfg c:\zz.txt && type c:\zz.txt > c:\zzz.txt")#cmd

with open(r"c:\zzz.txt","r") as f1:
	f2=open(r"c:\yyy(for).txt","a")
	state=0
	for i in f1:
		if "Access]" in i :
			state = 1
			f2.write("\n\n"+i)
		elif "Event Audit" in i:
			state = 2
			f2.write("\n\n"+i)
		elif "Privilege Rights" in i:
			state = 3
			f2.write("\n\n"+i)
		elif "Registry Values" in i:
			state = 4
			f2.write("\n\n"+i)
		patten(state,i,group)

os.remove(r"c:\zz.txt" )
os.remove(r"c:\zzz.txt")
print("--- %s seconds ---" % (time.time() - start_time))
f2.close()
