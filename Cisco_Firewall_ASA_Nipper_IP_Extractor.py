#/usr/bin/python
import re
import os
import time

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
Y = '\033[93m'
BOLD = '\033[1m'
END = '\033[0m'

#banner

def banner():

        print O+'#############################################################################################'
        print '#                        <<<Cisco Firewall ASA Nipper IP Extractor>>>                       #'
        print '#                                                                                           #'
        print '#                                Made by <<RISHABH SHARMA>>                                 #'
	print '#                                  Twitter : @blacknet22                                    #'
        print '#                                 operating system : KALI                                   #'
        print '#                                                                                           #'
        print '#############################################################################################'+END


#For extracting IPs from Cisco Firewall ASA nipper HTML output and make file with vulnerabilities name.
def Nipper_Vuln(Folder_Path,Output_Path):
	path = Folder_Path + '/'
	dirlist = os.listdir(path)
	#use for counting files number
	countn = 0
	#Reading HTML output file from mentioned folder
	path1 = Output_Path+ '/'
	print B+"Nipper Output..........."
	for filename in dirlist:
		countn = countn + 1
		ip =  '_'.join(filename.split('_')[0:4])
		ip = ip.replace('_','.')
		print BOLD+R+"IP ADDRESS: <<"+ip+">>"+END
		dir1 = Folder_Path+'/'+filename
		with open(dir1,'r') as f:
			content = f.readlines()
			count = 0
			for x in content:
				#Help so that file do not read after analysing paticular part of HTML output
				searchobj1 = re.search(r'(<span class="contentspart">3 <a href="#T133">Vulnerability Audit<\/a><\/span><br \/>)',x, re.I)
				#Search for vulnerability pattern in HTML output 
				searchobj = re.search(r'(<span class="contentssect">)(2\.\d)(.*)(">)(.*)(<\/a><\/span><br \/>)', x, re.I)
				if searchobj1:
					break
				if searchobj:
					count = count+1
					print O+"Total Vulnerability :"+str(count)
					a=  searchobj.group(5)
					a = a.replace('/',' ')
					vulpath = path1+a+'.txt'
					if os.path.isfile(vulpath):
						#if file exist with name then it append IP in that file
						f = open(vulpath , 'a+')
						f.write(ip)
						f.write('\n')
						f.close()
					else:
						#if file not exist it made new file
						f = open(vulpath , 'a+')
                                        	f.write(ip)
						f.write('\n')
                                        	f.close()

	#Reading files number that analyse so that it confirm that all file analyse.
	countn = str(countn)
	print BOLD+O+"Total File Analyse :"+countn+END

#This method is for analysing Nipper CIS benchmark vulnerabilities 
def CIS_Nipper(Folder_Path,CIS_Output):

	path = Folder_Path + '/'
        dirlist = os.listdir(path)
	countc = 0
        path1 = CIS_Output+ '/'
	print B+"CIS Benchmark............"
	for filename in dirlist:
		countc = countc+1
        	ip =  '_'.join(filename.split('_')[0:4])
        	ip = ip.replace('_','.')
        	print BOLD+R+"IP ADDRESS: <<"+ip+">>"+END
        	dir1 = Folder_Path+'/'+filename
        	with open(dir1,'r') as f:
                	content = f.readlines()
                	count = 0
                	for x in content:
                        	searchobj = re.search(r'(<tr><td>)([\w\s\'\d\.\-\(\)]*)(<\/td><td>)(.*)(<\/td><td><a href=.*)(">.*)(<\/a><\/td><\/tr>)',x, re.I)
                        	searchobj1 = re.search(r'(<tr class="evenrow"><td>)([\w\s\'\d\.\-\(\)]*)(<\/td><td>)(.*)(<\/td><td><a href=.*)(">.*)(<\/a><\/td><\/tr>)', x, re.I)
				searchobj2 = re.search(r'(<div class="reportparttitle">\d\s)(.*)(Configuration Report<\/a><\/div>)',x, re.I)
				if searchobj2:
					print "Breaking......"
					break
				if searchobj:
					count = count+1
                                	print O+"Total Vulnerability :"+str(count)
					a =  searchobj.group(2)
                                	a = a.replace('/',' ')
                                	vulpath = path1+a+'.txt'
                                	if os.path.isfile(vulpath):
                                        	f = open(vulpath , 'a+')
                                        	f.write(ip)
                                        	f.write('\n')
                                        	f.close()
                                	else:
                                        	f = open(vulpath , 'a+')
                                        	f.write(ip)
                                        	f.write('\n')
                                        	f.close()
				if searchobj1:
                                	count = count+1
                                	print O+"Total Vulnerability :"+str(count)
					a =  searchobj1.group(2)
                                	a = a.replace('/',' ')
                                	vulpath = path1+a+'.txt'
					if os.path.isfile(vulpath):
                                        	f = open(vulpath , 'a+')
                                        	f.write(ip)
                                        	f.write('\n')
                                       		f.close()
                                	else:
                                        	f = open(vulpath , 'a+')
                                        	f.write(ip)
                                        	f.write('\n')
                                        	f.close()
	print BOLD+O+"Total File Analyse :"+str(countc)+END

#Making csv file for the nipper output
def file_to_nippercsv(Output_Path):
        path = Output_Path + '/'
        dirlist = os.listdir(path)
	countfn = 0
        print B+"Making CSV File...."+END
        for filename in dirlist:
		countfn = countfn+1
                vuln_name =  '.'.join(filename.split('.')[0:1])
                print BOLD+R+vuln_name+END
                path1 = 'Nipper_CSV.csv'
                f = open(path1 , 'a+')
                f.write('\n')
                f.write(vuln_name)
                f.write('\n')
                f.close()
                dir1 = Output_Path+'/'+filename
                with open(dir1,'r') as f:
                        content = f.readlines()
                        for x in content:
                                print O+x
                                path1 = 'Nipper_CSV.csv'
                                f = open(path1 , 'a+')
                                f.write(x)
                                f.close()
	print BOLD+Y+"Total File in Nipper Output Direcory Analyse :"+str(countfn)+END

#Making csv file for CIS benchmark
def file_to_CIScsv(CIS_Output):
        pathCIS = CIS_Output + '/'
        dirlist = os.listdir(pathCIS)
	countfc = 0
        print B+"Making CSV File...."+END
        for filename in dirlist:
		countfc = countfc+1
                vuln_name =  '.'.join(filename.split('.')[0:1])
                print BOLD+R+vuln_name+END
                path1 = 'CISNipper_CSV.csv'
                f = open(path1 , 'a+')
                f.write('\n')
                f.write(vuln_name)
                f.write('\n')
                f.close()
                dir1 = CIS_Output+'/'+filename
                with open(dir1,'r') as f:
                        content = f.readlines()
                        for x in content:
                                print O+x
                                path1 = 'CISNipper_CSV.csv'
                                f = open(path1 , 'a+')
                                f.write(x)
                                f.close()
	print BOLD+Y+"Total Files in CIS Output Directory Analyse :"+str(countfc)+END

#This help to find older version 
def Version_Checker(Folder_Path,Version_Number):
	print BOLD+O+"Latest Version :"+Version_Number+END
	path = Folder_Path + '/'
        dirlist = os.listdir(path)
 	countv = 0 
        for filename in dirlist:
                ip =  '_'.join(filename.split('_')[0:4])
                ip = ip.replace('_','.')
		countv = countv+1
                dir1 = Folder_Path+'/'+filename
                with open(dir1,'r') as f:
                        content = f.readlines()
                        for x in content:
                                searchobj = re.search(r'(<tr><td>Cisco Adaptive Security Appliance Firewall<\/td><td>)(.*)(<\/td><td>[\w]+)(.)([\d\.\(\)]+)(<\/td><\/tr>)',x, re.I)
                                searchobj1 = re.search(r'(<p class="paragraphtitle">Security Audit Summary<\/p>)', x, re.I)
				if searchobj:
					olderversion = searchobj.group(5)
					version = olderversion
					olderversion = '('.join(olderversion.split('(')[0:1])
					if (olderversion == Version_Number):
						print ip+" : "+Version_Number+" :Latest_Version"
					else:
						if os.path.isfile("Older_Version.csv"):
							print C+ip+" : "+olderversion+END
							f = open("Older_Version.csv" , 'a+')
							oldv = ip+",ASA Version "+version
                                                	f.write(oldv)
                                                	f.write('\n')
                                                	f.close()
                                        	else:
                                                	print C+ip+" : "+olderversion+END
                                                	f = open("Older_Version.csv" , 'a+')
							oldv = ip+",ASA Version "+version
                                                	f.write(oldv)
                                                	f.write('\n')
                                                	f.close()
				if searchobj1:
					break

	countv = str(countv)
	print BOLD+O+"Total File Analyse: "+countv+END

def main():
        banner()
	Note = raw_input(Y+"Nipper HTML output file naming is like this (ex:172_1_1_1_nipper_txt.html).Do you want to proceed? (Y/N): ")
	if (Note == "Y" or Note == "y"):

		Folder_Path = raw_input(O+"Enter Folder Path Where All Nipper HTML Output Saved (ex: Nipper_Output): ")
		Output_Path = raw_input(O+"Enter Output Folder Name (ex: Nipper_Output): ")
		if not os.path.exists(Output_Path):
			os.makedirs(Output_Path)
		CIS_Output  = raw_input(O+"Enter Nipper CIS Output Folder Name (ex: CIS_Output): ")
		if not os.path.exists(CIS_Output):
                	os.makedirs(CIS_Output)
		Nipper_Vuln(Folder_Path,Output_Path)
		CIS_Nipper(Folder_Path,CIS_Output)
		print BOLD+O+"Start Making CSV For Both Nipper and CIS....."+END
		time.sleep(5)
		file_to_nippercsv(Output_Path)
		file_to_CIScsv(CIS_Output)
		print BOLD+Y+"File Saved ....."+END
		versioncheck = raw_input(Y+"DO You want To Scan For Older Version (ex: Y/N):")
		if (versioncheck == 'Y'):
			Version_Number = raw_input(R+"Enter Latest Version of Cisco Adaptive Security Appliance Firewall (ex: 9.8): "+END)
			Version_Checker(Folder_Path,Version_Number)
		else:
			print BOLD+O+"Thanks For Using This Tool..."+END
	else:
		print BOLD+O+"Thanks For Using This Tool..."+END

if __name__ =='__main__':
        main()
