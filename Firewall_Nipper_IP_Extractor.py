#/usr/bin/python
import re
import os

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

def banner():

        print O+'###########################################################################################'
        print '#                               <<<Firewall Nipper IP Extractor>>>                          #'
        print '#                                                            				   #'
        print '#                                Made by <<RISHABH SHARMA>>                                 #'
	print '#                                  Twitter : @blacknet22                                    #'
        print '#                                  operating system : KALI                                  #'
        print '#                                                                                           #'
        print '############################################################################################'


def Nipper_Vuln(Folder_Path,Output_Path):
	path = Folder_Path + '/'
	dirlist = os.listdir(path)
	path1 = Output_Path+ '/'
	print B+"Nipper Output..........."
	for filename in dirlist:
		ip =  '_'.join(filename.split('_')[0:4])
		ip = ip.replace('_','.')
		print BOLD+R+"IP ADDRESS: <<"+ip+">>"+END
		dir1 = Folder_Path+'/'+filename
		with open(dir1,'r') as f:
			content = f.readlines()
			count = 0
			for x in content:
				searchobj1 = re.search(r'(<span class="contentspart">3 <a href="#T133">Vulnerability Audit<\/a><\/span><br \/>)',x, re.I)
				searchobj = re.search(r'(<span class="contentssect">)(2\.\d)(.*)(">)(.*)(<\/a><\/span><br \/>)', x, re.I)
				if searchobj1:
					#print "breaking............."
					break
				if searchobj:
					count = count+1
					print O+"Total Vulnerability :"+str(count)
					a=  searchobj.group(5)
					a = a.replace('/',' ')
					vulpath = path1+a+'.txt'
					if os.path.isfile(vulpath):
						#print P+"File exist, Save IP in same file..."
						f = open(vulpath , 'a+')
						f.write(ip)
						f.write('\n')
						f.close()
					else:
						#print C+"File not exist, Creating new file..."
						f = open(vulpath , 'a+')
                                        	f.write(ip)
						f.write('\n')
                                        	f.close()


def CIS_Nipper(Folder_Path,CIS_Output):

	path = Folder_Path + '/'
        dirlist = os.listdir(path)
        path1 = CIS_Output+ '/'
	print B+"CIS Benchmark............"
	for filename in dirlist:
        	ip =  '_'.join(filename.split('_')[0:4])
        	ip = ip.replace('_','.')
        	print BOLD+R+"IP ADDRESS: <<"+ip+">>"+END
        	dir1 = Folder_Path+'/'+filename
        	with open(dir1,'r') as f:
                	content = f.readlines()
                	count = 0
                	for x in content:
                        	searchobj = re.search(r'(<tr><td>)([\w\s\']*)(<\/td><td>)(.*)(<\/td><td><a href=.*)(">.*)(<\/a><\/td><\/tr>)',x, re.I)
                        	searchobj1 = re.search(r'(<tr class="evenrow"><td>)([\w\s\']*)(<\/td><td>)(.*)(<\/td><td><a href=.*)(">.*)(<\/a><\/td><\/tr>)', x, re.I)
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
                                        	#print "file exist....................."
                                        	f = open(vulpath , 'a+')
                                        	f.write(ip)
                                        	f.write('\n')
                                        	f.close()
                                	else:
                                        	#print "file not exist........................."
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
                                        	#print "file exist....................."
                                        	f = open(vulpath , 'a+')
                                        	f.write(ip)
                                        	f.write('\n')
                                       		f.close()
                                	else:
                                        	#print "file not exist........................."
                                        	f = open(vulpath , 'a+')
                                        	f.write(ip)
                                        	f.write('\n')
                                        	f.close()

def main():
        banner()
	Folder_Path = raw_input(O+"Enter Folder Path Where All Nipper HTML Output Saved (ex: Nipper_Output): ")
	Output_Path = raw_input(O+"Enter Output Folder Name (ex: Nipper_Output): ")
	if not os.path.exists(Output_Path):
		os.makedirs(Output_Path)
	CIS_Output  = raw_input(O+"Enter Nipper CIS Output Folder Name (ex: CIS_Output): ")
	if not os.path.exists(CIS_Output):
                os.makedirs(CIS_Output)
	Nipper_Vuln(Folder_Path,Output_Path)
	CIS_Nipper(Folder_Path,CIS_Output)

if __name__ =='__main__':
        main()
