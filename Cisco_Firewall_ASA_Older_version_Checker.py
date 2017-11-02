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
        print '#                               <<<Cisco Firewall ASA Older Version Checker>>>              #'
        print '#                                                                                           #'
        print '#                                Made by <<RISHABH SHARMA>>                                 #'
        print '#                                  Twitter : @blacknet22                                    #'
        print '#                                  operating system : KALI                                  #'
        print '#                                                                                           #'
        print '############################################################################################'


def Version_Checker(Folder_Path,Version_Number):
	print BOLD+O+"Latest Version :"+Version_Number+END
	path = Folder_Path + '/'
        dirlist = os.listdir(path)
       # path1 = Output_Path+ '/'
 	count = 0 
        for filename in dirlist:
                ip =  '_'.join(filename.split('_')[0:4])
                ip = ip.replace('_','.')
                #print BOLD+R+"IP ADDRESS: <<"+ip+">>"+END
		count = count+1
		#count= str(count)
		#print BOLD+O+"Total File Analyse: "+count+END
                dir1 = Folder_Path+'/'+filename
                with open(dir1,'r') as f:
                        content = f.readlines()
                        
                        for x in content:
                                searchobj = re.search(r'(<tr><td>Cisco Adaptive Security Appliance Firewall<\/td><td>)(.*)(<\/td><td>[\w]+)(.)([\d\.\(\)]+)(<\/td><\/tr>)',x, re.I)
                                searchobj1 = re.search(r'(<p class="paragraphtitle">Security Audit Summary<\/p>)', x, re.I)
				if searchobj:
					olderversion = searchobj.group(5)
					olderversion = '('.join(olderversion.split('(')[0:1])
					if (olderversion == Version_Number):
						print ip+" : "+Version_Number+" :Latest_Version"
					else:
						
						if os.path.isfile("Older_Version.csv"):
							print C+ip+" : "+olderversion+END
							f = open("Older_Version.csv" , 'a+')
							oldv = ip+","+olderversion
                                                	f.write(oldv)
                                                	f.write('\n')
                                                	f.close()
                                        	else:
                                                	print C+ip+" : "+olderversion+END
                                                	f = open("Older_Version.csv" , 'a+')
							oldv = ip+","+olderversion
                                                	f.write(oldv)
                                                	f.write('\n')
                                                	f.close()
				if searchobj1:
					break

	count = str(count)
	print BOLD+O+"Total File Analyse: "+count+END

def main():
        banner()
        Folder_Path = raw_input(O+"Enter Folder Path Where All Nipper HTML Output Saved (ex: Nipper_Output): ")
	Version_Numer = raw_input(R+"Enter Latest Version of Cisco Adaptive Security Appliance Firewall (ex: 9.8): ")
	Version_Checker(Folder_Path,Version_Numer)

if __name__ =='__main__':
        main()
