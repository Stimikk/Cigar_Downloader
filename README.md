# Cigar_Downloader
Multistage malware downloader


  ! informational and educational purposes only !


Cigar is a tool that create a multistage malware downloader.This tool will generate other scripts, 
change some attributes in PE header of your file and encrypt it.

Requirements:
- Python 3.7.x
- Windows 10

Usage
Before execute Cigar.py, install the requirements with 
pip install -r requirements.txt

Cigar expects for two parameters, url and file.
Url is your host from where the files will be downloaded.
Example:

python cigar.py -url https://HostWebsite.com -file myProgram.exe

Cigar will create two folders, stage_1 and stage_2
In stage_1, cigar will create the scripts that are responsible for execute the steps.
The first step is download a script that will create task in windows scheduler; this task will be 
executed in the next minute. During your execution, the task lock the screen, this happen to miss the
user attention for next actions, behind the scenes, the task download the encrypted malware from 
stage_2, decrypt it and create other task. This other task will execute your malware in the next 
minute.

After Cigar create the folders with the files, copy them to your web context to be downloaded. If 
your domain is https://someDomain.net, the scripts expect to find https://someDomain.net/stage_1 
and https://someDomain.net/stage_2.
You have to create a LNK file with one of the code that cigar generates to you!

Dont rename any file created!
