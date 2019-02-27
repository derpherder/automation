#!/usr/bin/env python3.5

'''
This script is designed to set up a group of new hosts for SSH
CLI Arguments: hostnames file and keys file 
The hostnames file will be used as a list to set up SSH
The hosts will have their keys copied locally
	nd combined with the keys file
The combined list will then be distributed to all hosts

Written By: Matt Thorson
Created Date: 20190217
Revision No: 1.0
Revision Date: 20190217
'''

import sys
import os
import argparse
import subprocess

# Parse the arguments to make sure we're receving a file
parser = argparse.ArgumentParser(description='Copy SSH keys between hosts input via file')
parser.add_argument('filename', help='the file to read containing hostnames')
parser.add_argument('keyfile', help='the file to read containing keys')
parser.add_argument('--vsersion','-v', action='version', version='%(prog)s 1.0')
args = parser.parse_args()

# Iinitialize an empty list for use with function stripjunk
cleanhosts = []

# Function "stripjunk" will create a hostnames list 
# The function will ignore empty lines and comment lines
def stripjunk(lineinfile):
	if (lineinfile.startswith("#") == False):
		if (lineinfile.isspace() == False):
			cleanhosts.append(lineinfile.strip())
       
def remotesetup(freshhost):
	# RUN: ssh-keygen on remote host
	# ssh = subprocess.Popen(["ssh", freshhost, "ls -la"], #ORIGINAL TEST FILE (REMOVE AFTER LIVE TEST)
	# I dont have a great place to test this and dont want to screw up fuji so the ssh command is untested
	# However, this whole script works fine with the commented out commands to perform virtually the same thing
	# There is probably something to be said for testing if this file exists before regenerating like this
	ssh = subprocess.Popen(["ssh", freshhost, "ssh-keygen -b 2048 -t rsa -f .ssh/id_rsa -q -N \"\""],
		shell=False,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE)
	result = ssh.stdout.readlines()
	ssh.wait()
	if result == []:
		error = ssh.stderr.readlines()
		print >>sys.stderr, "ERROR: %s" % error
	else:
		print(result)
	# RUN: Pull the SSH to localhost with SCP
	# scppath = freshhost + ":/home/ubuntu/sshpytest" #ORIGINAL TEST FILE (REMOVE AFTER LIVE TEST)
	scppath = freshhost + ":/root/.ssh/id_rsa.pub"
	scpfile = freshhost + ".deleteme"
	scp = subprocess.Popen(["scp", scppath, scpfile])
	scp.wait()
	currhost = open(scpfile)
	with open("tempkeys.deleteme", "a") as nk:
		for line in currhost:
			nk.write(line)

def copykeys(freshhost):
	#RUN: Send the completed keys file out to all the hosts via scp
	print("Running Copy Keys function") 
	# scppath2 = freshhost + ":/home/ubuntu/" #ORIGINAL TEST FILE (REMOVE AFTER LIVE TEST)
	scppath2 = freshhost + "://root/.ssh/authorized_keys"
	scpfile2 = "tempkeys.deleteme"
	scp = subprocess.Popen(["scp", scpfile2, scppath2])
	scp.wait()
	
def cleanup():
	try:
		tempfiles = os.listdir()
		for file in tempfiles:
			if file.endswith(".deleteme"):
				os.remove(file)
	except OSError:
		pass


# Clean up any "tempkeys" file that might be leftover from an erronous script run
#cleanup()

# Make sure we can open the file or we throw an error
try:
	f = open(args.filename)
	k = open(args.keyfile)
except:
        print("Unable to open file. Please pass one argument(file) which contains hostnames to run against")
        sys.exit(1)
else:
	with f:
		hostnames = f.readlines()
		with k:
			with open("tempkeys.deleteme", "w") as tk:
				for line in k:
					tk.write(line)
	for host in hostnames:
		stripjunk(host)
	for chost in cleanhosts:
		print(">>>> RUN Keygen and pull key on Host:" + chost)
		remotesetup(chost)
		print("##########################################")
	for chost in cleanhosts:
		print(">>>> COPYING KEYS to HOST:" + chost)
		copykeys(chost)
		print("##########################################")
	cleanup()

