RunAsLou - "Run As Logged On User"

This simple program needs to be run with SYSTEM credentials in order to
work correctly. This can be accomplished with a scheduled task, a Windows
service, or by using the free psexec program from Microsoft Sysinternals.

Why?
===========
This program is useful for when you want to run a program *as* the user
that is logged onto a remote system. This means the program you run with
RunAsLou will show the user as the owner of the process in task manager.

I have found this tool to be useful for system administrators that need
to run certain monitoring or administrative applications under the 
identity (eg with the user's token) of the logged on user.


How to use
===========
This program must be run with SYSTEM privileges to work!

For example, if I want to run notepad.exe interactively, *as* the user on a remote
system, I can use psexec and RunAsLou. Note that notepad will be running
as the user, but will also have SYSTEM credentials as well.

	psexec \\192.168.1.105 -u Administrator -p p@ssw0rd! -s -i -c RunAsLou.exe "c:\windows\notepad.exe"

 "-s" switch = run RunAsLou.exe under the SYSTEM account
 "-i" switch = run interactively on the user's desktop (this can be excluded 
				if you don't need the user to see the application)
 "-c" switch = copy the program (RunAsLou.exe) to the remote system and then execute it
