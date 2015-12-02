# Razroid
razroid is intended to be a framework to perform dynamic analysis and enumeration for Android devices and Applications. It consists in 4 main categories
- Device Enumeration
- App Enumeration
- Listing
- Execution

        Usage:
                razroid.py -d{d,s} [Parameter]
                razroid.py -d{e,g,l,p,q,u}
                razroid.py -a{a,b,c,d,f i,l,m,p,q,r,s,x} [App]
                razroid.py -l{l,m} [App]
                razroid.py -s{a,c,m} {App} [Activity|Content Provider|Count]
                razroid.py -si {Action} [App/Receiver]
                razroid.py -ss {Service} {Code}
                razroid.py -s{u|t} {USSD Code | Secret Code}
                razroid.py -s{d|k}

        Device Enumeration
                -dd     Device Dumpsys
                -de     Device Environment
                -du     Device Dumpstate
                -dg     Device Getprop
                -dl     Device Logcat
                -dp     Device Permissions Types
                -dq     Device Process List
                -ds     Device Services

        Apps Enumeration
                -aa     App Enumerate Activities
                -ab     App Enumerate Broadcast Receiver
                -ac     App Enumerate Content Providers
                -ad     App Enumerate Data
                -ae     App Enumerate Databases
                -af     App Enumerate Features
                -ai     App Enumerate Intents
                -al     App Enumerate Libraries
                -am     App Enumerate Metadata
                -ap     App Enumerate Permissions
                -aq     App Enumerate Dangerous Permissions
                -ar     App Enumerate Providers
                -as     App Enumerate Services
                -at     App Enumerate Secret Codes
                -ax     App Enumerate Everything

        Listing
                -lm     Dump Manifest
                -ll     List Installed Applications

        Execute
                -sa     Start Activity
                -sc     Access Content Providers
                -sd     Send Screen Touches
                -si     Send Broadcast Intent
                -sk     Start Keylogger
                -sm     Start Monkey
                -ss     Start Service
                -st     Send Secret codes
