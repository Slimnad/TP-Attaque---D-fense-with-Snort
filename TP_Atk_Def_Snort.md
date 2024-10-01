# TP Attaque et Défense avec Snort (by Yanis)
*Voir procedure installation et configuration Snort3*

## Outils utilisés pour les attaques :
(notre target d'exemple est 10.0.0.105)

### Installation des outils :
(sudo si necessaire - mettre à jour les dépots)
(apt update - upgrade)

apt install nmap

apt install hydra-gtk

apt install hping3

- Nmap : pour les scans de ports et de services

nmap 10.0.0.105 (scan par défaut en TCP= SYN,SYN-ACK,ACK)

nmap -sS 10.0.0.105 (-sS = scan SYN seulement)

nmap -sS -f 10.0.105 (-f = active la fragmentation des paquets)

![image](https://github.com/user-attachments/assets/74145394-5684-426f-ad3e-ba64a7b4b002)


- Hydra : pour les attaques par force brute sur SSH

hydra -l user -P /chemin/vers/listemdp.txt 10.0.0.105 ssh

![image](https://github.com/user-attachments/assets/55396e59-8049-456c-997d-1debfbcc5537)


- DDoS basique : hping3 pour tester la robustesse contre les attaques de déni de service

hping3 -S --flood -V -p 443 10.0.0.105

    -S : Envoie des paquets SYN.
    --flood : Inonde la cible en envoyant des paquets aussi rapidement que possible.
    -V : Mode verbose pour afficher les détails.
    -p 443 : Spécifie que le flood sera dirigé vers le port 443 (HTTPS).

![image](https://github.com/user-attachments/assets/5c6567f8-4f38-44e6-9a8a-4848532304b1)



## Rules detection Snort3
(situé dans /etc/snort/rules/local.rules)

- Detectiond de ping : 

alert icmp any any -> any any (msg:"!!! ICMP Alert !!!";sid:1000001;rev:1;classtype:icmpevent;)

- Ecoute de port via Nmap :

alert tcp any any -> 10.0.0.112 1:1024 (msg:"Nmap TCP SYN scan detected";sid:1000002; rev:1;classtype:tcpevent;)

- Detection intrustion SSH :

alert tcp any any -> 10.0.0.112 22 (msg:"Possible SSH brute-force attempt";sid:1000003;rev:1;classtype:tcpevent;)
alert tcp any any -> 10.0.0.112 22 (msg:"!!! SSH ALERT !!!";sid:1000004;rev:1;classtype:tcpevent;)

- Detection HTTP et HTTPS :

alert tcp any any -> 10.0.0.112 443 (msg:"!!! HTTPS Alert !!!";sid:1000005;rev:1 classtype:icmpevent;)
alert tcp any any -> 10.0.0.112 80 (msg:"OSCUR HTTP ALERT !";sid:1000006;rev:1;)

![image](https://github.com/user-attachments/assets/02c0d202-0e35-4b8e-ade0-0a8cec5965de)

