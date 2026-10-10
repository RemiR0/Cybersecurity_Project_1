# 🛡️ Projet SIEM & IDS : Architecture de Sécurité et Détection d'Intrusions

![Ubuntu](https://img.shields.io/badge/OS-Ubuntu-E95420?logo=ubuntu&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Storage-Elasticsearch_8.x-005571?logo=elasticsearch&logoColor=white)
![Kibana](https://img.shields.io/badge/UI-Kibana_8.x-005571?logo=kibana&logoColor=white)
![Suricata](https://img.shields.io/badge/IDS-Suricata-EF3B2C?logo=suricata&logoColor=white)
![Apache](https://img.shields.io/badge/Web_Server-Apache2-D22128?logo=apache&logoColor=white)

---

## 📑 Sommaire
1. [Présentation du Projet](#1-présentation-du-projet)
2. [Architecture & Composants](#2-architecture--composants)
3. [Procédures d'Installation](#3-procédures-dinstallation)
4. [Scénarios d'Intrusion & Détection](#4-scénarios-dintrusion--détection)
5. [Visualisation Kibana & Dashboard](#5-visualisation-kibana--dashboard)
6. [Conclusion](#6-conclusion)

---

## 1. Présentation du Projet
Ce projet s'inscrit dans le cadre d'un TP de cybersécurité axé sur le déploiement d'une **stack SIEM (Security Information and Event Management)** et d'un **Système de Détection d'Intrusion (IDS)** centralisé sur un environnement Ubuntu.

L'objectif principal est de collecter, centraliser et analyser les journaux système/réseau en temps réel afin de détecter et visualiser **5 scénarios d'attaque web distincts** via l'interface Kibana.

---

## 2. Architecture & Composants

L'infrastructure s'articule autour des composants suivants :

| Composant | Rôle principal |
| :--- | :--- |
| **Apache2** | Serveur Web cible recevant le trafic légitime et malveillant. |
| **Suricata** | IDS/IPS Réseau chargé de l'inspection en direct du trafic et de la levée d'alertes. |
| **syslog-ng** | Collecteur centralisé de logs assurant le routage des événements système et applicatifs. |
| **Elasticsearch** | Moteur de recherche et de stockage de données indexées. |
| **Kibana** | Interface Web de visualisation (Discover, Analytics, Dashboards). |

---

## 3. Procédures d'Installation

### 3.1. Mise à jour du système & Dépendances
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget gnupg2 software-properties-common apt-transport-https
3.2. Installation d'Apache2
Bash
sudo apt install -y apache2
sudo systemctl enable --now apache2
3.3. Installation & Configuration de Suricata
Bash
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install -y suricata
sudo suricatanet-update
sudo systemctl enable --now suricata
3.4. Installation de Syslog-ng
Bash
sudo apt install -y syslog-ng
sudo systemctl enable --now syslog-ng
3.5. Déploiement de la Stack Elastic (Elasticsearch & Kibana)
Bash
# Ajout des clés et du dépôt Elastic
wget -qO - [https://artifacts.elastic.co/GPG-KEY-elasticsearch](https://artifacts.elastic.co/GPG-KEY-elasticsearch) | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] [https://artifacts.elastic.co/packages/8.x/apt](https://artifacts.elastic.co/packages/8.x/apt) stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt update
sudo apt install -y elasticsearch kibana

# Activation des services
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch kibana
sudo systemctl start elasticsearch kibana
4. Scénarios d'Intrusion & Détection
Les 5 scénarios suivants sont simulés et analysés à travers la stack :

🚨 Scénario 1 : Web Exploit (Injection / Payloads)
Description : Tentative d'exploitation de vulnérabilités applicatives sur le serveur Web.

Vecteur de simulation : Requêtes HTTP ciblées (curl / Web-Exploit).

Résultat / Log : (Insérer la capture Kibana ici)

🚨 Scénario 2 : Directory Traversal (/etc/passwd)
Description : Tentative de lecture de fichiers système sensibles via remontée de répertoires.

Vecteur de simulation : curl "http://127.0.0.1/index.php?file=../../../../etc/passwd"

Résultat / Log : (Insérer la capture Kibana ici)

🚨 Scénario 3 : Admin Reconnaissance / Scanning
Description : Balayage d'interfaces d'administration et de répertoires cachés (/admin, /phpmyadmin).

Vecteur de simulation : Requêtes d'énumération HTTP.

Résultat / Log : (Insérer la capture Kibana ici)

🚨 Scénario 4 : Scanner Nikto (User-Agent Malveillant)
Description : Audit automatisé via l'outil Nikto détecté par la signature de son User-Agent.

Vecteur de simulation : curl -A "Nikto" "http://127.0.0.1/"

Résultat / Log : (Insérer la capture Kibana ici)

🚨 Scénario 5 : Injection SQL (SQLi)
Description : Tentative d'injection de requêtes SQL non assainies dans les paramètres HTTP.

Vecteur de simulation : curl "http://127.0.0.1/login.php?user=' OR 1=1--"

Résultat / Log : (Insérer la capture Kibana ici)

5. Visualisation Kibana & Dashboard
Une fois la collecte opérationnelle dans Kibana, les logs sont filtrés dans Discover et agrégés dans un Dashboard centralisé.

📷 Capture globale de l'interface Kibana (Discover / Alerts Suricata) :
(Glissez-déposez votre capture générale Kibana ici)

6. Conclusion
L'intégration de Suricata et syslog-ng combinée à la puissance d'analyse de Elasticsearch & Kibana permet une supervision efficace du réseau et des applications. L'ensemble des 5 scénarios d'intrusion a permis de valider le fonctionnement de la chaîne de détection et d'alerte en temps réel.
