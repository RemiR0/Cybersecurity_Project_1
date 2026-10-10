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
