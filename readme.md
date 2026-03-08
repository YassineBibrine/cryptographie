# Cryptographie 

# Partie : Implémentation RSA

## Description

Ce projet présente une implémentation pédagogique de l’algorithme de cryptographie asymétrique **RSA (Rivest–Shamir–Adleman)** en Python.

L’objectif du projet est d’illustrer les principes mathématiques fondamentaux de RSA ainsi que son fonctionnement algorithmique à travers une implémentation complète incluant :

* génération des clés RSA
* chiffrement et déchiffrement
* optimisation du déchiffrement par le **théorème des restes chinois (CRT)**
* vérification de propriétés mathématiques via des **tests unitaires**

Ce projet a été réalisé dans le cadre d’un travail académique sur la cryptographie.

---

## Structure du projet

```
cryptographie
│
├── RSA
│   └── rsa_implementation.py
│
├── requirements.txt
│
├── README.md
│
└── .gitignore
```

---

## Fonctionnalités implémentées

L’implémentation comprend les éléments suivants :

* **Algorithme d’Euclide étendu** pour le calcul de l’inverse modulaire
* **Génération des clés RSA**

  * génération de nombres premiers aléatoires
  * calcul du module RSA
  * calcul de φ(n)
  * détermination de la clé privée
* **Chiffrement RSA**

```
C = M^e mod n
```

* **Déchiffrement RSA**

```
M = C^d mod n
```

* **Optimisation CRT (Chinese Remainder Theorem)**
  permettant d’accélérer le déchiffrement RSA.

* **Tests unitaires** permettant de vérifier :

  * la validité du chiffrement/déchiffrement
  * la propriété d’Euler
  * la relation fondamentale RSA
  * la robustesse face aux cas limites

---

## Installation

### 1. Cloner le projet

```
git clone https://github.com/YassineBibrine/cryptographie.git
cd cryptographie
```

---

### 2. Créer un environnement virtuel Python

```
python -m venv venv
```

---

### 3. Activer l’environnement virtuel

Sous Linux / macOS / Git Bash :

```
source venv/Scripts/activate
```

Sous Windows (PowerShell) :

```
venv\Scripts\activate
```

---

### 4. Installer les dépendances

```
pip install -r requirements.txt
```

---

## Exécution

Pour lancer les tests de validation de l’implémentation RSA :

```
python RSA/rsa_implementation.py
```

Le programme exécute automatiquement une suite de **tests unitaires**.

Exemple de sortie :

```
test_encrypt_decrypt_basic ... ok
test_crt_vs_standard ... ok
test_euler_theorem ... ok
test_key_pair_relation ... ok
test_boundary_messages ... ok
test_invalid_message_raises ... ok
test_no_inverse_raises ... ok

Ran 7 tests

OK
```

---

## Concepts cryptographiques utilisés

L’algorithme RSA repose sur plusieurs concepts mathématiques fondamentaux :

* arithmétique modulaire
* nombres premiers
* indicatrice d’Euler φ(n)
* exponentiation modulaire
* difficulté de la **factorisation d’entiers**

La sécurité de RSA repose sur la difficulté computationnelle de factoriser un entier :

```
n = p × q
```

où `p` et `q` sont deux grands nombres premiers.

---

## Optimisation CRT

Le déchiffrement standard RSA utilise :

```
M = C^d mod n
```

Grâce au **théorème des restes chinois**, on peut effectuer deux calculs plus petits :

```
M mod p
M mod q
```

puis reconstruire la solution finale.

Cette méthode permet d’obtenir un déchiffrement **jusqu’à 4 fois plus rapide**.

---

## Auteurs

Projet réalisé par :

* Yassine Bibrine
* Membres de l’équipe du projet *Cryptographie*

---

## Licence

Ce projet est fourni à des fins éducatives et pédagogiques.
