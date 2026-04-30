# Schema de semnătură digitală Guillou–Quisquater în Z\*<sub>n</sub>

> Proiect **Tehnici Criptografice Moderne**

Implementare în Java a schemei de semnătură digitală bazată pe identitate **Guillou–Quisquater**, împreună cu o demonstrație a protocolului și un benchmark comparativ față de **RSA**.

![Java](https://img.shields.io/badge/Java-8%2B-orange?logo=openjdk&logoColor=white)
![License](https://img.shields.io/badge/license-Academic-blue)
![Status](https://img.shields.io/badge/status-finalizat-brightgreen)

---

## Cuprins

1. [Descrierea fișierelor](#1-descrierea-fișierelor)
2. [Cerințe sistem](#2-cerințe-sistem)
3. [Compilare](#3-compilare)
4. [Rulare](#4-rulare)
5. [Rezultate așteptate](#5-rezultate-așteptate)
6. [Structura codului](#6-structura-codului)

---

## 1. Descrierea fișierelor

Proiectul conține **3 fișiere sursă Java** în directorul [`Implementare/`](Implementare/):

| Fișier                                              | Rol                                                                                                    |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`GQSignature.java`](Implementare/GQSignature.java) | Implementarea principală a algoritmului GQ (generare parametri, certificare, semnare, verificare)      |
| [`GQDemo.java`](Implementare/GQDemo.java)           | Demonstrație completă cu doi utilizatori (Alice și Bob). Include teste de integritate și autenticitate |
| [`GQBenchmark.java`](Implementare/GQBenchmark.java) | Măsurători comparative de performanță **GQ vs RSA**. Testează chei de 1024 și 2048 biți                |

În plus, în [`Docs/`](Docs/) se află referatul IEEE al proiectului:
[`GQ_Referat_IEEE.pdf`](Docs/GQ_Referat_IEEE.pdf).

---

## 2. Cerințe sistem

- **Java Development Kit (JDK) versiunea 8 sau mai nouă**

Verificare versiune:

```bash
java -version
javac -version
```

Dacă `javac` nu este disponibil, instalați JDK-ul complet:

| Sistem                | Instalare                                                         |
| --------------------- | ----------------------------------------------------------------- |
| Windows               | Descărcați de la [adoptium.net](https://adoptium.net/) sau Oracle |
| Linux (Ubuntu/Debian) | `sudo apt install default-jdk`                                    |
| macOS                 | `brew install openjdk`                                            |

---

## 3. Compilare

Deschideți un terminal în directorul [`Implementare/`](Implementare/) și rulați:

```bash
javac *.java
```

După compilare vor apărea fișierele `.class`:

- `GQSignature.class`
- `GQSignature$Semnatura.class` _(clasa internă pentru semnătură)_
- `GQDemo.class`
- `GQBenchmark.class`

> **Notă:** Fișierele `.class` sunt excluse din repository prin [`.gitignore`](.gitignore).

---

## 4. Rulare

### A) Demonstrația funcționalității

```bash
java GQDemo
```

Va afișa:

- Generarea parametrilor de sistem de către CA
- Înregistrarea utilizatorilor Alice și Bob
- Semnarea unui mesaj de către Alice
- Verificarea semnăturii de către Bob
- Test cu mesaj modificat (trebuie să fie **INVALID**)
- Test cu identitate falsă (trebuie să fie **INVALID**)
- Semnarea și verificarea unui mesaj de la Bob către Alice

### B) Benchmark — comparație performanță GQ vs RSA

```bash
java GQBenchmark
```

Va afișa:

- Timpi de execuție pentru chei de **1024 biți**
- Timpi de execuție pentru chei de **2048 biți**
- Comparație între GQ, RSA Signature și RSA Encryption

---

## 5. Rezultate așteptate

### A) La rularea `GQDemo`

```text

 DEMONSTRATIE SCHEMA GUILLOU-QUISQUATER

[PASUL 1] SETUP SISTEM - Autoritatea de Certificare (CA)
...
[PASUL 5] BOB VERIFICA SEMNATURA LUI ALICE
Rezultat verificare: VALIDA

[PASUL 6] TEST INTEGRITATE - Mesaj Modificat
Rezultat verificare: INVALIDA
Corect! Mesajul modificat a fost detectat.

[PASUL 7] TEST AUTENTICITATE - Identitate Falsa
Rezultat verificare: INVALIDA
Corect! Identitatea falsa a fost detectata.
...
TOATE TESTELE AU FOST EXECUTATE CU SUCCES!
```

### B) La rularea `GQBenchmark`

```text

 BENCHMARK GUILLOU-QUISQUATER vs RSA


--- Dimensiune cheie: 1024 biti ---

GUILLOU-QUISQUATER:
  Setup sistem:           XXX ms
  Generare certificat:    XXX ms
  Semnare (medie):        XXX ms
  Verificare (medie):     XXX ms
  Verificare valida:      DA
  Dimensiune semnatura:   XXX bytes

RSA SIGNATURE (SHA256withRSA):
  Generare chei:          XXX ms
  Semnare (medie):        XXX ms
  Verificare (medie):     XXX ms
  ...
```

---

## 6. Structura codului

### `GQSignature.java`

Clasa principală cu doi constructori:

- **`GQSignature(int bitLength, int k)`** — pentru Autoritatea de Certificare (CA)
  Generează parametrii: `p`, `q` (prime), `n = p·q`, `v = 65537`, `s = v⁻¹ mod φ(n)`
- **`GQSignature(BigInteger n, BigInteger v, int k)`** — pentru utilizatori obișnuiți
  Primește doar parametrii publici

**Metode principale:**

| Metodă                                                            | Descriere                       |
| ----------------------------------------------------------------- | ------------------------------- |
| `generareCertificat(String identitate)`                           | Calculează `J = H(ID)^s mod n`  |
| `semnare(String mesaj, String identitate, BigInteger certificat)` | Generează semnătura GQ          |
| `verificare(String mesaj, Semnatura sem)`                         | Verifică validitatea semnăturii |

### `GQDemo.java`

Demonstrație pas cu pas a protocolului complet.
Testează corectitudinea prin scenarii pozitive și negative.

### `GQBenchmark.java`

Măsurători de performanță cu **warmup JVM** și **100 de iterații**.
Compară GQ cu `java.security.Signature` (RSA) și `javax.crypto.Cipher` (RSA).
