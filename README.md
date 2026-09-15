# HSM Simulator — 0.6.0

Simulateur C++ pour Windows x64 / Visual Studio 2022, utilisant OpenSSL 3.5+.
L'interface utilise désormais les en-têtes officiels OASIS PKCS#11 3.2 fournis,
conservés sans modification dans include/oasis.

L'implémentation reste partielle : l'intégration des tables 3.2 est terminée,
mais la compatibilité de remplacement avec un client donné doit encore être
testée, notamment pour le PQC et sous Windows.

## Compilation VS 2022

OpenSSL est supposé déjà compilé en x64. Aucun téléchargement n'est effectué
par le preset CMake ; vcpkg n'est pas requis.

```powershell
cmake -S . -B out/build -G "Visual Studio 17 2022" -A x64 -DOPENSSL_ROOT_DIR=C:\OpenSSL-3.5
cmake --build out/build --config Release
ctest --test-dir out/build -C Release --output-on-failure
```

Sortie : out/build/Release/hsm-simulator.dll. Les DLL OpenSSL correspondantes
doivent être accessibles au processus client et aux tests (par exemple via PATH).
Le build Windows est limité à x64.

## Interface

- C_GetFunctionList renvoie la table historique 2.40.
- C_GetInterfaceList expose trois interfaces nommées "PKCS 11" : 3.2, 3.0 et 2.40.
- C_GetInterface sans version renvoie 3.2 ; une version explicite sélectionne
  la table correspondante. Les noms/versions/flags non supportés sont rejetés.
- Les 104 points d'entrée officiels sont exportés avec leurs prototypes réels.
- Les fonctions non implémentées renvoient CKR_FUNCTION_NOT_SUPPORTED.
- GetInfo annonce 3.2 : ce numéro décrit l'API, pas une certification de conformité.

Le wrapper include/pkcs11.h configure les macros de déclaration et le packing
Windows avant d'inclure les fichiers OASIS. Les tests compilent contre ces
mêmes définitions officielles. Les tables sont construites à partir de
pkcs11f.h plutôt qu'une liste d'offsets recopiée.

## Configuration et stockage

| Variable | Défaut | Usage |
|---|---|---|
| HSM_SIM_DATA_DIR | data | Racine du token |
| HSM_SIM_PIN | vide | PIN simplifié ; vide accepte tout PIN |
| HSM_SIM_P12_PASSWORD | vide | Mot de passe commun des PKCS#12 |

asymmetric/ contient les .p12/.pfx ; symmetric/ contient les clés AES .key
en hexadécimal. Les clés sont chargées à C_Initialize.
Un PKCS#12 expose une clé privée, une clé publique et un certificat si présent.
La génération n'invente pas de certificat.

La génération et l'unwrapping ajoutent un fichier .meta à côté de chaque clé.
Il conserve les labels exacts et les CKA_ID binaires par classe d'objet.
Conserver la clé et son .meta ensemble lors d'une copie ou sauvegarde.
Les templates public et privé peuvent avoir des labels distincts. Si un seul
fournit CKA_ID, cet ID est partagé. Sinon chaque ID explicite est conservé.

Les fichiers importés sans métadonnées restent lisibles : label = nom sans
extension ; ID par défaut = SHA-256 du nom avec extension. Ce défaut diffère
des versions antérieures à 0.4. Les noms de fichiers générés sont normalisés,
les labels exposés ne le sont pas. Les fichiers existants ne sont pas écrasés.

Les métadonnées sont publiées par fichier temporaire puis renommage. L'ensemble
clé + métadonnées n'est pas encore une transaction résistante aux coupures.
Utiliser un seul processus par répertoire de token. Un .meta invalide fait
échouer C_Initialize. Les fichiers de clés invalides nécessitent encore
une gestion d'erreur plus stricte.

## Cryptographie implémentée

- RSA PKCS#1 v1.5 brut et SHA-256/384/512 avec hachage intégré.
- RSA-PSS brut et SHA-256/384/512, paramètres copiés à Init, MGF1 et sel explicites.
- ECDSA brut et SHA-256/384/512 ; conversion DER OpenSSL vers r || s.
- Génération RSA, EC (OID DER dans CKA_EC_PARAMS) et AES.
- AES Key Wrap et Wrap Pad, IV par défaut uniquement ; clés privées en PKCS#8.
- Chemins EVP ML-DSA et SLH-DSA présents mais non testés avec OpenSSL 3.5.

CKM_RSA_PKCS signe les octets fournis sans hachage : le client fournit son
DigestInfo si nécessaire. CKM_ECDSA et CKM_RSA_PKCS_PSS reçoivent une empreinte.
Les mécanismes avec hachage intégré acceptent Update/Final ; le buffering
multipart est limité à 64 Mio. Les paramètres de signature hors RSA-PSS sont
encore rejetés, ainsi que les variantes Hash-PQC.

Les attributs de politique sont lisibles mais ne restreignent pas l'usage des
clés. La recherche compare les mêmes valeurs que GetAttributeValue.
La suppression conserve pour l'instant une sémantique par fichier : tous les
objets issus du même PKCS#12, ainsi que son .meta, sont supprimés ensemble.

## Tests effectués

Linux, GCC 13, OpenSSL 3.0.13 :

- 385 vérifications de chargement dynamique et d'interfaces ;
- 98 vérifications RSA/ECDSA ;
- 282 vérifications RSA-PSS ;
- 84 vérifications de persistance ;
- smoke test RSA/AES, wrapping et unwrapping.

Le test de chargement ne se lie pas au simulateur ; il utilise dlopen/dlsym
ou LoadLibrary/GetProcAddress. Les tests restent actifs en Release et CTest
crée des tokens uniques dans le répertoire de build, sans utiliser le token
configuré par l'utilisateur. Les trois en-têtes livrés ont été comparés
octet par octet aux fichiers fournis.

Windows/VS2022 et OpenSSL 3.5/PQC n'ont pas été exécutés ici. Les assertions
de layout Windows sont présentes, mais ne constituent pas un résultat de
compilation Windows.

## Travail restant

- PQC : contextes, hedge/déterminisme, variantes avec hachage et tests de tous
  les parameter sets avec OpenSSL 3.5.
- Objets de session, login partagé entre sessions, attributs de certificats,
  suppression individuelle des objets.
- Validation exhaustive des arguments/états et diagnostic des imports invalides.
- Écritures transactionnelles et accès interprocessus.
- Tests natifs VS2022 et tests avec une application PKCS#11 externe.
- OAEP optionnel. Les API de message, KEM, asynchrones et autres fonctions hors
  périmètre sont déclarées mais explicitement non supportées.

Les points d'entrée convertissent les exceptions C++ en codes PKCS#11 et
sérialisent les accès via un verrou commun. Cela ne rend pas valides les
pointeurs erronés d'un client et ne protège pas réellement les clés sur disque.
