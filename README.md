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

### Dériver une clé AES de wrapping

`C_DeriveKey` prend en charge `CKM_AES_ECB_ENCRYPT_DATA`, avec une clé
maître AES de 16, 24 ou 32 octets. Les données utilisent
`CK_KEY_DERIVATION_STRING_DATA` et leur longueur doit être un multiple de
16 octets. Le mécanisme chiffre sans padding et conserve les premiers
octets du résultat. Référence : [OASIS, section 2.15](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html).

Exemple pour obtenir directement une clé AES-128 (16 **octets**, 128 bits) :

```cpp
// contextBlock : 16 octets préparés par l'application.
CK_KEY_DERIVATION_STRING_DATA data{contextBlock, 16};
CK_MECHANISM mechanism{CKM_AES_ECB_ENCRYPT_DATA, &data, sizeof(data)};
CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
CK_KEY_TYPE type = CKK_AES;
CK_ULONG size = 16;
CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
CK_ATTRIBUTE attributes[] = {
    {CKA_CLASS, &cls, sizeof(cls)},
    {CKA_KEY_TYPE, &type, sizeof(type)},
    {CKA_VALUE_LEN, &size, sizeof(size)},
    {CKA_TOKEN, &no, sizeof(no)},
    {CKA_WRAP, &yes, sizeof(yes)},
    {CKA_UNWRAP, &yes, sizeof(yes)}
};
CK_OBJECT_HANDLE derived;
CK_RV rv = functions->C_DeriveKey(session, &mechanism, masterWrappingKey,
                                 attributes, 6, &derived);
// Si rv == CKR_OK : utiliser derived dans C_WrapKey/C_UnwrapKey.
```

`CKA_KEY_TYPE=CKK_AES` et `CKA_VALUE_LEN` sont requis dans cette
implémentation ; tailles de sortie : 16, 24 ou 32 octets. Les données doivent
être assez longues (32 octets minimum pour une sortie de 24 ou 32 octets).
Le simulateur ne hache pas et ne complète pas automatiquement le contexte.
En ECB, modifier un bloc écarté par la troncature ne change pas la clé :
l'application doit préparer les blocs de contexte effectivement utilisés.

Une clé dérivée est un objet de session par défaut (`CKA_TOKEN=FALSE`),
visible aux autres sessions du même processus, détruit à la fermeture de la
session créatrice. `CKA_TOKEN=TRUE` la persiste dans `symmetric/` avec ses
métadonnées et exige une session RW. `CKA_TOKEN=FALSE` est également pris
en charge pour la génération et l'unwrapping.

`CKA_DERIVE` est lisible et contrôlé sur la clé maître. `CKA_WRAP` et
`CKA_UNWRAP` sont contrôlés sur la clé dérivée utilisée pour ces opérations.
`CKM_EXTRACT_KEY_FROM_KEY`, les autres dérivations et la sortie générique
`CKK_GENERIC_SECRET` ne sont pas implémentés.

Test : `ctest --test-dir out/build -R '^derive$' --output-on-failure`
(ajouter `-C Release` sous Visual Studio). Le script Windows lance aussi ce
test sauf avec `-MldsaOnly`. Les tests vérifient un vecteur AES-ECB connu,
la troncature, le wrapping/unwrapping, les erreurs et la durée de vie des clés.

### Autres mécanismes

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

Les attributs de politique sont maintenant enregistrés et appliqués (voir
ci-dessous). La recherche compare les mêmes valeurs que GetAttributeValue.
La suppression conserve pour l'instant une sémantique par fichier : tous les
objets issus du même PKCS#12, ainsi que son .meta, sont supprimés ensemble.

## Attributs et politiques

Les templates de génération, dérivation et unwrapping enregistrent les
attributs fournis. `C_GetAttributeValue` les restitue ; `C_SetAttributeValue`
permet de modifier les usages, `CKA_LABEL`, `CKA_ID` et les politiques ci-dessous.

| Attribut | Contrôle |
|---|---|
| CKA_SIGN / CKA_VERIFY | Signature / vérification, y compris multipart |
| CKA_WRAP / CKA_UNWRAP | Usage de la clé de wrapping / unwrapping |
| CKA_DERIVE | Usage de la clé maître pour dériver |
| CKA_EXTRACTABLE | Une clé non extractible ne peut pas être wrappée |
| CKA_SENSITIVE | Lecture de CKA_VALUE d'une clé AES interdite si sensible |
| CKA_TOKEN | Persistance ou durée de vie de session |
| CKA_MODIFIABLE | Autorisation de C_SetAttributeValue |
| CKA_DESTROYABLE | Autorisation de C_DestroyObject |

La lecture de `CKA_VALUE` AES est également interdite si `CKA_EXTRACTABLE=FALSE`.
Une clé sensible reste wrappable si elle est extractible. Les opérations
interdites renvoient `CKR_KEY_FUNCTION_NOT_PERMITTED`, le wrapping d'une clé
non extractible `CKR_KEY_UNEXTRACTABLE`, et la lecture interdite
`CKR_ATTRIBUTE_SENSITIVE` avec `CK_UNAVAILABLE_INFORMATION`.

`CKA_SENSITIVE` peut passer de FALSE à TRUE, jamais l'inverse ;
`CKA_EXTRACTABLE` peut passer de TRUE à FALSE, jamais l'inverse.
`CKA_TOKEN`, la classe, le type, la longueur et les paramètres de clé ne sont
pas modifiables par SetAttributeValue. Un template mal formé ou une tentative
de modification interdite est rejeté sans application partielle.
La modification ou suppression d'un objet token exige une session RW.

Compatibilité des valeurs par défaut : les templates incomplets et les anciens
fichiers conservent les valeurs historiques (SIGN pour les clés privées,
VERIFY pour les publiques, WRAP/UNWRAP/DERIVE pour AES ; EXTRACTABLE=TRUE,
SENSITIVE=FALSE, MODIFIABLE=TRUE, DESTROYABLE=TRUE).
Les autres usages sont FALSE. Génération/unwrapping restent persistants par
défaut ; la dérivation reste temporaire. Fournir les valeurs explicitement
pour reproduire précisément la politique de votre HSM.

Les métadonnées HSM2 conservent labels, IDs et politiques par classe d'objet.
Les fichiers HSM1 restent lisibles et passent en HSM2 à la première modification.
SetAttributeValue remplace atomiquement le fichier de métadonnées ; un échec
conserve l'ancien état en mémoire et ne supprime pas le fichier de clé.
Le renommage du label ne renomme pas le fichier de clé.

Limites : ce n'est pas l'ensemble des attributs PKCS#11. `CKA_ENCRYPT`,
`CKA_DECRYPT` et `CKA_PRIVATE` sont mémorisés, mais Encrypt/Decrypt restent
non implémentés et PRIVATE n'ajoute pas de contrôle d'accès au login simplifié.
Les attributs historiques LOCAL/ALWAYS_SENSITIVE/NEVER_EXTRACTABLE et les
templates de politique imbriqués ne sont pas exposés.
Les deux membres d'une paire générée doivent avoir la même valeur TOKEN ;
les paires mixtes sont rejetées. La suppression des objets token reste par
fichier et refuse de supprimer un membre si son frère est non destructible.
Ces contrôles ne protègent pas les fichiers sur disque.

Validation : 152 vérifications de politique, 62 de dérivation, 464 de
régression/persistance et le smoke test passent sous Linux/OpenSSL 3.0.13.
Le test `policy` est intégré à CTest et au script Windows ; Windows/OpenSSL
3.5 reste à valider.

## Tests effectués

### Tester sur Windows avec votre OpenSSL 3.5+

Prérequis : Visual Studio 2022 avec les outils C++ x64 et le SDK Windows,
CMake 3.24+ et CTest dans le PATH, une installation OpenSSL x64 avec ses
en-têtes, bibliothèques d'import et DLL correspondantes. Aucun build GitHub
Actions n'est déclenché par ces scripts.

Depuis la racine du dépôt dans PowerShell :

```powershell
git pull
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-windows.ps1 -OpenSslRoot "C:\OpenSSL-3.5"
```

Pour ne lancer que le test ML-DSA : ajouter `-MldsaOnly`. Le script compile
tous les exécutables mais sélectionne uniquement ce test lors de l'exécution.
Si votre arborescence OpenSSL est différente, utiliser `-OpenSslBin` pour
le répertoire d'openssl.exe et des DLL, et `-OpenSslCryptoLibrary` pour le
chemin complet de la bibliothèque d'import libcrypto.lib.

Une configuration oqsprovider existante peut être sélectionnée explicitement :

```powershell
.\scripts\test-windows.ps1 -OpenSslRoot "C:\OpenSSL-3.5" -OpenSslConfig "C:\OpenSSL-3.5\ssl\openssl.cnf" -OpenSslModules "C:\OpenSSL-3.5\lib\ossl-modules" -MldsaOnly
```

ML-DSA est fourni nativement par OpenSSL 3.5 ; liboqs/oqsprovider n'est pas
nécessaire pour ce test. Le script conserve la configuration OpenSSL héritée
si aucune option ne la remplace. Une configuration ne chargeant que
oqsprovider peut rendre indisponibles AES ou les encodeurs PKCS#12 : conserver
également le provider default. Le journal indique les providers disponibles ;
il ne prétend pas valider spécifiquement l'implémentation liboqs.

Le nouveau test `mldsa` couvre ML-DSA-44/65/87 : génération, attributs,
lecture PKCS#12 indépendante, signature/vérification dans les deux sens
DLL/EVP, signature altérée, multipart, buffers NULL et trop petits,
wrapping AES-256, rejet d'un blob altéré, suppression puis unwrapping,
et signature après Finalize/Initialize avec recherche de nouveaux handles.
Il compare aussi la clé rechargée avec la clé initiale.
AES-KW sans padding exige un PKCS#8 aligné sur 8 octets ; sinon le test
attend son rejet et effectue le parcours complet avec AES-KWP.
Ce test ne couvre pas HashML-DSA, les contextes non vides ni SLH-DSA.

CTest crée un token isolé pour chaque test. Les journaux sont dans
`out/windows-tests/test-*.log` et `out/windows-tests/Testing/Temporary/LastTest.log`.
Les tokens de test sont conservés sous `out/windows-tests/test-tokens` pour
diagnostic. Ils contiennent les clés privées de test : partager le journal,
pas le répertoire complet. Le script renvoie un code non nul en cas d'échec.
Un succès doit afficher `ML-DSA-44 PASS`, `ML-DSA-65 PASS`, `ML-DSA-87 PASS`
puis le succès CTest. Ces nouveaux tests restent à exécuter avec OpenSSL 3.5+
et sous Windows ; leur ajout ne constitue pas une validation réussie.

### Résultats précédents

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
- Login partagé entre sessions, contrôle d'accès PRIVATE, attributs de certificats,
  suppression individuelle des objets.
- Validation exhaustive des arguments/états et diagnostic des imports invalides.
- Écritures transactionnelles et accès interprocessus.
- Tests natifs VS2022 et tests avec une application PKCS#11 externe.
- OAEP optionnel. Les API de message, KEM, asynchrones et autres fonctions hors
  périmètre sont déclarées mais explicitement non supportées.

Les points d'entrée convertissent les exceptions C++ en codes PKCS#11 et
sérialisent les accès via un verrou commun. Cela ne rend pas valides les
pointeurs erronés d'un client et ne protège pas réellement les clés sur disque.
