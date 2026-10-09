# Architecture et maintenance

Le simulateur expose une API C PKCS#11 et utilise des modules C++ internes dans
l'espace de noms `hsm`. Chaque `.cpp` est compilé séparément. Les `.hpp` décrivent
les contrats entre modules ; aucun fichier d'implémentation n'est inclus dans
un autre. Le découpage conserve les mécanismes et le stockage existants.

## Où lire et où modifier

| Répertoire / fichier | Responsabilité |
| --- | --- |
| `include/pkcs11.h` | Adaptateur ABI Windows/Linux : visibilité, convention d'appel et packing |
| `include/oasis/` | En-têtes officiels PKCS#11 3.2, à conserver sans modification |
| `src/pkcs11/entry_points.cpp` | Exports C des opérations implémentées, déléguant aux services internes |
| `src/pkcs11/unsupported.cpp` | Exports typés des opérations non prises en charge |
| `src/pkcs11/interfaces.cpp` | Tables 2.40/3.0/3.2 et découverte des interfaces |
| `src/pkcs11/boundary.hpp` | Verrouillage, contrôle d'initialisation et conversion des exceptions |
| `src/pkcs11/token.*` | Initialisation, finalisation, découverte des slots et informations des tokens |
| `src/pkcs11/sessions.*` | Sessions par slot, login USER/SO partagé, API PIN et durée de vie des objets de session |
| `src/core/runtime.*` | Types Slot/Object/Session/Operation, registre et contrôle d’accès par slot |
| `src/core/utilities.*` | Environnement, encodage hexadécimal et chaînes à largeur fixe |
| `src/core/openssl.hpp` | Propriété des allocations OpenSSL via des pointeurs RAII |
| `src/objects/template.*` | Lecture des templates d'attributs fournis par le client |
| `src/objects/policy.*` | Validation, valeurs par défaut et application des attributs booléens |
| `src/objects/attributes.*` | Lecture des attributs, conversion RSA/EC et modification persistante |
| `src/objects/objects.*` | Recherche et suppression des objets |
| `src/storage/key_store.*` | Chargement/sauvegarde des fichiers de clés et enregistrement des objets |
| `src/storage/slots.*` | Découverte des répertoires, lecture des mots de passe et remplacement atomique des PIN |
| `src/storage/metadata.*` | Lecture HSM1/HSM2 et écriture atomique des métadonnées |
| `src/crypto/mechanisms.*` | Catalogue PKCS#11 et correspondances avec les algorithmes OpenSSL |
| `src/crypto/key_generation.*` | Génération AES et de paires RSA, EC, ML-DSA, SLH-DSA ; aléatoire |
| `src/crypto/signature.*` | Signature/vérification, état multipart, PSS et conversion ECDSA |
| `src/crypto/wrapping.*` | AES-KW/AES-KWP et sérialisation PKCS#8 des clés privées |
| `src/crypto/derivation.*` | Dérivation AES-ECB et sélection des premiers octets |
| `src/hsm-simulator.def` | Noms publics non décorés des 104 exports Windows |
| `tests/` | Tests d'intégration utilisant l'API publique |

## Exemple de chemin d'appel

`C_Sign` dans `entry_points.cpp` appelle `invoke`, puis `hsm::Sign` dans
`signature.cpp`. Le service retrouve la session et son opération active,
contrôle les autorisations, appelle EVP et traduit le résultat en code PKCS#11.
La logique de signature ne manipule pas les tables de fonctions exportées.

Pour comprendre une génération, partir de `GenerateKeyPair`, puis consulter
`generationAlgorithm`, `applyCreationTemplate`, `saveKeyPair` et `registerKeyPair`.
Les contrôles de template précèdent la génération ; les métadonnées sont publiées
avant de rendre les handles au client.

## État, concurrence et propriété

Il existe un `RuntimeState` par module chargé : un registre ordonné de slots,
une racine de stockage, une table d'objets et une table de sessions. Un `Slot`
porte son répertoire, ses PIN, son mot de passe PKCS#12 et le rôle connecté.
Chaque `Object` et `Session` porte un `slotId`. Les handles sont uniques dans
le module et représentent des identifiants, jamais des adresses.

`findObject(sessionHandle, objectHandle)` impose l'appartenance au slot de la
session. Ne jamais utiliser directement `runtime.objects` pour résoudre un
handle fourni par le client. Après résolution, `objectAccessStatus` protège la
lecture/utilisation des objets ; `requireUserLogin` protège les mutations et
l'accès aux clés secrètes. Les boucles de recherche filtrent aussi le slot.
Le stockage des clés prend le répertoire et le mot de passe du slot explicite.

`C_Login` et `C_Logout` affectent toutes les sessions du slot. La fermeture de
sa dernière session réinitialise son login. `C_CloseAllSessions` ne touche que
le slot demandé. Logout annule ses opérations/recherches en cours et détruit
ses objets de session protégés. Les autres slots restent intacts.
La découverte n'est publiée qu'après validation ; un échec d'initialisation
vide les registres pour permettre une nouvelle tentative.

Toute opération publique avec état traverse `invoke`. Ce point prend un mutex,
vérifie l'initialisation si nécessaire, puis convertit les exceptions en codes
PKCS#11. Les services internes supposent ce verrou déjà détenu. **Ne pas appeler
un export `C_*` depuis un service interne** : appeler directement le service,
sinon le verrou non récursif serait repris. Les trois fonctions de découverte
des interfaces utilisent uniquement des tables statiques et sont disponibles
avant `C_Initialize`.

Les pointeurs renvoyés par `findObject` et `findSession` sont empruntés aux tables :
ne pas les conserver après suppression de l'entrée ou après l'appel public.
`OpenSslPtr` libère les objets OpenSSL temporaires. Les objets asymétriques
conservent leur clé EVP avec `std::shared_ptr`. `registerKeyPair` prend possession
de la clé et du certificat reçus et crée les objets privé, public puis certificat.
Les parcours de génération/unwrapping s'appuient encore sur cet ordre de handles.

`Object::ownerSession == 0` représente un objet token persistant. Une autre
valeur représente la session créatrice ; sa fermeture détruit les objets concernés.
Un PKCS#12 peut représenter plusieurs objets : supprimer un objet token supprime
actuellement tous les objets liés au même fichier. Le verrou est intra-processus ;
il faut toujours un seul processus par répertoire de token.

## Contrats à conserver

- Ne pas modifier le packing, les prototypes C ni l'ordre des tables PKCS#11.
  Les tables restent construites à partir des en-têtes OASIS.
- Un buffer de signature NULL ou trop petit ne consomme pas l'opération.
  `SignUpdate` et `VerifyUpdate` partagent le même contrôle multipart.
- `CKM_RSA_PKCS`, `CKM_ECDSA` et `CKM_RSA_PKCS_PSS` utilisent les données préparées
  par le client ; ne pas leur ajouter un hachage implicite.
- Les signatures ECDSA PKCS#11 sont `r || s` ; EVP utilise du DER.
- Le multipart est limité à 64 Mio par opération. Les mécanismes bruts rejettent
  les appels Update, comme avant la refonte.
- Les fichiers PKCS#12 passent par des buffers DER et des flux C++. Ne pas
  réintroduire d'API OpenSSL prenant un `FILE*` : cela rétablirait la dépendance
  Windows à `OPENSSL_Applink`.
- Les `.meta` conservent labels, IDs binaires et politiques par classe. La lecture
  HSM1 reste supportée. Les fichiers sans métadonnées gardent leurs valeurs par défaut.
- Le remplacement atomique des métadonnées ne constitue pas une transaction
  complète clé + métadonnées. Les limitations de stockage restent celles du README.
- Les permissions sont évaluées dans `policyValue`. Les valeurs absentes gardent
  les valeurs historiques. Les contrôles de login et d’appartenance au slot
  sont distincts des permissions d’usage des clés.

## Ajouter une fonctionnalité

1. Ajouter la logique dans le module concerné et déclarer son contrat dans le `.hpp`.
2. Pour une fonction actuellement non supportée, déplacer son export de
   `unsupported.cpp` vers `entry_points.cpp`, en passant par `invoke`.
3. Pour un mécanisme, mettre à jour `mechanisms.*`, son annonce via
   `GetMechanismInfo`, les conversions et la validation des paramètres.
4. Ajouter un test du comportement public : résultat cryptographique,
   erreurs attendues et rechargement si la fonctionnalité écrit sur disque.
5. Pour un nouveau `.cpp`, compléter `HSM_SOURCES` dans `CMakeLists.txt`.

## Style et outils

Les sources et tests utilisent quatre espaces, des accolades Allman, une largeur
cible de 100 colonnes et des noms explicites. Les commentaires expliquent les
contraintes PKCS#11/OpenSSL et la propriété des données. Les tests ont été
reformatés sans changer leurs assertions. `.editorconfig` harmonise l'édition ;
`.clang-format` est la référence pour la mise en forme C++.

Avec clang-format installé et détecté lors de la configuration CMake :

```text
cmake --build out/build-x86 --target format
cmake --build out/build-x86 --target check-format
```

Ces cibles restent facultatives : elles ne sont pas exécutées pendant une
compilation normale et excluent les en-têtes OASIS. Pour une sortie reproductible,
utiliser la même version de clang-format dans l'équipe (refonte formatée avec
23.1.2). Aucune CI distante n'est ajoutée.

## Validation de cette refonte

L'environnement de travail dispose de Linux/GCC 13 et d'OpenSSL 3.0.13. La
compilation CMake de contrôle utilise une copie temporaire dont le minimum
OpenSSL est abaissé à 3.0 ; **le dépôt conserve OpenSSL 3.5 comme prérequis**.
Les sept suites disponibles dans cet environnement passent : policy, derive,
loader, smoke, persistence, pss et regression. Le test ML-DSA compile mais son
exécution requiert OpenSSL 3.5+. Cette vérification ne remplace pas les tests
Windows x86/OpenSSL 3.5 après recompilation.

Avant cette refonte, les huit suites Windows x86/OpenSSL 3.5.4 ont été exécutées
avec succès sur la machine du mainteneur, ainsi que le chargement du simulateur
par DxSP11KeyGen, la génération RSA/CSR et la vérification de cette CSR par OpenSSL.
Ces résultats concernent la version précédente, pas le nouveau découpage.


## Validation des slots (0.7.0)

`tests/slots.cpp` utilise les seuls points d'entrée publics : découverte,
labels et compteurs, isolation des handles, login partagé, USER/SO, changements
et réinitialisations de PIN, échec d'écriture sans changement du PIN actif,
persistance et reprise après configuration invalide. Il exerce également
RSA/AES, dérivation, wrapping/unwrapping et relit les PKCS#12 directement avec
EVP pour vérifier les mots de passe propres à chaque slot.

Huit suites ont été exécutées ici sous Linux/OpenSSL 3.0.13, avec le même
abaissement du prérequis dans une copie temporaire : slots et les sept suites
historiques hors ML-DSA. La cible ML-DSA compile ; son exécution et la validation
Windows x86 restent à effectuer avec OpenSSL 3.5+. Le dépôt exige toujours 3.5.
