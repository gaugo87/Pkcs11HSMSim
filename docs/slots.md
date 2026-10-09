# Slots et mots de passe

Depuis la version 0.7, `HSM_SIM_DATA_DIR` désigne la racine des slots. Par
exemple, configurer les chemins suivants :

| Chemin | Contenu |
| --- | --- |
| `data/0_DEV/pin.txt` | PIN USER du slot 0, par exemple `1234` |
| `data/0_DEV/so-pin.txt` | PIN SO du slot 0, optionnel |
| `data/0_DEV/p12-password.txt` | Mot de passe des PKCS#12 du slot 0, optionnel |
| `data/0_DEV/asymmetric/` | Clés RSA, EC, ML-DSA et SLH-DSA en PKCS#12 |
| `data/0_DEV/symmetric/` | Clés AES en hexadécimal et métadonnées |
| `data/1_TEST/pin.txt` | PIN USER du slot 1, par exemple `5678` |
| `data/1_TEST/asymmetric/` | Clés asymétriques du slot 1 |
| `data/1_TEST/symmetric/` | Clés AES du slot 1 |

Les sous-répertoires de clés sont créés automatiquement s'ils manquent.
Les PIN sont des fichiers texte UTF-8, de 0 à 256 octets après retrait d'un BOM
UTF-8 optionnel et d'une fin de ligne LF/CRLF optionnelle. Les espaces font
partie du PIN. NUL et les retours à la ligne internes sont rejetés. Un fichier
vide configure un PIN vide : le client doit quand même appeler `C_Login`.
Les mots de passe sont stockés en clair pour ce simulateur de développement.

## Créer deux slots sous Windows

Dans **PowerShell**, créer une racine dédiée, sans écraser le stockage actuel :

```powershell
$root = 'C:\GIT\Pkcs11HSMSim-main\data-slots'
New-Item -ItemType Directory -Force "$root\0_DEV", "$root\1_TEST"
Set-Content -LiteralPath "$root\0_DEV\pin.txt" -Value '1234' -Encoding ASCII -NoNewline
Set-Content -LiteralPath "$root\1_TEST\pin.txt" -Value '5678' -Encoding ASCII -NoNewline
Set-Content -LiteralPath "$root\0_DEV\so-pin.txt" -Value 'admin-dev' -Encoding ASCII -NoNewline
$env:HSM_SIM_DATA_DIR = $root
```

Les exemples utilisent ASCII, sous-ensemble d'UTF-8. Pour des PIN non ASCII,
utiliser un éditeur enregistrant en UTF-8 ; ne pas utiliser UTF-16.
Relancer l'application cliente après modification des dossiers ou fichiers.

Dans **le même terminal PowerShell**, depuis le dossier de votre utilitaire :

```powershell
.\DxSP11KeyGen.exe list -libraryPath C:\GIT\Pkcs11HSMSim-main\out\build-x86\Release\hsm-simulator.dll -slotId 0 -slotListMethod INDEX -password 1234
.\DxSP11KeyGen.exe list -libraryPath C:\GIT\Pkcs11HSMSim-main\out\build-x86\Release\hsm-simulator.dll -slotId 1 -slotListMethod INDEX -password 5678
```

Dans un terminal **cmd.exe** distinct, définir d'abord :

```bat
set "HSM_SIM_DATA_DIR=C:\GIT\Pkcs11HSMSim-main\data-slots"
```

Un nouveau slot est vide : la commande `list` ne crée aucune clé. Générer
une clé avec votre utilitaire ou y copier les fichiers de test existants.
Chaque génération, dérivation persistante ou unwrapping écrit dans le slot
de la session ; des clés portant le même label peuvent exister dans deux slots.

## Identifiants et labels

Le premier `_` sépare l'identifiant décimal du label : `7_INTEGRATION_TEST`
donne l'identifiant **7** et le label **INTEGRATION_TEST**. Le label du token
est exposé dans les 32 octets de `CK_TOKEN_INFO.label`, complété d'espaces ou
tronqué ; la description du slot dispose de 64 octets.

`C_GetSlotList` renvoie les identifiants par ordre numérique croissant.
L'index d'une liste est distinct de l'identifiant : avec `0_DEV` et `7_TEST`,
`-slotId 1 -slotListMethod INDEX` sélectionne le deuxième slot, d'identifiant 7.
L'API `C_OpenSession` reçoit toujours l'identifiant PKCS#11 réel.

Les labels peuvent contenir `_`. Les autres dossiers sont ignorés. Un
identifiant dupliqué (`0_DEV` et `00_OTHER`), un identifiant dépassant la taille
de `CK_SLOT_ID`, un label vide (`3_`) ou un fichier de PIN invalide fait échouer
`C_Initialize` avec `CKR_DEVICE_ERROR`. Sur Windows, les identifiants sont
représentés sur 32 bits, y compris pour la DLL x64.
Les slots sont découverts à l'initialisation ; aucun ajout à chaud ni
`C_WaitForSlotEvent` n'est implémenté.

## Login et gestion des PIN

| API | Comportement |
| --- | --- |
| `C_Login(session, CKU_USER, ...)` | Vérifie le PIN utilisateur du slot |
| `C_Login(session, CKU_SO, ...)` | Vérifie `so-pin.txt` ; session RW et aucune session RO sur ce slot |
| `C_Logout(session)` | Déconnecte toutes les sessions de ce slot |
| `C_SetPIN(session, old, new)` | Change le PIN SO si SO connecté, sinon le PIN USER ; exige RW et l'ancien PIN |
| `C_InitPIN(session, new)` | Initialise ou réinitialise le PIN USER ; exige RW et SO connecté |
| `C_CloseAllSessions(slot)` | Ferme uniquement les sessions du slot demandé |

Le login est partagé entre toutes les sessions d'un même token, dans le même
processus. Les rôles USER et SO sont exclusifs. Une seconde connexion du même
rôle renvoie `CKR_USER_ALREADY_LOGGED_IN` ; l'autre rôle renvoie
`CKR_USER_ANOTHER_ALREADY_LOGGED_IN`. Un PIN erroné renvoie `CKR_PIN_INCORRECT`.
La fermeture de la dernière session d'un slot réinitialise sa connexion.

Sans `pin.txt`, un `HSM_SIM_PIN` non vide sert de PIN USER de secours. Sans
l'un ni l'autre, un slot nommé exige une initialisation : le login USER renvoie
`CKR_USER_PIN_NOT_INITIALIZED`. Pour l'initialiser via PKCS#11, créer d'abord
`so-pin.txt`, redémarrer le client, ouvrir une session RW, se connecter SO,
appeler `C_InitPIN`, se déconnecter, puis se connecter USER.
Le PIN SO n'a pas de valeur par défaut dans les slots nommés.
`C_InitToken` et `C_LoginUser` restent non implémentés.

Le login USER est requis pour la génération, la dérivation, le wrapping,
l'unwrapping et les modifications/suppressions d'objets d'un slot protégé.
Les clés privées et AES ne sont visibles/utilisables qu'après ce login,
même si `CKA_PRIVATE=FALSE`. Pour les objets publics ou certificats,
`CKA_PRIVATE=TRUE` impose aussi le login ; sinon lecture et vérification
publique restent disponibles. Il s'agit d'une règle simple du simulateur,
plus restrictive que les seules politiques `CKA_PRIVATE` de certains HSM.
Un handle provenant d'un autre slot est rejeté comme invalide.

Logout annule les opérations et recherches en cours du slot et détruit ses
objets de session protégés. Les objets token restent sur disque. Les autres
slots, leurs connexions et leurs opérations ne sont pas affectés.

`C_SetPIN` et `C_InitPIN` écrivent dans `pin.txt` ou `so-pin.txt` via un fichier
`.tmp` puis un renommage. Un échec d'écriture conserve le PIN actif précédent.
Le fichier remplace la valeur de secours de l'environnement lors des prochains
chargements. Les changements de fichiers faits hors API nécessitent une
nouvelle initialisation. Utiliser un seul processus par racine de stockage.

## PIN et mot de passe PKCS#12

Le PIN contrôle les opérations PKCS#11. Le mot de passe PKCS#12 sert à lire et
écrire les conteneurs de clés : ce sont deux valeurs indépendantes.
`p12-password.txt` permet de choisir un mot de passe PKCS#12 par slot ; à défaut,
le simulateur utilise `HSM_SIM_P12_PASSWORD`, ou une chaîne vide.
Le fichier optionnel utilise le même format texte que les fichiers de PIN.

Changer le PIN ne réencode aucun PKCS#12. Changer `p12-password.txt` ne
rechiffre pas les fichiers existants : ils doivent déjà utiliser ce mot de
passe. Tous les PKCS#12 d'un même slot utilisent le même mot de passe.
Les fichiers non déchiffrables sont actuellement ignorés au chargement,
comme dans la version précédente.

## Conserver ou migrer l'ancien stockage

Sans dossier `slotID_SlotLABEL`, l'ancien stockage `data/asymmetric/` et
`data/symmetric/` reste exposé comme **slot 1**, label **HSM Simulator**.
Sans PIN USER ni SO, il conserve l'ancien comportement permissif ; ajouter
`pin.txt` ou configurer `HSM_SIM_PIN` active la protection du slot.

Pour migrer, arrêter les clients, créer par exemple `data/0_DEV/`, puis déplacer
les deux dossiers `asymmetric` et `symmetric` à l'intérieur. Conserver chaque
clé et son `.meta` ensemble. Ajouter `data/0_DEV/pin.txt`. Si vos PKCS#12 ont
un mot de passe, conserver `HSM_SIM_P12_PASSWORD` ou créer `p12-password.txt`.
Ne pas laisser d'anciens dossiers de clés à la racine : une arborescence mixte
fait échouer l'initialisation pour éviter de masquer des clés existantes.

## Recompiler et tester

Depuis la racine du dépôt, après `git pull`, avec CMake/CTest dans le PATH :

```bat
cmake -S . -B out/build-x86
cmake --build out/build-x86 --config Release
ctest --test-dir out/build-x86 -C Release --output-on-failure
```

La première commande réutilise l'architecture Win32 et les chemins OpenSSL
du cache existant. Pour un nouveau build, suivre la section x86 du README.
Si les commandes ne sont pas dans le PATH, utiliser leur chemin complet dans
`C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin`.

La suite comporte désormais neuf tests. Pour ne lancer que les tests des slots :

```bat
ctest --test-dir out/build-x86 -C Release -R "^slots$" --output-on-failure
```

CTest utilise des répertoires temporaires distincts et ne lit pas vos slots.
