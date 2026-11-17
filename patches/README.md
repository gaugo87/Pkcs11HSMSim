# Patch C++20 vers C++17

[`cpp20-to-cpp17.patch`](cpp20-to-cpp17.patch) reproduit les sept fichiers
modifiés par le commit `7222c971428a0f833a7b3fca9c75af94718802af` de la branche
`cpp17`, à partir de la version C++20
`cfc5293b29b302fa7f1000fac38839ae0306407a` de `main`.

Il contient les adaptations du code, de CMake, du formatage et de la
documentation. Le patch est déjà appliqué dans la branche `cpp17` ; il est
fourni pour reporter ces changements dans une autre copie du projet C++20.

## Application

Télécharger le fichier patch, puis se placer à la racine de la copie C++20.
Dans cet exemple, le patch est enregistré dans le répertoire parent :

```bat
git apply --check ../cpp20-to-cpp17.patch
git apply ../cpp20-to-cpp17.patch
```

La première commande vérifie que le patch correspond aux fichiers présents.
Si elle échoue, vérifier la version de départ et les modifications locales
avant de poursuivre. `git apply` modifie les fichiers sans créer de commit.

Reconfigurer ensuite le build pour appliquer le standard C++17. Pour un
répertoire Windows x86 déjà configuré :

```bat
cmake -S . -B out/build-x86
cmake --build out/build-x86 --config Release
ctest --test-dir out/build-x86 -C Release --output-on-failure
```

## Vérification

Le patch a été vérifié avec `git apply --check --whitespace=error-all`, puis
appliqué à une copie de la version de départ. Les sept fichiers obtenus sont
identiques octet par octet à ceux du commit C++17. Cette version a passé les
neuf suites CTest sous Linux/GCC 14.2/OpenSSL 3.5.7 ; la compilation native
Windows reste à valider sur la machine cible.
