# PL/I-80 v1.4 : surface CP/M observée et à confirmer

## Portée et qualité des éléments

Cette note prépare le prochain jalon « compiler un vrai programme PL/I-80 » sans implémenter CP/M. Le paquet local est celui fourni dans `~/pli/cpm/pli80/DISK1` et `DISK2`, daté du 8 août 2013. La bannière de `PLI.COM` annonce explicitement « PL/I-80 Compiler Version 1.4 », Copyright 1980–1982 Digital Research. La copie de référence locale utilisée dans les travaux précédents a les mêmes tailles et empreintes pour les binaires répertoriés ci-dessous. Cela établit l’identité des copies locales, pas leur chaîne de distribution d’origine.

Niveaux de preuve employés :

* **Dynamique complète pour un scénario** : copie temporaire de l'image QX-10/CP/M Plus, MAME 0.289, commande CCP `PLI OPTIMIST`, tous les appels à `0005h` capturés jusqu'au premier retour au warm boot `0000h`. Aucun artefact propriétaire n'a été ajouté au dépôt.
* **Dynamique antérieure, sélective** : journaux conservés dans `~/pli/cpm/pli80/out[-full]`; certains breakpoints filtraient les fonctions 0, 1, 6, 10 et 16. Ils restent utiles pour les résultats/fichiers antérieurs, mais ne constituent pas le census complet ci-dessous.
* **Statique** : désassemblage `PLI-resident.lst` du `PLI.COM` de 8064 octets. Les adresses et valeurs ci-dessous sont reproductibles depuis le binaire, mais une valeur de registre ne prouve pas à elle seule qu'un chemin a été pris lors de la compilation choisie.
* **Documentation CP/M/PL/I** : références imprimées en fin de note. Le guide PL/I accessible est l'Applications Guide de décembre 1980, antérieur à la révision locale v1.4 ; ses conventions ne remplacent donc pas une observation v1.4.

Le census complet établit les fonctions BDOS effectivement appelées lors de `PLI OPTIMIST` sur cette image CP/M Plus. Il ne généralise pas à toutes les options, CCP, versions CP/M ou programmes PL/I.

## Artéfacts examinés

Provenance locale pour tous les éléments ci-dessous : `~/pli/cpm/pli80/DISK1` ou `DISK2`; copie miroir : `~/projects/retroE/pli/artefacts/pli80-v14-reference`. Les empreintes ont été comparées entre les deux répertoires pour les fichiers de DISK1. Dates de répertoire montrées par l'utilisateur : 8 août 2013. Les fichiers historiques ne sont pas ajoutés au dépôt ; leur statut de redistribution n'est pas établi. Le guide Digital Research porte lui-même une mention propriétaire.

| Fichier | Taille | SHA-256 | Usage / version |
|---|---:|---|---|
| `PLI.COM` | 8064 | `c6d9c7b697b8909e7ff7326f25bf870d0e9f52b6444fe517c2484742a23bcd80` | compilateur résident ; bannière v1.4 |
| `PLI0.OVL` | 18048 | `e78818eca27d051d604b42c6b3202b30e5db6c46df6cf4b498fca601a86d7bff` | overlay numéroté 0 |
| `PLI1.OVL` | 34816 | `1ed6d00f423ffb55ab4ea9a49c33a72617b7ccc5ead5ecdcb5bbf1733214e564` | overlay numéroté 1 |
| `PLI2.OVL` | 33792 | `80b0eba656a0730c0e6e8ccac8882271323daa4020429da7163dc5536e7f454a` | overlay numéroté 2 |
| `PLILIB.IRL` | 71808 | `c0d63ac67766e9d01ec37625289aac47347ec4f13e0b86757bca73287f133d2d` | bibliothèque indexée documentée pour LINK |
| `LINK.COM` | 15744 | `977938c3706b2c2a75db33e012d8a85c871bd651ddb458295a9dbd8a0b929bbb` | LINK-80, non exécuté dans cette enquête |
| `LIB.COM` | 7168 | `fb5bbedbe1a389fa608febf04bc9407a024bc01ccced930cdd6afb0f4455234d` | utilitaire livré, non exécuté |
| `RMAC.COM` | 13568 | `3704a8faeec8cb6a2e05216217a395b96c56a0cc65b9b814163c2aaf50a4cbb9` | assembleur livré, non exécuté |
| `OPTIMIST.COM` | 8704 | `db98507cd2bb42e138299ed71f7822139112509b8e662f732345f3f8a598f512` | programme exemple déjà compilé |
| `OPTIMIST.PLI` (DISK1) | 1408 | `880e307219759a7a5d9a0995b21803f73f2e60057f6ecb7f2a993f3eab84b0e6` | source livré dans le paquet compilateur |
| `OPTIMIST.PLI` (DISK2) | 1664 | `2e0066a2804c5bbf3c5941842999ebcee5594706238a285395c65779217a67f0` | source d'exemple réellement présent sur le disque d'exemples |
| `XREF.COM` | 15488 | `75bb1b8cb9aa6474583b02befe6d31fb476c11109ee034a34f8eb737e13ced7a` | XREF, non exécuté dans cette enquête |
| `Z80.LIB` | 6016 | `5ada15ee2a04a3e0749e334a32440af0ec97b3262e252a58ca27a3ad08c78080` | bibliothèque livrée, non utilisée par le scénario observé |
| `A.PLI` (DISK2) | 128 | `74f9d7c021d5863e55bc40a78d0651e2854cdbee3633e140f60b145d2af0e3cd` | petit exemple de procédure externe ; pas choisi comme test de bout en bout |
| `DEMO.PLI` (DISK2) | 256 | `30c95c5da50194843e7b40c0f1d556288b96920fb3ecb0d4894926916fb45869` | exemple interactif, compilé dans les campagnes locales |

Le zip miroir local `pli80-v14-reference.zip` est mentionné dans le manifeste de recherche antérieur (193484 octets, SHA-256 `4724c6b4b72f35af963b8bb0ebf743398a242cdbdebd36070d2c42956b4f8d64`). Aucun artefact propriétaire n'est recopié dans le dépôt Runes.

## Scénario de compilation de référence et fichiers

Le Digital Research *PL/I-80 Applications Guide*, §1 (pages imprimées 6–7), donne la commande `PLI OPTIMIST`, annonce trois passes, puis `OPTIMIST.REL`; il indique qu'un listing peut être demandé avec `PLI OPTIMIST $L`, et que LINK produit ensuite `OPTIMIST.COM`. Ce scénario documenté et de bout en bout a été choisi comme référence; `A.PLI` est plus petit mais est une procédure externe, non un programme autonome équivalent. Une exécution observée sous MAME 0.289 / QX-10 / CP/M Plus avec la commande CCP exacte `PLI OPTIMIST` s'est terminée par warm boot `0000h`, statut de commande `ok`, après 37,411 secondes émulateur. Une exécution antérieure `PLI OPTIMIST $P$V$K` a aussi terminé, avec capture cohérente de l'INT de passe 1 vers passe 2 (499 octets identiques), mais n'est pas le run utilisé pour le census complet. Une tentative avec ces options dans un autre harness a bloqué sur le service d'impression : ce n'est pas un résultat de compilation négatif.

État disque postérieur conservé dans `out-full/OPTIMIST/directory.txt` : `OPTIMIST.PLI` (2 KiB CP/M, 11 records) et `OPTIMIST.REL` (2 KiB, 11 records), ainsi que les outils et sources d'exemples déjà présents. La copie extraite de `OPTIMIST.REL` fait 1408 octets, SHA-256 `5fca1ffe38d11c30d20cfb99a23fe2baf002c569790bda83e09151cf36032b15`. La commande historique utilisée produisait aussi des captures hôtes de VIR/EIR/SIR/MIR/NIR/AIR/CIR/TIR/IIR/LIR via l'outil XPORT d'instrumentation ; ces extensions ne sont pas attribuées à BDOS/PL/I et ne sont pas des sorties d'une session CP/M standard.

On n'a pas conservé un listing initial et final byte-exact d'un disque vierge : l'image de travail contenait déjà `OPTIMIST.REL`. Le guide affirme que le REL est produit, l'image post-run le contient, et le census observe ses writes; il a donc été écrit/réécrit, mais on ne peut pas prouver qu'il a été créé plutôt que tronqué/remplacé ni fournir ici son hash produit par ce run. Les entrées montrent aussi des accès à `OPTIMIST.INT`; ce temporaire n'est pas présent dans le répertoire final. Le census donne l'ordre global par service, mais pas un journal exhaustif de chaque FCB avant/après chaque appel.

Un `PLI.OVL` unique n'existe pas dans ce paquet : la distribution utilise `PLI0.OVL`, `PLI1.OVL`, `PLI2.OVL`. Le code résident possède des fonctions BDOS `OPEN`/`READ SEQUENTIAL` et les traces dynamiques montrent des fermetures d'overlays. Le contrat raisonnable est donc une lecture de fichiers CP/M vers de la RAM par BDOS, pas une image complète chargée magiquement par le runner. Les adresses de destination précises et la correspondance entre passes et overlays restent à confirmer par capture DMA/FCB et comparaison mémoire.

## Page zéro et lancement CCP

Constats applicables :

* CP/M classique appelle le BDOS par le vecteur à `0005h`; le mot à `0006h` pointe sur la base BDOS et peut servir à calculer la mémoire disponible. Le guide système CP/M 2 décrit aussi le COM chargé à `0100h`, les FCB par défaut à `005Ch` et `006Ch`, et le buffer DMA initial à `0080h`.
* Le listing résident v1.4 lit `0006h` puis `SPHL` (`0391h`–`0394h`) pour initialiser/réinitialiser son stack depuis le haut de mémoire disponible. Il lit également des octets de `005Ch`, `006Ch` et initialise ou utilise `0080h` comme buffer de 128 octets (`03FEh` appelle la routine `03EEh`, qui demande BDOS Set DMA).
* Plusieurs références statiques à `005Ch` et `006Ch` établissent une dépendance aux zones default FCB. On ne sait pas encore quels champs extent/RC/CR/allocation sont lus après chaque service sans trace de données ciblée.
* Le run dynamique employé a reçu `PLI OPTIMIST` (sans options). La commande nécessite un nom dans le FCB par défaut; l'appel dynamique ouvre `OPTIMIST.PLI` à FCB `005Ch`. Le binaire référence aussi `0080h` et un setter DMA y dirige un buffer. La longueur/tail CCP conforme (longueur à `0080h`, texte à `0081h`, CR final usuel) est documentée, mais les octets exacts de cette mémoire n'ont pas été capturés : casse, remplissage et terminaison observés restent à confirmer.
* Le runner Runes a déjà une convention synthétique à `0005h`; la compatibilité de stack exige un mot raisonnable à `0006h/0007h`. Elle ne doit pas prétendre émuler l'opcode réel de jump BDOS ou la base variable d'un CP/M particulier.

## Census BDOS du scénario observé

La routine commune de service vérifie un marqueur, préserve BC/DE puis saute vers `0005h` via `01AD4h`; plusieurs appelants ont un CALL direct local, d'autres passent par un helper. Le logger MAME enregistrait PC de retour, C, DE, A, DMA courant et un aperçu FCB. Le census ci-dessous ne compte que les 1936 entrées avant le témoin `termination witness: warmboot-0000`. Les compteurs sont donc reproductibles pour ce run précis, non une spécification de toute option/compiler.

| Fonction (hex / déc.) | Nom conventionnel | Appels | Paramètres observés / Landmark d'appel (site; entrée fiable si connue) | Résultat consommé / rôle prudent | Preuve / priorité |
|---|---|---:|---|---|---|
| `02h / 2` | Console Output | 425 | `C=02`; retour PC `048F`, site `048Ch`, routine `0480h`; `DE` contient le caractère | effet console; callbacks incluent messages/caractères du compilateur | dynamique + statique; haute |
| `0Bh / 11` | Console Status | 18 | `C=0B`, `DE=0000`; retour `0449`, site `0446`, routine `0441h` | statut console interrogé; interprétation du retour dépend du chemin | dynamique + statique; haute |
| `0Ch / 12` | Get Version | 1 | `C=0C`, `DE=0000`; retour `05C7`, site `05C4`, code autour de `05B2h` | version CP/M détectée | dynamique + statique; haute, version sensible |
| `0Fh / 15` | Open File | 7 | retour `073C`, site `0739`, routine `072Ah`; `DE` notamment `005C` | ouvre `OPTIMIST.PLI` et `CPM3.SYS` via FCB par défaut; autres FCB variables | dynamique + statique; haute |
| `10h / 16` | Close File | 5 | retour `075C`, site `0759`, routine `074Ch`; `DE` FCB | ferme notamment PLI0/1/2.OVL; quelques instantanés FCB illisibles | dynamique + statique; haute |
| `13h / 19` | Delete File | 3 | retour `0417`, site `0414`, routine `0405h`; DE pointe vers FCB/mot indirect `02061h` | opération delete exercée; les noms instantanés ne sont pas fiables | dynamique + statique; haute |
| `14h / 20` | Read Sequential | 712 | retour `0427`, site `0424`, routine `0418h`; DE FCB, données dans DMA | lit source, CPM3.SYS, overlays et intermédiaires | dynamique + statique; haute |
| `15h / 21` | Write Sequential | 15 | retour `0437`, site `0434`, routine `0428h`; DE FCB, données depuis DMA | écrit OPTIMIST.INT et OPTIMIST.REL, entre autres appels à FCB non décodables | dynamique + statique; haute |
| `16h / 22` | Make File | 2 | retour `0782`, site `077F`, routine `0770h`; DE FCB | création de deux fichiers; FCB à cet instant non décodés sûrement | dynamique + statique; haute |
| `1Ah / 26` | Set DMA | 747 | retour `03FD`, site `03FA`, helper `03EEh`; `DE` reçoit l'adresse DMA | `0080h` au démarrage et divers buffers internes (p.ex. `2200h`, `2280h`, `1D0Ah`, `ED06h`) | dynamique + statique; haute |
| `6Ch / 108` | Get/Set Program Return Code (CP/M 3) | 1 | retour `05ED`, site `05EAh`, code autour de `05B2h`; `DE=0000` | code retour positionné à 0 avant warm boot selon la convention CP/M 3 | dynamique + guide CP/M Plus; haute, CP/M-3-only |

Les services `05h/5` List Output (site `0456h`, DE construit depuis C), `19h/25` Current Disk (site statique `043Dh`), `01h/1` Console Input (`046Ch`, `06AEh`), `09h/9` Print String (`047Ch`), et une autre forme statique de fn108 sont identifiés dans le listing, mais hors des appels compilateur comptabilisés ici. Une capture sélective antérieure montre une sortie List avec `DE=000Ch`, retour `0459h`; on ne l'ajoute pas au comptage de ce run. Aucun appel pré-warmboot aux fonctions `17/18` Search, `23` Rename, `33/34` Read/Write Random, `35` Compute File Size ou `36` Set Random Record n'a été capturé. Les fonctions 0/1/5/9/25 n'en deviennent pas inutiles pour d'autres modes : elles sont seulement hors du sous-ensemble observé ici.

Après le témoin warm boot, le firmware/CCP et l'automatisation MAME exécutent huit appels supplémentaires (`0Ah` une fois, `02h` quatre fois, `31h` deux fois, `62h` une fois). Ils sont exclus du census compilateur. `0Ah` est Read Console Buffer, `31h` Access SCB et `62h` Get Free Space (CP/M Plus); leur présence post-run ne prouve pas un besoin de PLI.COM. Les fonctions CP/M Plus 49/98 n'ont pas d'équivalent standard CP/M 2.2.

### Repères de désassemblage réutilisables

Adresses dans le désassemblage du COM chargé à `0100h`; « entrée » est une limite de routine visible dans le listing, pas une attribution de nom source récupéré.

| Adresse site | Entrée candidate | Rôle provisoire | Repères / paramètres | Confiance |
|---|---|---|---|---|
| `01AD4h` (JMP `0005h`) | `01ABBh` | passerelle commune BDOS | garde un marqueur à `02155h`, sauve/restaure BC/DE ; les callers alimentent C et DE | élevée pour passerelle, noms manquants |
| `03FAh` | `03EEh` | setter DMA interne (`set_dma`) | BC copié puis transmis en DE à fn 1Ah ; `03FEh` appelle avec `0080h` | élevée |
| `0414h` | `0405h` | `delete_fcb` (provisoire) | DE depuis `02061h`; prépare DMA via `03FEh`; dynamique : 3 appels, ret `0417h` | élevée pour fonction/site; FCB name inconnu |
| `0424h` | `0418h` | `read_sequential` (provisoire) | DE depuis `02063h`; DMA; dynamique : 712 appels, ret `0427h` | élevée |
| `0434h` | `0428h` | `write_sequential` (provisoire) | DE depuis `02065h`; DMA; dynamique : 15 appels, ret `0437h` | élevée |
| `043Dh` | `0438h` | site fn 19h / current disk | DE nul | moyenne |
| `0446h` | `0441h` | site fn 0Bh / console status | DE nul; dynamique 18 appels, ret `0449h` | élevée |
| `0456h` | `044Ah` | site fn 05h / sortie d'un caractère via LST | DE construit depuis C; pas dans le census complet du run décrit | élevée pour service, basse pour but global |
| `046Ch`, `06AEh` | `0467h`, `06A9h` | entrée console bloquante candidate | fn 01h, DE nul | élevée pour appel, usage pendant compile inconnu |
| `047Ch` | `0470h` | sortie chaîne console | DE vient d'un mot d'argument, fn 09h; non appelée dans ce run | élevée pour site |
| `048Ch` | `0480h` | sortie caractère console | DE caractère étendu; dynamique 425 appels, ret `048Fh`; appels multiples vers même helper probable | élevée |
| `05C4h` | `05B2h` | interrogation version/feature | fn 0Ch; dynamique une fois, ret `05C7h`; ensuite branchement de compatibilité | élevée pour appel |
| `05EAh` | `05B2h` | set return code CP/M Plus | fn 6Ch, DE `0000h`; dynamique une fois, ret `05EDh`, juste avant warmboot | élevée pour usage du run |
| `0739h` | `072Ah` | `open_fcb` (provisoire) | DE depuis `02085h`; A comparé à FFh; dynamique 7 appels, ret `073Ch`; message d'erreur voisin `0243h` | élevée |
| `0759h` | `074Ch` | `close_fcb` (provisoire) | DE récupéré de l'argument sur pile; dynamique 5 appels, ret `075Ch`; erreur près `024Ch` | élevée |
| `077Fh` | `0770h` | `make_fcb` (provisoire) | DE depuis `02085h`; A comparé à FFh; dynamique 2 appels, ret `0782h`; erreur près `0257h` | élevée |

Landmarks où une fonction existe mais l'identité d'appelant reste à préciser : `03FAh` (fn26, helper `03EEh`, 747 appels; adresses DMA montrent de nombreux buffers), `043Dh` (fn25, statique seulement), `046Ch` et `06AEh` (fn1, statiques seulement). Les appels `048Ch`, `0739h` et `0759h` sont chacun répétés depuis plusieurs contextes runtime ou FCB; ils doivent être suivis comme sites partagés, pas interprétés comme un seul fichier/routine logique. Les retours BDOS capturés permettent d'identifier le CALL local; pour les fonctions exécutées via le setter DMA, le caller réel varie.

À ne pas surinterpréter : les chaînes d'erreur en `0243h`, `024Ch`, `0257h` sont accessibles en imprimable dans le binaire mais leur association précise au type d'échec demande validation. Les noms FCB indiqués ci-dessous viennent d'un aperçu mémoire pris à l'entrée BDOS; certains FCB transitoires sont en cours de construction/réutilisation et s'affichent comme `!E` ou indécodables `?`. Les CALL sites ont été recoupés par le PC de retour (`site=ret-3`) et le listing. Une adresse de retour dans une zone overlay peut toutefois désigner du code écrasé/chargé dynamiquement : la routine logique n'est pas attribuée sans comparaison avec les octets en RAM.

## FCB, DMA et modes d'accès

Les pointeurs FCB transmis dynamiquement sont `DE`. Aperçu des noms reconnus à l'entrée (compteur d'appels du census ci-dessus) :

| Service / FCB `DE` | Nom 8.3 lisible dans l'instantané | Nombre | Interprétation prudente |
|---|---|---:|---|
| OPEN `005Ch` | `OPTIMIST.PLI` | 1 | FCB par défaut du nom source |
| OPEN `005Ch` | `CPM3.SYS` | 2 | fichier de système/compatibilité effectivement ouvert |
| OPEN `01C5Dh` | `!E` | 3 | nom non fiable, buffer probablement transitoire |
| OPEN `01CA2h` | `?` | 1 | non décodé |
| READ `005Ch` | `OPTIMIST.PLI` (16); `CPM3.SYS` (12) | 28 | lectures séquentielles observées |
| READ `01C5Dh` | `PLI0.OVL` (40); `PLI1.OVL` (58); `PLI2.OVL` (77); `!E` (505) | 680 | les 175 lectures d'overlay correspondent à leurs records dans l'ordre rencontré; autres noms pas sûrs |
| READ `01CA2h` | `OPTIMIST.INT` (3); `?` (1) | 4 | temporaire intermédiaire observé |
| WRITE `01CE4h` | `OPTIMIST.REL` (7); `?` (4) | 11 | REL écrit; autres noms incertains |
| WRITE `01CA2h` | `OPTIMIST.INT` (2); `?` (2) | 4 | intermédiaire écrit |
| MAKE `01CE4h`, `01CA2h` | `?` | 1 chacun | les octets FCB de ces événements ne donnaient pas un nom stable |
| DELETE `01CA2h`, `01CE4h` | `?` | 2 et 1 | temporaires probables, association non démontrée |
| CLOSE `01C5Dh` | `PLI0.OVL` (1), `!E` (2) | 3 | fermeture overlay démontrée pour PLI0 |
| CLOSE `01CA2h`, `01CE4h` | `?` | 1 chacun | non décodé |

Les champs réellement identifiés comme fiables dans ces observations sont le pointeur FCB, le drive/name/type au moment où la chaîne est décodable, et le fait que l'appelant utilise les opérations séquentielles. Il n'y a pas eu de diff octet par octet des champs avant/après chaque BDOS : extent, S1/S2, RC, allocation et CR consommé ne sont donc pas encore établis champ par champ. Il faut conserver le FCB visible en RAM et instrumenter ses mutations plutôt que d'affirmer que les octets d'allocation sont invisibles.

Le DMA est une adresse mémoire mutable. L'entrée fn 1Ah a DE=`0080h` pour le buffer page zéro et aussi divers buffers internes; exemples de valeurs observées : `2200h`, `2280h`, `1D0Ah`, `1D8Ch`, `ED06h` (ces adresses ne sont pas nécessairement toutes des destinations de record complet; le DMA peut être réutilisé pour structures auxiliaires). Le code fait 747 appels Set DMA. Les appels READ/WRITE suivants utilisent l'adresse DMA courante. Le premier backend doit raisonner en records CP/M de 128 octets, dont le padding et Ctrl-Z éventuel doivent être reproduits/validés, pas assimiler directement à une lecture fichier hôte.

Pour cette compilation, aucune opération random (33–36), recherche directory (17/18) ou rename n'a eu lieu avant warm boot. Les 712 READ SEQUENTIAL couvrent notamment 175 appels attribués par contenu aux trois overlays (PLI0 40, PLI1 58, PLI2 77); ils sont lus record par record. PLI0/1/2 ont donc un contrat d'entrées BDOS ordinaires et non une injection magique par Runner. Aucun WRITE vers ces overlays n'a été observé. Le nombre de reads source observé n'est pas nécessairement le nombre de records distincts consommés : FCB et DMA évoluent; il faut éviter d'en déduire un format interne sans trace ciblée.

## LINK / OPTIMIST / XREF, disques et versions

Le guide §1 décrit explicitement le flux `PLI OPTIMIST` → `OPTIMIST.REL` → `LINK OPTIMIST`, où LINK associe le REL à `PLILIB.IRL` et produit/remplace `OPTIMIST.COM`. Nous n'avons pas exécuté LINK, OPTIMIST.COM ni XREF dans l'environnement Runes/MAME dans ce tour. La fonction OPTIMIST est interactive selon le guide (console input); XREF et LINK introduisent vraisemblablement des besoins d'analyse de fichiers ou de command tail, mais aucune exigence supplémentaire ne doit encore être déclarée observée. Le tableau minimal de suites est donc :

| Composant | Besoin additionnel établi / probable | État |
|---|---|---|
| PLI.COM | tail + FCB par défaut, DMA, fichiers séquentiels, console, page zéro | code statique + exécutions CP/M Plus réussies |
| LINK.COM | lire `.REL` et `PLILIB.IRL`, créer `.COM` selon le guide | documenté; non exécuté dans cette étude |
| OPTIMIST.COM | console interactive selon l'Applications Guide | documenté; pas testé ici |
| XREF.COM | prend probablement source/object et produit listing/références | inconnu, enquête statique/dynamique nécessaire |
| RMAC.COM / LIB.COM | assembler et manipuler bibliothèques pour certains workflows | livrés; hors scénario observé |

Le harness MAME basculait le disque de travail vers B:; les outils, source et sortie du scénario étaient sur le disque courant, sans preuve d'accès simultané à plusieurs drives ou à des user numbers. Les octets de préfixe drive vus dans tous les FCB utiles ne sont pas documentés ici comme un usage explicite multi-drive. Le FCB drive byte et les sites statiques Current Disk / fn108 invitent néanmoins à ne pas figer l'API filesystem sur un chemin hôte global.

Les captures proviennent de CP/M Plus sur QX-10. Le BDOS 108 (6Ch, Get/Set Program Return Code) est CP/M 3, pas un service CP/M 2.2 standard. Le site existe dans le code ; on ignore encore si la compilation requiert le comportement, ou si c'est un chemin conditionnel. Get Version (0Ch) est également appelé et vraisemblablement sert à différencier l'environnement. Le cœur minimal doit répondre de manière compatible au résultat de version attendu par le chemin voulu ou tracer ces appels et prendre une décision explicite ; ne pas coder les valeurs CP/M Plus en dur sans observation du contrôle de flot.

## Frontière filesystem recommandée

Une première surface suffisamment petite, sans secteurs physiques :

1. Normaliser les noms CP/M 8.3 ASCII sans dépendre de la casse de l'hôte; rejeter ou représenter explicitement les wildcards.
2. Résoudre `A:`–`P:` en disques virtuels, avec disque courant et user séparés du backend; premier run peut n'avoir qu'un drive mais garder cette frontière.
3. Maintenir FCB en mémoire comme état visible, handles ouverts indexés par FCB/identité de fichier; prendre en charge séquentiel record 128 octets et le DMA bus.
4. Faire les répertoires de recherche déterministes (tri CP/M normalisé), prévoir snapshot/diff et source des octets, mais différer cela après le premier compile.
5. Implémenter d'abord les fonctions effectivement atteintes dans le census : console output/status, get version, OPEN/CLOSE/DELETE/READ SEQ/WRITE SEQ/MAKE, SET DMA et CP/M Plus return-code. Traiter fn108 comme compatibilité versionnée (le run l'appelle réellement) et établir une politique explicite CP/M 2.2 avant d'émuler le compileur sur cette version; ne pas ajouter Search/Random par anticipation.

Disque A hôte pour la distribution et un disque RAM scratch seraient pratiques pour isoler entrées/sorties, mais rien dans l'exécution conservée ne nécessite la lettre M: ou un second disque. Commencer avec un drive virtuel backend configurable, et éventuellement mapper une image de distribution read-only plus un scratch memory-backed sur lettres configurées. Ne pas coder M: comme convention historique.

## Étapes d'implémentation proposées

1. **Re-run contrôlé sur disque vierge** : conserver par événement le FCB 36 octets avant/après, DMA, résultat A et octets du tail/page zéro; snapshot avant/après pour prouver create/truncate/delete, padding et hash de REL/INT.
2. **Process environment + filesystem séquentiel** : tail CCP, default FCB 1/2, drive courant, DMA, services dynamiquement observés, records CP/M déterministes, version et retour CP/M 3 explicitement configurés.
3. **Compiler Runes** : charger v1.4 + trois overlays + OPTIMIST.PLI, obtenir REL; comparer contenu, taille/padding et diagnostics à MAME.
4. **LINK puis utilitaires** : confirmer REL/IRL/COM avec LINK; ensuite mesurer les delta-fonctions de XREF/OPTIMIST et n'ajouter search/random/rename que sur preuve.

## Sources

* Digital Research, *CP/M Operating System Manual*, CP/M 2, §5.1, pages imprimées 5-2 (page zéro, `0005h`, `0006h`, COM à `0100h`, warm boot) et §5.2, pages 5-8 et suivantes (FCB `005Ch`, DMA `0080h`, records de 128 octets). Copie HTML/OCR consultable : [CP/M Operating System Manual](https://studylib.net/doc/18146759/digital-research-tm-cp-m-operating-system-manual-cp-m).
* Digital Research, *PL/I-80 Applications Guide*, décembre 1980, §1, pages imprimées 6–7 (fichiers OVL, commande compile, passes, REL puis LINK), §2, page 8 (options), §4 pages 18–20 (sequential/direct), §5 (exemples). [PDF conservé par Bitsavers](https://www.bitsavers.org/pdf/digitalResearch/pl1/PL1-80_Applications_Guide_Dec80.pdf). C'est un guide de l'environnement PL/I-80 et non une preuve de toutes les spécificités du binaire v1.4.
* Digital Research, *CP/M Plus Programmer's Guide*, BDOS fn 108 / 6Ch, Get/Set Program Return Code; [copie Bitsavers](https://bitsavers.org/pdf/digitalResearch/cpm_plus/CPM_Plus_Programmers_Guide_Jan83.pdf). Sert seulement à interpréter la fonction CP/M 3 chargée statiquement.
* Preuve binaire locale : `DISK1/PLI.COM` SHA-256 ci-dessus; désassemblage Intel 8085 produit avec `dasm85`, fichier local de travail `PLI-resident.lst`. Les sections et sites de ce document sont des adresses de ce listing.
* Preuve dynamique : run temporaire MAME 0.289 / QX-10 / CP/M Plus, commande CCP `PLI OPTIMIST`, breakpoint à toute entrée BDOS, census borné au premier témoin PC=`0000h`; durée indiquée ci-dessus. Les anciens journaux `out-full/OPTIMIST/mame.log`, `out-full/OPTIMIST/directory.txt`, captures `OPTIMIST-*.INT.*` et `out/ADDC/mame.log` sont des corroborations antérieures, certaines filtrées. Les logs complets temporaires ne sont pas archivés dans le dépôt; les comptes, sites et FCB décodables sont résumés dans les tables.

### Questions ouvertes

* Quel est le census avec options de compilation/listing/impression, et quels retours BDOS sont consommés pour chaque erreur/succès ?
* Quels champs FCB sont lus/écrits à chaque étape, et les fichiers intermédiaires exacts sont-ils supprimés/recréés ?
* Comment sont formés précisément le tail et les FCB1/FCB2 par le CCP QX-10/CP/M Plus; les essais historiques avec lettre de drive/options diffèrent-ils du CCP CP/M 2.2 ?
* Où et comment chaque overlay est-il chargé (adresse cible, record order, durée de vie) ? Les adresses d'exécution overlay doivent être établies par snapshot mémoire, pas déduites d'un nom FCB seul.
* Le service 108 est appelé dans le run compilateur CP/M Plus et fixe le code retour à zéro; quelle réponse doit fournir une personnalité CP/M 2.2 sans fn108 ?
* Qu'ajoutent réellement LINK, XREF et OPTIMIST exécutables à la surface du compilateur ?
* Quelle variation de résultat vient des conventions CP/M 2.2 vs CP/M Plus (notamment version, code retour, EOF et retours A) ?

La réponse à ces questions doit venir de runs différenciés et de snapshots d'état, pas d'une généralisation du manuel CP/M ni d'une interprétation forcée des « garbage FCB » des logs existants.
