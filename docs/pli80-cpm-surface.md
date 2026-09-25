# PL/I-80 v1.4 : surface CP/M observée et à confirmer

> **Contrat d'architecture Runes : CP/M 2.2 userspace minimal.** CP/M Plus sur
> QX-10/MAME est seulement un environnement d'observation/différentiel; sa
> disponibilité ne définit pas le runtime cible. Les comportements propres à
> CP/M Plus sont des extensions futures possibles, jamais des prérequis par
> défaut. Un run forcé de la seule réponse BDOS 12 ne constitue pas un vrai
> run CP/M 2.2.

## Portée et qualité des éléments

Cette note prépare le prochain jalon « compiler un vrai programme PL/I-80 » sans implémenter CP/M. Le paquet local est celui fourni dans `~/pli/cpm/pli80/DISK1` et `DISK2`, daté du 8 août 2013. La bannière de `PLI.COM` annonce explicitement « PL/I-80 Compiler Version 1.4 », Copyright 1980–1982 Digital Research. La copie de référence locale utilisée dans les travaux précédents a les mêmes tailles et empreintes pour les binaires répertoriés ci-dessous. Cela établit l’identité des copies locales, pas leur chaîne de distribution d’origine.

Niveaux de preuve employés :

* **Dynamique complète pour un scénario** : copie temporaire de l'image QX-10/CP/M Plus, MAME 0.289, commande CCP `PLI OPTIMIST`, tous les appels à `0005h` capturés jusqu'au premier retour au warm boot `0000h`. Aucun artefact propriétaire n'a été ajouté au dépôt.
* **Dynamique antérieure, sélective** : journaux conservés dans `~/pli/cpm/pli80/out[-full]`; certains breakpoints filtraient les fonctions 0, 1, 6, 10 et 16. Ils restent utiles pour les résultats/fichiers antérieurs, mais ne constituent pas le census complet ci-dessous.
* **Statique** : désassemblage `PLI-resident.lst` du `PLI.COM` de 8064 octets. Les adresses et valeurs ci-dessous sont reproductibles depuis le binaire, mais une valeur de registre ne prouve pas à elle seule qu'un chemin a été pris lors de la compilation choisie.
* **Documentation CP/M/PL/I** : références imprimées en fin de note. Le guide PL/I accessible est l'Applications Guide de décembre 1980, antérieur à la révision locale v1.4 ; ses conventions ne remplacent donc pas une observation v1.4.

Le census complet établit les fonctions BDOS appelées lors de `PLI OPTIMIST` sur cette image CP/M Plus. Il ne généralise pas à toutes les options, CCP ou programmes PL/I. Une nouvelle capture contrôlée sur une copie de l'image de référence, sans REL préalable, est rapportée plus bas et corrige plusieurs identifications antérieures.

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

État disque postérieur d'une nouvelle expérience contrôlée (copie de l'image de référence, source et outils présents, `OPTIMIST.REL`/`.INT` absents avant lancement) : `OPTIMIST.REL` apparaît comme 1408 octets (`11 × 128`), SHA-256 `5fca1ffe38d11c30d20cfb99a23fe2baf002c569790bda83e09151cf36032b15`; `OPTIMIST.INT` est absent à la fin. `OPTIMIST.PLI` faisait 1408 octets (`11 × 128`) avant et après. Les overlays sont eux aussi des multiples exacts de 128 (141, 272, 264 records respectivement). La compilation forcée vers la réponse de version `0022h` produit le même REL octet par octet. La commande historique antérieure produisait aussi des captures hôtes via XPORT; celles-ci ne sont pas des sorties BDOS standard.

Contrairement à l'étude précédente, cette copie propre établit que le REL était absent puis apparaît après MAKE/écritures/CLOSE; l'INT temporaire n'est plus présent à la fin. Le nouveau journal ordonne les opérations mais n'est pas un dump octet par octet après chaque appel BDOS.

Un `PLI.OVL` unique n'existe pas dans ce paquet : la distribution utilise `PLI0.OVL`, `PLI1.OVL`, `PLI2.OVL`. Le code résident possède des fonctions BDOS `OPEN`/`READ SEQUENTIAL` et les traces dynamiques montrent des fermetures d'overlays. Le contrat raisonnable est donc une lecture de fichiers CP/M vers de la RAM par BDOS, pas une image complète chargée magiquement par le runner. Les adresses de destination précises et la correspondance entre passes et overlays restent à confirmer par capture DMA/FCB et comparaison mémoire.

## Page zéro et lancement CCP

Constats applicables :

* CP/M classique appelle le BDOS par le vecteur à `0005h`; le mot à `0006h` pointe sur la base BDOS et peut servir à calculer la mémoire disponible. Le guide système CP/M 2 décrit aussi le COM chargé à `0100h`, les FCB par défaut à `005Ch` et `006Ch`, et le buffer DMA initial à `0080h`.
* Le listing résident v1.4 lit `0006h` puis `SPHL` (`0391h`–`0394h`) pour initialiser/réinitialiser son stack depuis le haut de mémoire disponible. Il lit également `005Ch`, `006Ch`; `03FEh` choisit `0080h` comme DMA en appelant `03EEh`/BDOS 26.
* Les nouvelles traces confirment la dépendance aux FCB par défaut et aux champs extent/RC/CR visibles pendant les reads; elles ne montrent pas le retour mémoire immédiat de chaque service.
* Pour `PLI OPTIMIST`, snapshot CP/M Plus au premier PC `0100h`, avant la première instruction PLI: `0000..000F = C3 03 F7 FF 01 C3 06 F1 FF FF FF FF FF FF FF FF`; donc le vecteur `0005h` est `JMP F106h` et le mot `0006h` vaut `F106h`. `0050..005F = 02 00 00 00 00 00 00 FF FF FF FF FF 00 4F 50 54`; `0060..006F = 49 4D 49 53 54 20 20 20 00 00 00 00 00 20 20 20`; `0070..007F = 20 20 20 20 20 20 20 00 00 00 00 00 00 FF FF`; `0080..008F = 09 20 4F 50 54 49 4D 49 53 54 00 AA 28 00 00 00`. Ainsi la longueur vaut 9, le texte est exactement ` OPTIMIST` (espace initial, uppercase, sans extension), et l'octet suivant est NUL, pas CR, dans CE CCP Plus. La FCB1 visible à `005Ch` commence par `00 'OPTIMIST' 'PLI'`; FCB2 à `006Ch` chevauche physiquement la zone allocation de FCB1 et commence par des espaces. Ce sont des octets observés CP/M Plus, pas des règles à imposer au CCP CP/M 2.2. Le format documenté CP/M 2.2 reste le contrat cible à initialiser explicitement.
* Le runner Runes a déjà une convention synthétique à `0005h`; la compatibilité de stack exige un mot raisonnable à `0006h/0007h`. Elle ne doit pas prétendre émuler l'opcode réel de jump BDOS ou la base variable d'un CP/M particulier.

## Census BDOS du scénario observé

La routine commune de service vérifie un marqueur, préserve BC/DE puis saute vers `0005h` via `01AD4h`; plusieurs appelants ont un CALL direct local, d'autres passent par un helper. Le logger MAME enregistrait PC de retour, C, DE, A, DMA courant et un aperçu FCB. Le census ci-dessous ne compte que les 1936 entrées avant le témoin `termination witness: warmboot-0000`. Les compteurs sont donc reproductibles pour ce run précis, non une spécification de toute option/compiler.

| Fonction (hex / déc.) | Nom conventionnel | Appels | Paramètres observés / Landmark d'appel (site; entrée fiable si connue) | Résultat consommé / rôle prudent | Preuve / priorité |
|---|---|---:|---|---|---|
| `02h / 2` | Console Output | 425 | `C=02`; retour PC `048F`, site `048Ch`, routine `0480h`; `DE` contient le caractère | effet console; callbacks incluent messages/caractères du compilateur | dynamique + statique; haute |
| `0Bh / 11` | Console Status | 18 | `C=0B`, `DE=0000`; retour `0449`, site `0446`, routine `0441h` | `A=00` à chaque appel de cette exécution sans touche pending; les callers traitent ce chemin comme absence d'entrée | dynamique + statique; haute pour cas idle |
| `0Ch / 12` | Get Version | 1 | `C=0C`, `DE=0000`; retour `05C7`, site `05C4`, code autour de `05B2h` | version CP/M détectée | dynamique + statique; haute, version sensible |
| `0Fh / 15` | Open File | 7 appels dans le processus PLI; 8 ouverts capturés au total en incluant le chargement CCP de `PLI.COM` | retour `073C`, site `0739`, routine `072Ah`; `DE` notamment `005C` | source et overlays/intermédiaire; **aucun CPM3.SYS dans le run contrôlé** | dynamique + statique; haute |
| `10h / 16` | Close File | 5 | retour `075C`, site `0759`, routine `074Ch`; `DE` FCB | ferme overlays, INT et REL; identités établies dans la capture propre | dynamique + statique; haute |
| `13h / 19` | Delete File | 3 | retour `0417`, site `0414`, routine `0405h`; DE pointe vers FCB/mot indirect `02061h` | opération delete exercée; les noms instantanés ne sont pas fiables | dynamique + statique; haute |
| `14h / 20` | Read Sequential | 712 dans le census compilateur antérieur | retour `0427`, site `0424`, routine `0418h`; DE FCB, données dans DMA | run propre: source, trois overlays et INT; aucun CPM3.SYS | dynamique + statique; haute |
| `15h / 21` | Write Sequential | 15 | retour `0437`, site `0434`, routine `0428h`; DE FCB, données depuis DMA | écrit OPTIMIST.INT et OPTIMIST.REL, entre autres appels à FCB non décodables | dynamique + statique; haute |
| `16h / 22` | Make File | 2 | retour `0782`, site `077F`, routine `0770h`; DE FCB | création de deux fichiers; FCB à cet instant non décodés sûrement | dynamique + statique; haute |
| `1Ah / 26` | Set DMA | 747 | retour `03FD`, site `03FA`, helper `03EEh`; `DE` reçoit l'adresse DMA | `0080h` au démarrage et divers buffers internes (p.ex. `2200h`, `2280h`, `1D0Ah`, `ED06h`) | dynamique + statique; haute |
| `6Ch / 108` | Get/Set Program Return Code (CP/M 3) | 1 | retour `05ED`, site `05EAh`, `DE=0000` dans le succès observé | appel avec valeur zéro avant warm boot; extension non CP/M 2.2. Une expérience forçant seulement BDOS 12 à retourner `0022h` l'appelle toujours; voir ci-dessous. | dynamique + statique; appel établi, compatibilité CP/M 2.2 non établie |

Les services `05h/5` List Output (site `0456h`, DE construit depuis C), `19h/25` Current Disk (site statique `043Dh`), `01h/1` Console Input (`046Ch`, `06AEh`), `09h/9` Print String (`047Ch`), et une autre forme statique de fn108 sont identifiés dans le listing, mais hors des appels compilateur comptabilisés ici. Une capture sélective antérieure montre une sortie List avec `DE=000Ch`, retour `0459h`; on ne l'ajoute pas au comptage de ce run. Aucun appel pré-warmboot aux fonctions `17/18` Search, `23` Rename, `33/34` Read/Write Random, `35` Compute File Size ou `36` Set Random Record n'a été capturé. Les fonctions 0/1/5/9/25 n'en deviennent pas inutiles pour d'autres modes : elles sont seulement hors du sous-ensemble observé ici.

Après le témoin warm boot, le firmware/CCP et l'automatisation MAME exécutent des appels supplémentaires (`0Ah`, `02h`, `31h`, `62h`), exclus du census transient. `31h` Access SCB et `62h` Get Free Space sont CP/M Plus; leur présence post-run ne prouve pas un besoin de PLI.COM. Les fonctions CP/M Plus n'ont pas d'équivalent standard CP/M 2.2.

### Repères de désassemblage réutilisables

Adresses dans le désassemblage du COM chargé à `0100h`; « entrée » est une limite de routine visible dans le listing, pas une attribution de nom source récupéré.

| Adresse site | Entrée candidate | Rôle provisoire | Repères / paramètres | Confiance |
|---|---|---|---|---|
| `01AD4h` (JMP `0005h`) | `01ABBh` | passerelle commune BDOS | garde un marqueur à `02155h`, sauve/restaure BC/DE ; les callers alimentent C et DE | élevée pour passerelle, noms manquants |
| `03FAh` | `03EEh` | setter DMA interne (`set_dma`) | BC copié puis transmis en DE à fn 1Ah ; `03FEh` appelle avec `0080h` | élevée |
| `0414h` | `0405h` | `delete_fcb` (provisoire) | DE depuis `02061h`, FCB RAM réutilisé; 3 appels, ret `0417h`: initial REL absent, INT absent, puis INT existant | élevée pour site/opération; FCB name par instantané |
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

À ne pas surinterpréter : les chaînes d'erreur en `0243h`, `024Ch`, `0257h` restent à associer précisément au type d'échec. Les anciennes mentions `!E`/`?` sur les FCB transitoires sont supersédées par la capture propre. Les CALL sites sont recoupés via PC de retour (`site=ret-3`) et le listing. Une adresse dans une zone overlay ne désigne pas nécessairement le même code après écrasement/rechargement.

## Capture contrôlée FCB, DMA et modes d'accès (CP/M Plus)

La nouvelle capture utilise une copie de `PLI80-QXPLUS.base.imd`; le disque de référence n'a pas été modifié. Le snapshot initial confirme l'absence de `OPTIMIST.REL` et `.INT`; la sortie est un REL de 1408 octets et l'INT temporaire a disparu à warm boot. Cette observation prouve création du REL (un DELETE préalable échoue avec `A=FF`, puis MAKE réussit avec `A=00`), écriture puis fermeture; elle ne permet pas de distinguer si CP/M crée/tronque le fichier à MAKE de la même façon pour tous les cas.

Le lancement observé est CP/M Plus/QX-10, et ne doit pas être copié aveuglément en CP/M 2.2. La page zéro au premier `PC=0100h` est donnée ci-dessus. La zone FCB initiale comporte les octets `005C..006B = 00 4F 50 54 49 4D 49 53 54 50 4C 49 00 00 00 00`: FCB1 est `OPTIMIST.PLI`; les octets `006C..008B` sont partagés avec l'allocation de FCB1 et la zone FCB2. Une représentation FCB1/FCB2 ne doit donc pas les copier comme deux tableaux non chevauchants sans respecter le layout CP/M.

Dans les traces d'entrée BDOS, l'ordre des champs FCB CP/M standard (`EX,S1,S2,RC`, allocation, `CR`, `R0..R2`) reste lisible, mais S1/S2 portent ici des valeurs non nulles `02/80` sur les fichiers ouverts; ne les normalisez pas comme des champs ignorés sans tests. Par exemple, source `OPTIMIST.PLI` a `RC=0B` et CR évolue de `00` à `0A`; PLI0 a `RC=8D`, PLI1 `RC=10` après 272 records, PLI2 `RC=08` après 264 records. Le journal a été complété par des snapshots des 36 octets FCB immédiatement après le retour de DELETE, OPEN, CLOSE et MAKE. Ceux-ci confirment notamment l'état de directory/extent retourné par OPEN et le CR/RC final visible après CLOSE. Les snapshots de READ et WRITE immédiatement après service ne sont pas capturés: leurs mutations ne peuvent être attribuées avec certitude au BDOS plutôt qu'au code client à partir du seul FCB observé au prochain appel.

Résultats observés en CP/M Plus: `OPEN` réussi retourne `A=00`; échec (notamment l'absence initiale de REL avant DELETE) `A=FF`; `MAKE` réussi `A=00`; `CLOSE` `A=00`; `WRITE SEQ` `A=00`; `READ SEQ` retourne `A=00` pour record disponible et `A=01` pour EOF. `DELETE` absent retourne `A=FF`, la suppression réussie `A=00`. Les wrappers PLI testent des résultats (lecture par comparaison avec zéro, ouverture/création par comparaison à FFh); ne pas généraliser les détails de CP/M Plus aux codes CP/M 2.2 sans contrôle. Les 18 appels Console Status du run retournent zéro (aucune touche disponible); ce run n'établit pas le chemin d'une touche en attente.

FCB identité par durée de vie (les adresses sont réutilisées, elles ne nomment pas un fichier de façon permanente):

| FCB RAM | Durée/rôle observé | Opérations et état utile | Confiance |
|---|---|---|---|
| `005Ch` | default FCB issu du tail; source | `OPEN OPTIMIST.PLI`; lectures séquentielles de ses 11 records lors de plusieurs passes; `RC=0B`, `CR` vu de `00` à `0A`; ouvert à nouveau entre passes | haute pour identité; mutations pré/appel observées |
| `01C5Dh` | FCB de fichiers overlay, réécrit pour chaque nom | ouvre/lit/ferme successivement `PLI0.OVL`, `PLI1.OVL`, `PLI2.OVL`; compte par overlay 141/272/264 records disponibles puis un READ EOF; adresse réutilisée | haute |
| `01CA2h` | FCB d'INT | `DELETE OPTIMIST.INT` absent (`FF`), `MAKE` (`00`), 4 writes, CLOSE, OPEN/read (4 records), DELETE réussi (`00`) en fin | haute |
| `01CE4h` | FCB de sortie REL | `DELETE OPTIMIST.REL` absent (`FF`), MAKE (`00`), 11 `WRITE SEQ`, `RC=0B`, `CR=0A` au CLOSE; CLOSE réussi | haute |

La table de census historique qui appelait des FCB `01C5Dh` « `!E` » et `01CA2h` « `?` » est supersédée par les instantanés propres ci-dessus. Les octets de FCB capturés à l'entrée révèlent le nom ASCII; les lignes d'événements permettent de distinguer ses réutilisations.

Les DMA de lecture overlays repartent tous à `2200h`, avancent de `80h` par record et sont contigus: `PLI0.OVL` 141 records, dernière destination de données `6800h` (le 142e appel à `6880h` signale EOF); `PLI1.OVL` 272 records, dernière `A980h` (EOF `AA00h`); `PLI2.OVL` 264 records, dernière `A580h` (EOF `A600h`). Ces plages se recouvrent exactement dès `2200h`, preuve forte que les fichiers sont lus vers une même fenêtre RAM successive et donc que les overlays se remplacent. Première adresse d'exécution de chaque image non capturée dans ce run: le début DMA n'est pas à lui seul une preuve d'entry point.

`OPTIMIST.INT` reçoit quatre records via DMA `1D8Ch` (`1D8Ch`, `1E0Ch`, `1E8Ch`, `1F0Ch`), est fermé puis réouvert/lu à partir de `1D8Ch`, et est supprimé en fin. `OPTIMIST.REL` reçoit onze records depuis le DMA `1D0Ah`, à `CR=00..0A`, puis est fermé. REL final 1408 octets; INT temporaire absent après exécution. Tous les contenus cités sont divisibles exactement par 128, donc cette compilation ne discrimine pas les règles de padding d'un dernier record partiel; aucune conclusion sur `1Ah` (Ctrl-Z) ou sur un EOF partiel n'est justifiée.

Le census antérieur attribuait des opérations à `CPM3.SYS`; cette attribution est infirmée pour le scénario contrôlé: aucune ouverture/lecture de ce nom n'apparaît dans le journal propre. Sur l'image CP/M Plus la compilation complète réussit sans cet accès. Le motif de l'ancienne observation n'est pas récupérable à partir des données résumées et demeure non expliqué; n'en faites pas une exigence de runtime.

Les pointeurs FCB transmis dynamiquement sont `DE`. Les comptes plus fins suivants proviennent du journal contrôlé, borné au lancement transient et au premier warm boot:

| Service / FCB `DE` | Nom 8.3 lisible dans l'instantané | Nombre | Interprétation prudente |
|---|---|---:|---|
| OPEN `005Ch` | `OPTIMIST.PLI` | 3 | source, réouverture pour passes |
| OPEN `01C5Dh` | `PLI0.OVL`, `PLI1.OVL`, `PLI2.OVL` | 1 chacun | overlays successifs |
| OPEN `01CA2h` | `OPTIMIST.INT` | 1 | intermédiaire relu |
| READ `005Ch` | `OPTIMIST.PLI` | 28 | nombre inclut passages/EOF |
| READ `01C5Dh` | PLI0 (142), PLI1 (273), PLI2 (265) | 680 | 141/272/264 records + EOF respectivement |
| READ `01CA2h` | `OPTIMIST.INT` | 4 | records séquentiels de l'intermédiaire (le fichier avait 4 writes) |
| WRITE `01CE4h` | `OPTIMIST.REL` | 11 | 11 records |
| WRITE `01CA2h` | `OPTIMIST.INT` | 4 | quatre records temporaires |
| MAKE/DELETE/CLOSE | `01CA2h`, `01CE4h`, `01C5Dh` | voir cycle ci-dessus | identity variable à `01CA2h`; ne pas raisonner adresse→nom permanent |

Les snapshots de retour précités donnent la mutation immédiate pour DELETE/OPEN/CLOSE/MAKE dans ce run CP/M Plus; ils ne couvrent pas READ/WRITE. Dans les cas observés, DELETE ne modifie pas le FCB transmis. MAKE laisse le nom fourni, initialise les champs de directory/record observés, et renvoie `A=00`; OPEN remplit l'état de fichier et l'allocation visible; CLOSE laisse notamment `RC=0B`, `CR=0B` pour le REL de 11 records. Les valeurs Plus de `S1/S2` et d'allocation ne sont pas un contrat CP/M 2.2. Le premier FS doit garder les 36 octets FCB en RAM visibles au programme; synthétiser l'allocation disque réelle est plausible, mais la sûreté des champs réservés sur CP/M 2.2 reste à vérifier contre le manuel/tests. Les valeurs de retour OPEN/CLOSE/MAKE/DELETE concordent avec le manuel CP/M 2.2 pour les cas observés, mais seule une exécution sur un BDOS 2.2 authentique validera les détails de mutation.

Le DMA est une adresse mémoire mutable; les READ/WRITE observés utilisent la valeur courante. `0080h` sert au départ de buffer et aux FCB/default tail, les overlays utilisent `2200h` puis la fenêtre contiguë, l'INT `1D8Ch`, REL `1D0Ah`. Les autres adresses `ED06h` etc. appartiennent à des buffers non liés aux records source ou ont été vues lors de lectures source. Le backend doit transférer des records CP/M de 128 octets vers/depuis cette RAM, pas assimiler la lecture séquentielle à une lecture hôte directe.

Pour cette compilation, aucune opération random (33–36), recherche directory (17/18) ou rename n'a eu lieu avant warm boot. Les 712 READ SEQUENTIAL se ventilent en 680 appels overlays (141/272/264 records plus un EOF chacun), 28 source et 4 INT. PLI0/1/2 ont donc un contrat d'entrées BDOS ordinaires et non une injection magique par Runner. Aucun WRITE vers ces overlays n'a été observé.

## LINK / OPTIMIST / XREF, disques et versions

Le guide §1 décrit explicitement le flux `PLI OPTIMIST` → `OPTIMIST.REL` → `LINK OPTIMIST`, où LINK associe le REL à `PLILIB.IRL` et produit/remplace `OPTIMIST.COM`. Nous n'avons pas exécuté LINK, OPTIMIST.COM ni XREF dans l'environnement Runes/MAME dans ce tour. La fonction OPTIMIST est interactive selon le guide (console input); XREF et LINK introduisent vraisemblablement des besoins d'analyse de fichiers ou de command tail, mais aucune exigence supplémentaire ne doit encore être déclarée observée. Le tableau minimal de suites est donc :

| Composant | Besoin additionnel établi / probable | État |
|---|---|---|
| PLI.COM | tail + FCB par défaut, DMA, fichiers séquentiels, console, page zéro | code statique + exécutions CP/M Plus réussies |
| LINK.COM | lire `.REL` et `PLILIB.IRL`, créer `.COM` selon le guide | documenté; non exécuté dans cette étude |
| OPTIMIST.COM | console interactive selon l'Applications Guide | documenté; pas testé ici |
| XREF.COM | prend probablement source/object et produit listing/références | inconnu, enquête statique/dynamique nécessaire |
| RMAC.COM / LIB.COM | assembler et manipuler bibliothèques pour certains workflows | livrés; hors scénario observé |

Le harness MAME basculait le disque de travail vers B:; les outils, source et sortie du scénario étaient sur ce disque courant, sans preuve d'accès simultané à plusieurs drives ou à des user numbers. Le premier Runes peut utiliser A: virtuel par défaut et user 0; garder les sélections drive/user séparées du chemin hôte pour une extension ultérieure.

### Choix explicite de personnalité : CP/M 2.2

Runes cible CP/M 2.2.0 de façon déterministe, une seule version/personnalité dans le premier backend. Le QX-10/CP/M Plus est une source de comportement observé et un différentiel, pas une raison d'adopter ses extensions.

* Sur QX-10/CP/M Plus, le retour BDOS 12 observé à `PLI.COM` est `A=31h`, `HL=0031h` (appel site `05C4h`, retour `05C7h`). Le chemin suivant compare `HL` à `0130h` (calcul `0130h-HL`, helper `01B2Ch`, `ORA L`, `JZ 05EDh`). Comme `0031h != 0130h`, il suit `05D1h`, puis appelle BDOS `6Ch` à `05DFh` ou `05EAh` selon le byte interne `02011h`. Succès observé: `02011h=0`, `DE=0000h`, donc site `05EAh`: CP/M Plus fn108 **set** le program return code à zéro, puis warm boot. L'autre branche `DE=FF00h` setterait un code d'échec. Le résultat de SET n'est pas consommé par le code appelant; le retour A/HL capturé zéro n'est pas un état lu par PLI.
* La valeur conventionnelle CP/M 2.2 pour BDOS 12 est `HL=0022h` (`H=00`, `L=22h`; compatibilité de retour `A=L=22h`, `B=H=00h`). Elle ne correspond pas à `0130h`, donc le contrôle statique conduit également à `05D1h`. Une expérience sur MAME Plus a remplacé `HL` par `0022h` au breakpoint `05C7h`: compilation et REL restent identiques, `CPM3.SYS` reste absent, mais l'appel BDOS 108 est tout de même exécuté. C'est une injection contrôlée de la réponse uniquement, pas un CP/M 2.2 complet.
* Ainsi on ne peut pas soutenir que `PLI.COM` n'appelle jamais 108 sous une réponse 2.2. Le service 108 est néanmoins une extension CP/M Plus et Runes ne doit pas l'implémenter par défaut. La sonde CP/M 2.2 authentique ci-dessous confirme que l'appel observé avec `DE=0000h` revient à zéro et ne bloque pas la fin du run.
* `CPM3.SYS` n'est ouvert dans aucun des deux nouveaux runs propres (réponse native 0031 et réponse forcée 0022); la première trace antérieure qui l'attribuait à ce run est infirmée. Les fichiers source, overlays, INT et REL suivent autrement le même workflow dans l'observation forcée. On ne sait pas encore quel état/harness a causé les anciennes lignes `CPM3.SYS`; aucune opération ne montre un accès conditionnel après la comparaison de version.
* CP/M Plus peut être ajouté ensuite comme delta explicitement versionné: BDOS 108 (si souhaité), différences de tail/FCB/EOF constatées sous son CCP, et autres services Plus uniquement sur preuve. Pas de `CPM3.SYS` synthétique ni de code retour 108 dans le runtime CP/M 2.2 initial.

### Authentic CP/M 2.2 validation

Cette observation indépendante a été réalisée sous **z80pack cpmsim 1.39**, avec le système annoncé au démarrage comme `64K CP/M Vers. 2.2` (Z80 CBIOS V1.2). Le CBIOS est propre à l'environnement de simulation; les résultats ci-dessous portent sur son BDOS CP/M 2.2, pas sur un comportement QX-10. Elle complète, sans les confondre, le run QX-10/CP/M Plus et l'expérience distincte où seule la réponse de version du BDOS Plus avait été forcée à `HL=0022h`.

* Une sonde COM a observé BDOS 12: `A=22h, B=00h, H=00h, L=22h` (`HL=0022h`). Elle a aussi appelé le numéro 108 (`C=6Ch`, `DE=0000h`) et observé `A=00h, B=00h, H=00h, L=00h`, sans échec. **108 n'est pas un service CP/M 2.2**: cette observation confirme uniquement que le comportement hors plage zéro-retour de ce BDOS suffit pour l'appel de fin de `PLI.COM`; Runes n'implémente pas la sémantique CP/M Plus de code retour.
* Sur ce système authentique, `PLI OPTIMIST` termine normalement au CCP. Le compilateur v1.4 affiche `NO ERROR(S) IN PASS 1`, `NO ERROR(S) IN PASS 2`, puis `END COMPILATION`. Le répertoire final contient `OPTIMIST.PLI` et `OPTIMIST.REL`, mais pas `OPTIMIST.INT`.
* `OPTIMIST.REL` extrait de l'image CP/M 2.2 fait **1408 octets**, SHA-256 `5fca1ffe38d11c30d20cfb99a23fe2baf002c569790bda83e09151cf36032b15`; il est byte-identical à la référence QX-10/CP/M Plus. Pour ce scénario, cela valide différentiellement le chemin compileur et sa sortie entre les deux personnalités.
* Le premier état d'exécution de `PLI.COM` n'a pas été capturé: les bytes exacts `005Ch..008Fh` (FCB1/FCB2 et tail) restent à vérifier. Le snapshot QX-10/Plus ne doit pas être substitué au layout CCP CP/M 2.2. Cette lacune demeure un point de comparaison au lancement Runes, mais ne bloque plus le premier slice: l'exécution authentique, la réponse BDOS 12, le fallback 108 et la sortie REL sont établis.

**Décision d'implémentation : READY** pour commencer le premier environnement CP/M 2.2 Runes. Cela ne lève que le blocage de validation de personnalité; les octets exacts de lancement FCB/tail et les détails d'autres scénarios restent des points ouverts.

## Frontière filesystem recommandée

Une première surface suffisamment petite, sans secteurs physiques :

1. Normaliser les noms CP/M 8.3 ASCII sans dépendre de la casse de l'hôte; rejeter ou représenter explicitement les wildcards.
2. Résoudre `A:`–`P:` en disques virtuels, avec disque courant et user séparés du backend; premier run peut n'avoir qu'un drive mais garder cette frontière.
3. Maintenir FCB en mémoire comme état visible, handles ouverts indexés par FCB/identité de fichier; prendre en charge séquentiel record 128 octets et le DMA bus.
4. Faire les répertoires de recherche déterministes (tri CP/M normalisé), prévoir snapshot/diff et source des octets, mais différer cela après le premier compile.
5. Pour la personnalité CP/M 2.2, répondre à GET VERSION avec `HL=0022h`, fournir CONSOLE STATUS déterministe « aucun caractère » (`A=00`), ne fournir aucun `CPM3.SYS`, et ne pas implémenter la sémantique BDOS 108. Le BDOS 2.2 testé retourne zéro pour l'appel 108 hors plage avec `DE=0000h`; conserver le fallback CP/M 2.2 zéro-retour sans état de program-return-code. Ne pas ajouter Search/Random par anticipation.

Disque A hôte pour la distribution et un disque RAM scratch seraient pratiques pour isoler entrées/sorties, mais rien dans l'exécution conservée ne nécessite la lettre M: ou un second disque. Commencer avec un drive virtuel backend configurable, et éventuellement mapper une image de distribution read-only plus un scratch memory-backed sur lettres configurées. Ne pas coder M: comme convention historique.

## Étapes d'implémentation proposées

1. **CP/M 2.2 process environment + fichiers séquentiels** : initialiser page zéro/tail et FCB chevauchants selon le contrat CP/M 2.2 (ne pas copier le CCP Plus observé), drive 0/user 0, DMA `0080h`; conserver FCB RAM visible. Implémenter OPEN/CLOSE/DELETE/READ SEQ/WRITE SEQ/MAKE/SET DMA, records 128 octets, codes succès/EOF/erreur et console output/status sur références CP/M 2.2. GET VERSION répond `0022h`; aucun `CPM3.SYS` ni état BDOS 108 CP/M Plus. Pour l'appel hors-plage 108, le fallback CP/M 2.2 zéro est confirmé pour `DE=0000h`.
2. **Compile différentiel Runes** : charger v1.4 + overlays + source dans le drive virtuel; compiler `PLI OPTIMIST`; comparer diagnostics, REL exact et durée de vie INT aux références CP/M 2.2 et MAME. À l'entrée, capturer les bytes page-zéro/FCB/tail CP/M 2.2 pour fermer le point de comparaison du lancement.
3. **Filesystem complet plus tard** : snapshot/diff, host-backed et memory-backed drives; ajouter random/search/rename uniquement après LINK/XREF ou autres tests.
4. **LINK puis utilitaires** : confirmer REL/IRL/COM avec LINK; ensuite mesurer le delta CP/M de XREF/OPTIMIST et n'ajouter search/random/rename que sur preuve.

## Contrat initial CP/M 2.2 à implémenter

Cette checklist privilégie le manuel CP/M 2.2; les octets observés sur le CCP Plus sont informatifs mais pas normatifs pour Runes.

* Persona/version: BDOS function 12 retourne `HL=0022h`, `H=00`, `L=22h` (CP/M 2.2, machine 8080). La doc CP/M 2 indique le retour `HL`, et que le type CP/M est `H=00`, version 2.2 `L=22h`.
* Processus: drive courant `A:` (`0`), user `0`; DMA initial `0080h`; chargement COM à `0100h`; adresse `0005h` reste l'entrée BDOS abstraite Runes; `0006h` fournit un mot haut mémoire cohérent avec le layout runner, pas l'adresse MAME `F106h`.
* Tail: à `0080h`, premier octet longueur; `0081h...` est le tail après nom COM, avec espaces et lettres normalisées uppercase par CCP. N'imposer aucun CR/NUL terminal: CP/M 2 documente le count + caractères et dit la mémoire après la fin non initialisée. Pour déterminisme, Runes peut mettre à zéro le suffixe inutilisé, mais PL/I ne doit pas dépendre de ce remplissage.
* FCB: construire FCB1 à `005Ch` et FCB2 à `006Ch`; le second chevauche l'aire allocation du premier, il faut déplacer ses champs initiaux avant un OPEN de FCB1. Pour la commande `PLI OPTIMIST`, le CCP 2.2 construit le premier nom `OPTIMIST` (extension non spécifiée donc blancs), et FCB2 vide; le compilateur peut ensuite compléter/parsing `.PLI` à partir du tail. Champs décrits par CP/M 2: drive/name/type des deux FCB; les autres champs jusqu'à `CR` sont zéro, sauf que les 16 bytes FCB2 occupent `006Ch..007Bh` dans le stockage de FCB1. Ne pas recopier `.PLI` à partir du snapshot CCP Plus.
* SET DMA (26): `DE` remplace le pointeur DMA courant; DMA désigne 128 octets exacts utilisés par READ/WRITE. Le caller sélectionne les adresses; le BDOS n'impose pas d'alignement d'adresses.
* OPEN (15): FCB nom/drive; success `A=0..3` (directory code), missing `A=FF`; succès laisse les informations directory/allocation dans FCB. La compilation ouvre fichiers nommés sans wildcard.
* READ SEQ (20): copie 128 octets à DMA, avance `CR`, bascule l'extent au débordement; `A=0` succès, tout nonzero signifie pas de données au prochain record (EOF observé CP/M Plus `A=1`). Ne pas injecter Ctrl-Z: ce run compile des fichiers en records pleins et ne tranche pas un dernier record partiel.
* MAKE (22): crée un fichier vide et active le FCB; success `A=0..3`, échec espace directory `FF`; le compilateur fait un DELETE préalable pour éviter les doublons.
* WRITE SEQ (21): écrit le record DMA (128 octets), avance CR/extent; `A=0` succès, nonzero échec (disque plein). WRITE vers REL/INT observés.
* CLOSE (16): nécessaire après WRITE pour rendre la taille/état répertoire permanent; success `A=0..3`, fail `FF`. CLOSE read-only optionnel selon manuel.
* DELETE (19): success `A=0..3`, absent `FF`; PLI tolère le cas absent avant MAKE.
* Console: BDOS 2 émet l'octet `E` exactement; BDOS 11 retourne `A=0` si aucune touche, `A=FF` si disponible. Aucun caractère pending testé; l'option abort exige éventuellement console input et reste hors du premier test batch.
* BDOS 108 / 6Ch: ne pas implémenter l'état sémantique « Get/Set Program Return Code » CP/M Plus. Dans CP/M 2.2, 108 est au-delà des fonctions définies; la sonde z80pack cpmsim 1.39 avec `DE=0000h` observe zéro dans `A`, `B` et `HL`, sans échec. Le fallback CP/M2 générique « fonction inconnue => zéro » suffit à cet appel de fin, sans état de program-return-code.
* Fin: `PC=0000h` termine l'expérience Runes en `Warm_boot`; ne lance pas de CCP/BIOS. C'est le retour transitoire CP/M conventionnel modélisé à la frontière userspace.

L'API filesystem peut rester « drive virtuel + nom CP/M normalisé + FCB RAM visible + records 128 octets + DMA », avec stockage d'allocation/extent synthétique tant que les champs observables ci-dessus concordent. Un seul drive A et user 0 suffisent à `PLI OPTIMIST`; conserver une frontière drive/user distincte pour LINK et l'étape multi-disques ultérieure.

## Sources

* Digital Research, *CP/M Operating System Manual*, CP/M 2, §5.1, pages imprimées 5-2 (page zéro, `0005h`, `0006h`, COM à `0100h`, warm boot) et §5.2 (page zéro, tail/FCB, BDOS return values, fichiers séquentiels, DMA et records 128 octets). Copie HTML/OCR : [CP/M System Interface, section 5](https://ftpmirror.infania.net/sites/www.gaby.de/cpm/manuals/archive/cpm22htm/ch5.htm). Sections Web 5.2: version §5.2/Function 12; page zero/default FCB/tail §5.2; fonctions 15–22 et 26.
* Digital Research, *PL/I-80 Applications Guide*, décembre 1980, §1, pages imprimées 6–7 (fichiers OVL, commande compile, passes, REL puis LINK), §2, page 8 (options), §4 pages 18–20 (sequential/direct), §5 (exemples). [PDF conservé par Bitsavers](https://www.bitsavers.org/pdf/digitalResearch/pl1/PL1-80_Applications_Guide_Dec80.pdf). C'est un guide de l'environnement PL/I-80 et non une preuve de toutes les spécificités du binaire v1.4.
* Digital Research, *CP/M Plus Programmer's Guide*, p. 3-89, BDOS fn 108 / 6Ch, Get/Set Program Return Code (`DE=FFFFh` get; toute autre valeur set); [copie Bitsavers](https://bitsavers.org/pdf/digitalResearch/cpm_plus/CPM_Plus_Programmers_Guide_Jan83.pdf). Sert seulement à interpréter la fonction CP/M 3 chargée statiquement.
* Preuve binaire locale : `DISK1/PLI.COM` SHA-256 ci-dessus; désassemblage Intel 8085 produit avec `dasm85`, fichier local de travail `PLI-resident.lst`. Les sections et sites de ce document sont des adresses de ce listing.
* Preuve dynamique : run temporaire MAME 0.289 / QX-10 / CP/M Plus, commande CCP `PLI OPTIMIST`, breakpoint à toute entrée BDOS, census borné au premier témoin PC=`0000h`; durée indiquée ci-dessus. Les anciens journaux `out-full/OPTIMIST/mame.log`, `out-full/OPTIMIST/directory.txt`, captures `OPTIMIST-*.INT.*` et `out/ADDC/mame.log` sont des corroborations antérieures, certaines filtrées. Les logs complets temporaires ne sont pas archivés dans le dépôt; les comptes, sites et FCB décodables sont résumés dans les tables.
* Capture de cette mise à jour : MAME 0.289 QX-10 / CP/M Plus, copie disposable de `PLI80-QXPLUS.base.imd` (hash image source `1a3172c2990f0a6804fd30fdde7ce5800faaf8690b5b872691d5874126753dd1`), `PLI OPTIMIST`, 34.839 s émulateur; snapshot page zéro à premier `PC=0100h`, événements FCB/BDOS jusqu'au warm boot. Seconde exécution même copie-baseline avec action de breakpoint `HL=0022h` juste après le retour BDOS12: même fichier REL/hash, aucun `CPM3.SYS`, BDOS108 toujours appelé. Cela n'émule pas les réponses/effets complets d'un CP/M2 réel.

## Observations authentiques CP/M 2.2 : READ et transitions d'extent

Sonde COM temporaire sur z80pack cpmsim **1.39**, bannière `64K CP/M Vers. 2.2 (Z80 CBIOS V1.2 for Z80SIM)`. Le programme a ouvert `B:PLI1.OVL` par BDOS 15 puis a effectué un seul flux continu de BDOS 20, en gardant le FCB en RAM et en affichant les snapshots après les appels. `PLI1.OVL` extrait de `disks/driveb.dsk` faisait **34 816 octets / 272 records**, SHA-256 `1ed6d00f423ffb55ab4ea9a49c33a72617b7ccc5ead5ecdcb5bbf1733214e564`. Le disque source n'a pas été modifié; son image de travail était une copie jetable. Le probe imprime le code A sauvegardé juste après le service, avant les appels BDOS 2/9 servant à l'affichage.

Valeurs affichées dans l'ordre `A / EX / S1 / S2 / RC / CR`, toutes en hexadécimal :

| Point après service | CP/M 2.2 authentique | Runes après correction |
|---|---|---|
| OPEN | `03 / 00 / 00 / 80 / 80 / 00` | `00 / 00 / 00 / 80 / 80 / 00` |
| 126e READ réussi | `00 / 00 / 00 / 80 / 80 / 7E` | `00 / 00 / 00 / 80 / 80 / 7E` |
| 127e READ réussi | `00 / 00 / 00 / 80 / 80 / 7F` | `00 / 00 / 00 / 80 / 80 / 7F` |
| 128e READ réussi | `00 / 00 / 00 / 80 / 80 / 80` | `00 / 00 / 00 / 80 / 80 / 80` |
| 129e READ réussi | `00 / 01 / 00 / 80 / 80 / 01` | `00 / 01 / 00 / 80 / 80 / 01` |
| 254e READ réussi | `00 / 01 / 00 / 80 / 80 / 7E` | `00 / 01 / 00 / 80 / 80 / 7E` |
| 255e READ réussi | `00 / 01 / 00 / 80 / 80 / 7F` | `00 / 01 / 00 / 80 / 80 / 7F` |
| 256e READ réussi | `00 / 01 / 00 / 80 / 80 / 80` | `00 / 01 / 00 / 80 / 80 / 80` |
| 257e READ réussi | `00 / 02 / 00 / 80 / 10 / 01` | `00 / 02 / 00 / 80 / 10 / 01` |
| 271e READ réussi | `00 / 02 / 00 / 80 / 10 / 0F` | `00 / 02 / 00 / 80 / 10 / 0F` |
| 272e READ réussi | `00 / 02 / 00 / 80 / 10 / 10` | `00 / 02 / 00 / 80 / 10 / 10` |
| premier EOF après 272 records | `01 / 02 / 00 / 80 / 10 / 10` | `01 / 02 / 00 / 80 / 10 / 10` |

Le code OPEN authentique `03` est un code de répertoire réussi; Runes choisit `00` de façon déterministe. Les deux sont dans la plage contractuelle `00h..03h`, donc ce n'est pas un mismatch CP/M-visible de succès/échec, mais Runes ne reproduit pas le code de slot physique. Les nouveaux snapshots FCB READ concordent exactement avec les valeurs CP/M 2.2.

L'implémentation FCB distingue maintenant le module logique (S2 bits 0..3) du write-flag (bit 7); EX fournit les cinq bits bas de l'extent. Les bits S2 4..6 ne participent pas à l'adresse d'extent. Ainsi les 512 extents représentent exactement 65 536 records. OPEN et MAKE mettent le write-flag visible. Le source BDOS CP/M 2.2 montre qu'un WRITE ordinaire le retire quand le FCB est modifié; au dernier record, le chemin séquentiel ouvre/prépare aussi l'extent suivant et son OPEN/MAKE remet le flag. Le modèle suit cette distinction. CLOSE consomme l'état dirty côté répertoire mais ne réarme pas le flag du FCB utilisateur.

Après le 128e et le 256e READ réussi, Runes garde désormais l'ancien `EX`, `RC=80h` et expose `CR=80h`. Le READ suivant utilise cette position pour lire le premier record de l'extent suivant, puis retourne `EX` incrémenté, son `RC` et `CR=01h`. EOF ne modifie pas le FCB. **EXTENT MATCH** pour les snapshots READ testés, y compris OPEN au niveau du contrat succès/échec; le code de répertoire OPEN n'est pas comparé bit-à-bit. Le source CP/M 2.2 utilise un calendrier distinct pour WRITE: après le dernier record d'un extent, WRITE prépare l'extent suivant avant le retour, tandis que READ ne le sélectionne qu'au prochain appel. Runes conserve ce calendrier de WRITE; il efface le write-flag sur une mutation ordinaire et le réarme quand le prochain extent est préparé. Les snapshots authentiques WRITE restent à sonder. Cette observation ne couvre pas non plus le WRITE terminal à 8 MiB.

### Questions ouvertes

* Quel est le census avec options de compilation/listing/impression, et quels retours BDOS sont consommés pour chaque erreur/succès ?
* Quels champs FCB sont lus/écrits à chaque étape, et les fichiers intermédiaires exacts sont-ils supprimés/recréés ?
* Les bytes réels de FCB1/FCB2 et du command tail au premier `PC=0100h` sous CCP CP/M 2.2 n'ont pas été capturés; le layout documenté sert de contrat initial et devra être comparé à l'entrée Runes. Le comportement de BDOS 108 observé dans z80pack est limité à l'appel testé `DE=0000h`.
* Où chaque overlay commence à s'exécuter après le chargement contigu? DMA établit le buffer `2200h`, pas l'entry point.
* Les bytes de DMA pré/post-service, EOF exact à l'octet, tailles logiques des INT supprimés, et dernier record partiel restent non capturés / non discriminés.
* Qu'ajoutent réellement LINK, XREF et OPTIMIST exécutables à la surface du compilateur ?
* Quelle variation de résultat vient des conventions CP/M 2.2 vs CP/M Plus (notamment version, code retour, EOF et retours A) ?

La réponse à ces questions doit venir de runs différenciés et de snapshots d'état, pas d'une généralisation du manuel CP/M ni d'une interprétation forcée des « garbage FCB » des logs existants.
