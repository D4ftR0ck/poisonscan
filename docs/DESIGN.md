# poisonscan : détection de l'empoisonnement « collecte → LLM »

Projet open source et public. Ce document est une note de conception : rien n'est encore implémenté.

## Problème
De plus en plus de systèmes collectent automatiquement des contenus externes (mails, pages web, flux RSS, PDF, tickets, scraping…), les stockent, puis les passent à un LLM : dans un RAG, un assistant, un agent ou une étape d'enrichissement. Un attaquant peut glisser dans ces contenus des instructions ou des affirmations fabriquées. On parle d'**injection de prompt indirecte** et d'**empoisonnement de corpus RAG**.

## Positionnement : ce qui distingue le projet
La plupart des outils existants surveillent le canal **utilisateur → LLM**, c'est-à-dire le prompt tapé par une personne au moment où elle l'envoie.
poisonscan surveille le canal **collecte → LLM** : le contenu ingéré automatiquement, qu'aucun humain n'a relu, et qui sera lu par un LLM plus tard.
- **Pas d'utilisateur à surveiller** : l'origine, c'est une source (expéditeur, domaine, URL, flux), et on attribue un niveau de confiance à chaque source.
- **Effet différé** : un contenu empoisonné peut rester des semaines dans une base. Le projet propose donc un contrôle à l'ingestion **et** une analyse complète du stock existant, avec une traçabilité (empreinte, source, date).
- **Volume** : des corpus de plusieurs dizaines de Go ou plus, d'où le choix de Rust et d'une analyse en flux.
- **Signaux propres à la collecte** :
  - texte caché (HTML invisible, caractères zéro-largeur, tags Unicode, texte blanc sur fond blanc, métadonnées PDF) ;
  - instructions adressées « à l'IA » dans un mail ou une page ;
  - une même charge qui revient d'une source à l'autre ;
  - une source peu fiable qui devient soudain abondante ;
  - des passages « aimants » qui remontent pour beaucoup trop de requêtes.
- **Hors périmètre** : les journaux applicatifs. En général, ils ne contiennent pas le texte collecté, seulement des messages de fonctionnement.

## Références techniques
- **PoisonedRAG** (Zou et al., USENIX Security 2025) : environ 5 textes fabriqués par question visée suffisent à imposer la réponse de l'attaquant dans environ 90 % des cas, même dans une base de plusieurs millions de documents.
- **EchoLeak** (Microsoft 365 Copilot, 2025, CVE-2025-32711) : un mail reçu, sans clic de la victime, est indexé, puis ses instructions font fuiter des données.
- **Slack AI** (2024, signalé par PromptArmor) : un message dans un canal public fait fuiter, par l'assistant, le contenu de canaux privés.
- **MITRE ATLAS AML.T0070 (RAG Poisoning)** : la technique de référence, avec des recommandations de traçabilité (requête, passages retrouvés, scores, source, niveau de confiance).
- **Greshake et al. 2023**, « Not what you've signed up for » : fondement de l'injection indirecte.
- (Dates et numéros de CVE à vérifier avant publication.)

## L'existant open source
- **Crates Rust** (récentes, peu éprouvées) : `atlas-detect` (97 règles MITRE ATLAS dans un `RegexSet`), `jailguard` (petit classifieur MLP embarqué), `llm-security`, `prompt-inj-rs`, `llm-kernel`.
- **Python** : LLM Guard, Vigil (règles YARA), Rebuff (archivé), prompt-armor. Garak est un outil de red-team, pas un détecteur.
- **Spécifique au RAG** : Cisco Adversarial Hubness Detector (analyse de l'index vectoriel), Semantic Chameleon (code de recherche).
- Rien de mûr pour le canal collecte → LLM. Les licences et l'état de maintenance restent à vérifier avant d'en réutiliser quoi que ce soit.

## Architecture
Un moteur Rust, deux usages :
1. **Contrôle à l'ingestion** : une bibliothèque appelée par le collecteur avant l'enregistrement. Elle renvoie un score, des explications et un verdict (accepter, marquer, mettre en quarantaine). Liaisons prévues : Rust natif, Python (PyO3), et plus tard une interface C ou un mode « pipe » pour les autres langages.
2. **`scan-store`** : un parcours complet d'un stock existant, fait une fois, puis de façon incrémentale, avec un rapport classé (passage, source, empreinte, date d'ingestion, règles déclenchées).

Espace de travail Cargo :
- `poisonscan-core` : sans E/S. Normalisation (Unicode NFKC, décodage HTML et MIME, extraction du texte caché), une chaîne de détecteurs (trait `Detector`), puis le score avec explications.
- `poisonscan-sources` : des adaptateurs (trait `Source`) en lecture seule. Pour commencer : fichiers et dossiers, JSONL, SQLite, Maildir/mbox. Plus tard : PostgreSQL et quelques bases vectorielles courantes.
- `poisonscan-cli` : `scan-store`, `explain <id>`, `rules lint`, `rules test`.
- `poisonscan-py` : liaison PyO3.

Ajouter un type de stockage, c'est ajouter un `Source` ; ajouter une méthode de détection, c'est ajouter un `Detector`. Le reste ne change pas.

## Entrée standardisée : l'« enveloppe document »
Le principe : un format d'entrée unique, publié et versionné, que n'importe quel pipeline peut produire. Les adaptateurs `Source` ne servent qu'à convertir un stockage vers ce format.
- **Format** : JSON Lines, un document par ligne, décrit par un schéma JSON (`envelope/v1`) :
  ```json
  {"schema":"poisonscan.envelope/v1","id":"…","source":{"type":"email|web|rss|pdf|ticket|api|other","uri":"…","trust":"low|medium|high"},
   "collected_at":"2026-11-18T10:00:00Z","content_type":"text/plain|text/html|message/rfc822|application/pdf",
   "content":"…","content_encoding":"utf8|base64","metadata":{}}
  ```
  Le format est volontairement proche de l'objet `File` / `Email` d'OCSF et des champs `email.*` / `url.*` d'ECS, pour qu'un événement de sortie s'y relie facilement.
- **Canaux d'entrée** :
  - stdin ou pipe (`poisonscan scan -`) ;
  - fichiers et dossiers en JSONL ;
  - appel de bibliothèque (Rust ou PyO3) avec la même structure ;
  - adaptateurs `Source` natifs (SQLite, Maildir, dossiers…) qui produisent l'enveloppe.
- **Décodeurs par `content_type`** : HTML (texte visible et texte caché séparés), MIME (parties et pièces jointes), PDF (texte et métadonnées). Tous les décodeurs sont plafonnés en taille et en profondeur.
- **Pas de serveur HTTP d'entrée dans le cœur** : Vector, Fluent Bit ou Logstash peuvent écrire du JSONL vers un fichier ou un pipe (sortie `exec` ou `file`). Un mode service HTTP pourra venir plus tard, dans une crate à part et désactivé par défaut.
- Le niveau de confiance de la source (`trust`) est fourni par l'appelant et pondère le score.

## Sortie standardisée et intégration SIEM
Le principe : des formats standard plutôt que des connecteurs écrits pour chaque produit. Le transport est laissé aux agents existants.
- **Événements de sortie** en JSON Lines, avec un schéma versionné, et deux formats prioritaires :
  - **OCSF** : classe Detection Finding, pour Splunk, AWS Security Lake et les autres outils qui l'adoptent ;
  - **ECS** : pour Elastic et OpenSearch.
  CEF et syslog RFC 5424 sont prévus en option pour les SIEM plus anciens.
- Chaque alerte porte `mitre.technique = AML.T0070` (et l'identifiant de la règle, la version du pack, l'empreinte, la source, le score). **Jamais d'extrait brut**, car les assistants LLM intégrés aux SIEM pourraient le relire et refaire l'attaque.
- **Destinations** : fichier, stdout, syslog, journald. En option, plus tard : un webhook HTTP générique, dans une crate à part.
- **Dossier `integrations/`** (configurations, pas de code dans le moteur) :
  - Splunk : `props.conf` et `transforms.conf`, requêtes SPL, tableau de bord ;
  - Elastic : template d'index, pipeline d'ingestion, règles de détection ;
  - Microsoft Sentinel et Defender XDR : table personnalisée dans Log Analytics et requêtes KQL de corrélation ;
  - exemples Vector et Fluent Bit.
- **MDE** : en lecture uniquement, par corrélation dans Sentinel ou Defender XDR. Pousser des indicateurs (domaines, URL) vers MDE reste un script d'exemple, désactivé par défaut et soumis à une validation humaine.

## Sécurité
Le contenu analysé est hostile par définition.
- `#![forbid(unsafe_code)]` dans le cœur, qui n'a ni accès réseau ni accès fichier.
- Moteur de regex en temps linéaire : pas de ReDoS.
- Taille par élément et profondeur de décodage plafonnées, contre les bombes de décompression et les encodages imbriqués.
- Adaptateurs strictement en lecture seule.
- Exemple d'unité systemd durcie fourni : `PrivateNetwork`, `ProtectSystem=strict`, `NoNewPrivileges`, `SystemCallFilter`.
- **Aucun extrait brut dans les alertes**, pour ne pas réinjecter la charge dans un autre LLM : identifiant, empreinte, règle et score seulement. `explain` affiche un extrait neutralisé.
- Chaîne d'approvisionnement : `cargo-deny`, `cargo-audit`, `Cargo.lock` versionné, peu de dépendances.

## Performance (faible charge CPU)
- Entonnoir : pré-filtre Aho-Corasick et balayage d'octets en O(n), puis `RegexSet` en une passe, puis classifieur ML (fonctionnalité Cargo optionnelle) seulement au-dessus d'un seuil.
- Incrémental : un curseur par source et une empreinte xxh3 par élément. Un élément n'est réanalysé que si son contenu ou la version des règles change.
- Lecture en flux par lots de taille fixe : mémoire constante quelle que soit la taille du stock.
- Pas de démon obligatoire. Parallélisme `rayon` réglable (nombre de threads), pour tourner aussi sur de petites machines (ARM, VM d'1 vCPU).
- Banc d'essai public : débit (Mo/s) et pic mémoire publiés pour chaque version.

## Maintenabilité des règles (contributions externes)
- **Règles séparées du code** : un dépôt ou dossier `rules/`, une règle par fichier YAML, rangée par famille (`hidden-text/`, `ai-directed/`, `exfil/`…).
- **Format inspiré de Sigma et YARA**, décrit par un schéma JSON : `id` stable (`PSN-0042`), `title`, `version`, `status` (`experimental` / `stable` / `deprecated`), `author`, `date`, `references`, `severity`, `channel`, `match`, `exceptions`.
- **Des exemples dans chaque règle** : `tests.positive` et `tests.negative`, vérifiés à chaque contribution.
- **CI** (`rules lint`, `rules test`) : schéma, compilation, plafond de coût par règle, exemples, unicité des id, et non-régression sur un corpus commun (piégé + sain) avec un seuil de faux positifs.
- **Versionnement** : le pack de règles est versionné (semver) séparément du moteur, et le moteur déclare la version de format qu'il accepte. Chaque verdict enregistre la version du pack utilisée.
- **Cycle de vie** : une règle n'est jamais supprimée, elle passe en `deprecated` ; un id n'est jamais réutilisé ; un `CHANGELOG` est tenu pour le pack.
- **Contribution** : `CONTRIBUTING.md`, modèle de règle, revue obligatoire, corpus de test enrichi avec des échantillons anonymisés.
- **Faux positifs** : `explain` montre quelle règle a déclenché ; on corrige par une exception ou un exemple négatif, sans toucher au moteur.
- **Confiance** : les packs publiés sont signés (minisign) et le moteur vérifie la signature.
- **Démarrage** : un convertisseur ponctuel depuis les règles existantes (Vigil YARA, atlas-detect, LLM Guard), en respectant leurs licences.

## Gouvernance du projet
- Licence MIT OR Apache-2.0 pour le moteur. La licence du pack de règles est à choisir (par ex. la même, ou la Detection Rule License, comme Sigma).
- `SECURITY.md` : procédure de signalement privé des contournements.
- Corpus de test public, sans aucune donnée personnelle.

## Ordre de travail
1. Spécifier le format des règles (schéma) et constituer un premier corpus piégé et sain, inspiré d'EchoLeak, de PoisonedRAG et de Slack AI.
2. `poisonscan-core` + `rules lint/test` + CI.
3. `poisonscan-sources` (fichiers, JSONL, SQLite, Maildir) + `scan-store` + `explain`. Fait pour SQLite : `tag-sqlite` (marqueurs dans `poisonscan_tags`, analyse incrémentale, nettoyage des orphelins, clé par empreinte du contenu au besoin).
4. Liaison PyO3 et exemple d'intégration dans un pipeline d'ingestion RAG.
5. Banc d'essai public, puis première version publiée.

## Points ouverts
- Alerter seulement, ou aussi mettre en quarantaine par défaut ?
- Détection des passages « aimants » : réutiliser les embeddings d'un index existant, ou en calculer ?
- Nom définitif du projet (« poisonscan » est provisoire, vérifier qu'il est libre).

## Vérification
- Le corpus piégé est entièrement détecté ; le taux de faux positifs sur le corpus sain reste sous le seuil fixé.
- Débit et pic mémoire mesurés sur une machine modeste et sur une machine courante.
