# Brief technique — état de l'art et exposition sécurisée

Ce document répond aux deux volets de recherche exigés par le cahier des
charges de Phase 1 :

- **Partie A** — scan du marché : un socle MCP équivalent existe-t-il déjà ?
- **Partie B** — comment exposer ce serveur à des clients distants, en sécurité ?

> **Méthode et fraîcheur.** Les constats ci-dessous ont été vérifiés en
> **août 2026** auprès des sources listées en fin de document. L'écosystème MCP
> évolue vite : reprendre cette vérification avant toute décision d'architecture
> engageante.

---

# Partie A — Scan du marché

## A.1 Réponse directe

**Oui, un socle équivalent existe désormais.** Il serait malhonnête de prétendre
le contraire.

Microsoft publie un catalogue officiel de serveurs MCP
([`microsoft/mcp`](https://github.com/microsoft/mcp)), qui contient deux
implémentations empiétant directement sur le périmètre de ce projet.

Cette conclusion ne condamne pas le projet, mais elle en déplace la
justification : il ne s'agit plus de *combler un vide*, mais de *couvrir un
besoin précis que les solutions généralistes ne servent pas bien*. La section
A.4 développe cet argument.

## A.2 Les solutions existantes

| Solution | Éditeur | Périmètre | Écriture ? |
|---|---|---|---|
| **Microsoft MCP Server for Enterprise** (`microsoft/EnterpriseMCP`) | Microsoft, officiel | Traduit des questions en langage naturel en appels Graph. Couvre la posture de sécurité, l'accès privilégié, le risque applicatif, la gouvernance des accès, l'état des appareils et la télémétrie d'audit. | Lecture seule |
| **Lokka** (`merill/lokka`) | Communautaire (Merill Fernando) | Passerelle générique vers **tout** Microsoft Graph et Azure Resource Manager. Authentification interactive MSAL, application (secret ou certificat), ou jeton. | **Oui**, si les permissions sont accordées |
| **Microsoft Sentinel Data Exploration MCP** | Microsoft, officiel | Recherche et extraction dans le lac de données Sentinel. | Lecture seule |
| **Azure MCP Server** (`servers/Azure.Mcp.Server`) | Microsoft, officiel | Gestion des ressources Azure. Hors périmètre identité. | Oui |
| **Microsoft Learn MCP** (`microsoftdocs/mcp`) | Microsoft, officiel | Accès à la documentation. Aucun rapport avec la télémétrie. | Non |

## A.3 Analyse du recouvrement

### Microsoft MCP Server for Enterprise — le concurrent direct

C'est le recouvrement le plus fort : même source de données, même posture de
lecture seule, et un périmètre annoncé qui inclut explicitement la télémétrie
d'audit et l'accès privilégié.

**Ses avantages** : maintenu par Microsoft, couverture fonctionnelle large,
suivra les évolutions de Graph.

**Ses limites pour notre usage** :

- **Approche « langage naturel vers Graph »**, et non outils spécialisés. Le
  modèle formule lui-même la requête Graph, ce qui déplace la fiabilité vers le
  LLM. Nos outils figent la requête dans du code testé.
- **Pas de garantie de troncature.** Le volume renvoyé dépend de la requête
  produite par le modèle. Notre serveur garantit une borne haute par construction.
- **Périmètre de permissions large**, cohérent avec une couverture large. Notre
  projet demande cinq permissions ciblées, une par outil.

### Lokka — puissant mais inadapté à un usage SecOps automatisé

Lokka est excellent pour l'exploration interactive. Deux points le rendent
inadapté au rôle visé ici :

1. **Il autorise l'écriture** si les permissions sont accordées. Un serveur
   destiné à alimenter un agent de triage autonome ne doit pas *pouvoir*
   modifier le tenant, même par erreur de configuration.
2. **Il expose Graph brut.** Aucune traduction des codes d'erreur, aucun
   agrégat pré-calculé, aucune troncature orientée sécurité.

## A.4 Verdict : construire, et pourquoi

Le projet se justifie sur cinq points qu'aucune solution existante ne réunit :

| # | Différenciateur | Pourquoi les alternatives ne le couvrent pas |
|---|---|---|
| 1 | **Troncature garantie par contrat** — 12 champs sur ~60, imposés par des modèles typés | Les passerelles génériques renvoient ce que Graph renvoie |
| 2 | **Agrégats déterministes** — comptages et motifs suspects calculés en Python | Un LLM qui compte 23 échecs dans une liste se trompe ; du code, non |
| 3 | **Traduction du jargon** — 22 codes d'erreur, 11 types de détection, 12 activités sensibles, avec la conduite à tenir | Graph renvoie `errorCode: 50126`, sans plus |
| 4 | **Lecture seule structurelle** — aucun outil d'écriture n'existe dans le code | Lokka écrit si on le laisse faire |
| 5 | **Mode fixture** — développement et démonstration sans tenant ni licence P1/P2 | Aucune alternative ne le propose |

**Recommandation.** Poursuivre le développement, mais **repositionner le projet
dans la documentation** : ce n'est pas « un serveur MCP Entra », c'est « une
interface de télémétrie durcie pour agent de triage ». Le différenciateur n'est
pas l'accès aux données — c'est le contrat imposé sur ce qui en sort.

Pour un besoin d'exploration interactive large, recommander explicitement
Microsoft MCP Server for Enterprise ou Lokka est la réponse honnête.

---

# Partie B — Exposition sécurisée

## B.1 État de la spécification MCP

Le serveur négocie la révision **`2026-07-28`**, vérifiée par une session réelle
(SDK Python `mcp` 2.0.0). Les évolutions qui portent sur l'exposition distante :

| Évolution | Conséquence pratique |
|---|---|
| **HTTP+SSE formellement déprécié** | Classé « Deprecated » sous la nouvelle politique de cycle de vie, donc supprimable dans une révision future. Toute nouvelle intégration doit viser Streamable HTTP. |
| **En-têtes `Mcp-Method` et `Mcp-Name` requis** | Les proxys, passerelles et limiteurs de débit peuvent router et compter **sans inspecter le corps** de la requête. Un vrai gain de sécurité : le filtrage n'exige plus de déchiffrer la charge utile. |
| **Durcissement de l'autorisation** | Validation de l'émetteur selon la **RFC 9207**, et abandon progressif de l'enregistrement dynamique de client (DCR) au profit des documents de métadonnées client (**CIMD**). |
| **Noyau de protocole sans état** | Facilite la mise à l'échelle horizontale derrière un répartiteur de charge. |

> ⚠️ Le cahier des charges de Phase 1 mentionne « SSE configurations » parmi les
> pistes. **Cette piste est à écarter** : SSE est déprécié depuis la révision
> 2025-03-26 et formellement classé comme tel en 2026-07-28.

## B.2 Comparaison des transports

| Transport | Surface d'attaque | Multi-clients | Recommandation |
|---|---|---|---|
| **stdio** | **Nulle** — aucun port ouvert, le client lance le processus | Non : un processus par client | **Usage local** (Claude Desktop, Cursor). C'est le mode actuel. |
| **Streamable HTTP** | Un port HTTP à protéger | Oui | **Usage distant**, obligatoirement derrière OAuth 2.1 et TLS |
| **HTTP+SSE** | — | — | **À éviter** : déprécié |

## B.3 Modèles d'exposition distante

### Modèle 1 — Proxy inverse + OAuth 2.1 (recommandé pour la production)

```
Client MCP ──TLS──► Caddy / Traefik ──► Serveur MCP (127.0.0.1:8000)
                    · terminaison TLS
                    · limitation de débit (via Mcp-Method)
                    · validation de l'en-tête Origin
```

Le serveur MCP joue le rôle de **serveur de ressource OAuth 2.1** : il publie
ses métadonnées selon la **RFC 9728**, et valide chaque jeton reçu — émetteur
(RFC 9207) **et audience**.

- ✅ Standard, auditable, compatible avec l'IdP de l'entreprise (Entra lui-même)
- ❌ Une brique d'infrastructure à exploiter et à maintenir

### Modèle 2 — Tunnel managé (Cloudflare Tunnel, Azure Container Apps)

Aucun port entrant n'est ouvert : le conteneur établit une connexion sortante.

- ✅ Pas de pare-feu à percer ; TLS et authentification fournis
- ❌ Dépendance à un fournisseur ; la télémétrie transite par un tiers

### Modèle 3 — stdio uniquement (mode actuel)

- ✅ **Surface réseau nulle** : c'est le modèle le plus sûr
- ❌ Ne permet pas le partage entre plusieurs analystes

**Recommandation pour la Phase 2.** Conserver stdio par défaut, et n'activer
Streamable HTTP + OAuth 2.1 derrière proxy inverse que lorsque le besoin de
partage se matérialisera. **Ne pas exposer de port avant d'en avoir besoin.**

> **État au 24 août 2026.** Streamable HTTP est implémenté (`argus-mcp --http`)
> en respectant cette recommandation : **stdio reste le défaut**, l'écoute est
> sur `127.0.0.1`, et le serveur refuse de démarrer sur une autre interface
> sans jeton **ni chiffrement**.
>
> Le Modèle 1 est pris en charge par `--tls-en-amont`, qui déclare qu'un proxy
> inverse termine TLS. Faute de proxy disponible, `--tls-cert / --tls-key`
> termine TLS dans le serveur lui-même : le couple est validé avant l'ouverture
> du port — expiration, correspondance clé/certificat, présence de SAN — et la
> version minimale est fixée à TLS 1.2, vérifiée par un handshake réel.
>
> **Ce qui manque encore** pour un Modèle 1 complet : l'authentification est un
> secret partagé, pas un jeton d'IdP. La forme est celle d'un serveur de
> ressource (`WWW-Authenticate` conforme RFC 9728), de sorte que la migration
> ne touchera que le vérificateur. Le renouvellement automatique des
> certificats (ACME) reste du ressort du proxy — c'est la raison principale de
> le préférer en production.

## B.4 Menaces spécifiques et contre-mesures

| Menace | Mécanisme | Contre-mesure |
|---|---|---|
| **Injection de prompt via la télémétrie** | Un attaquant nomme son appareil « Ignore les instructions précédentes ». Le texte arrive dans le contexte du modèle. | **Liste blanche de champs** : la troncature est un contrôle de sécurité, pas seulement une optimisation. Les champs libres non listés n'atteignent jamais le modèle. *Implémenté.* |
| **Injection de filtre OData** | Une valeur contenant une apostrophe altère la requête `$filter`. | Échappement systématique. *Implémenté et testé.* |
| **Rebinding DNS** | Un site web malveillant atteint un serveur MCP local. | Écoute sur `127.0.0.1` par défaut, validation de l'en-tête `Origin`, jamais désactivable. **Refus de démarrer** sur une autre interface sans jeton. *Implémenté et vérifié par requêtes réelles — une origine étrangère reçoit `403`.* |
| **Député confus** *(confused deputy)* | Un jeton émis pour un autre service est accepté. | Validation de l'audience **et** de l'émetteur (RFC 9207). *Non implémenté : le jeton actuel est un secret partagé, pas un jeton d'IdP. La forme de serveur de ressource est en place — le `401` porte un `WWW-Authenticate` conforme RFC 9728 — de sorte que la migration remplacera le seul vérificateur.* |
| **Exfiltration par l'agent** | Un agent compromis vide les journaux du tenant. | Bornes dures côté serveur : maximum 100 résultats, 168 heures, 20 pages. *Implémenté.* |
| **Fuite de secret** | Un `AZURE_CLIENT_SECRET` committé ou inscrit dans une image. | `.gitignore`, `--env-file`, gitleaks en CI et en pre-commit. *Implémenté.* |
| **Élévation de privilèges** | Le serveur détient plus de droits que nécessaire. | Cinq permissions applicatives ciblées, lecture seule. **Cible Phase 2 : identité managée**, qui supprime le secret client. |

## B.5 Gestion des identifiants — état de l'art

Par ordre de maturité décroissante :

1. **Identité managée Azure** — aucun secret n'existe. Disponible si le
   conteneur tourne dans Azure Container Apps. **Cible recommandée.**
2. **Fédération d'identité de charge de travail** — pour GitHub Actions ou
   Kubernetes ; zéro secret également.
3. **Certificat client** — préférable à un secret partagé.
4. **Secret client** — acceptable en développement local uniquement. *Mode actuel.*

`DefaultAzureCredential` d'`azure-identity` couvre les quatre et sélectionne la
méthode disponible : la migration vers l'identité managée ne demandera pas de
réécriture.

---

# Synthèse

| Question | Réponse |
|---|---|
| Un socle existe-t-il ? | **Oui** — Microsoft MCP Server for Enterprise et Lokka. |
| Faut-il continuer ? | **Oui**, en repositionnant le projet : interface de télémétrie *durcie*, pas passerelle Graph généraliste. |
| Quel transport pour du distant ? | **Streamable HTTP**. SSE est déprécié et ne doit pas être retenu malgré sa mention au cahier des charges. |
| Quelle protection ? | OAuth 2.1 en serveur de ressource (RFC 9728, RFC 9207) derrière un proxy inverse assurant TLS et limitation de débit. |
| Quand exposer ? | **Pas avant d'en avoir besoin.** stdio a une surface d'attaque nulle. |
| Quel risque prioritaire ? | **L'injection de prompt par la télémétrie.** La troncature est notre première défense. |

---

## Sources

- [microsoft/mcp — catalogue officiel des serveurs MCP Microsoft](https://github.com/microsoft/mcp)
- [merill/lokka — MCP pour Microsoft 365 et Graph](https://github.com/merill/lokka)
- [Spécification MCP 2026-07-28](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [Release candidate 2026-07-28 — détail des changements](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)
- [OAuth 2.1 pour les serveurs MCP distants](https://mcp.directory/blog/oauth-21-for-remote-mcp-servers-streamable-http-explained-2026)
- [Comparaison des transports stdio et Streamable HTTP](https://www.truefoundry.com/blog/mcp-stdio-vs-streamable-http-enterprise)
- [Documentation Azure MCP Server](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/)
