# Le domaine identité : permissions, licences, validation

Les six outils Entra sont **les seuls d'ARGUS à toucher un tenant réel**. Tous
les autres interrogent des sources publiques ou des corpus embarqués ; ceux-ci
lisent l'annuaire d'une organisation et ses journaux d'authentification.

Ce document existe pour trois raisons :

1. **Accorder au plus juste.** Chaque permission demandée doit être justifiée
   par un appel précis, pas par confort.
2. **Ne pas confondre licence et permission.** Microsoft répond `403` dans les
   deux cas. Chercher la mauvaise cause fait perdre des jours.
3. **Valider en conditions réelles.** Le mode fixture permet de tout
   développer sans tenant — c'est un atout, et c'est aussi le risque : rien ne
   garantit qu'un appel réel se comporte comme la fixture tant qu'on ne l'a
   pas fait.

> Toutes les exigences ci-dessous ont été relevées dans la documentation
> Microsoft Graph, page par page, et non reprises de mémoire. Les liens
> pointent la page exacte qui porte l'affirmation.

---

## 1 · Ce que chaque outil appelle réellement

Relevé dans le code, pas dans une intention.

| Outil | Appel Microsoft Graph |
|---|---|
| `get_user_context` | `GET /users` (filtré sur l'UPN) **puis** `GET /users/{id}/memberOf` |
| `get_user_signins` | `GET /auditLogs/signIns` |
| `get_risky_users` | `GET /identityProtection/riskyUsers` |
| `get_risk_detections` | `GET /identityProtection/riskDetections` |
| `get_directory_audits` | `GET /auditLogs/directoryAudits` |
| `get_conditional_access_policies` | `GET /identity/conditionalAccess/policies` |

Six outils, sept appels — `get_user_context` en fait deux, ce qui a une
conséquence développée en [section 3](#3--pourquoi-directoryreadall-et-pas-userreadall).

Tous sont des `GET`. **Aucun outil n'écrit**, et aucune permission en écriture
n'est demandée : c'est vérifiable dans le tableau ci-dessous, où aucun nom ne
se termine par `.ReadWrite.All`.

---

## 2 · Le jeu de permissions minimal

**Cinq permissions d'application** (surtout pas déléguées : ARGUS s'authentifie
en client credentials, sans utilisateur connecté).

| Permission | Débloque | Source |
|---|---|---|
| `Directory.Read.All` | `get_user_context` | [user-list-memberof](https://learn.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0) |
| `AuditLog.Read.All` | `get_user_signins`, `get_directory_audits` | [signin-list](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0), [directoryaudit-list](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0) |
| `IdentityRiskyUser.Read.All` | `get_risky_users` | [riskyuser-list](https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0) |
| `IdentityRiskEvent.Read.All` | `get_risk_detections` | [riskdetection-list](https://learn.microsoft.com/en-us/graph/api/riskdetection-list?view=graph-rest-1.0) |
| `Policy.Read.All` | `get_conditional_access_policies` | [conditionalaccessroot-list-policies](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0) |

Le consentement administrateur doit être **accordé explicitement**. Sans ce
clic, Graph répond `403` sur tout.

---

## 3 · Pourquoi `Directory.Read.All` et pas `User.Read.All`

C'est la seule permission du jeu qui mérite une discussion, parce que c'est la
plus large — et elle n'est pas exigée par l'appel qu'on croit.

| Appel | Permission minimale |
|---|---|
| `GET /users` | `User.Read.All` suffit |
| `GET /users/{id}/memberOf` | **`Directory.Read.All` exigé** |

C'est donc la lecture des **appartenances** — groupes et rôles d'annuaire — qui
impose la permission large. Or ces appartenances sont exactement ce qui
détermine la gravité d'un incident : une connexion suspecte sur un compte
ordinaire et sur un administrateur global n'appellent pas la même réponse.

### Si vous accordez seulement `User.Read.All`

L'outil ne tombe pas. Il rend la fiche du compte, et signale que les
appartenances sont illisibles :

```json
{
  "user_principal_name": "sarah.n@contoso.com",
  "is_privileged": false,
  "memberships_readable": false,
  "notes": [
    "APPARTENANCES ILLISIBLES : groupes et rôles n'ont PAS pu être lus
     (Permission insuffisante (403)). « is_privileged: false » signifie ici
     INCONNU, pas « sans privilège » — la gravité de l'incident ne peut pas
     être conclue à partir de cette fiche."
  ]
}
```

**Pourquoi ce détail compte plus qu'il n'en a l'air.** Sans appartenances,
`is_privileged` retombe mécaniquement à `false`. Rendre cela en silence
présenterait une administratrice globale comme un compte ordinaire, et ferait
sous-évaluer un incident majeur — précisément le « confondre inconnu et sain »
que le projet s'interdit partout ailleurs. Le champ `memberships_readable`
existe pour que `is_privileged` ne soit jamais lu comme une réponse quand c'est
une ignorance.

**Recommandation :** accordez `Directory.Read.All`. Le mode dégradé existe pour
qu'un refus soit lisible, pas pour être un régime de fonctionnement.

---

## 4 · Les licences, vérifiées une par une

Microsoft renvoie `403` aussi bien pour une permission manquante que pour une
licence insuffisante. ARGUS distingue les deux dans son message d'erreur, mais
encore faut-il savoir ce qui est réellement exigé.

| Outil | Licence | Ce que dit la source, mot pour mot |
|---|---|---|
| `get_user_context` | aucune | — |
| `get_conditional_access_policies` | aucune | — |
| `get_directory_audits` | aucune | aucune mention de licence sur la page de la ressource ni de l'API |
| `get_user_signins` | **P1 ou P2** | « You must have a Microsoft Entra ID P1 or P2 license to download sign-in logs by using the Microsoft Graph API » — [resources/signin](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0) |
| `get_risk_detections` | **P1 ou P2** | « You must have a Microsoft Entra ID P1 or P2 license to use the risk detection API » — [riskdetection-list](https://learn.microsoft.com/en-us/graph/api/riskdetection-list?view=graph-rest-1.0) |
| `get_risky_users` | **P2 seulement** | « Using the riskyUsers API requires a Microsoft Entra ID P2 license » — [resources/riskyuser](https://learn.microsoft.com/en-us/graph/api/resources/riskyuser?view=graph-rest-1.0) |

Ce que cela donne concrètement :

| Tenant | Outils utilisables |
|---|---|
| Sans licence premium | **3 sur 6** — contexte, audits d'annuaire, accès conditionnel |
| P1 | **5 sur 6** — tout sauf `get_risky_users` |
| P2 | **6 sur 6** |

> Un piège écarté au passage. La table de rétention des rapports Entra indique
> que les connexions sont conservées 7 jours en édition gratuite, ce qui laisse
> croire que l'API fonctionne sans licence. C'est faux : la rétention concerne
> les rapports du portail, l'accès **par l'API Graph** exige P1 ou P2. Les deux
> pages ne parlent pas de la même chose.

---

## 5 · Une limite connue : la fenêtre de 7 jours

`get_user_signins` et `get_directory_audits` bornent leur fenêtre à **168
heures**, soit 7 jours.

Sur un tenant P1 ou P2, Microsoft conserve pourtant **30 jours** de journaux.
Ces deux outils n'atteignent donc pas la profondeur d'historique que la licence
paie déjà. Ce n'est pas un défaut de correction — la borne protège d'une
réponse énorme — mais c'est une limite assumée, pas une propriété de Graph.

---

## 6 · Checklist de validation sur un tenant réel

À faire **une fois**, par quelqu'un qui a accès à un vrai tenant. Toutes les
étapes sont en lecture seule : rien n'est modifié, ni créé, ni supprimé.

### Avant de commencer

- [ ] Une inscription d'application Entra existe, avec un secret client valide
- [ ] Les cinq permissions de la [section 2](#2--le-jeu-de-permissions-minimal)
      sont accordées **en type Application**
- [ ] Le consentement administrateur a été accordé (le bouton, pas seulement
      l'ajout des permissions)
- [ ] Vous savez quelle licence porte le tenant (Free, P1 ou P2) — cela
      détermine ce qui doit marcher

```bash
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export ENTRA_DATA_SOURCE=graph     # sortir du mode fixture
```

### Le diagnostic intégré d'abord

```bash
python -m entra_secops_mcp --check
```

Le serveur ne démarre pas : il vérifie la configuration, l'authentification,
les permissions consenties et l'accès à **chaque** endpoint, puis quitte. S'il
échoue, inutile d'aller plus loin — rien d'autre ne marchera, et son message
dit lequel des trois niveaux a cédé.

### Puis outil par outil

| # | Outil | Ce qu'on attend | Si ça échoue |
|---|---|---|---|
| 1 | `get_user_context` sur un compte **ordinaire** | fiche rendue, `memberships_readable: true`, `is_privileged: false` | `memberships_readable: false` → `Directory.Read.All` manque ou n'est pas consentie |
| 2 | `get_user_context` sur un compte **administrateur connu** | `is_privileged: true`, le rôle apparaît dans `privileged_roles` | `false` alors que le compte EST admin → vérifier `memberships_readable` avant tout |
| 3 | `get_user_context` sur un UPN inexistant | erreur claire « Aucun compte ne correspond » | une autre erreur → le filtre OData ne passe pas |
| 4 | `get_user_signins` sur un compte actif, 24 h | des événements, ou une liste vide justifiée | `403` → licence P1/P2, **pas** une permission |
| 5 | `get_directory_audits`, 24 h | des entrées si l'annuaire a bougé | `403` → permission `AuditLog.Read.All` |
| 6 | `get_conditional_access_policies` | les politiques du tenant, avec leur état | `403` → `Policy.Read.All` |
| 7 | `get_risky_users` | comptes à risque, ou liste vide | `403` → **P2** requis |
| 8 | `get_risk_detections` | détections, ou liste vide | `403` → P1 ou P2 requis |

### Le point le plus important de cette liste

**L'étape 2.** C'est la seule qui vérifie que la gravité d'un incident est
correctement établie. Un `is_privileged: false` sur un compte réellement
administrateur est le seul résultat de cette checklist qui soit *dangereux*
plutôt que simplement gênant : il ne ressemble pas à une panne, et rien
n'attire l'attention dessus.

Vérifiez toujours `memberships_readable` avant de croire `is_privileged`.

### Distinguer les deux `403`

ARGUS le fait déjà dans son message. Pour le contrôler à la main :

- **licence** — l'appel échoue pour *tous* les comptes, y compris le vôtre, et
  seulement sur les outils marqués P1/P2 en [section 4](#4--les-licences-vérifiées-une-par-une)
- **permission** — l'appel échoue sur un endpoint précis alors que d'autres
  passent ; le diagnostic le signale avant tout appel métier

---

## 7 · Ce que cette validation ne couvre pas

Dit ici plutôt que découvert plus tard :

- **Un seul tenant.** Réussir sur un tenant ne garantit rien sur un autre :
  licences, politiques d'accès conditionnel et volumes diffèrent.
- **Les volumes réels.** Les fixtures comptent quelques dizaines d'entrées. Un
  tenant de plusieurs milliers de comptes exercera la pagination et la
  limitation de débit autrement.
- **La durée.** Un secret client expire. Rien dans cette checklist ne teste ce
  que fait ARGUS le jour où il expire.
