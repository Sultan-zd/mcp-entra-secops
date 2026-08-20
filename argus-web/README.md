# ARGUS Web

Interface web de la plateforme SecOps ARGUS.

![Java](https://img.shields.io/badge/Java-25-orange?logo=openjdk&logoColor=white)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.1-6DB33F?logo=springboot&logoColor=white)
![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)
![MCP](https://img.shields.io/badge/MCP%20SDK-2.0.1-brightgreen)

Deux étages, découpés selon ce que chaque outil exige réellement :

| Étage | Outils | Condition d'accès |
|---|---|---|
| **Public** | Les 5 outils de messagerie — SPF, DKIM, DMARC, en-têtes, posture | Aucune. Ils ne lisent que le **DNS public** |
| **Compte** | Renseignement sur les menaces (4) et identité Entra (6) | Vos propres clés d'API et votre tenant |

L'étage public est celui qui est implémenté aujourd'hui.

---

## La décision d'architecture

**Le backend Java ne réimplémente aucune analyse. C'est un client MCP.**

Les quinze outils d'ARGUS sont écrits en Python et couverts par 288 tests. Les
réécrire en Java donnerait deux implémentations de la même règle — la limite des
dix résolutions SPF, la fusion des verdicts, l'alignement DMARC — qui
divergeraient en silence dès la première correction appliquée d'un seul côté.

```
Navigateur ──HTTP──> Spring Boot ──MCP/stdio──> serveurs Python ──> DNS public
                     (client MCP)               (déjà écrits, déjà testés)
```

Accessoirement, c'est la démonstration de l'intérêt réel de MCP : **les mêmes
serveurs servent Claude Desktop et cette application web**, sans une ligne de
code en double. Un protocole indépendant du langage, utilisé pour ce qu'il est.

### Pourquoi un groupe de processus

Un client MCP en mode stdio possède **un** couple de tubes vers **un** processus.
Deux requêtes HTTP simultanées passant par le même client entrelaceraient leurs
trames JSON-RPC. Et démarrer un interpréteur Python coûte près d'une seconde :
le faire par requête dominerait le temps de réponse.

Les processus sont donc démarrés au lancement, empruntés le temps d'un appel,
puis rendus. Un client dont le transport tombe en panne n'est pas remis dans le
groupe : il est fermé et remplacé.

### La liste d'autorisation des outils

Un serveur MCP annonce lui-même ses outils. S'y fier laisserait l'ajout d'un
outil côté Python l'exposer aussitôt sur le web, sans que personne ne l'ait
décidé. La configuration nomme donc explicitement les outils exposés.

---

## Démarrer

### Prérequis

- **JDK 25** (le projet compile en `--release 25`)
- **Node 20+**
- Le paquet Python ARGUS installé : depuis la racine du dépôt,
  `pip install -e ".[dev]"`

### Backend

```bash
cd argus-web/backend

# DOIT pointer vers le Python de l'environnement où ARGUS est installé.
export ARGUS_MCP_PYTHON="/chemin/vers/venv/Scripts/python.exe"

./mvnw spring-boot:run        # http://127.0.0.1:7998
```

### Frontend

```bash
cd argus-web/frontend
npm install
npm run dev                   # http://127.0.0.1:5173, mandataire vers 7998
```

Pour un seul port, construisez le front dans les ressources du backend :

```bash
npm run build                 # écrit dans backend/src/main/resources/static
```

Le backend sert alors l'interface et l'API sur **7998**, une seule origine —
donc aucun CORS à configurer.

---

## L'API publique

| Route | Objet |
|---|---|
| `POST /api/public/domain-posture` | Note sur 100 : SPF, DKIM et DMARC ensemble |
| `POST /api/public/spf` | SPF seul, dont le compte de résolutions DNS |
| `POST /api/public/dmarc` | Politique DMARC et ce qu'elle laisse passer |
| `GET /api/public/health` | État des serveurs MCP |

```bash
curl -X POST http://127.0.0.1:7998/api/public/domain-posture \
     -H "Content-Type: application/json" \
     -d '{"domain":"github.com"}'
```

Toutes les erreurs ont la même forme : `{"detail": "…"}`.

---

## Ce qui protège l'étage public

Une page ouverte à tous qui déclenche des requêtes DNS sortantes vers un domaine
choisi par l'appelant est, sans garde-fou, un relais de reconnaissance commode.

- **Limitation de débit** en seau à jetons, par appelant : 10 de capacité,
  5 jetons rendus par minute. Le seau se remplit en continu, ce qui autorise une
  courte rafale sans punir l'utilisateur normal en bord de fenêtre.
- **`X-Forwarded-For` n'est lu que si `argus.derriere-mandataire` est activé.**
  Cet en-tête est écrit par le client : le lire aveuglément offrirait un
  contournement de la limitation à quiconque invente une adresse par appel.
- **Validation du domaine avant tout travail**, pour ne pas dépenser un
  processus et des résolutions DNS sur une saisie évidemment fautive.
- **Aucune trace d'exception n'atteint le navigateur** : elle nommerait des
  classes et des chemins de fichiers.

---

## Différences avec le tableau de bord DMARC

Les deux projets partagent l'identité Teknologiia et la même structure de
paquets. Deux écarts délibérés :

| | DMARC Dashboard | ARGUS Web |
|---|---|---|
| Java / Spring Boot | 17 / 3.3.4 | **25 / 4.1.1** |
| Lombok | oui | **non** |

Spring Boot 4.1 est la version stable courante et prend Java 25 en charge de
première classe ; c'est aussi le seul JDK installé sur la machine de
développement. Lombok est écarté parce que son traitement d'annotations suit les
nouvelles versions du JDK avec du retard — un risque inutile pour économiser des
accesseurs.
