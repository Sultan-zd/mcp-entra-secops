import { useEffect, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Fingerprint,
  KeyRound,
  Loader2,
  Lock,
  Search,
  ShieldCheck,
  Siren,
} from 'lucide-react'

import Chat from '../components/Chat.jsx'
import { analyserPosture, sante } from '../services/api.js'
import './Landing.css'

/** Les quatre notes possibles, de la mieux protégée à la plus exposée. */
const CLASSE_NOTE = { A: 'note-a', B: 'note-b', C: 'note-c', D: 'note-d', F: 'note-f' }

const CLASSE_GRAVITE = {
  none: 'gravite-ok',
  low: 'gravite-ok',
  medium: 'gravite-moyenne',
  high: 'gravite-haute',
  critical: 'gravite-haute',
}

function Mecanisme({ icone: Icone, titre, sousTitre, gravite, constats }) {
  return (
    <div className={`mecanisme ${CLASSE_GRAVITE[gravite] ?? 'gravite-moyenne'}`}>
      <div className="mecanisme-tete">
        <Icone size={17} aria-hidden="true" />
        <h3>{titre}</h3>
      </div>
      <p className="mecanisme-etat">{sousTitre}</p>
      {constats?.length > 0 && (
        <ul className="mecanisme-constats">
          {constats.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

export default function Landing() {
  const [domaine, setDomaine] = useState('')
  const [resultat, setResultat] = useState(null)
  const [erreur, setErreur] = useState(null)
  const [enCours, setEnCours] = useState(false)
  const [pret, setPret] = useState(true)
  const zoneResultat = useRef(null)

  useEffect(() => {
    // Si les serveurs d'analyse sont à l'arrêt, mieux vaut le dire tout de
    // suite que de laisser l'utilisateur découvrir la panne après sa saisie.
    sante().then((s) => setPret(s.ready !== false))
  }, [])

  async function soumettre(evenement) {
    evenement.preventDefault()
    const saisi = domaine.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '')
    if (!saisi) return

    setEnCours(true)
    setErreur(null)
    setResultat(null)
    try {
      const donnees = await analyserPosture(saisi)
      setResultat(donnees)
      // Sur mobile le résultat naît sous la ligne de flottaison : sans ce
      // défilement, l'utilisateur croit qu'il ne s'est rien passé.
      requestAnimationFrame(() =>
        zoneResultat.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
      )
    } catch (e) {
      setErreur(e.message)
    } finally {
      setEnCours(false)
    }
  }

  return (
    <div className="page">
      <header className="barre">
        <div className="contenu barre-contenu">
          <div className="marque">
            <ShieldCheck size={20} aria-hidden="true" />
            <span>
              ARGUS<span className="marque-suffixe"> · Teknologiia</span>
            </span>
          </div>
          <nav>
            <a href="#verifie">Ce qui est vérifié</a>
            <a href="#compte">Aller plus loin</a>
          </nav>
        </div>
      </header>

      <main>
        <section className="hero">
          <div className="contenu hero-grille">
            <div className="hero-texte">
              <p className="surtitre">Branchez votre modèle · vos clés restent les vôtres</p>
              <h1>
                Posez la question. L'IA <em>mène l'enquête</em>.
              </h1>
              <p className="chapeau">
                Connectez Claude — ou le modèle de votre choix — et interrogez votre
                sécurité en français. Le modèle appelle lui-même les outils d'analyse
                d'ARGUS et vous montre lesquels, un par un.
              </p>
              <ul className="hero-points">
                <li>
                  <strong>Rien à installer.</strong> Ni client de bureau, ni fichier de
                  configuration à éditer.
                </li>
                <li>
                  <strong>Le modèle rapporte, il ne juge pas.</strong> Les scores et les
                  gravités viennent de code déterministe, pas de son appréciation.
                </li>
                <li>
                  <strong>Tous les outils sont en lecture seule.</strong> Rien n'est
                  modifié, nulle part.
                </li>
              </ul>
            </div>
            <Chat />
          </div>
        </section>

        <section className="analyseur">
          <div className="contenu">
            <p className="surtitre">Sans clé d'API · sans inscription</p>
            <h2>Ou testez un domaine tout de suite</h2>
            <p className="chapeau">
              Un attaquant qui envoie un courriel signé du nom de votre entreprise n'a
              besoin d'aucun accès à votre messagerie. Seule votre configuration DNS
              l'en empêche. Cette analyse la lit et la note sur 100.
            </p>

            <form className="recherche" onSubmit={soumettre}>
              <label className="visuellement-cache" htmlFor="domaine">
                Nom de domaine à analyser
              </label>
              <div className="recherche-champ">
                <Search size={18} aria-hidden="true" />
                <input
                  id="domaine"
                  type="text"
                  value={domaine}
                  onChange={(e) => setDomaine(e.target.value)}
                  placeholder="teknologiia.com"
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck="false"
                  disabled={enCours}
                />
              </div>
              <button type="submit" disabled={enCours || !domaine.trim()}>
                {enCours ? (
                  <>
                    <Loader2 size={17} className="tourne" aria-hidden="true" />
                    Analyse…
                  </>
                ) : (
                  <>
                    Analyser
                    <ArrowRight size={17} aria-hidden="true" />
                  </>
                )}
              </button>
            </form>

            <p className="mention">
              <Lock size={13} aria-hidden="true" />
              Rien n'est envoyé au domaine analysé : tout se lit dans le DNS public.
              Vous pouvez donc analyser un domaine que vous ne possédez pas.
            </p>

            {!pret && (
              <p className="alerte alerte-panne" role="status">
                Le service d'analyse est momentanément indisponible.
              </p>
            )}
            {erreur && (
              <p className="alerte alerte-erreur" role="alert">
                <AlertTriangle size={15} aria-hidden="true" />
                {erreur}
              </p>
            )}
          </div>
        </section>

        {resultat && (
          <section className="resultat" ref={zoneResultat} aria-live="polite">
            <div className="contenu">
              <div className="resultat-tete">
                <div>
                  <p className="surtitre">Résultat pour</p>
                  <h2>{resultat.domain}</h2>
                </div>
                <div className={`note ${CLASSE_NOTE[resultat.grade] ?? 'note-c'}`}>
                  <span className="note-lettre">{resultat.grade}</span>
                  <span className="note-score">{resultat.score}/100</span>
                </div>
              </div>

              <div className="mecanismes">
                <Mecanisme
                  icone={ShieldCheck}
                  titre="SPF"
                  sousTitre={
                    resultat.spf?.valid
                      ? `Valide · ${resultat.spf.dns_lookups}/${resultat.spf.lookup_limit} résolutions DNS`
                      : 'Aucun enregistrement exploitable'
                  }
                  gravite={resultat.spf?.severity}
                  constats={resultat.spf?.findings}
                />
                <Mecanisme
                  icone={KeyRound}
                  titre="DKIM"
                  sousTitre={
                    resultat.dkim?.keys_found > 0
                      ? `${resultat.dkim.keys_found} sélecteur(s) actif(s)`
                      : 'Aucun sélecteur trouvé parmi les noms courants'
                  }
                  gravite={resultat.dkim?.severity}
                  constats={resultat.dkim?.findings}
                />
                <Mecanisme
                  icone={Fingerprint}
                  titre="DMARC"
                  sousTitre={
                    resultat.dmarc?.policy
                      ? `p=${resultat.dmarc.policy} · appliqué à ${resultat.dmarc.percentage ?? 100} %`
                      : 'Aucune politique publiée'
                  }
                  gravite={resultat.dmarc?.severity}
                  constats={resultat.dmarc?.findings}
                />
              </div>

              {resultat.priority_actions?.length > 0 ? (
                <div className="actions">
                  <h3>
                    <Siren size={16} aria-hidden="true" />À corriger, par gain de sécurité
                    décroissant
                  </h3>
                  <ol>
                    {resultat.priority_actions.map((action) => (
                      <li key={action}>{action}</li>
                    ))}
                  </ol>
                </div>
              ) : (
                <div className="actions actions-ok">
                  <h3>
                    <CheckCircle2 size={16} aria-hidden="true" />
                    Rien à corriger
                  </h3>
                  <p>
                    Les trois mécanismes sont en place et cohérents. Surveillez les
                    rapports agrégés pour que cela le reste.
                  </p>
                </div>
              )}
            </div>
          </section>
        )}

        <section id="verifie" className="explique">
          <div className="contenu">
            <h2>Ce que l'analyse regarde</h2>
            <p className="chapeau">
              Trois mécanismes répondent à trois questions différentes. Ils ne se
              remplacent pas : il faut les trois.
            </p>
            <div className="cartes">
              <article>
                <ShieldCheck size={20} aria-hidden="true" />
                <h3>SPF — qui a le droit d'écrire en votre nom</h3>
                <p>
                  La liste des serveurs autorisés. La norme impose une limite de dix
                  résolutions DNS : au-delà, l'enregistrement paraît correct mais ne
                  protège plus rien. Cette limite est comptée, et signalée avant
                  qu'elle ne casse.
                </p>
              </article>
              <article>
                <KeyRound size={20} aria-hidden="true" />
                <h3>DKIM — la signature du message</h3>
                <p>
                  Un sceau cryptographique. Le DNS ne permet pas de lister les
                  sélecteurs : ils se devinent. Quand aucun nom courant ne répond,
                  le rapport dit « indéterminé » plutôt que « absent », et ne
                  retire aucun point.
                </p>
              </article>
              <article>
                <Fingerprint size={20} aria-hidden="true" />
                <h3>DMARC — la consigne donnée aux autres</h3>
                <p>
                  Ce que les serveurs destinataires doivent faire d'un message non
                  conforme. <code>p=none</code> n'est qu'une observation : il ne
                  bloque rien. Un <code>pct=</code> inférieur à 100 n'applique la
                  règle qu'à une fraction du trafic.
                </p>
              </article>
            </div>
          </div>
        </section>

        <section id="compte" className="compte">
          <div className="contenu compte-grille">
            <div>
              <p className="surtitre">Avec un compte</p>
              <h2>Les dix autres outils</h2>
              <p>
                L'analyse de messagerie ne demande rien parce qu'elle ne lit que le DNS
                public. Le reste de la plateforme interroge des services qui exigent
                des identifiants : vous fournissez vos propres clés, elles restent les
                vôtres.
              </p>
              <ul className="liste-avantages">
                <li>
                  <strong>Renseignement sur les menaces</strong> — réputation d'une IP,
                  d'un domaine ou d'une empreinte de fichier, croisée entre VirusTotal,
                  AbuseIPDB et GreyNoise.
                </li>
                <li>
                  <strong>Identité Microsoft Entra</strong> — connexions, comptes à
                  risque, modifications d'annuaire, sur votre propre tenant.
                </li>
                <li>
                  <strong>Triage automatique</strong> — l'agent enchaîne les outils et
                  rend un dossier argumenté. Il propose des actions ; il n'en exécute
                  aucune.
                </li>
              </ul>
            </div>
            <aside className="encadre">
              <h3>Tous les outils sont en lecture seule</h3>
              <p>
                La plateforme ne détient aucun droit d'écriture, ni sur votre annuaire,
                ni sur votre messagerie. Une erreur d'analyse ne peut donc pas se
                transformer en incident.
              </p>
            </aside>
          </div>
        </section>
      </main>

      <footer className="pied">
        <div className="contenu pied-contenu">
          <span>ARGUS · Teknologiia</span>
          <a href="https://github.com/Sultan-zd/mcp-entra-secops">
            github.com/Sultan-zd/mcp-entra-secops
          </a>
        </div>
      </footer>
    </div>
  )
}
