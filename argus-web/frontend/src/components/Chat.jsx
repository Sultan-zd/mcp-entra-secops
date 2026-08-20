import { useEffect, useRef, useState } from 'react'
import {
  AlertTriangle,
  Check,
  ChevronDown,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  SendHorizontal,
  Wrench,
  X,
} from 'lucide-react'

import { chargerFournisseurs, chargerOutils, converser } from '../services/chat.js'
import './Chat.css'

/**
 * La clé vit dans `sessionStorage`, pas `localStorage` : elle disparaît à la
 * fermeture de l'onglet. Un secret qui survit à la session sur une machine
 * partagée est un secret qu'on a perdu.
 */
const CLE_STOCKAGE = 'argus.apiKey'
const FOURNISSEUR_STOCKAGE = 'argus.provider'
const MODELE_STOCKAGE = 'argus.model'

const EXEMPLES = [
  'Le domaine teknologiia.com peut-il être usurpé ?',
  'La CVE-2021-44228 est-elle activement exploitée ?',
  'Fais un audit complet de github.com : DNS, SSL, messagerie.',
]

function Outil({ appel }) {
  return (
    <div className={`outil ${appel.etat}`}>
      <span className="outil-icone">
        {appel.etat === 'encours' && <Loader2 size={13} className="tourne" aria-hidden="true" />}
        {appel.etat === 'ok' && <Check size={13} aria-hidden="true" />}
        {appel.etat === 'echec' && <X size={13} aria-hidden="true" />}
      </span>
      <code>{appel.name}</code>
      {appel.arguments && Object.keys(appel.arguments).length > 0 && (
        <span className="outil-args">{Object.values(appel.arguments).join(', ')}</span>
      )}
      {appel.summary && <span className="outil-resume">{appel.summary}</span>}
    </div>
  )
}

export default function Chat() {
  const [fournisseurs, setFournisseurs] = useState([])
  const [fournisseur, setFournisseur] = useState('')
  const [modele, setModele] = useState('')
  const [cle, setCle] = useState('')
  const [cleVisible, setCleVisible] = useState(false)
  const [outils, setOutils] = useState([])
  const [panneauOuvert, setPanneauOuvert] = useState(true)
  const [outilsOuverts, setOutilsOuverts] = useState(false)

  const [messages, setMessages] = useState([])
  const [saisie, setSaisie] = useState('')
  const [enCours, setEnCours] = useState(false)

  const filActif = useRef(null)
  const basDuFil = useRef(null)

  useEffect(() => {
    chargerFournisseurs().then((liste) => {
      setFournisseurs(liste)
      const memorise = sessionStorage.getItem(FOURNISSEUR_STOCKAGE)
      const choisi = liste.find((f) => f.id === memorise) ?? liste[0]
      if (choisi) {
        setFournisseur(choisi.id)
        setModele(sessionStorage.getItem(MODELE_STOCKAGE) ?? choisi.models[0])
      }
    })
    chargerOutils().then(setOutils)

    const cleMemorisee = sessionStorage.getItem(CLE_STOCKAGE)
    if (cleMemorisee) {
      setCle(cleMemorisee)
      setPanneauOuvert(false)
    }
  }, [])

  useEffect(() => {
    basDuFil.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [messages])

  const infoFournisseur = fournisseurs.find((f) => f.id === fournisseur)
  const connecte = Boolean(cle.trim() && fournisseur)

  function memoriser() {
    sessionStorage.setItem(CLE_STOCKAGE, cle.trim())
    sessionStorage.setItem(FOURNISSEUR_STOCKAGE, fournisseur)
    sessionStorage.setItem(MODELE_STOCKAGE, modele)
    setPanneauOuvert(false)
  }

  function oublier() {
    sessionStorage.removeItem(CLE_STOCKAGE)
    setCle('')
    setPanneauOuvert(true)
  }

  async function envoyer(texte) {
    const question = (texte ?? saisie).trim()
    if (!question || enCours || !connecte) return

    // L'historique envoyé au modèle est celui d'AVANT cette question : le
    // backend ajoute la question lui-même, et l'envoyer deux fois la ferait
    // apparaître en double dans le contexte.
    const historique = messages
      .filter((m) => m.role === 'user' || (m.role === 'assistant' && m.text))
      .map((m) => ({ role: m.role, content: m.text }))

    setMessages((actuels) => [
      ...actuels,
      { id: crypto.randomUUID(), role: 'user', text: question },
      { id: crypto.randomUUID(), role: 'assistant', text: '', outils: [], erreur: null },
    ])
    setSaisie('')
    setEnCours(true)

    const controleur = new AbortController()
    filActif.current = controleur

    const majDernier = (transformer) =>
      setMessages((actuels) => {
        const copie = [...actuels]
        const dernier = copie.length - 1
        copie[dernier] = transformer(copie[dernier])
        return copie
      })

    try {
      await converser(
        { message: question, provider: fournisseur, model: modele, apiKey: cle.trim(), history: historique },
        (evenement) => {
          const { type, payload } = evenement
          if (type === 'text') {
            majDernier((m) => ({ ...m, text: m.text ? `${m.text}\n\n${payload.text}` : payload.text }))
          } else if (type === 'tool') {
            majDernier((m) => ({
              ...m,
              outils: [
                ...m.outils,
                { name: payload.name, arguments: payload.arguments, etat: 'encours' },
              ],
            }))
          } else if (type === 'tool_result') {
            majDernier((m) => {
              const outilsMaj = [...m.outils]
              // Le dernier appel encore en cours portant ce nom est celui qui
              // vient de répondre — deux appels au même outil sont possibles.
              for (let i = outilsMaj.length - 1; i >= 0; i -= 1) {
                if (outilsMaj[i].name === payload.name && outilsMaj[i].etat === 'encours') {
                  outilsMaj[i] = {
                    ...outilsMaj[i],
                    etat: payload.ok ? 'ok' : 'echec',
                    summary: payload.summary,
                  }
                  break
                }
              }
              return { ...m, outils: outilsMaj }
            })
          } else if (type === 'error') {
            majDernier((m) => ({ ...m, erreur: payload.detail }))
          }
        },
        controleur.signal,
      )
    } catch (e) {
      if (e.name !== 'AbortError') {
        majDernier((m) => ({ ...m, erreur: 'La connexion au serveur a été interrompue.' }))
      }
    } finally {
      setEnCours(false)
      filActif.current = null
    }
  }

  function interrompre() {
    filActif.current?.abort()
    setEnCours(false)
  }

  return (
    <div className="chat">
      <div className="chat-tete">
        <button
          type="button"
          className={`connexion ${connecte ? 'connectee' : ''}`}
          onClick={() => setPanneauOuvert((o) => !o)}
          aria-expanded={panneauOuvert}
        >
          <KeyRound size={15} aria-hidden="true" />
          {connecte ? `${infoFournisseur?.displayName ?? fournisseur} · ${modele}` : 'Connecter un modèle'}
          <ChevronDown size={14} aria-hidden="true" />
        </button>
        {outils.length > 0 && (
          <button
            type="button"
            className="compte-outils"
            onClick={() => setOutilsOuverts((o) => !o)}
            aria-expanded={outilsOuverts}
          >
            <Wrench size={13} aria-hidden="true" />
            {outils.length} outils
          </button>
        )}
      </div>

      {panneauOuvert && (
        <div className="panneau">
          <div className="panneau-champs">
            <label>
              Fournisseur
              <select
                value={fournisseur}
                onChange={(e) => {
                  setFournisseur(e.target.value)
                  const f = fournisseurs.find((x) => x.id === e.target.value)
                  if (f) setModele(f.models[0])
                }}
              >
                {fournisseurs.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.displayName}
                  </option>
                ))}
              </select>
            </label>

            <label>
              Modèle
              <select value={modele} onChange={(e) => setModele(e.target.value)}>
                {(infoFournisseur?.models ?? []).map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </label>

            <label className="champ-cle">
              Clé d’API
              <div className="cle-saisie">
                <input
                  type={cleVisible ? 'text' : 'password'}
                  value={cle}
                  onChange={(e) => setCle(e.target.value)}
                  placeholder="sk-ant-…"
                  autoComplete="off"
                  spellCheck="false"
                />
                <button
                  type="button"
                  onClick={() => setCleVisible((v) => !v)}
                  aria-label={cleVisible ? 'Masquer la clé' : 'Afficher la clé'}
                >
                  {cleVisible ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </label>
          </div>

          <p className="panneau-note">
            Votre clé reste dans cet onglet et accompagne chaque question le temps de
            l’appel. Elle n’est ni enregistrée sur le serveur, ni journalisée. Elle
            disparaît à la fermeture de l’onglet.
            {infoFournisseur?.keyUrl && (
              <>
                {' '}
                <a href={infoFournisseur.keyUrl} target="_blank" rel="noreferrer">
                  Obtenir une clé
                </a>
              </>
            )}
          </p>

          <div className="panneau-actions">
            <button type="button" className="principal" onClick={memoriser} disabled={!cle.trim()}>
              Connecter
            </button>
            {sessionStorage.getItem(CLE_STOCKAGE) && (
              <button type="button" onClick={oublier}>
                Oublier la clé
              </button>
            )}
          </div>
        </div>
      )}

      {outilsOuverts && (
        <div className="catalogue">
          <p>
            Le modèle choisit lui-même parmi ces outils. Ceux marqués
            <span className="pastille-distant">distant</span> interrogent un service
            tiers : ARGUS n'y envoie jamais une adresse interne.
          </p>
          <ul>
            {outils.map((o) => (
              <li key={o.name}>
                <code>{o.name}</code>
                <span>{o.description}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="fil">
        {messages.length === 0 && (
          <div className="accueil-fil">
            <p>
              Posez une question en français. L’assistant choisit lui-même les outils
              d’analyse à appeler, et vous voyez lesquels au fur et à mesure.
            </p>
            <div className="exemples">
              {EXEMPLES.map((exemple) => (
                <button
                  key={exemple}
                  type="button"
                  onClick={() => envoyer(exemple)}
                  disabled={!connecte}
                >
                  {exemple}
                </button>
              ))}
            </div>
            {!connecte && (
              <p className="accueil-note">
                Connectez d’abord un modèle avec votre clé d’API.
              </p>
            )}
          </div>
        )}

        {messages.map((m) => (
          <div key={m.id} className={`message ${m.role}`}>
            <div className="message-corps">
              {m.outils?.length > 0 && (
                <div className="outils">
                  {m.outils.map((appel, i) => (
                    <Outil key={`${appel.name}-${i}`} appel={appel} />
                  ))}
                </div>
              )}
              {m.text && <div className="message-texte">{m.text}</div>}
              {m.role === 'assistant' && !m.text && !m.erreur && enCours && (
                <div className="reflexion">
                  <Loader2 size={14} className="tourne" aria-hidden="true" />
                  Analyse en cours…
                </div>
              )}
              {m.erreur && (
                <div className="message-erreur">
                  <AlertTriangle size={14} aria-hidden="true" />
                  {m.erreur}
                </div>
              )}
            </div>
          </div>
        ))}
        <div ref={basDuFil} />
      </div>

      <form
        className="saisie"
        onSubmit={(e) => {
          e.preventDefault()
          envoyer()
        }}
      >
        <textarea
          value={saisie}
          onChange={(e) => setSaisie(e.target.value)}
          onKeyDown={(e) => {
            // Entrée envoie, Maj+Entrée passe à la ligne : la convention que
            // tout le monde a déjà dans les doigts.
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault()
              envoyer()
            }
          }}
          placeholder={connecte ? 'Votre question…' : 'Connectez un modèle pour commencer'}
          rows={1}
          disabled={!connecte}
        />
        {enCours ? (
          <button type="button" onClick={interrompre} className="stop" aria-label="Interrompre">
            <X size={17} aria-hidden="true" />
          </button>
        ) : (
          <button type="submit" disabled={!connecte || !saisie.trim()} aria-label="Envoyer">
            <SendHorizontal size={17} aria-hidden="true" />
          </button>
        )}
      </form>
    </div>
  )
}
