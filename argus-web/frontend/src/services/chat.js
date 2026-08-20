/**
 * Conversation en flux avec le backend.
 *
 * `EventSource` ne sait faire que des GET, et la question, l'historique et la
 * clé d'API n'ont rien à faire dans une URL — elle est journalisée par les
 * mandataires et reste dans l'historique du navigateur. On lit donc le flux
 * d'événements serveur à la main, sur un POST.
 */

/**
 * Découpe un flux SSE en événements.
 *
 * Un bloc peut arriver en plusieurs morceaux réseau : le tampon garde ce qui
 * n'est pas encore terminé par la ligne vide qui sépare deux événements.
 */
function decouper(tampon) {
  const evenements = []
  let reste = tampon

  let coupure = reste.indexOf('\n\n')
  while (coupure !== -1) {
    const bloc = reste.slice(0, coupure)
    reste = reste.slice(coupure + 2)

    let type = 'message'
    const donnees = []
    for (const ligne of bloc.split('\n')) {
      if (ligne.startsWith('event:')) type = ligne.slice(6).trim()
      else if (ligne.startsWith('data:')) donnees.push(ligne.slice(5).trim())
    }
    if (donnees.length > 0) {
      try {
        evenements.push({ type, payload: JSON.parse(donnees.join('\n')) })
      } catch {
        // Un bloc illisible ne doit pas interrompre la conversation entière.
      }
    }
    coupure = reste.indexOf('\n\n')
  }
  return { evenements, reste }
}

/**
 * Envoie une question et rappelle `surEvenement` à chaque étape.
 *
 * @returns {Promise<void>} résolue quand le flux se termine
 */
export async function converser({ message, provider, model, apiKey, history }, surEvenement, signal) {
  const reponse = await fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, provider, model, apiKey, history }),
    signal,
  })

  // Une erreur avant le flux (429, 400) revient en JSON, pas en SSE.
  if (!reponse.ok) {
    let detail = 'La conversation n’a pas pu démarrer.'
    try {
      const charge = await reponse.json()
      if (charge?.detail) detail = charge.detail
    } catch {
      // Corps illisible : le message par défaut fera l'affaire.
    }
    surEvenement({ type: 'error', payload: { detail } })
    return
  }

  const lecteur = reponse.body.getReader()
  const decodeur = new TextDecoder()
  let tampon = ''

  for (;;) {
    const { done, value } = await lecteur.read()
    if (done) break
    tampon += decodeur.decode(value, { stream: true })
    const { evenements, reste } = decouper(tampon)
    tampon = reste
    evenements.forEach(surEvenement)
  }
}

export async function chargerFournisseurs() {
  try {
    const r = await fetch('/api/chat/providers')
    return r.ok ? await r.json() : []
  } catch {
    return []
  }
}

export async function chargerOutils() {
  try {
    const r = await fetch('/api/chat/tools')
    return r.ok ? await r.json() : []
  } catch {
    return []
  }
}
