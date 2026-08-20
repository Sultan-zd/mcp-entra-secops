/**
 * Accès à l'API publique.
 *
 * Le backend rend toujours ses erreurs sous la forme {"detail": "…"} : une
 * seule forme à traiter ici, et un message déjà rédigé pour être affiché.
 */
const JSON_HEADERS = { 'Content-Type': 'application/json' }

async function post(chemin, corps) {
  const reponse = await fetch(chemin, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(corps),
  })

  let charge = null
  try {
    charge = await reponse.json()
  } catch {
    // Une réponse sans corps JSON (502 d'un mandataire, coupure réseau) ne doit
    // pas se transformer en « undefined » affiché à l'utilisateur.
    charge = null
  }

  if (!reponse.ok) {
    const detail = charge?.detail ?? "L'analyse n'a pas abouti. Réessayez dans un instant."
    const erreur = new Error(detail)
    erreur.status = reponse.status
    throw erreur
  }
  return charge
}

export function analyserPosture(domain) {
  return post('/api/public/domain-posture', { domain })
}

export async function sante() {
  try {
    const reponse = await fetch('/api/public/health')
    if (!reponse.ok) return { ready: false }
    return await reponse.json()
  } catch {
    return { ready: false }
  }
}
