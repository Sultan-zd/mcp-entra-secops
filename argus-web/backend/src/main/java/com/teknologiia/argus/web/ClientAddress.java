package com.teknologiia.argus.web;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Identifie l'appelant pour la limitation de débit.
 *
 * <p>Le point délicat : {@code X-Forwarded-For} est écrit par le client et
 * n'est digne de confiance que si un mandataire de confiance l'a réécrit.
 * Le lire aveuglément offrirait à n'importe qui un contournement de la
 * limitation — il suffirait d'inventer une adresse différente à chaque appel.
 *
 * <p>L'en-tête n'est donc consulté que si le déploiement déclare tourner
 * derrière un mandataire.
 */
public final class ClientAddress {

    private ClientAddress() {
    }

    public static String of(HttpServletRequest requete, boolean derriereMandataire) {
        if (derriereMandataire) {
            String transmis = requete.getHeader("X-Forwarded-For");
            if (transmis != null && !transmis.isBlank()) {
                // La liste va du client d'origine au dernier relais : la
                // première entrée est l'appelant réel.
                int virgule = transmis.indexOf(',');
                String premier = (virgule >= 0 ? transmis.substring(0, virgule) : transmis).trim();
                if (!premier.isEmpty()) {
                    return premier;
                }
            }
        }
        String distant = requete.getRemoteAddr();
        return distant != null ? distant : "inconnu";
    }
}
