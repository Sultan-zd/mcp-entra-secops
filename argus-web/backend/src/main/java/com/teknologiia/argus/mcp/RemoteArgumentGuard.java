package com.teknologiia.argus.mcp;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Ce qui n'a pas le droit de partir vers un serveur MCP tiers.
 *
 * <p>ARGUS tient depuis le debut une regle : <strong>une adresse privee ne
 * sort jamais vers un service de reputation</strong>. Elle ne sert a rien la-bas
 * — aucun tiers ne sait quoi dire de {@code 10.0.0.5} — et elle revele la
 * topologie du reseau interne a qui la recoit.
 *
 * <p>Cette regle vivait en Python, dans le serveur de renseignement. Brancher
 * un serveur MCP distant la contournerait : ses outils accepteraient
 * volontiers une adresse interne. Le controle est donc rejoue ici, sur les
 * arguments, avant qu'ils ne quittent la machine.
 *
 * <p>Il ne s'applique qu'aux serveurs declares distants. Les serveurs locaux
 * portent deja leurs propres controles, et rien ne sort d'eux.
 */
final class RemoteArgumentGuard {

    /** Suffixes qui designent, par convention, un nom interne. */
    private static final List<String> SUFFIXES_INTERNES =
            List.of(".local", ".internal", ".intranet", ".lan", ".corp", ".home", ".localdomain");

    /** Une valeur qui ressemble a une adresse IP, v4 ou v6. */
    private static final Pattern RESSEMBLE_A_UNE_IP =
            Pattern.compile("^[0-9a-fA-F.:]+$");

    private RemoteArgumentGuard() {
    }

    /**
     * Verifie chaque argument avant un appel distant.
     *
     * @throws McpToolException si une valeur ne doit pas quitter la machine
     */
    static void verifier(String outil, Map<String, Object> arguments) {
        if (arguments == null) {
            return;
        }
        arguments.forEach((cle, valeur) -> inspecter(outil, valeur));
    }

    private static void inspecter(String outil, Object valeur) {
        switch (valeur) {
            case null -> {
            }
            case String texte -> verifierTexte(outil, texte);
            // Les outils groupes prennent des listes d'indicateurs : une seule
            // adresse interne au milieu suffirait a fuiter.
            case List<?> liste -> liste.forEach(v -> inspecter(outil, v));
            case Map<?, ?> carte -> carte.values().forEach(v -> inspecter(outil, v));
            default -> {
            }
        }
    }

    private static void verifierTexte(String outil, String brut) {
        String valeur = brut.trim().toLowerCase(Locale.ROOT);
        if (valeur.isEmpty()) {
            return;
        }
        // Une URL ou un courriel porte l'hote apres le schema ou l'arobase.
        String hote = valeur;
        int schema = hote.indexOf("://");
        if (schema >= 0) {
            hote = hote.substring(schema + 3);
        }
        int arobase = hote.lastIndexOf('@');
        if (arobase >= 0) {
            hote = hote.substring(arobase + 1);
        }
        int barre = hote.indexOf('/');
        if (barre >= 0) {
            hote = hote.substring(0, barre);
        }
        int port = hote.lastIndexOf(':');
        if (port > 0 && hote.indexOf(':') == port) {
            hote = hote.substring(0, port);
        }
        hote = hote.replace("[", "").replace("]", "");

        if (hote.isEmpty()) {
            return;
        }
        if (hote.equals("localhost") || SUFFIXES_INTERNES.stream().anyMatch(hote::endsWith)) {
            throw refus(outil, brut, "un nom interne");
        }
        if (RESSEMBLE_A_UNE_IP.matcher(hote).matches() && estNonPublique(hote)) {
            throw refus(outil, brut, "une adresse non publique");
        }
    }

    /**
     * Une adresse qui ne circule pas sur l'Internet public.
     *
     * <p>{@link InetAddress#getByName} est appele sur une valeur qui ressemble
     * deja a une adresse IP : il ne declenche donc aucune resolution DNS, et ne
     * peut pas servir de canal de fuite a lui seul.
     */
    private static boolean estNonPublique(String hote) {
        try {
            InetAddress adresse = InetAddress.getByName(hote);
            return adresse.isSiteLocalAddress()
                    || adresse.isLoopbackAddress()
                    || adresse.isLinkLocalAddress()
                    || adresse.isAnyLocalAddress()
                    || adresse.isMulticastAddress();
        } catch (UnknownHostException e) {
            // Ni une adresse valide, ni un nom resolvable : il n'y a rien a
            // proteger, et l'outil distant refusera de lui-meme.
            return false;
        }
    }

    private static McpToolException refus(String outil, String valeur, String quoi) {
        return new McpToolException(
                "« " + valeur + " » est " + quoi + " : ARGUS ne l'envoie pas a un "
                        + "service tiers (outil « " + outil + " »). Cela ne donnerait "
                        + "aucun resultat utile et revelerait la topologie du reseau interne.",
                true);
    }
}
