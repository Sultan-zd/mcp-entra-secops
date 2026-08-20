package com.teknologiia.argus.chat;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.Map;

/**
 * Les formes echangees avec le navigateur pendant une conversation.
 *
 * <p>Regroupees dans un seul fichier parce qu'elles n'ont pas de comportement :
 * ce sont des contrats, et les eparpiller en huit fichiers d'une ligne
 * rendrait le protocole plus difficile a lire, pas moins.
 */
public final class ChatContracts {

    private ChatContracts() {
    }

    /** Un tour de conversation deja echange, renvoye par le navigateur. */
    public record Turn(String role, String content) {
    }

    /**
     * Demande de conversation.
     *
     * <p>La cle d'API voyage a chaque requete et n'est <strong>jamais</strong>
     * conservee cote serveur. C'est deliberé : stocker les cles de modele des
     * visiteurs ferait de cette application une cible autrement plus
     * interessante qu'elle ne doit l'etre.
     */
    public record ChatRequest(
            @NotBlank(message = "Ecrivez une question.")
            @Size(max = 4000, message = "Cette question est trop longue.")
            String message,

            @NotBlank(message = "Choisissez un fournisseur de modele.")
            String provider,

            String model,

            @NotBlank(message = "Renseignez votre cle d'API.")
            String apiKey,

            List<Turn> history) {

        /** L'historique, jamais nul, borne pour ne pas laisser gonfler le contexte. */
        public List<Turn> safeHistory() {
            if (history == null || history.isEmpty()) {
                return List.of();
            }
            // Au-dela, le cout par question grimpe sans que la reponse
            // s'ameliore : les premiers echanges d'une investigation ne
            // servent plus a rien une fois le sujet etabli.
            int depuis = Math.max(0, history.size() - 20);
            return history.subList(depuis, history.size());
        }
    }

    /** Ce qu'un fournisseur declare savoir faire, pour peupler l'interface. */
    public record ProviderInfo(String id, String displayName, List<String> models, String keyUrl) {
    }

    /**
     * Un evenement pousse vers le navigateur pendant la conversation.
     *
     * @param type    text | tool | tool_result | done | error
     * @param payload contenu de l'evenement
     */
    public record ChatEvent(String type, Map<String, Object> payload) {

        public static ChatEvent text(String texte) {
            return new ChatEvent("text", Map.of("text", texte));
        }

        public static ChatEvent tool(String nom, Map<String, Object> arguments) {
            return new ChatEvent("tool", Map.of("name", nom, "arguments", arguments));
        }

        public static ChatEvent toolResult(String nom, boolean ok, String resume) {
            return new ChatEvent("tool_result", Map.of("name", nom, "ok", ok, "summary", resume));
        }

        public static ChatEvent done(int tours, int appels) {
            return new ChatEvent("done", Map.of("turns", tours, "toolCalls", appels));
        }

        public static ChatEvent error(String detail) {
            return new ChatEvent("error", Map.of("detail", detail));
        }
    }
}
