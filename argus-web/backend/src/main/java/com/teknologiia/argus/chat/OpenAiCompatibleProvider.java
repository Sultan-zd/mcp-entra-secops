package com.teknologiia.argus.chat;

import com.teknologiia.argus.chat.ChatContracts.ChatEvent;
import com.teknologiia.argus.chat.ChatContracts.ChatRequest;
import com.teknologiia.argus.chat.ChatContracts.ProviderInfo;
import com.teknologiia.argus.chat.ChatContracts.Turn;
import com.teknologiia.argus.mcp.McpToolException;
import io.modelcontextprotocol.spec.McpSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Tout modele qui parle « /v1/chat/completions ».
 *
 * <p>C'est-a-dire ChatGPT, mais aussi Mistral, DeepSeek, Groq, Together, et un
 * Ollama local — cette forme d'API est devenue le standard de fait. Une seule
 * implementation, une URL de base differente, et « et autres » est traite.
 *
 * <p><strong>Pourquoi pas le SDK officiel ?</strong> Un choix delibere. Faire
 * cohabiter trois SDK de fournisseurs dans une meme application, c'est trois
 * systemes de types a traduire vers la meme boucle, et les dependances
 * transitives de l'un (protobuf, guava) qui entrent en conflit avec Spring
 * Boot. Claude garde son SDK officiel parce qu'il est seul de sa forme ; la
 * famille compatible OpenAI se traite en une fois.
 */
public class OpenAiCompatibleProvider implements LlmProvider {

    private static final Logger log = LoggerFactory.getLogger(OpenAiCompatibleProvider.class);

    private static final int MAX_TOURS = 12;

    private final String id;
    private final String libelle;
    private final String baseUrl;
    private final List<String> modeles;
    private final String urlCle;
    private final LlmHttp http;

    public OpenAiCompatibleProvider(String id, String libelle, String baseUrl,
                                    List<String> modeles, String urlCle, LlmHttp http) {
        this.id = id;
        this.libelle = libelle;
        this.baseUrl = baseUrl;
        this.modeles = modeles;
        this.urlCle = urlCle;
        this.http = http;
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public ProviderInfo info() {
        return new ProviderInfo(id, libelle, modeles, urlCle);
    }

    @Override
    public void converse(ChatRequest requete, ToolBridge outils, Consumer<ChatEvent> emettre) {
        List<Map<String, Object>> declarations = declarer(outils.catalog());
        List<Map<String, Object>> messages = new ArrayList<>();
        messages.add(Map.of("role", "system", "content", Prompts.SYSTEME));
        for (Turn tour : requete.safeHistory()) {
            if (tour.content() != null && !tour.content().isBlank()) {
                messages.add(Map.of(
                        "role", "assistant".equalsIgnoreCase(tour.role()) ? "assistant" : "user",
                        "content", tour.content()));
            }
        }
        messages.add(Map.of("role", "user", "content", requete.message()));

        int tours = 0;
        int appels = 0;

        while (tours < MAX_TOURS) {
            Map<String, Object> corps = new LinkedHashMap<>();
            corps.put("model", Prompts.modeleAutorise(requete.model(), modeles));
            corps.put("messages", messages);
            if (!declarations.isEmpty()) {
                corps.put("tools", declarations);
            }

            Map<String, Object> reponse = http.postJson(
                    baseUrl + "/chat/completions", requete.apiKey(), null, corps);
            tours++;

            Map<String, Object> message = premierMessage(reponse);
            if (message == null) {
                emettre.accept(ChatEvent.error("Le modele n'a rien renvoye."));
                return;
            }

            Object texte = message.get("content");
            if (texte instanceof String s && !s.isBlank()) {
                emettre.accept(ChatEvent.text(s));
            }

            List<Map<String, Object>> demandes = liste(message.get("tool_calls"));
            if (demandes.isEmpty()) {
                emettre.accept(ChatEvent.done(tours, appels));
                return;
            }

            messages.add(message);
            for (Map<String, Object> demande : demandes) {
                appels++;
                messages.add(executer(demande, outils, emettre));
            }
        }

        emettre.accept(ChatEvent.error(
                "L'investigation a atteint sa limite de " + MAX_TOURS + " tours sans conclure."));
    }

    private Map<String, Object> executer(Map<String, Object> demande, ToolBridge outils,
                                         Consumer<ChatEvent> emettre) {
        Map<String, Object> fonction = carte(demande.get("function"));
        String nom = String.valueOf(fonction.get("name"));
        // Les arguments arrivent en chaine JSON, pas en objet : c'est la forme
        // de cette API, et la parser en dur casserait sur un echappement.
        Map<String, Object> arguments = http.parseObjet(String.valueOf(fonction.get("arguments")));

        emettre.accept(ChatEvent.tool(nom, arguments));
        String contenu;
        try {
            Map<String, Object> sortie = outils.call(nom, arguments);
            emettre.accept(ChatEvent.toolResult(nom, true, Prompts.resume(sortie)));
            contenu = http.ecrire(sortie);
        } catch (McpToolException e) {
            emettre.accept(ChatEvent.toolResult(nom, false, e.getMessage()));
            contenu = "Erreur : " + e.getMessage();
        }

        return Map.of(
                "role", "tool",
                "tool_call_id", String.valueOf(demande.get("id")),
                "content", contenu);
    }

    /** Traduit le catalogue MCP en declarations de fonctions. */
    private List<Map<String, Object>> declarer(List<McpSchema.Tool> catalogue) {
        List<Map<String, Object>> declarations = new ArrayList<>();
        for (McpSchema.Tool outil : catalogue) {
            Map<String, Object> schema = outil.inputSchema() != null
                    ? outil.inputSchema()
                    : Map.of("type", "object", "properties", Map.of());
            declarations.add(Map.of(
                    "type", "function",
                    "function", Map.of(
                            "name", outil.name(),
                            "description", outil.description() != null ? outil.description() : outil.name(),
                            "parameters", schema)));
        }
        return declarations;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> premierMessage(Map<String, Object> reponse) {
        Object choix = reponse.get("choices");
        if (choix instanceof List<?> l && !l.isEmpty() && l.getFirst() instanceof Map<?, ?> c) {
            Object m = ((Map<String, Object>) c).get("message");
            if (m instanceof Map<?, ?> msg) {
                return new LinkedHashMap<>((Map<String, Object>) msg);
            }
        }
        log.warn("Reponse sans message exploitable de {}.", id);
        return null;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> liste(Object valeur) {
        return valeur instanceof List<?> l ? (List<Map<String, Object>>) l : List.of();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> carte(Object valeur) {
        return valeur instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
    }
}
