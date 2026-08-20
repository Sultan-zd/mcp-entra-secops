package com.teknologiia.argus.chat;

import com.teknologiia.argus.chat.ChatContracts.ChatEvent;
import com.teknologiia.argus.chat.ChatContracts.ChatRequest;
import com.teknologiia.argus.chat.ChatContracts.ProviderInfo;
import com.teknologiia.argus.chat.ChatContracts.Turn;
import com.teknologiia.argus.mcp.McpToolException;
import io.modelcontextprotocol.spec.McpSchema;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Conversation outillee avec Gemini.
 *
 * <p>Le format differe de la famille compatible OpenAI sur trois points : les
 * tours s'appellent {@code contents} et le role du modele est {@code model},
 * les appels d'outils sont des {@code functionCall} dans les {@code parts}, et
 * la consigne systeme a son propre champ.
 */
@Component
public class GeminiProvider implements LlmProvider {

    private static final String BASE = "https://generativelanguage.googleapis.com/v1beta/models/";

    private static final List<String> MODELES =
            List.of("gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash");

    private static final int MAX_TOURS = 12;

    /**
     * Mots-cles de JSON Schema que Gemini refuse.
     *
     * <p>Son schema de fonction est un sous-ensemble d'OpenAPI, pas du JSON
     * Schema complet. Un {@code additionalProperties} laisse dans la
     * declaration fait echouer la requete entiere avec un message peu clair —
     * et nos outils MCP en produisent.
     */
    private static final Set<String> REFUSES = Set.of(
            "$schema", "$id", "$ref", "$defs", "definitions", "additionalProperties",
            "exclusiveMinimum", "exclusiveMaximum", "const", "examples", "default",
            "allOf", "oneOf", "not", "patternProperties", "propertyNames", "title");

    private final LlmHttp http;

    public GeminiProvider(LlmHttp http) {
        this.http = http;
    }

    @Override
    public String id() {
        return "gemini";
    }

    @Override
    public ProviderInfo info() {
        return new ProviderInfo("gemini", "Gemini (Google)", MODELES,
                "https://aistudio.google.com/apikey");
    }

    @Override
    public void converse(ChatRequest requete, ToolBridge outils, Consumer<ChatEvent> emettre) {
        List<Map<String, Object>> declarations = declarer(outils.catalog());
        List<Map<String, Object>> contents = new ArrayList<>();

        for (Turn tour : requete.safeHistory()) {
            if (tour.content() != null && !tour.content().isBlank()) {
                contents.add(Map.of(
                        "role", "assistant".equalsIgnoreCase(tour.role()) ? "model" : "user",
                        "parts", List.of(Map.of("text", tour.content()))));
            }
        }
        contents.add(Map.of("role", "user", "parts", List.of(Map.of("text", requete.message()))));

        String url = BASE + Prompts.modeleAutorise(requete.model(), MODELES) + ":generateContent";
        int tours = 0;
        int appels = 0;

        while (tours < MAX_TOURS) {
            Map<String, Object> corps = new LinkedHashMap<>();
            corps.put("systemInstruction", Map.of("parts", List.of(Map.of("text", Prompts.SYSTEME))));
            corps.put("contents", contents);
            if (!declarations.isEmpty()) {
                corps.put("tools", List.of(Map.of("functionDeclarations", declarations)));
            }

            // La cle passe en en-tete, jamais en parametre d'URL : une URL est
            // journalisee par les mandataires et reste dans les traces.
            Map<String, Object> reponse = http.postJson(url, requete.apiKey(), "x-goog-api-key", corps);
            tours++;

            List<Map<String, Object>> parts = premieresParts(reponse);
            if (parts.isEmpty()) {
                emettre.accept(ChatEvent.error("Le modele n'a rien renvoye."));
                return;
            }

            List<Map<String, Object>> demandes = new ArrayList<>();
            for (Map<String, Object> part : parts) {
                if (part.get("text") instanceof String texte && !texte.isBlank()) {
                    emettre.accept(ChatEvent.text(texte));
                }
                if (part.get("functionCall") instanceof Map<?, ?> appel) {
                    demandes.add(carte(appel));
                }
            }

            if (demandes.isEmpty()) {
                emettre.accept(ChatEvent.done(tours, appels));
                return;
            }

            contents.add(Map.of("role", "model", "parts", parts));

            List<Map<String, Object>> reponses = new ArrayList<>();
            for (Map<String, Object> demande : demandes) {
                appels++;
                reponses.add(executer(demande, outils, emettre));
            }
            contents.add(Map.of("role", "user", "parts", reponses));
        }

        emettre.accept(ChatEvent.error(
                "L'investigation a atteint sa limite de " + MAX_TOURS + " tours sans conclure."));
    }

    private Map<String, Object> executer(Map<String, Object> demande, ToolBridge outils,
                                         Consumer<ChatEvent> emettre) {
        String nom = String.valueOf(demande.get("name"));
        Map<String, Object> arguments = carte(demande.get("args"));

        emettre.accept(ChatEvent.tool(nom, arguments));
        Map<String, Object> charge;
        try {
            Map<String, Object> sortie = outils.call(nom, arguments);
            emettre.accept(ChatEvent.toolResult(nom, true, Prompts.resume(sortie)));
            charge = sortie;
        } catch (McpToolException e) {
            emettre.accept(ChatEvent.toolResult(nom, false, e.getMessage()));
            charge = Map.of("error", e.getMessage());
        }

        return Map.of("functionResponse", Map.of("name", nom, "response", charge));
    }

    private List<Map<String, Object>> declarer(List<McpSchema.Tool> catalogue) {
        List<Map<String, Object>> declarations = new ArrayList<>();
        for (McpSchema.Tool outil : catalogue) {
            Map<String, Object> schema = nettoyer(outil.inputSchema());
            Map<String, Object> declaration = new LinkedHashMap<>();
            declaration.put("name", outil.name());
            declaration.put("description",
                    outil.description() != null ? outil.description() : outil.name());
            // Un outil sans parametre doit omettre le champ : un objet vide est
            // refuse.
            if (schema != null && !schema.isEmpty()) {
                declaration.put("parameters", schema);
            }
            declarations.add(declaration);
        }
        return declarations;
    }

    /** Retire recursivement les mots-cles que Gemini n'accepte pas. */
    private Map<String, Object> nettoyer(Map<String, Object> schema) {
        if (schema == null) {
            return null;
        }
        Map<String, Object> propre = new LinkedHashMap<>();
        schema.forEach((cle, valeur) -> {
            if (REFUSES.contains(cle)) {
                return;
            }
            propre.put(cle, nettoyerValeur(valeur));
        });
        return propre;
    }

    @SuppressWarnings("unchecked")
    private Object nettoyerValeur(Object valeur) {
        if (valeur instanceof Map<?, ?> m) {
            return nettoyer((Map<String, Object>) m);
        }
        if (valeur instanceof List<?> l) {
            return l.stream().map(this::nettoyerValeur).toList();
        }
        return valeur;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> premieresParts(Map<String, Object> reponse) {
        if (reponse.get("candidates") instanceof List<?> candidats
                && !candidats.isEmpty()
                && candidats.getFirst() instanceof Map<?, ?> premier) {
            Object contenu = ((Map<String, Object>) premier).get("content");
            if (contenu instanceof Map<?, ?> c) {
                Object parts = ((Map<String, Object>) c).get("parts");
                if (parts instanceof List<?> l) {
                    return l.stream().map(this::carte).toList();
                }
            }
        }
        return List.of();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> carte(Object valeur) {
        return valeur instanceof Map<?, ?> m
                ? new LinkedHashMap<>((Map<String, Object>) m)
                : Map.of();
    }
}
