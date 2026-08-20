package com.teknologiia.argus.chat;

import com.anthropic.client.AnthropicClient;
import com.anthropic.client.okhttp.AnthropicOkHttpClient;
import com.anthropic.core.JsonValue;
import com.anthropic.models.messages.ContentBlock;
import com.anthropic.models.messages.ContentBlockParam;
import com.anthropic.models.messages.Message;
import com.anthropic.models.messages.MessageCreateParams;
import com.anthropic.models.messages.MessageParam;
import com.anthropic.models.messages.StopReason;
import com.anthropic.models.messages.ThinkingConfigAdaptive;
import com.anthropic.models.messages.Tool;
import com.anthropic.models.messages.ToolResultBlockParam;
import com.anthropic.models.messages.ToolUseBlock;
import com.teknologiia.argus.chat.ChatContracts.ChatEvent;
import com.teknologiia.argus.chat.ChatContracts.ChatRequest;
import com.teknologiia.argus.chat.ChatContracts.ProviderInfo;
import com.teknologiia.argus.chat.ChatContracts.Turn;
import com.teknologiia.argus.mcp.McpToolException;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Conversation outillee avec Claude.
 *
 * <p><strong>Le modele navigue, il ne juge pas.</strong> C'est la regle qui
 * concilie cette interface avec le principe fondateur d'ARGUS — « le code
 * decide, jamais le prompt ». Les scores, les notes et les niveaux de gravite
 * sont calcules par du Python teste ; le modele choisit quels outils appeler et
 * met en francais ce qu'ils rendent. Il ne recalcule rien.
 *
 * <p>Cette distinction n'est pas cosmetique. Un enregistrement DNS et un
 * en-tete de courriel sont ecrits par l'attaquant. S'ils pouvaient inflechir un
 * verdict, l'outil serait retournable contre son proprietaire. Ici ils
 * n'atteignent que la redaction, jamais la decision.
 */
@Component
public class AnthropicProvider implements LlmProvider {

    private static final Logger log = LoggerFactory.getLogger(AnthropicProvider.class);

    /**
     * Borne du nombre d'allers-retours avec le modele.
     *
     * <p>Un modele qui boucle sur un outil en echec consommerait le quota de
     * l'utilisateur sans jamais conclure.
     */
    private static final int MAX_TOURS = 12;

    private static final long MAX_TOKENS = 16_000L;

    @Override
    public String id() {
        return "anthropic";
    }

    @Override
    public ProviderInfo info() {
        return new ProviderInfo(
                "anthropic",
                "Claude (Anthropic)",
                List.of("claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5"),
                "https://console.anthropic.com/settings/keys");
    }

    @Override
    public void converse(ChatRequest requete, ToolBridge outils, Consumer<ChatEvent> emettre) {
        AnthropicClient client = AnthropicOkHttpClient.builder()
                .apiKey(requete.apiKey())
                .build();

        List<Tool> declarations = declarer(outils.catalog());
        List<MessageParam> messages = historique(requete);

        int tours = 0;
        int appels = 0;

        while (tours < MAX_TOURS) {
            MessageCreateParams.Builder params = MessageCreateParams.builder()
                    .model(Prompts.modeleAutorise(requete.model(), info().models()))
                    .maxTokens(MAX_TOKENS)
                    .system(Prompts.SYSTEME)
                    .thinking(ThinkingConfigAdaptive.builder().build());
            declarations.forEach(params::addTool);
            messages.forEach(params::addMessage);

            Message reponse = client.messages().create(params.build());
            tours++;

            // Un refus de securite est une reponse valide du service, pas une
            // panne : le sujet — la securite offensive — est precisement celui
            // ou les classificateurs se declenchent.
            if (reponse.stopReason().filter(s -> s.equals(StopReason.REFUSAL)).isPresent()) {
                emettre.accept(ChatEvent.error(
                        "Le modele a decline cette demande. Reformulez-la en termes "
                                + "defensifs, ou choisissez un autre modele."));
                return;
            }

            for (ContentBlock bloc : reponse.content()) {
                bloc.text().ifPresent(t -> emettre.accept(ChatEvent.text(t.text())));
            }

            List<ToolUseBlock> demandes = reponse.content().stream()
                    .flatMap(b -> b.toolUse().stream())
                    .toList();

            if (demandes.isEmpty()) {
                emettre.accept(ChatEvent.done(tours, appels));
                return;
            }

            messages.add(reponse.toParam());

            List<ContentBlockParam> resultats = new ArrayList<>();
            for (ToolUseBlock demande : demandes) {
                appels++;
                resultats.add(executer(demande, outils, emettre));
            }
            // Tous les resultats dans UN seul message utilisateur : les
            // repartir sur plusieurs apprend au modele a cesser de paralleliser.
            messages.add(MessageParam.builder()
                    .role(MessageParam.Role.USER)
                    .contentOfBlockParams(resultats)
                    .build());
        }

        emettre.accept(ChatEvent.error(
                "L'investigation a atteint sa limite de " + MAX_TOURS + " tours sans conclure."));
    }

    /** Execute un outil et emballe sa sortie pour le prochain tour du modele. */
    private ContentBlockParam executer(ToolUseBlock demande, ToolBridge outils,
                                       Consumer<ChatEvent> emettre) {
        Map<String, Object> arguments = arguments(demande);
        emettre.accept(ChatEvent.tool(demande.name(), arguments));

        try {
            Map<String, Object> sortie = outils.call(demande.name(), arguments);
            emettre.accept(ChatEvent.toolResult(demande.name(), true, Prompts.resume(sortie)));
            return ContentBlockParam.ofToolResult(ToolResultBlockParam.builder()
                    .toolUseId(demande.id())
                    .content(json(sortie))
                    .build());
        } catch (McpToolException e) {
            // L'echec repart vers le modele plutot que d'interrompre : il peut
            // corriger son argument et reessayer, ce qu'un arret lui interdit.
            emettre.accept(ChatEvent.toolResult(demande.name(), false, e.getMessage()));
            return ContentBlockParam.ofToolResult(ToolResultBlockParam.builder()
                    .toolUseId(demande.id())
                    .content("Erreur : " + e.getMessage())
                    .isError(true)
                    .build());
        }
    }

    /** Traduit le catalogue MCP en declarations d'outils Claude. */
    private List<Tool> declarer(List<McpSchema.Tool> catalogue) {
        List<Tool> declarations = new ArrayList<>();
        for (McpSchema.Tool outil : catalogue) {
            Map<String, Object> schema = outil.inputSchema() != null ? outil.inputSchema() : Map.of();

            Tool.InputSchema.Properties.Builder proprietes = Tool.InputSchema.Properties.builder();
            if (schema.get("properties") instanceof Map<?, ?> brut) {
                brut.forEach((cle, valeur) ->
                        proprietes.putAdditionalProperty(String.valueOf(cle), JsonValue.from(valeur)));
            }

            Tool.InputSchema.Builder entree = Tool.InputSchema.builder().properties(proprietes.build());
            if (schema.get("required") instanceof List<?> requis) {
                entree.required(requis.stream().map(String::valueOf).toList());
            }

            declarations.add(Tool.builder()
                    .name(outil.name())
                    .description(outil.description() != null ? outil.description() : outil.name())
                    .inputSchema(entree.build())
                    .build());
        }
        return declarations;
    }

    private List<MessageParam> historique(ChatRequest requete) {
        List<MessageParam> messages = new ArrayList<>();
        for (Turn tour : requete.safeHistory()) {
            if (tour.content() == null || tour.content().isBlank()) {
                continue;
            }
            MessageParam.Role role = "assistant".equalsIgnoreCase(tour.role())
                    ? MessageParam.Role.ASSISTANT
                    : MessageParam.Role.USER;
            messages.add(MessageParam.builder().role(role).content(tour.content()).build());
        }
        messages.add(MessageParam.builder()
                .role(MessageParam.Role.USER)
                .content(requete.message())
                .build());
        return messages;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> arguments(ToolUseBlock demande) {
        try {
            Object converti = demande._input().convert(Map.class);
            return converti instanceof Map<?, ?> m
                    ? new LinkedHashMap<>((Map<String, Object>) m)
                    : Map.of();
        } catch (Exception e) {
            log.warn("Arguments d'outil illisibles pour {} : {}", demande.name(), e.toString());
            return Map.of();
        }
    }

    private String json(Map<String, Object> sortie) {
        try {
            return McpJsonDefaults.getMapper().writeValueAsString(sortie);
        } catch (Exception e) {
            return String.valueOf(sortie);
        }
    }

}
