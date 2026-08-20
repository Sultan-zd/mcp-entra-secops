package com.teknologiia.argus.chat;

import com.teknologiia.argus.chat.ChatContracts.ChatEvent;
import com.teknologiia.argus.chat.ChatContracts.ChatRequest;
import com.teknologiia.argus.chat.ChatContracts.ProviderInfo;

import java.util.function.Consumer;

/**
 * Un modele de langage capable de mener une conversation outillee.
 *
 * <p>L'interface existe pour que Claude ne soit pas cable en dur : les
 * fournisseurs different par leur SDK et par la forme de leurs appels d'outils,
 * mais pas par ce que la plateforme attend d'eux — mener la boucle, appeler les
 * outils MCP, rendre une reponse.
 */
public interface LlmProvider {

    /** Identifiant stable, celui que le navigateur renvoie. */
    String id();

    /** Ce que ce fournisseur propose, pour peupler l'interface. */
    ProviderInfo info();

    /**
     * Mene la conversation jusqu'a une reponse finale.
     *
     * <p>Les evenements sont emis au fil de l'eau : une investigation qui
     * enchaine cinq outils ne doit pas laisser l'analyste devant un sablier.
     *
     * @param requete la question et le contexte
     * @param outils  acces aux outils MCP
     * @param emettre recoit chaque evenement a pousser vers le navigateur
     */
    void converse(ChatRequest requete, ToolBridge outils, Consumer<ChatEvent> emettre);
}
