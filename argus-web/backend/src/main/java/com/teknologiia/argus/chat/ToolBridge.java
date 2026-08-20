package com.teknologiia.argus.chat;

import com.teknologiia.argus.mcp.McpToolGateway;
import io.modelcontextprotocol.spec.McpSchema;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Ce que les fournisseurs de modele voient des outils MCP.
 *
 * <p>Une couche mince, mais elle a une raison d'etre : chaque fournisseur
 * traduit le catalogue dans son propre format de declaration d'outils, et
 * aucun n'a besoin de connaitre les groupes de processus, les serveurs, ni la
 * liste d'autorisation qui vit derriere.
 */
@Component
public class ToolBridge {

    private final McpToolGateway gateway;

    public ToolBridge(McpToolGateway gateway) {
        this.gateway = gateway;
    }

    /** Les outils disponibles, decrits par les serveurs MCP eux-memes. */
    public List<McpSchema.Tool> catalog() {
        return gateway.catalog();
    }

    /** Execute un outil. Les erreurs remontent en {@link com.teknologiia.argus.mcp.McpToolException}. */
    public Map<String, Object> call(String outil, Map<String, Object> arguments) {
        return gateway.callByName(outil, arguments);
    }
}
