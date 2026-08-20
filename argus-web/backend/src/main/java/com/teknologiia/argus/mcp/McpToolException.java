package com.teknologiia.argus.mcp;

/**
 * Un appel d'outil MCP qui n'a pas abouti.
 *
 * <p>Distinguée d'une exception technique quelconque parce que la réponse HTTP
 * n'est pas la même : un outil qui refuse un domaine mal formé est une erreur
 * du client (400), un serveur MCP qui ne démarre pas est une panne (503).
 */
public class McpToolException extends RuntimeException {

    private final boolean clientFault;

    public McpToolException(String message, boolean clientFault) {
        super(message);
        this.clientFault = clientFault;
    }

    public McpToolException(String message, Throwable cause) {
        super(message, cause);
        this.clientFault = false;
    }

    /** {@code true} si l'entrée fournie est en cause, {@code false} si c'est la plateforme. */
    public boolean isClientFault() {
        return clientFault;
    }
}
