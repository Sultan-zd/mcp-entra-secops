package com.teknologiia.argus.mcp;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.ServerParameters;
import io.modelcontextprotocol.client.transport.StdioClientTransport;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpClientTransport;
import io.modelcontextprotocol.spec.McpSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Un groupe de processus pour <em>un</em> serveur MCP.
 *
 * <p>Deux raisons d'avoir un groupe plutôt qu'un client unique :
 *
 * <ul>
 *   <li>Un client stdio possède un seul couple de tubes vers un seul processus.
 *       Deux requêtes HTTP simultanées passant par le même client
 *       entrelaceraient leurs trames JSON-RPC.</li>
 *   <li>Démarrer un interpréteur Python coûte près d'une seconde. Le faire à
 *       chaque requête dominerait complètement le temps de réponse.</li>
 * </ul>
 *
 * <p>Les processus sont donc démarrés une fois, empruntés le temps d'un appel,
 * puis rendus.
 */
class McpServerPool implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(McpServerPool.class);

    private final String name;
    private final McpProperties props;
    private final McpProperties.Server spec;
    private final Set<String> allowedTools;

    /** Clients disponibles. Un client absent de la file est en cours d'usage. */
    private final BlockingQueue<McpSyncClient> idle;

    /** Tous les clients créés, pour pouvoir les fermer proprement. */
    private final List<McpSyncClient> all = new ArrayList<>();

    private volatile boolean closed;

    McpServerPool(String name, McpProperties props, McpProperties.Server spec) {
        this.name = name;
        this.props = props;
        this.spec = spec;
        this.allowedTools = new LinkedHashSet<>(spec.getAllowedTools());
        this.idle = new ArrayBlockingQueue<>(Math.max(1, props.getPoolSize()));
    }

    /**
     * Démarre les processus et négocie MCP avec chacun.
     *
     * <p>Un échec ici n'empêche pas l'application de démarrer : un serveur
     * indisponible doit donner une panne lisible sur les routes qui en
     * dépendent, pas empêcher le site entier de se lancer.
     */
    void start() {
        for (int i = 0; i < Math.max(1, props.getPoolSize()); i++) {
            try {
                McpSyncClient client = create();
                all.add(client);
                idle.offer(client);
            } catch (Exception e) {
                log.error("Serveur MCP « {} » : démarrage du processus {} impossible — {}",
                        name, i + 1, e.toString());
            }
        }
        if (!all.isEmpty()) {
            log.info("Serveur MCP « {} » : {} processus prêt(s), outils autorisés {}",
                    name, all.size(), allowedTools);
        }
    }

    private McpSyncClient create() {
        McpClientTransport transport = "http".equalsIgnoreCase(spec.getTransport())
                ? transportDistant()
                : transportLocal();

        McpSyncClient client = McpClient.sync(transport)
                .clientInfo(new McpSchema.Implementation("argus-web", "ARGUS Web", "1.0.0"))
                .requestTimeout(props.getRequestTimeout())
                .initializationTimeout(props.getStartupTimeout())
                .build();

        client.initialize();
        return client;
    }

    /**
     * Serveur MCP distant, joint en HTTP.
     *
     * <p>Aucun processus a lancer : ni interpreteur a demarrer, ni tubes a
     * surveiller. Le groupe reste utile malgre tout, une session MCP n'etant
     * pas prevue pour porter plusieurs requetes de front.
     */
    private McpClientTransport transportDistant() {
        return HttpClientStreamableHttpTransport.builder(spec.getUrl())
                .endpoint(spec.getEndpoint())
                .jsonMapper(McpJsonDefaults.getMapper())
                .build();
    }

    private McpClientTransport transportLocal() {
        // L'environnement est HÉRITÉ puis complété. Ne transmettre que nos
        // propres variables priverait Python de PATH et de SYSTEMROOT, et il ne
        // démarrerait pas du tout sous Windows.
        Map<String, String> env = new HashMap<>(System.getenv());
        env.putAll(spec.getEnv());
        // Les sorties des outils sont en français : sans cette variable, un
        // accent suffit à faire échouer l'écriture sur la sortie standard de
        // Python sous Windows.
        env.putIfAbsent("PYTHONIOENCODING", "utf-8");

        // Un module Python est le cas courant ; une commande libre permet
        // d'accueillir un serveur MCP ecrit dans n'importe quel langage.
        ServerParameters params = spec.getCommand() != null && !spec.getCommand().isBlank()
                ? ServerParameters.builder(spec.getCommand()).args(spec.getArgs()).env(env).build()
                : ServerParameters.builder(props.getPython())
                        .args("-m", spec.getModule()).env(env).build();

        StdioClientTransport transport =
                new StdioClientTransport(params, McpJsonDefaults.getMapper());

        // En transport stdio, stdout porte le protocole et stderr porte les
        // journaux du serveur. On redirige ces derniers vers le journal Java
        // plutôt que de les laisser se perdre.
        transport.setStdErrorHandler(ligne -> log.debug("[mcp:{}] {}", name, ligne));
        return transport;
    }

    /**
     * Appelle un outil et rend sa sortie structurée.
     *
     * @throws McpToolException si l'outil est refusé, absent, en erreur, ou si
     *                          aucun processus n'est disponible
     */
    Map<String, Object> call(String tool, Map<String, Object> arguments) {
        if (!autorise(tool)) {
            // Refus volontairement explicite : c'est une erreur de
            // configuration côté serveur, pas une saisie de l'utilisateur.
            throw new McpToolException(
                    "L'outil « " + tool + " » n'est pas exposé par ce serveur.", false);
        }
        if (closed || all.isEmpty()) {
            throw new McpToolException(
                    "Le serveur d'analyse « " + name + " » n'est pas disponible.", false);
        }

        if (spec.isRemote()) {
            RemoteArgumentGuard.verifier(tool, arguments);
        }

        McpSyncClient client = borrow();
        boolean sain = true;
        try {
            McpSchema.CallToolResult result = client.callTool(
                    McpSchema.CallToolRequest.builder(tool).arguments(arguments).build());

            if (Boolean.TRUE.equals(result.isError())) {
                // L'outil a refusé l'entrée — domaine mal formé, indicateur
                // invalide. C'est la faute du client HTTP, pas une panne.
                throw new McpToolException(texte(result), true);
            }
            return structure(result, tool);
        } catch (McpToolException e) {
            throw e;
        } catch (Exception e) {
            // Une panne de transport laisse le client dans un état douteux :
            // le rendre au groupe propagerait le problème à la requête suivante.
            sain = false;
            throw new McpToolException(
                    "Le serveur d'analyse « " + name + " » n'a pas répondu.", e);
        } finally {
            if (sain) {
                idle.offer(client);
            } else {
                remplacer(client);
            }
        }
    }

    /** Un outil expose, soit nomme, soit couvert par une ouverture explicite. */
    private boolean autorise(String outil) {
        return spec.isAllowAllTools() || allowedTools.contains(outil);
    }

    private McpSyncClient borrow() {
        try {
            McpSyncClient client = idle.poll(props.getBorrowTimeout().toMillis(), TimeUnit.MILLISECONDS);
            if (client == null) {
                throw new McpToolException(
                        "Trop d'analyses en cours. Réessayez dans un instant.", false);
            }
            return client;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new McpToolException("Analyse interrompue.", e);
        }
    }

    /** Ferme un client suspect et tente d'en remettre un neuf dans le groupe. */
    private void remplacer(McpSyncClient mort) {
        synchronized (all) {
            all.remove(mort);
        }
        try {
            mort.close();
        } catch (Exception ignored) {
            // Le processus est peut-être déjà parti : rien à sauver ici.
        }
        if (closed) {
            return;
        }
        try {
            McpSyncClient neuf = create();
            synchronized (all) {
                all.add(neuf);
            }
            idle.offer(neuf);
            log.info("Serveur MCP « {} » : processus remplacé après incident.", name);
        } catch (Exception e) {
            log.error("Serveur MCP « {} » : remplacement impossible — {}", name, e.toString());
        }
    }

    /**
     * Extrait la sortie structurée d'un résultat d'outil.
     *
     * <p>Les outils ARGUS déclarent tous un {@code output_schema} et répondent
     * donc en {@code structuredContent}. Si ce n'était pas le cas, mieux vaut
     * une erreur nette qu'un texte libre remonté au navigateur comme s'il
     * s'agissait de données.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> structure(McpSchema.CallToolResult result, String tool) {
        Object structured = result.structuredContent();
        if (structured instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        throw new McpToolException(
                "L'outil « " + tool + " » n'a pas renvoyé de sortie structurée.", false);
    }

    /** Concatène les contenus textuels d'un résultat, pour un message d'erreur. */
    private String texte(McpSchema.CallToolResult result) {
        if (result.content() == null || result.content().isEmpty()) {
            return "L'analyse a échoué.";
        }
        StringBuilder sb = new StringBuilder();
        for (McpSchema.Content c : result.content()) {
            if (c instanceof McpSchema.TextContent t) {
                if (!sb.isEmpty()) {
                    sb.append(' ');
                }
                sb.append(t.text());
            }
        }
        return sb.isEmpty() ? "L'analyse a échoué." : sb.toString();
    }

    /**
     * Les outils autorises de ce serveur, tels que le serveur les decrit.
     *
     * <p>Le schema d'entree vient du serveur MCP lui-meme : c'est lui qui fait
     * autorite sur ce que chaque outil attend. Le recopier a la main ici
     * produirait une seconde description qui divergerait en silence.
     */
    List<McpSchema.Tool> listTools() {
        if (closed || all.isEmpty()) {
            return List.of();
        }
        McpSyncClient client = borrow();
        try {
            return client.listTools().tools().stream()
                    .filter(t -> autorise(t.name()))
                    .toList();
        } catch (Exception e) {
            throw new McpToolException(
                    "Le serveur d'analyse « " + name + " » n'a pas pu lister ses outils.", e);
        } finally {
            idle.offer(client);
        }
    }

    boolean isReady() {
        return !closed && !all.isEmpty();
    }

    String getName() {
        return name;
    }

    Set<String> getAllowedTools() {
        return allowedTools;
    }

    /** Vrai si ce serveur porte cet outil, pour le routage par nom. */
    boolean porte(String outil) {
        return autorise(outil);
    }

    boolean isRemote() {
        return spec.isRemote();
    }

    String getLabel() {
        return spec.getLabel() != null ? spec.getLabel() : name;
    }

    @Override
    public void close() {
        closed = true;
        List<McpSyncClient> copie;
        synchronized (all) {
            copie = List.copyOf(all);
            all.clear();
        }
        for (McpSyncClient client : copie) {
            try {
                client.close();
            } catch (Exception e) {
                log.debug("Fermeture du client MCP « {} » : {}", name, e.toString());
            }
        }
        idle.clear();
    }
}
