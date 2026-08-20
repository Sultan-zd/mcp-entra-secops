package com.teknologiia.argus.mcp;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Où trouver les serveurs MCP, et comment les lancer.
 *
 * <p>Rien ici ne décrit une analyse. Cette application ne réimplémente aucune
 * logique de sécurité : les serveurs MCP Python la portent déjà, avec leurs
 * tests. Ce fichier dit seulement quel processus démarrer.
 */
@ConfigurationProperties(prefix = "argus.mcp")
public class McpProperties {

    /**
     * Interpréteur Python de l'environnement où le paquet ARGUS est installé.
     *
     * <p>Le paquet étant installé (« pip install -e »), {@code python -m
     * email_security_mcp} fonctionne depuis n'importe quel répertoire — ce qui
     * tombe bien, car {@code ServerParameters} n'expose pas de répertoire de
     * travail.
     */
    private String python = "python";

    /**
     * Nombre de processus maintenus par serveur.
     *
     * <p>Un client MCP en mode stdio possède <em>un</em> couple de tubes vers
     * <em>un</em> processus. Deux requêtes simultanées sur le même client
     * entrelaceraient leurs trames JSON-RPC. La concurrence passe donc par
     * plusieurs processus, pas par plusieurs fils sur un seul.
     */
    private int poolSize = 2;

    /** Délai au-delà duquel un outil qui ne répond pas est abandonné. */
    private Duration requestTimeout = Duration.ofSeconds(30);

    /** Délai laissé à un processus Python pour démarrer et négocier MCP. */
    private Duration startupTimeout = Duration.ofSeconds(45);

    /** Attente maximale d'un client libre quand tous sont occupés. */
    private Duration borrowTimeout = Duration.ofSeconds(20);

    /** Serveurs déclarés, par nom logique (« email », « intel »…). */
    private Map<String, Server> servers = new LinkedHashMap<>();

    public static class Server {

        /** {@code stdio} pour un processus local, {@code http} pour un serveur distant. */
        private String transport = "stdio";

        /** Module Python à lancer, passé à {@code python -m}. Transport stdio. */
        private String module;

        /** Commande arbitraire, si le serveur n'est pas un module Python. */
        private String command;

        /** Arguments de {@link #command}. */
        private List<String> args = List.of();

        /** Racine du serveur distant, par exemple {@code https://exemple.com}. */
        private String url;

        /** Chemin du point d'entrée MCP sur ce serveur. */
        private String endpoint = "/mcp";

        /**
         * Serveur tiers, hors de notre controle.
         *
         * <p>Les arguments qui partent vers lui sont filtres : une adresse
         * interne envoyee a un service de reputation ne rend rien d'utile et
         * revele la topologie du reseau.
         */
        private boolean remote;

        /**
         * Expose tous les outils annonces par ce serveur.
         *
         * <p>Doit etre demande explicitement. Un serveur qui en publie
         * cinquante-cinq rend la liste nominative impraticable, mais laisser
         * l'ouverture par defaut ferait entrer n'importe quel outil ajoute en
         * amont sans que personne ne l'ait decide.
         */
        private boolean allowAllTools;

        /** Libelle affiche a l'utilisateur. */
        private String label;

        /** Variables d'environnement ajoutées à celles héritées. */
        private Map<String, String> env = new LinkedHashMap<>();

        /**
         * Outils que ce serveur a le droit d'exposer par cette application.
         *
         * <p>C'est une liste d'autorisation, pas une documentation. Un serveur
         * MCP annonce ses outils lui-même ; s'y fier laisserait l'ajout d'un
         * outil côté Python l'exposer aussitôt sur le web, sans que personne
         * ne l'ait décidé ici.
         */
        private List<String> allowedTools = List.of();

        public String getTransport() {
            return transport;
        }

        public void setTransport(String transport) {
            this.transport = transport;
        }

        public String getModule() {
            return module;
        }

        public void setModule(String module) {
            this.module = module;
        }

        public String getCommand() {
            return command;
        }

        public void setCommand(String command) {
            this.command = command;
        }

        public List<String> getArgs() {
            return args;
        }

        public void setArgs(List<String> args) {
            this.args = args;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public String getEndpoint() {
            return endpoint;
        }

        public void setEndpoint(String endpoint) {
            this.endpoint = endpoint;
        }

        public boolean isRemote() {
            return remote;
        }

        public void setRemote(boolean remote) {
            this.remote = remote;
        }

        public boolean isAllowAllTools() {
            return allowAllTools;
        }

        public void setAllowAllTools(boolean allowAllTools) {
            this.allowAllTools = allowAllTools;
        }

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public Map<String, String> getEnv() {
            return env;
        }

        public void setEnv(Map<String, String> env) {
            this.env = env;
        }

        public List<String> getAllowedTools() {
            return allowedTools;
        }

        public void setAllowedTools(List<String> allowedTools) {
            this.allowedTools = allowedTools;
        }
    }

    public String getPython() {
        return python;
    }

    public void setPython(String python) {
        this.python = python;
    }

    public int getPoolSize() {
        return poolSize;
    }

    public void setPoolSize(int poolSize) {
        this.poolSize = poolSize;
    }

    public Duration getRequestTimeout() {
        return requestTimeout;
    }

    public void setRequestTimeout(Duration requestTimeout) {
        this.requestTimeout = requestTimeout;
    }

    public Duration getStartupTimeout() {
        return startupTimeout;
    }

    public void setStartupTimeout(Duration startupTimeout) {
        this.startupTimeout = startupTimeout;
    }

    public Duration getBorrowTimeout() {
        return borrowTimeout;
    }

    public void setBorrowTimeout(Duration borrowTimeout) {
        this.borrowTimeout = borrowTimeout;
    }

    public Map<String, Server> getServers() {
        return servers;
    }

    public void setServers(Map<String, Server> servers) {
        this.servers = servers;
    }
}
