package com.teknologiia.argus.controller;

import com.teknologiia.argus.mcp.McpToolException;
import com.teknologiia.argus.mcp.McpToolGateway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Le contrôleur public est la seule surface exposée sans authentification.
 *
 * <p>La passerelle MCP est simulée : ces tests portent sur ce que le contrôleur
 * laisse passer, pas sur l'analyse elle-même — celle-ci a ses 288 tests côté
 * Python, et les rejouer ici les dupliquerait sans rien prouver de neuf.
 */
@SpringBootTest
@AutoConfigureMockMvc
class PublicAnalysisControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private McpToolGateway gateway;

    private static final String ROUTE = "/api/public/domain-posture";

    @Test
    @DisplayName("un domaine valide atteint l'outil et sa sortie est rendue telle quelle")
    void domaineValide() throws Exception {
        when(gateway.call(eq("email"), eq("check_domain_posture"), any()))
                .thenReturn(Map.of("domain", "teknologiia.com", "score", 100, "grade", "A"));

        mvc.perform(post(ROUTE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"domain\":\"teknologiia.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.grade").value("A"))
                .andExpect(jsonPath("$.score").value(100));
    }

    @Test
    @DisplayName("une saisie qui n'est pas un domaine n'atteint jamais l'outil")
    void saisieInvalideNAtteintPasLOutil() throws Exception {
        mvc.perform(post(ROUTE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"domain\":\"pas un domaine\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").exists());

        // Le point du test : refuser tôt évite de dépenser un processus et des
        // résolutions DNS pour une saisie évidemment fautive.
        verify(gateway, never()).call(any(), any(), any());
    }

    @Test
    @DisplayName("une tentative d'injection de commande est refusée par le motif")
    void injectionRefusee() throws Exception {
        mvc.perform(post(ROUTE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"domain\":\"github.com; rm -rf /\"}"))
                .andExpect(status().isBadRequest());

        verify(gateway, never()).call(any(), any(), any());
    }

    @Test
    @DisplayName("un domaine refusé par l'outil devient un 400, pas une panne")
    void refusDeLOutilEst400() throws Exception {
        when(gateway.call(any(), any(), any()))
                .thenThrow(new McpToolException("Ce domaine est introuvable.", true));

        mvc.perform(post(ROUTE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"domain\":\"exemple-inexistant.test\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value("Ce domaine est introuvable."));
    }

    @Test
    @DisplayName("un serveur MCP en panne devient un 503")
    void panneEst503() throws Exception {
        when(gateway.call(any(), any(), any()))
                .thenThrow(new McpToolException("Le serveur d'analyse « email » n'est pas disponible.", false));

        mvc.perform(post(ROUTE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"domain\":\"teknologiia.com\"}"))
                .andExpect(status().isServiceUnavailable());
    }

    @Test
    @DisplayName("aucune trace d'exception n'atteint le navigateur")
    void aucuneTraceExposee() throws Exception {
        when(gateway.call(any(), any(), any()))
                .thenThrow(new IllegalStateException("com.teknologiia.Secret à /etc/mot-de-passe"));

        mvc.perform(post(ROUTE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"domain\":\"teknologiia.com\"}"))
                .andExpect(status().isInternalServerError())
                // Le message d'origine nomme une classe et un chemin : il est
                // journalisé, jamais rendu.
                .andExpect(jsonPath("$.detail").value("Une erreur interne est survenue."));
    }
}
