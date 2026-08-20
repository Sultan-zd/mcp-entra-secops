package com.teknologiia.argus.chat;

import com.teknologiia.argus.chat.ChatContracts.ChatRequest;
import com.teknologiia.argus.chat.ChatContracts.Turn;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Ce qui se verifie sans appeler un modele.
 *
 * <p>La conversation elle-meme exige une cle d'API valide et facture son
 * proprietaire : la tester automatiquement demanderait un secret dans la chaine
 * d'integration. Ce qui est teste ici, c'est tout ce qui entoure l'appel — et
 * c'est la que vivent les erreurs qu'on peut commettre.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ChatControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private ToolBridge outils;

    @Test
    @DisplayName("un fournisseur inconnu est refuse avant tout appel")
    void fournisseurInconnu() throws Exception {
        mvc.perform(post("/api/chat")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"message":"bonjour","provider":"inexistant",
                                 "apiKey":"sk-test","model":"claude-opus-5"}"""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").exists());
    }

    @Test
    @DisplayName("une question sans cle d'API est refusee")
    void cleManquante() throws Exception {
        mvc.perform(post("/api/chat")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"message":"bonjour","provider":"anthropic","apiKey":""}"""))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("une question vide est refusee")
    void questionVide() throws Exception {
        mvc.perform(post("/api/chat")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"message":"  ","provider":"anthropic","apiKey":"sk-test"}"""))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("les fournisseurs disponibles sont annonces avec leurs modeles")
    void fournisseursAnnonces() throws Exception {
        mvc.perform(post("/api/chat").contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());

        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .get("/api/chat/providers"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value("anthropic"))
                .andExpect(jsonPath("$[0].models").isArray());
    }

    // ----------------------------------------------------------------------
    // Bornage de l'historique
    // ----------------------------------------------------------------------
    @Test
    @DisplayName("l'historique renvoye par le navigateur est borne")
    void historiqueBorne() {
        List<Turn> longue = IntStream.range(0, 60)
                .mapToObj(i -> new Turn(i % 2 == 0 ? "user" : "assistant", "tour " + i))
                .toList();

        ChatRequest requete = new ChatRequest("question", "anthropic", null, "sk-test", longue);

        // Sans borne, chaque question renverrait toute la conversation au
        // modele : le cout grimpe sans que la reponse s'ameliore.
        assertThat(requete.safeHistory()).hasSize(20);
        assertThat(requete.safeHistory().getLast().content()).isEqualTo("tour 59");
    }

    @Test
    @DisplayName("un historique absent ne fait pas tomber la requete")
    void historiqueAbsent() {
        ChatRequest requete = new ChatRequest("question", "anthropic", null, "sk-test", null);
        assertThat(requete.safeHistory()).isEmpty();
    }
}
