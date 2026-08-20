package com.teknologiia.argus.chat;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Les fournisseurs de la famille compatible OpenAI.
 *
 * <p>Ils partagent une implementation et ne different que par leur URL, leurs
 * modeles et l'adresse ou obtenir une cle. Les declarer ici plutot que
 * d'ecrire une classe par fournisseur evite quatre copies du meme code — et
 * en ajouter un revient a ajouter cinq lignes.
 */
@Configuration
public class ProviderConfiguration {

    @Bean
    LlmProvider openai(LlmHttp http) {
        return new OpenAiCompatibleProvider(
                "openai",
                "ChatGPT (OpenAI)",
                "https://api.openai.com/v1",
                List.of("gpt-5.2", "gpt-5.2-mini", "gpt-5.1", "gpt-4.1"),
                "https://platform.openai.com/api-keys",
                http);
    }

    @Bean
    LlmProvider mistral(LlmHttp http) {
        return new OpenAiCompatibleProvider(
                "mistral",
                "Mistral",
                "https://api.mistral.ai/v1",
                List.of("mistral-large-latest", "mistral-medium-latest", "mistral-small-latest"),
                "https://console.mistral.ai/api-keys",
                http);
    }

    @Bean
    LlmProvider deepseek(LlmHttp http) {
        return new OpenAiCompatibleProvider(
                "deepseek",
                "DeepSeek",
                "https://api.deepseek.com/v1",
                List.of("deepseek-chat", "deepseek-reasoner"),
                "https://platform.deepseek.com/api_keys",
                http);
    }

    @Bean
    LlmProvider groq(LlmHttp http) {
        return new OpenAiCompatibleProvider(
                "groq",
                "Groq",
                "https://api.groq.com/openai/v1",
                List.of("llama-3.3-70b-versatile", "openai/gpt-oss-120b"),
                "https://console.groq.com/keys",
                http);
    }
}
