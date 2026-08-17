import json
import os
from mcp.server.fastmcp import FastMCP

# Initialisation du serveur MCP
mcp = FastMCP("EntraSecOpsServer")

@mcp.tool()
def get_user_signins(upn: str) -> str:
    """
    Récupère les journaux de connexion récents pour un utilisateur (UPN) spécifique.
    """
    # 1. SIMULATION : Au lieu de faire un requests.get() vers Microsoft, on lit notre fichier local
    try:
        with open("mock_graph_response.json", "r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        return "Erreur : Fichier de simulation introuvable."

    # 2. TRONCATURE AGRESSIVE : On filtre les données massives
    filtered_logs = []
    
    for signin in data.get("value", []):
        # On vérifie si le log correspond à l'utilisateur demandé
        if signin.get("userPrincipalName") == upn:
            
            # On extrait UNIQUEMENT les indicateurs de sécurité ciblés
            clean_log = {
                "Timestamp": signin.get("createdDateTime"),
                "App Name": signin.get("appDisplayName"),
                "IP Address": signin.get("ipAddress"),
                "Geo-location": f"{signin.get('location', {}).get('city')}, {signin.get('location', {}).get('countryOrRegion')}",
                "Login Status": "Failure" if signin.get("status", {}).get("errorCode") != 0 else "Success",
                "Failure Reason": signin.get("status", {}).get("failureReason")
            }
            filtered_logs.append(clean_log)

    # 3. Formatage en chaîne JSON propre pour l'IA
    if not filtered_logs:
        return f"Aucun log de connexion trouvé pour {upn}."
        
    return json.dumps(filtered_logs, indent=2)

if __name__ == "__main__":
    # Démarre le serveur
    mcp.run()