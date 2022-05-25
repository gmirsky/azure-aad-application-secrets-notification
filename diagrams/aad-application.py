from diagrams import Cluster, Diagram
from diagrams.azure.identity import ActiveDirectory
from diagrams.azure.web import APIConnections
from diagrams.azure.security import KeyVaults
from diagrams.azure.integration import LogicApps

with Diagram("AAD Application", direction="TB"):
    tenant = ActiveDirectory("App Registration")
    with Cluster("Application"):
        api_keyvault = APIConnections("Key Vault API")
        api_office365 = APIConnections("Office365 API")
        key_vault = KeyVaults("Key Vault")
        logic_app = LogicApps("Logic App")

    logic_app >> api_keyvault >> logic_app
    logic_app >> tenant >> logic_app
    api_keyvault >> key_vault >> api_keyvault
    logic_app >> api_office365 >> logic_app
