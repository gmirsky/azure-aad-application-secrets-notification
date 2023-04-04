//
// azure-aad-application-secrets-notification Bicep file
//

/* 

To get the full list of regional names use the following Azure CLI command:

    az account list-locations -o table

Azure naming rule limits

  https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules

*/

targetScope = 'resourceGroup'

@description('The name of the API connection used to connect to the Azure Key Vault')
@minLength(1)
@maxLength(80)
param connections_keyvault_name string = 'keyvault'

@description('The name of the API connection used to connect to Office 365')
@minLength(1)
@maxLength(80)
param connections_office365_name string = 'office365'

@description('The Azure Key Vault Name for this application')
@minLength(3)
@maxLength(24)
param key_vault_name string

@description('The Azure region name to deploy into')
@allowed([
  'eastus'
  'eastus2'
  'southcentralus'
  'westus2'
  'westus3'
  'australiaeast'
  'southeastasia'
  'northeurope'
  'swedencentral'
  'uksouth'
  'westeurope'
  'centralus'
  'southafricanorth'
  'centralindia'
  'eastasia'
  'japaneast'
  'koreacentral'
  'canadacentral'
  'francecentral'
  'germanywestcentral'
  'norwayeast'
  'brazilsouth'
  'eastus2euap'
  'centralusstage'
  'eastusstage'
  'eastus2stage'
  'northcentralusstage'
  'southcentralusstage'
  'westusstage'
  'westus2stage'
  'asia'
  'asiapacific'
  'australia'
  'brazil'
  'canada'
  'europe'
  'france'
  'germany'
  'global'
  'india'
  'japan'
  'korea'
  'norway'
  'southafrica'
  'switzerland'
  'uae'
  'uk'
  'unitedstates'
  'unitedstateseuap'
  'eastasiastage'
  'southeastasiastage'
  'northcentralus'
  'westus'
  'jioindiawest'
  'switzerlandnorth'
  'uaenorth'
  'centraluseuap'
  'westcentralus'
  'southafricawest'
  'australiacentral'
  'australiacentral2'
  'australiasoutheast'
  'japanwest'
  'jioindiacentral'
  'koreasouth'
  'southindia'
  'westindia'
  'canadaeast'
  'francesouth'
  'germanynorth'
  'norwaywest'
  'switzerlandwest'
  'ukwest'
  'uaecentral'
  'brazilsoutheast'
])
param deployment_location string = 'eastus' //resourceGroup().location

@description('Workflow name of the application')
#disable-next-line secure-secrets-in-params   // Doesn't contain a secret
param workflows_azure_aad_application_secrets_notification_name string = 'azure-aad-application-secrets-notification'

@secure()
@description('the Application (client) ID from the Azure Active Directory Application registration')
// @metadata({
//   regex: '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$'
// })
param client_id_secret string

@secure()
@description('the client secret value from from the Azure Active Directory Application registration secret')
param client_secret_secret string

@secure()
@description('the Directory (tenant) ID from the Azure Active Directory Application registration')
@metadata({
  regex: '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$'
})
param tenant_id_secret string

@description('Tags to be applied to the provisioned Azure assets')
param tags object = {
  Bicep_Managed: true
  Maintainer: 'Gregory N. Mirsky'
  Cost_Center: 'Infrastructure-General'
}

var VaultURL = environment().suffixes.keyvaultDns

resource key_vault_name_resource 'Microsoft.KeyVault/vaults@2021-11-01-preview' = {
  name: key_vault_name
  location: deployment_location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: tenant_id_secret
    accessPolicies: [
      {
        tenantId: tenant_id_secret
        objectId: '2be10a4e-e094-4606-8aca-006e1969575b'
        permissions: {
          keys: [
            'get'
            'list'
            'update'
            'create'
            'import'
            'delete'
            'recover'
            'backup'
            'restore'
            'getrotationpolicy'
            'setrotationpolicy'
            'rotate'
          ]
          secrets: [
            'get'
            'list'
            'set'
            'delete'
            'recover'
            'backup'
            'restore'
          ]
          certificates: [
            'get'
            'list'
            'update'
            'create'
            'import'
            'delete'
            'recover'
            'backup'
            'restore'
            'managecontacts'
            'manageissuers'
            'getissuers'
            'listissuers'
            'setissuers'
            'deleteissuers'
          ]
        }
      }
    ]
    enabledForDeployment: true
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enableRbacAuthorization: false
    //vaultUri: 'https://${key_vault_name}.vault.azure.net/'
    vaultUri: 'https://${key_vault_name}${VaultURL}/'
    provisioningState: 'Succeeded'
    publicNetworkAccess: 'Enabled'
  }
}

resource connections_keyvault_name_resource 'Microsoft.Web/connections@2016-06-01' = {
  name: connections_keyvault_name
  tags: tags
  location: deployment_location
  //kind: 'V1'
  properties: {
    displayName: connections_keyvault_name
    statuses: [
      {
        status: 'Connected'
      }
    ]
    customParameterValues: {}
    nonSecretParameterValues: {
      vaultName: key_vault_name
    }
    //createdTime: '2022-04-27T18:44:13.5915342Z'
    //changedTime: '2022-04-28T19:36:31.8214052Z'
    api: {
      name: connections_keyvault_name
      displayName: 'Azure Key Vault'
      description: 'Azure Key Vault is a service to securely store and access secrets.'
      iconUri: 'https://connectoricons-prod.azureedge.net/releases/v1.0.1566/1.0.1566.2741/${connections_keyvault_name}/icon.png'
      brandColor: '#0079d6'
      //id: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Web/locations/eastus/managedApis/${connections_keyvault_name}'
      type: 'Microsoft.Web/locations/managedApis'
    }
    testLinks: []
  }
}

resource connections_office365_name_resource 'Microsoft.Web/connections@2016-06-01' = {
  name: connections_office365_name
  tags: tags
  location: deployment_location
  properties: {
    displayName: connections_office365_name
    statuses: [
      {
        status: 'Connected'
      }
    ]
    customParameterValues: {}
    nonSecretParameterValues: {}
    //createdTime: '2022-04-27T18:44:13.5903867Z'
    //changedTime: '2022-04-28T19:36:48.5647905Z'
    api: {
      name: connections_office365_name
      displayName: 'Office 365 Outlook'
      description: 'Microsoft Office 365 is a cloud-based service that is designed to help meet your organization\'s needs for robust security, reliability, and user productivity.'
      iconUri: 'https://connectoricons-prod.azureedge.net/releases/v1.0.1573/1.0.1573.2770/${connections_office365_name}/icon.png'
      brandColor: '#0078D4'
      //id: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Web/locations/eastus/managedApis/${connections_office365_name}'
      type: 'Microsoft.Web/locations/managedApis'
    }
    testLinks: [
      {
        #disable-next-line no-hardcoded-env-urls
        requestUri: 'https://management.azure.com:443/subscriptions/${subscription().subscriptionId}/resourceGroups/${key_vault_name}/providers/Microsoft.Web/connections/${connections_office365_name}/extensions/proxy/testconnection?api-version=2016-06-01'
        method: 'get'
      }
    ]
  }
}

resource key_vault_name_client_id 'Microsoft.KeyVault/vaults/secrets@2021-11-01-preview' = {
  parent: key_vault_name_resource
  tags: tags
  name: 'client-id'
  properties: {
    attributes: {
      enabled: true
    }
    value: client_id_secret
  }
}

resource key_vault_name_client_secret 'Microsoft.KeyVault/vaults/secrets@2021-11-01-preview' = {
  parent: key_vault_name_resource
  tags: tags
  name: 'client-secret'
  properties: {
    attributes: {
      enabled: true
    }
    value: client_secret_secret
  }
}

resource key_vault_name_tenant_id 'Microsoft.KeyVault/vaults/secrets@2021-11-01-preview' = {
  parent: key_vault_name_resource
  tags: tags
  name: 'tenant-id'
  properties: {
    attributes: {
      enabled: true
    }
    value: tenant_id_secret
  }
}

resource workflows_azure_aad_application_secrets_notification_name_resource 'Microsoft.Logic/workflows@2019-05-01' = {
  name: workflows_azure_aad_application_secrets_notification_name
  tags: tags
  location: deployment_location
  properties: {
    state: 'Disabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
      }
      triggers: {
        Recurrence_every_X_days: {
          recurrence: {
            frequency: 'Day'
            interval: 1
          }
          evaluatedRecurrence: {
            frequency: 'Day'
            interval: 1
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Close_HTML_tags: {
          runAfter: {
            Until: [
              'Succeeded'
            ]
          }
          type: 'AppendToStringVariable'
          inputs: {
            name: 'html'
            value: '<tbody></table>'
          }
        }
        Get_Auth_Token: {
          runAfter: {
            Initialize_daysTilExpiration: [
              'Succeeded'
            ]
          }
          type: 'Http'
          inputs: {
            body: 'grant_type=client_credentials\n&client_id=@{body(\'Get_Client-id_from_key_vault\')?[\'value\']}\n&client_secret=@{body(\'Get_Client-secret_from_key_vault\')?[\'value\']}\n&scope=https://graph.microsoft.com/.default'
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            }
            method: 'POST'
            #disable-next-line no-hardcoded-env-urls
            uri: 'https://login.microsoftonline.com/@{body(\'Get_Tenant-id_from_key_vault\')?[\'value\']}/oauth2/v2.0/token'
          }
        }
        'Get_Client-id_from_key_vault': {
          runAfter: {
            'Get_Tenant-id_from_key_vault': [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'keyvault\'][\'connectionId\']'
              }
            }
            method: 'get'
            path: '/secrets/@{encodeURIComponent(\'client-id\')}/value'
          }
          runtimeConfiguration: {
            secureData: {
              properties: [
                'inputs'
                'outputs'
              ]
            }
          }
        }
        'Get_Client-secret_from_key_vault': {
          runAfter: {
            'Get_Client-id_from_key_vault': [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'keyvault\'][\'connectionId\']'
              }
            }
            method: 'get'
            path: '/secrets/@{encodeURIComponent(\'client-secret\')}/value'
          }
          runtimeConfiguration: {
            secureData: {
              properties: [
                'inputs'
                'outputs'
              ]
            }
          }
        }
        'Get_Tenant-id_from_key_vault': {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'keyvault\'][\'connectionId\']'
              }
            }
            method: 'get'
            path: '/secrets/@{encodeURIComponent(\'tenant-id\')}/value'
          }
          runtimeConfiguration: {
            secureData: {
              properties: [
                'inputs'
                'outputs'
              ]
            }
          }
        }
        'Initialize_-_NextLink': {
          runAfter: {
            'Parse_JSON_-_Retrieve_token_Info': [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'NextLink'
                type: 'string'
                value: 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=999'
              }
            ]
          }
        }
        'Initialize_-_keyCredential': {
          runAfter: {
            Initialize_passwordCredential: [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'keyCredential'
                type: 'array'
              }
            ]
          }
        }
        Initialize_appid: {
          runAfter: {
            'Get_Client-secret_from_key_vault': [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'AppID'
                type: 'string'
                value: ''
              }
            ]
          }
        }
        Initialize_daysTilExpiration: {
          runAfter: {
            Initialize_html: [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'daysTilExpiration'
                type: 'float'
                value: 30
              }
            ]
          }
        }
        Initialize_displayName: {
          runAfter: {
            Initialize_appid: [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'displayName'
                type: 'string'
                value: ''
              }
            ]
          }
        }
        Initialize_html: {
          runAfter: {
            Initialize_styles: [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'html'
                type: 'string'
                value: '<table  @{variables(\'styles\').tableStyle}><thead><th  @{variables(\'styles\').headerStyle}>Application ID</th><th  @{variables(\'styles\').headerStyle}>Display Name</th><th @{variables(\'styles\').headerStyle}> Key Id</th><th  @{variables(\'styles\').headerStyle}>Days until Expiration</th><th  @{variables(\'styles\').headerStyle}>Type</th><th  @{variables(\'styles\').headerStyle}>Expiration Date</th><th @{variables(\'styles\').headerStyle}>Owner</th></thead><tbody>'
              }
            ]
          }
        }
        Initialize_passwordCredential: {
          runAfter: {
            Initialize_displayName: [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'passwordCredential'
                type: 'array'
              }
            ]
          }
        }
        Initialize_styles: {
          runAfter: {
            'Initialize_-_keyCredential': [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'styles'
                type: 'object'
                value: {
                  cellStyle: 'style="font-family: Calibri; padding: 5px; border: 1px solid black;"'
                  headerStyle: 'style="font-family: Helvetica; padding: 5px; border: 1px solid black;"'
                  redStyle: 'style="background-color:red; font-family: Calibri; padding: 5px; border: 1px solid black;"'
                  tableStyle: 'style="border-collapse: collapse;"'
                  yellowStyle: 'style="background-color:yellow; font-family: Calibri; padding: 5px; border: 1px solid black;"'
                }
              }
            ]
          }
        }
        'Parse_JSON_-_Retrieve_token_Info': {
          runAfter: {
            Get_Auth_Token: [
              'Succeeded'
            ]
          }
          type: 'ParseJson'
          inputs: {
            content: '@body(\'Get_Auth_Token\')'
            schema: {
              properties: {
                access_token: {
                  type: 'string'
                }
                expires_in: {
                  type: 'integer'
                }
                ext_expires_in: {
                  type: 'integer'
                }
                token_type: {
                  type: 'string'
                }
              }
              type: 'object'
            }
          }
          runtimeConfiguration: {
            secureData: {
              properties: [
                'inputs'
              ]
            }
          }
        }
        Send_the_list_of_applications: {
          runAfter: {
            Close_HTML_tags: [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            body: {
              Body: '<p>@{variables(\'html\')}</p>'
              Subject: 'Azure AD Application Secrets and Certificates near,  or at, expiration'
              To: 'gregory.mirsky@gfk.com;sam.ramachandran@gfk.com;Edward.Walsh@gfk.com'
            }
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'office365\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/v2/Mail'
          }
          runtimeConfiguration: {
            secureData: {
              properties: [
                'inputs'
                'outputs'
              ]
            }
          }
        }
        Until: {
          actions: {
            'Foreach_-_apps': {
              foreach: '@body(\'Parse_JSON\')?[\'value\']'
              actions: {
                'For_each_-_PasswordCred': {
                  foreach: '@items(\'Foreach_-_apps\')?[\'passwordCredentials\']'
                  actions: {
                    Condition: {
                      actions: {
                        DifferentAsDays: {
                          runAfter: {
                            StartTimeTickValue: [
                              'Succeeded'
                            ]
                          }
                          type: 'Compose'
                          inputs: '@div(div(div(mul(sub(outputs(\'EndTimeTickValue\'),outputs(\'StartTimeTickValue\')),100),1000000000) , 3600), 24)'
                        }
                        EndTimeTickValue: {
                          runAfter: {}
                          type: 'Compose'
                          inputs: '@ticks(item()?[\'endDateTime\'])'
                        }
                        Get_Secret_Owner: {
                          runAfter: {
                            Set_variable: [
                              'Succeeded'
                            ]
                          }
                          type: 'Http'
                          inputs: {
                            headers: {
                              Authorization: 'Bearer @{body(\'Parse_JSON_-_Retrieve_token_Info\')?[\'access_token\']}'
                            }
                            method: 'GET'
                            uri: 'https://graph.microsoft.com/v1.0/applications/@{items(\'Foreach_-_apps\')?[\'id\']}/owners'
                          }
                        }
                        In_Case_of_No_Owner: {
                          actions: {
                            Append_to_string_variable_4: {
                              runAfter: {}
                              type: 'AppendToStringVariable'
                              inputs: {
                                name: 'html'
                                value: '<tr><td @{variables(\'styles\').cellStyle}><a href="https://ms.portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Credentials/appId/@{variables(\'appId\')}/isMSAApp/">@{variables(\'appId\')}</a></td><td @{variables(\'styles\').cellStyle}>@{variables(\'displayName\')}</td><td @{variables(\'styles\').cellStyle}>@{items(\'For_each_-_PasswordCred\')?[\'keyId\']}</td><td @{if(less(variables(\'daystilexpiration\'),100),variables(\'styles\').redStyle,if(less(variables(\'daystilexpiration\'),150),variables(\'styles\').yellowStyle,variables(\'styles\').cellStyle))}>@{variables(\'daystilexpiration\')} </td><td @{variables(\'styles\').cellStyle}>Secret</td><td @{variables(\'styles\').cellStyle}>@{formatDateTime(item()?[\'endDateTime\'],\'g\')}</td><td @{variables(\'styles\').cellStyle}>No Owner</td></tr>'
                              }
                            }
                          }
                          runAfter: {
                            Get_Secret_Owner: [
                              'Succeeded'
                            ]
                          }
                          else: {
                            actions: {
                              Append_to_string_variable: {
                                runAfter: {}
                                type: 'AppendToStringVariable'
                                inputs: {
                                  name: 'html'
                                  value: '<tr><td @{variables(\'styles\').cellStyle}><a href="https://ms.portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Credentials/appId/@{variables(\'appId\')}/isMSAApp/">@{variables(\'appId\')}</a></td><td @{variables(\'styles\').cellStyle}>@{variables(\'displayName\')}</td><td @{variables(\'styles\').cellStyle}>@{items(\'For_each_-_PasswordCred\')?[\'keyId\']}</td><td @{if(less(variables(\'daystilexpiration\'),100),variables(\'styles\').redStyle,if(less(variables(\'daystilexpiration\'),150),variables(\'styles\').yellowStyle,variables(\'styles\').cellStyle))}>@{variables(\'daystilexpiration\')} </td><td @{variables(\'styles\').cellStyle}>Secret</td><td @{variables(\'styles\').cellStyle}>@{formatDateTime(item()?[\'endDateTime\'],\'g\')}</td><td @{variables(\'styles\').cellStyle}><a href="mailto:@{body(\'Get_Secret_Owner\')?[\'value\'][0]?[\'userPrincipalName\']}">@{body(\'Get_Secret_Owner\')?[\'value\'][0]?[\'givenName\']} @{body(\'Get_Secret_Owner\')?[\'value\'][0]?[\'surname\']}</a></td></tr>'
                                }
                              }
                              Condition_3: {
                                actions: {
                                  Compose_2: {
                                    runAfter: {}
                                    type: 'Compose'
                                    inputs: 'Hello @{body(\'Get_Secret_Owner\')?[\'value\'][0]?[\'givenName\']},<br/>\nYou are owner of the application <strong>@{items(\'Foreach_-_apps\')?[\'displayName\']}</strong>.<br/>\n\nOne of the secrets of this application is going to expire in @{variables(\'daysTilExpiration\')} days.<br/>\n\nPlease take action to avoid any authentication issues related to the expiration of the secret.<br/><br/>\n\nHere are the details of the secret :<br/>\n<strong>Secret Id :</strong> @{items(\'For_each_-_PasswordCred\')?[\'keyId\']}<br/>\n<strong>Expiration time :</strong> @{formatDateTime(items(\'For_each_-_PasswordCred\')?[\'endDateTime\'],\'g\')}<br/>\n<strong>App Id :</strong> <a href="https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Credentials/appId/@{items(\'Foreach_-_apps\')?[\'appId\']}/isMSAApp/" >@{items(\'Foreach_-_apps\')?[\'appId\']}</a><br/><br/>\n\n\nThank you'
                                  }
                                  'Send_an_email_(V2)_2': {
                                    runAfter: {
                                      Compose_2: [
                                        'Succeeded'
                                      ]
                                    }
                                    type: 'ApiConnection'
                                    inputs: {
                                      body: {
                                        Body: '<p>@{outputs(\'Compose_2\')}</p>'
                                        Importance: 'Normal'
                                        Subject: 'Secrets are going to expire soon | @{items(\'Foreach_-_apps\')?[\'displayName\']}'
                                        To: '@{body(\'Get_Secret_Owner\')?[\'value\'][0]?[\'userPrincipalName\']}'
                                      }
                                      host: {
                                        connection: {
                                          name: '@parameters(\'$connections\')[\'office365\'][\'connectionId\']'
                                        }
                                      }
                                      method: 'post'
                                      path: '/v2/Mail'
                                    }
                                  }
                                }
                                runAfter: {
                                  Append_to_string_variable: [
                                    'Succeeded'
                                  ]
                                }
                                expression: {
                                  and: [
                                    {
                                      less: [
                                        '@variables(\'daysTilExpiration\')'
                                        '@float(\'15\')'
                                      ]
                                    }
                                  ]
                                }
                                type: 'If'
                              }
                            }
                          }
                          expression: {
                            and: [
                              {
                                equals: [
                                  '@length(body(\'Get_Secret_Owner\')?[\'value\'])'
                                  '@int(\'0\')'
                                ]
                              }
                            ]
                          }
                          type: 'If'
                        }
                        Set_variable: {
                          runAfter: {
                            DifferentAsDays: [
                              'Succeeded'
                            ]
                          }
                          type: 'SetVariable'
                          inputs: {
                            name: 'daysTilExpiration'
                            value: '@outputs(\'DifferentAsDays\')'
                          }
                        }
                        StartTimeTickValue: {
                          runAfter: {
                            EndTimeTickValue: [
                              'Succeeded'
                            ]
                          }
                          type: 'Compose'
                          inputs: '@ticks(utcnow())'
                        }
                      }
                      runAfter: {}
                      expression: {
                        and: [
                          {
                            greaterOrEquals: [
                              '@body(\'Get_future_time\')'
                              '@items(\'For_each_-_PasswordCred\')?[\'endDateTime\']'
                            ]
                          }
                        ]
                      }
                      type: 'If'
                    }
                  }
                  runAfter: {
                    'Set_variable_-_keyCredential': [
                      'Succeeded'
                    ]
                  }
                  type: 'Foreach'
                }
                For_each_KeyCred: {
                  foreach: '@items(\'Foreach_-_apps\')?[\'keyCredentials\']'
                  actions: {
                    Condition_2: {
                      actions: {
                        Condition_5: {
                          actions: {
                            Append_Certificate_to_HTML_without_owner: {
                              runAfter: {}
                              type: 'AppendToStringVariable'
                              inputs: {
                                name: 'html'
                                value: '<tr><td @{variables(\'styles\').cellStyle}><a href="https://ms.portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Credentials/appId/@{variables(\'appId\')}/isMSAApp/">@{variables(\'appId\')}</a></td><td @{variables(\'styles\').cellStyle}>@{variables(\'displayName\')}</td><td @{variables(\'styles\').cellStyle}>@{items(\'For_each_KeyCred\')?[\'keyId\']}</td><td @{if(less(variables(\'daystilexpiration\'), 15), variables(\'styles\').redStyle, if(less(variables(\'daystilexpiration\'), 30), variables(\'styles\').yellowStyle, variables(\'styles\').cellStyle))}>@{variables(\'daystilexpiration\')} </td><td @{variables(\'styles\').cellStyle}>Certificate</td><td @{variables(\'styles\').cellStyle}>@{formatDateTime(item()?[\'endDateTime\'], \'g\')}</td><td @{variables(\'styles\').cellStyle}>No Owner</td></tr>'
                              }
                            }
                          }
                          runAfter: {
                            Get_Certificate_Owner: [
                              'Succeeded'
                            ]
                          }
                          else: {
                            actions: {
                              Append_Certificate_to_HTML_with_owner: {
                                runAfter: {}
                                type: 'AppendToStringVariable'
                                inputs: {
                                  name: 'html'
                                  value: '<tr><td @{variables(\'styles\').cellStyle}><a href="https://ms.portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Credentials/appId/@{variables(\'appId\')}/isMSAApp/">@{variables(\'appId\')}</a></td><td @{variables(\'styles\').cellStyle}>@{variables(\'displayName\')}</td><td @{variables(\'styles\').cellStyle}>@{items(\'For_each_KeyCred\')?[\'keyId\']}</td><td @{if(less(variables(\'daystilexpiration\'), 15), variables(\'styles\').redStyle, if(less(variables(\'daystilexpiration\'), 30), variables(\'styles\').yellowStyle, variables(\'styles\').cellStyle))}>@{variables(\'daystilexpiration\')} </td><td @{variables(\'styles\').cellStyle}>Certificate</td><td @{variables(\'styles\').cellStyle}>@{formatDateTime(item()?[\'endDateTime\'], \'g\')}</td><td @{variables(\'styles\').cellStyle}><a href="mailto:@{body(\'Get_Certificate_Owner\')?[\'value\'][0]?[\'userPrincipalName\']}">@{body(\'Get_Certificate_Owner\')?[\'value\'][0]?[\'givenName\']} @{body(\'Get_Certificate_Owner\')?[\'value\'][0]?[\'surname\']}</a></td></tr>'
                                }
                              }
                              Condition_4: {
                                actions: {
                                  'Prepare_HTML_for_owner_-_Certificate': {
                                    runAfter: {}
                                    type: 'Compose'
                                    inputs: 'Hi @{body(\'Get_Certificate_Owner\')?[\'value\'][0]?[\'givenName\']},<br/>\nWe want to update you that, you are owner of the application <strong>@{items(\'Foreach_-_apps\')?[\'displayName\']}</strong><br/>\n\nOne of the secrets of this applicatin is going to expire in @{variables(\'daysTilExpiration\')} days.<br/>\n\nPlease take an action to avoid any authentication issues related to this secret.\n<br/><br/>\nHere are the details of the Certificate :<br/>\n<strong>Certificate Id :</strong> @{items(\'For_each_KeyCred\')?[\'keyId\']}<br/>\n<strong>Expiration time :</strong> @{formatDateTime(items(\'For_each_KeyCred\')?[\'endDateTime\'], \'g\')}<br/>\n<strong>App Id :</strong> <a href="https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Credentials/appId/@{items(\'Foreach_-_apps\')?[\'appId\']}/isMSAApp/>@{items(\'Foreach_-_apps\')?[\'appId\']}</a><br/><br/>\n\n\nThank you'
                                  }
                                  'Send_an_email_(V2)_3': {
                                    runAfter: {
                                      'Prepare_HTML_for_owner_-_Certificate': [
                                        'Succeeded'
                                      ]
                                    }
                                    type: 'ApiConnection'
                                    inputs: {
                                      body: {
                                        Body: '<p>@{outputs(\'Prepare_HTML_for_owner_-_Certificate\')}</p>'
                                        Importance: 'Normal'
                                        Subject: ' secrets are going to expire soon | @{items(\'Foreach_-_apps\')?[\'displayName\']}'
                                        To: '@{body(\'Get_Certificate_Owner\')?[\'value\'][0]?[\'mail\']}'
                                      }
                                      host: {
                                        connection: {
                                          name: '@parameters(\'$connections\')[\'office365\'][\'connectionId\']'
                                        }
                                      }
                                      method: 'post'
                                      path: '/v2/Mail'
                                    }
                                  }
                                }
                                runAfter: {
                                  Append_Certificate_to_HTML_with_owner: [
                                    'Succeeded'
                                  ]
                                }
                                expression: {
                                  and: [
                                    {
                                      less: [
                                        '@variables(\'daysTilExpiration\')'
                                        '@float(\'15\')'
                                      ]
                                    }
                                  ]
                                }
                                type: 'If'
                              }
                            }
                          }
                          expression: {
                            and: [
                              {
                                equals: [
                                  '@length(body(\'Get_Certificate_Owner\')?[\'value\'])'
                                  '@int(\'0\')'
                                ]
                              }
                            ]
                          }
                          type: 'If'
                        }
                        DifferentAsDays2: {
                          runAfter: {
                            StartTimeTickValue2: [
                              'Succeeded'
                            ]
                          }
                          type: 'Compose'
                          inputs: '@div(div(div(mul(sub(outputs(\'EndTimeTickValue2\'),outputs(\'StartTimeTickValue2\')),100),1000000000) , 3600), 24)'
                        }
                        EndTimeTickValue2: {
                          runAfter: {}
                          type: 'Compose'
                          inputs: '@ticks(item()?[\'endDateTime\'])'
                        }
                        Get_Certificate_Owner: {
                          runAfter: {
                            Store_Days_till_expiration: [
                              'Succeeded'
                            ]
                          }
                          type: 'Http'
                          inputs: {
                            headers: {
                              Authorization: 'Bearer @{body(\'Parse_JSON_-_Retrieve_token_Info\')?[\'access_token\']}'
                            }
                            method: 'GET'
                            uri: 'https://graph.microsoft.com/v1.0/applications/@{items(\'Foreach_-_apps\')?[\'id\']}/owners'
                          }
                        }
                        StartTimeTickValue2: {
                          runAfter: {
                            EndTimeTickValue2: [
                              'Succeeded'
                            ]
                          }
                          type: 'Compose'
                          inputs: '@ticks(utcnow())'
                        }
                        Store_Days_till_expiration: {
                          runAfter: {
                            DifferentAsDays2: [
                              'Succeeded'
                            ]
                          }
                          type: 'SetVariable'
                          inputs: {
                            name: 'daysTilExpiration'
                            value: '@outputs(\'DifferentAsDays2\')'
                          }
                        }
                      }
                      runAfter: {}
                      expression: {
                        and: [
                          {
                            greaterOrEquals: [
                              '@body(\'Get_future_time\')'
                              '@items(\'For_each_KeyCred\')?[\'endDateTime\']'
                            ]
                          }
                        ]
                      }
                      type: 'If'
                    }
                  }
                  runAfter: {
                    'For_each_-_PasswordCred': [
                      'Succeeded'
                    ]
                  }
                  type: 'Foreach'
                }
                'Set_variable_-_appId': {
                  runAfter: {}
                  type: 'SetVariable'
                  inputs: {
                    name: 'AppID'
                    value: '@items(\'Foreach_-_apps\')?[\'appId\']'
                  }
                }
                'Set_variable_-_displayName': {
                  runAfter: {
                    'Set_variable_-_appId': [
                      'Succeeded'
                    ]
                  }
                  type: 'SetVariable'
                  inputs: {
                    name: 'displayName'
                    value: '@items(\'Foreach_-_apps\')?[\'displayName\']'
                  }
                }
                'Set_variable_-_keyCredential': {
                  runAfter: {
                    'Set_variable_-_passwordCredential': [
                      'Succeeded'
                    ]
                  }
                  type: 'SetVariable'
                  inputs: {
                    name: 'keyCredential'
                    value: '@items(\'Foreach_-_apps\')?[\'keyCredentials\']'
                  }
                }
                'Set_variable_-_passwordCredential': {
                  runAfter: {
                    'Set_variable_-_displayName': [
                      'Succeeded'
                    ]
                  }
                  type: 'SetVariable'
                  inputs: {
                    name: 'passwordCredential'
                    value: '@items(\'Foreach_-_apps\')?[\'passwordCredentials\']'
                  }
                }
              }
              runAfter: {
                Get_future_time: [
                  'Succeeded'
                ]
              }
              type: 'Foreach'
              runtimeConfiguration: {
                concurrency: {
                  repetitions: 1
                }
              }
            }
            Get_future_time: {
              runAfter: {
                Parse_JSON: [
                  'Succeeded'
                ]
              }
              type: 'Expression'
              kind: 'GetFutureTime'
              inputs: {
                interval: 1
                timeUnit: 'Month'
              }
            }
            'HTTP_-_Get_AzureAD_Applications': {
              runAfter: {}
              type: 'Http'
              inputs: {
                headers: {
                  Authorization: 'Bearer @{body(\'Parse_JSON_-_Retrieve_token_Info\')?[\'access_token\']}'
                }
                method: 'GET'
                uri: '@variables(\'NextLink\')'
              }
            }
            Parse_JSON: {
              runAfter: {
                'HTTP_-_Get_AzureAD_Applications': [
                  'Succeeded'
                ]
              }
              type: 'ParseJson'
              inputs: {
                content: '@body(\'HTTP_-_Get_AzureAD_Applications\')'
                schema: {
                  properties: {
                    properties: {
                      properties: {
                        '@@odata.context': {
                          properties: {
                            type: {
                              type: 'string'
                            }
                          }
                          type: 'object'
                        }
                        value: {
                          properties: {
                            items: {
                              properties: {
                                properties: {
                                  properties: {
                                    '@@odata.id': {
                                      properties: {
                                        type: {
                                          type: 'string'
                                        }
                                      }
                                      type: 'object'
                                    }
                                    appId: {
                                      properties: {
                                        type: {
                                          type: 'string'
                                        }
                                      }
                                      type: 'object'
                                    }
                                    displayName: {
                                      properties: {
                                        type: {
                                          type: 'string'
                                        }
                                      }
                                      type: 'object'
                                    }
                                    keyCredentials: {
                                      properties: {
                                        type: {
                                          type: 'string'
                                        }
                                      }
                                      type: 'object'
                                    }
                                    passwordCredentials: {
                                      properties: {
                                        items: {
                                          properties: {
                                            properties: {
                                              properties: {
                                                customKeyIdentifier: {
                                                  properties: {}
                                                  type: 'object'
                                                }
                                                displayName: {
                                                  properties: {
                                                    type: {
                                                      type: 'string'
                                                    }
                                                  }
                                                  type: 'object'
                                                }
                                                endDateTime: {
                                                  properties: {
                                                    type: {
                                                      type: 'string'
                                                    }
                                                  }
                                                  type: 'object'
                                                }
                                                hint: {
                                                  properties: {
                                                    type: {
                                                      type: 'string'
                                                    }
                                                  }
                                                  type: 'object'
                                                }
                                                keyId: {
                                                  properties: {
                                                    type: {
                                                      type: 'string'
                                                    }
                                                  }
                                                  type: 'object'
                                                }
                                                secretText: {
                                                  properties: {}
                                                  type: 'object'
                                                }
                                                startDateTime: {
                                                  properties: {
                                                    type: {
                                                      type: 'string'
                                                    }
                                                  }
                                                  type: 'object'
                                                }
                                              }
                                              type: 'object'
                                            }
                                            required: {
                                              items: {
                                                type: 'string'
                                              }
                                              type: 'array'
                                            }
                                            type: {
                                              type: 'string'
                                            }
                                          }
                                          type: 'object'
                                        }
                                        type: {
                                          type: 'string'
                                        }
                                      }
                                      type: 'object'
                                    }
                                  }
                                  type: 'object'
                                }
                                required: {
                                  items: {
                                    type: 'string'
                                  }
                                  type: 'array'
                                }
                                type: {
                                  type: 'string'
                                }
                              }
                              type: 'object'
                            }
                            type: {
                              type: 'string'
                            }
                          }
                          type: 'object'
                        }
                      }
                      type: 'object'
                    }
                    type: {
                      type: 'string'
                    }
                  }
                  type: 'object'
                }
              }
            }
            Update_Next_Link: {
              runAfter: {
                'Foreach_-_apps': [
                  'Succeeded'
                ]
              }
              type: 'SetVariable'
              inputs: {
                name: 'NextLink'
                value: '@{body(\'Parse_JSON\')?[\'@odata.nextLink\']}'
              }
            }
          }
          runAfter: {
            'Initialize_-_NextLink': [
              'Succeeded'
            ]
          }
          expression: '@not(equals(variables(\'NextLink\'), null))'
          limit: {
            count: 60
            timeout: 'PT1H'
          }
          type: 'Until'
        }
      }
      outputs: {}
    }
    parameters: {
      '$connections': {
        value: {
          keyvault: {
            connectionId: connections_keyvault_name_resource.id
            connectionName: 'keyvault'
            id: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Web/locations/eastus/managedApis/keyvault'
          }
          office365: {
            connectionId: connections_office365_name_resource.id
            connectionName: 'office365'
            id: '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Web/locations/eastus/managedApis/office365'
          }
        }
      }
    }
  }
}

@description('The resource group the availability set was deployed into')
output resourceGroupName string = resourceGroup().name

@description('The subscription that the resources were deployed into')
output subscriptionId string = subscription().subscriptionId
