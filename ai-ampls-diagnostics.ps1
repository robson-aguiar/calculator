<#
    ai-ampls-diagnostics.ps1

    Consolidated diagnostics for Azure Application Insights connectivity via AMPLS/Private Link,
    WebApp VNet integration, BYOS storage linkage, and CMK permissions in Key Vault.

    Notes:
    - Requires Az PowerShell modules and an authenticated context (Connect-AzAccount) with access to resources.
    - Cross-platform: DNS checks attempt Resolve-DnsName and fallback to nslookup/dig if unavailable.
    - Port reachability check uses a TCP client (works on Windows/Linux/macOS).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$AppInsightsName,

    [Parameter(Mandatory = $true)]
    [string]$WebAppName = "ptdes-pre-webapp-01",

    [Parameter(Mandatory = $true)]
    [string]$BYOSStorageAccountName,

    [Parameter(Mandatory = $true)]
    [string]$KeyVaultName,

    [Parameter(Mandatory = $true)]
    [string]$CMKKeyName = "storage-cmk-key",

    [Parameter(Mandatory = $true)]
    [string]$AMPLSResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$AMPLSName
)

function Write-Section {
    param([string]$Text)
    Write-Host ("`n--- {0} ---" -f $Text)
}

function Normalize-Endpoint {
    param([string]$Url)
    if (-not $Url) { return $null }
    try {
        $uri = [System.Uri]::new($Url)
        return ($uri.Scheme + "://" + $uri.Host).TrimEnd('/').ToLowerInvariant()
    } catch {
        return $Url.TrimEnd('/').ToLowerInvariant()
    }
}

function Resolve-Hostname {
    param([Parameter(Mandatory=$true)][string]$Hostname)
    $results = @()
    $hasResolve = Get-Command Resolve-DnsName -ErrorAction SilentlyContinue
    if ($hasResolve) {
        try {
            $dns = Resolve-DnsName -Name $Hostname -ErrorAction Stop
            $results = $dns | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -Unique
        } catch { }
    }
    if (-not $results -or $results.Count -eq 0) {
        $nslookup = Get-Command nslookup -ErrorAction SilentlyContinue
        if ($nslookup) {
            try {
                $out = & $nslookup $Hostname 2>$null
                $ips = ($out | Select-String -Pattern "Address:\s*(?<ip>\d+\.\d+\.\d+\.\d+)").Matches | ForEach-Object { $_.Groups['ip'].Value }
                if ($ips) { $results = $ips | Select-Object -Unique }
            } catch { }
        }
    }
    if (-not $results -or $results.Count -eq 0) {
        $dig = Get-Command dig -ErrorAction SilentlyContinue
        if ($dig) {
            try {
                $out = & $dig +short $Hostname 2>$null
                $ips = $out | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" }
                if ($ips) { $results = $ips | Select-Object -Unique }
            } catch { }
        }
    }
    return $results
}

function Test-TcpPortOpen {
    param(
        [Parameter(Mandatory=$true)][string]$Hostname,
        [int]$Port = 443,
        [int]$TimeoutMs = 5000
    )
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $async = $client.BeginConnect($Hostname, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $client.Close()
            return $false
        }
        $client.EndConnect($async)
        $client.Close()
        return $true
    } catch {
        return $false
    }
}

Write-Host "Iniciando o diagnóstico de conectividade do Application Insights com Private Link..."

# 0. Contexto de Assinatura
try {
    $ctx = Get-AzContext -ErrorAction Stop
    Write-Host ("Contexto atual: SubscriptionId={0}, TenantId={1}" -f $ctx.Subscription.Id, $ctx.Tenant.Id)
} catch {
    Write-Warning "Nenhum contexto do Az encontrado. Execute Connect-AzAccount antes de rodar este script."
}

# 1. Detalhes do Application Insights
Write-Section "Obtendo detalhes do Application Insights"
try {
    $appInsights = Get-AzApplicationInsights -ResourceGroupName $ResourceGroupName -Name $AppInsightsName -ErrorAction Stop
    Write-Host ("Application Insights encontrado: {0}" -f $appInsights.Name)
    Write-Host ("  Instrumentation Key: {0}" -f $appInsights.InstrumentationKey)
    Write-Host ("  Connection String: {0}" -f $appInsights.ConnectionString)

    $ingestionEndpoint = $null
    $liveMetricsEndpoint = $null
    if ($appInsights.ConnectionString) {
        $ingestionMatch = [regex]::Match($appInsights.ConnectionString, 'IngestionEndpoint=([^;]+)', 'IgnoreCase')
        if ($ingestionMatch.Success) { $ingestionEndpoint = $ingestionMatch.Groups[1].Value }
        $liveMatch = [regex]::Match($appInsights.ConnectionString, 'LiveEndpoint=([^;]+)', 'IgnoreCase')
        if ($liveMatch.Success) { $liveMetricsEndpoint = $liveMatch.Groups[1].Value }
    }
    Write-Host ("  Ingestion Endpoint: {0}" -f $ingestionEndpoint)
    Write-Host ("  Live Endpoint: {0}" -f $liveMetricsEndpoint)
    Write-Host ("  Public Network Access for Ingestion: {0}" -f $appInsights.PublicNetworkAccessForIngestion)
    Write-Host ("  Public Network Access for Query: {0}" -f $appInsights.PublicNetworkAccessForQuery)
} catch {
    Write-Error ("Erro ao obter detalhes do Application Insights: {0}" -f $_.Exception.Message)
    exit 1
}

# 2. Verificação de DNS e Conectividade (simulada fora da VNet)
Write-Section "Verificando Resolução de DNS e Conectividade"
Write-Host "Esta etapa usa DNS público apenas como referência. Para validação final, execute nslookup/dig dentro da VNet do WebApp."
try {
    $ingestionHostname = $null
    if ($ingestionEndpoint) {
        try { $ingestionHostname = ([System.Uri]$ingestionEndpoint).Host } catch { $ingestionHostname = ($ingestionEndpoint -replace 'https://','' -replace '/','') }
    }
    Write-Host ("  Hostname de Ingestão: {0}" -f $ingestionHostname)

    if ($ingestionHostname) {
        Write-Host ("  Tentando resolver DNS publicamente para {0}..." -f $ingestionHostname)
        $publicIps = Resolve-Hostname -Hostname $ingestionHostname
        if ($publicIps -and $publicIps.Count -gt 0) {
            Write-Host ("  IPs Públicos Resolvidos: {0}" -f ($publicIps -join ', '))
        } else {
            Write-Warning ("  Não foi possível resolver {0} publicamente." -f $ingestionHostname)
        }

        $tcpOk = Test-TcpPortOpen -Hostname $ingestionHostname -Port 443 -TimeoutMs 5000
        Write-Host ("  Teste de porta TCP 443 (saída pública): {0}" -f ($(if ($tcpOk) { 'OK' } else { 'FALHA' })))
    }

    Write-Host ("  Para validar a resolução de DNS PRIVADA, execute 'nslookup {0}' ou 'dig {0}' de dentro da VNet do WebApp." -f $ingestionHostname)
    if ($appInsights.PublicNetworkAccessForIngestion -eq 'Disabled') {
        Write-Host "  Como PublicNetworkAccessForIngestion está 'Disabled', a resolução dentro da VNet deve retornar IP privado."
    }
} catch {
    Write-Error ("Erro na verificação de DNS/Conectividade: {0}" -f $_.Exception.Message)
}

# 3. Verificação de vínculo AMPLS (Private Link Scope)
Write-Section "Verificando vínculo do Application Insights ao AMPLS"
try {
    $ampls = Get-AzResource -ResourceGroupName $AMPLSResourceGroupName -ResourceType "microsoft.insights/privateLinkScopes" -Name $AMPLSName -ErrorAction Stop
    $scopedResources = $null
    try {
        $scopedResources = Get-AzResource -ResourceId ("{0}/scopedResources" -f $ampls.ResourceId) -ErrorAction Stop
    } catch {
        $scopedResources = @()
    }

    $isLinkedToAmpls = $false
    if ($scopedResources) {
        foreach ($sr in $scopedResources) {
            $linkedId = $sr.Properties.linkedResourceId
            if ($linkedId -and ($linkedId.Trim().ToLowerInvariant() -eq $appInsights.Id.Trim().ToLowerInvariant())) { $isLinkedToAmpls = $true; break }
        }
    }

    if ($isLinkedToAmpls) {
        Write-Host ("  Application Insights '{0}' está vinculado ao AMPLS '{1}'." -f $AppInsightsName, $AMPLSName)
        Write-Host "  O tráfego de ingestão DEVE fluir via Private Link quando origina da VNet vinculada."
    } else {
        Write-Warning ("  Application Insights '{0}' NÃO está vinculado ao AMPLS '{1}'. Verifique a configuração deScoped Resources." -f $AppInsightsName, $AMPLSName)
    }
} catch {
    Write-Error ("Erro ao consultar AMPLS: {0}" -f $_.Exception.Message)
}

# 4. Verificação da Integração da VNet do WebApp
Write-Section "Verificando Integração da VNet do WebApp"
try {
    $webApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $WebAppName -ErrorAction Stop
    Write-Host ("WebApp encontrado: {0}" -f $webApp.Name)
    try {
        $vnetIntegration = Get-AzWebAppVnetConnection -ResourceGroupName $ResourceGroupName -Name $WebAppName -ErrorAction Stop
    } catch {
        $vnetIntegration = $null
    }
    if ($vnetIntegration) {
        Write-Host ("  Integração de VNet: {0} / Sub-rede: {1}" -f $vnetIntegration.VnetName, $vnetIntegration.SubnetName)
        Write-Host "  Garanta que essa VNet tenha alcance ao Private Endpoint do AMPLS (mesma VNet ou via peering)."
    } else {
        Write-Warning ("  WebApp '{0}' NÃO está integrado a uma VNet. Isso é CRÍTICO para Private Link." -f $WebAppName)
    }
} catch {
    Write-Error ("Erro ao verificar integração da VNet do WebApp: {0}" -f $_.Exception.Message)
}

# 5. Verificação da Configuração do Storage BYOS e CMK
Write-Section "Verificando Configuração do Storage BYOS e CMK"
try {
    $byosStorage = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $BYOSStorageAccountName -ErrorAction Stop
    Write-Host ("Conta de Armazenamento BYOS encontrada: {0}" -f $byosStorage.Name)

    # Vinculação do BYOS ao Application Insights
    try {
        $linkedStorages = Get-AzApplicationInsights -ResourceGroupName $ResourceGroupName -Name $AppInsightsName -ErrorAction Stop | Get-AzApplicationInsightsLinkedStorageAccount -ErrorAction Stop
    } catch { $linkedStorages = @() }

    $isByosLinked = $false
    foreach ($ls in $linkedStorages) {
        if ($ls.LinkedStorageAccountResourceId -and ($ls.LinkedStorageAccountResourceId.Trim().ToLowerInvariant() -eq $byosStorage.Id.Trim().ToLowerInvariant())) {
            $isByosLinked = $true; break
        }
    }
    if ($isByosLinked) {
        Write-Host "  Status Vinculação AI-BYOS: OK - Conta BYOS vinculada ao Application Insights."
    } else {
        Write-Warning ("  Status Vinculação AI-BYOS: ALERTA - Conta BYOS NÃO vinculada ao Application Insights '{0}'." -f $AppInsightsName)
    }

    # Permissões da Managed Identity do AI na conta BYOS
    Write-Host "  Verificando permissões da Managed Identity do Application Insights na conta BYOS..."
    $appInsightsManagedIdentity = $appInsights.Identity.PrincipalId
    if ($appInsightsManagedIdentity) {
        $roleAssignments = Get-AzRoleAssignment -ObjectId $appInsightsManagedIdentity -Scope $byosStorage.Id -ErrorAction SilentlyContinue
        $hasBlobDataContributor = $false
        if ($roleAssignments) {
            $hasBlobDataContributor = $roleAssignments | Where-Object { $_.RoleDefinitionName -eq "Storage Blob Data Contributor" }
        }
        if ($hasBlobDataContributor) {
            Write-Host "  Status Permissão BYOS: OK - Managed Identity do AI tem 'Storage Blob Data Contributor'."
        } else {
            Write-Warning "  Status Permissão BYOS: ALERTA - Managed Identity do AI NÃO tem 'Storage Blob Data Contributor' na conta BYOS. Necessário para Profiler/Debugger."
        }
    } else {
        Write-Warning "  Application Insights não tem Managed Identity atribuída. Isso pode impedir acesso ao BYOS."
    }

    # CMK na conta de armazenamento
    Write-Host "  Verificando configuração de CMK na conta BYOS..."
    $keySource = $byosStorage.Encryption.KeySource
    if ($keySource -and ($keySource.ToString() -ieq "Microsoft.Keyvault")) {
        Write-Host "  CMK habilitado para a conta de armazenamento BYOS."
        $keyUri = $byosStorage.Encryption.KeyVaultProperties.KeyUri
        if ($keyUri) { Write-Host ("  URI da Chave CMK: {0}" -f $keyUri) }

        $storageAccountCMKIdentity = $byosStorage.Identity.PrincipalId
        if ($storageAccountCMKIdentity) {
            $keyVault = $null
            try { $keyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -ErrorAction Stop } catch { }
            if ($keyVault) {
                # Access Policies (modo legado)
                $storageIdentityPolicy = $null
                try {
                    $policies = Get-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ErrorAction Stop
                    $storageIdentityPolicy = $policies | Where-Object { $_.ObjectId -eq $storageAccountCMKIdentity }
                } catch { }

                $hasRequiredApPermissions = $false
                if ($storageIdentityPolicy) {
                    $permissionsToKeys = $storageIdentityPolicy.PermissionsToKeys
                    if (-not $permissionsToKeys) { $permissionsToKeys = $storageIdentityPolicy.Permissions.Keys }
                    $required = @('Get','WrapKey','UnwrapKey')
                    if ($permissionsToKeys) {
                        $missing = $required | Where-Object { ($permissionsToKeys -notcontains $_) }
                        if (-not $missing -or $missing.Count -eq 0) { $hasRequiredApPermissions = $true }
                    }
                }

                if ($hasRequiredApPermissions) {
                    Write-Host "  Status Permissões Key Vault (Access Policy): OK - Get, WrapKey, UnwrapKey presentes."
                } else {
                    Write-Warning "  Status Permissões Key Vault (Access Policy): insuficientes ou inexistentes para a identidade da conta de armazenamento."
                }

                # RBAC (Azure Roles) no Key Vault
                $kvRoleAssignments = Get-AzRoleAssignment -Scope $keyVault.ResourceId -ObjectId $storageAccountCMKIdentity -ErrorAction SilentlyContinue
                if ($kvRoleAssignments -and $kvRoleAssignments.Count -gt 0) {
                    $roleNames = $kvRoleAssignments | Select-Object -ExpandProperty RoleDefinitionName -Unique
                    Write-Host ("  RBAC no Key Vault para identidade do Storage: {0}" -f ($roleNames -join ', '))
                    $hasCryptoRole = $roleNames | Where-Object { $_ -match 'Key Vault Crypto (User|Officer)' }
                    if ($hasCryptoRole) {
                        Write-Host "  RBAC indica permissões de criptografia potencialmente suficientes (wrap/unwrap)."
                    } else {
                        Write-Warning "  RBAC encontrado, mas não detectado papel 'Key Vault Crypto User/Officer'. Verifique se wrap/unwrap está permitido."
                    }
                } else {
                    Write-Host "  Nenhum RBAC encontrado no Key Vault para a identidade da conta de armazenamento."
                }
            } else {
                Write-Warning ("  Key Vault '{0}' não encontrado no grupo '{1}'." -f $KeyVaultName, $ResourceGroupName)
            }
        } else {
            Write-Warning "  Conta de armazenamento BYOS não tem Managed Identity atribuída. CMK pode não funcionar."
        }
    } else {
        Write-Warning ("  CMK NÃO habilitado para a conta de armazenamento BYOS. Fonte da chave: {0}" -f $keySource)
    }
} catch {
    Write-Error ("Erro ao verificar Storage BYOS e CMK: {0}" -f $_.Exception.Message)
}

# 6. Verificação de Configurações do WebApp para Application Insights
Write-Section "Verificando Configurações do WebApp para Application Insights"
try {
    $webAppConfig = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $WebAppName -ErrorAction Stop
    $appSettings = $null
    if ($webAppConfig.SiteConfig -and $webAppConfig.SiteConfig.AppSettings) {
        $appSettings = $webAppConfig.SiteConfig.AppSettings
    }
    if (-not $appSettings) {
        # Fallback robusto via Invoke-AzResourceAction
        try {
            $resp = Invoke-AzResourceAction -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.Web/sites/config" -ResourceName ("{0}/{1}" -f $WebAppName,'appsettings') -Action list -Force -ErrorAction Stop
            if ($resp.Properties) {
                $appSettings = @()
                foreach ($k in $resp.Properties.Keys) {
                    $appSettings += [pscustomobject]@{ Name = $k; Value = $resp.Properties[$k] }
                }
            }
        } catch {
            Write-Warning "  Não foi possível obter App Settings via API de fallback."
        }
    }

    function Get-AppSettingValue {
        param([string]$Name)
        if (-not $appSettings) { return $null }
        $item = $appSettings | Where-Object { $_.Name -eq $Name }
        if ($item) { return $item.Value }
        # Tentativa case-insensitive
        $item = $appSettings | Where-Object { $_.Name -ieq $Name }
        if ($item) { return $item.Value }
        return $null
    }

    $profilerVersion = Get-AppSettingValue -Name "APPINSIGHTS_PROFILERFEATURE_VERSION"
    $snapshotVersion = Get-AppSettingValue -Name "APPINSIGHTS_SNAPSHOTFEATURE_VERSION"
    $webAppConnStr = Get-AppSettingValue -Name "APPLICATIONINSIGHTS_CONNECTION_STRING"

    Write-Host ("  APPINSIGHTS_PROFILERFEATURE_VERSION: {0}" -f $profilerVersion)
    Write-Host ("  APPINSIGHTS_SNAPSHOTFEATURE_VERSION: {0}" -f $snapshotVersion)
    Write-Host ("  APPLICATIONINSIGHTS_CONNECTION_STRING: {0}" -f $webAppConnStr)

    $normalizedIngestion = Normalize-Endpoint -Url $ingestionEndpoint
    $normalizedInConnStr = $null
    if ($webAppConnStr) {
        $ingestionInConnMatch = [regex]::Match($webAppConnStr, 'IngestionEndpoint=([^;]+)', 'IgnoreCase')
        if ($ingestionInConnMatch.Success) { $normalizedInConnStr = Normalize-Endpoint -Url $ingestionInConnMatch.Groups[1].Value }
    }

    if ($normalizedIngestion -and $normalizedInConnStr -and ($normalizedIngestion -ne $normalizedInConnStr)) {
        Write-Warning ("  A Connection String do WebApp aponta para '{0}', mas o AI aponta para '{1}'." -f $normalizedInConnStr, $normalizedIngestion)
    }

    Write-Host "  Para validar o acesso ao Private Endpoint do AMPLS, confira NSGs/UDRs e firewalls na sub-rede integrada do WebApp."
} catch {
    Write-Error ("Erro ao verificar configurações do WebApp: {0}" -f $_.Exception.Message)
}

Write-Host "`nDiagnóstico concluído. Revise as mensagens acima para identificar possíveis problemas."
Write-Host "Lembre-se: a validação de DNS/Conectividade definitiva deve ser feita de DENTRO da VNet do WebApp."

