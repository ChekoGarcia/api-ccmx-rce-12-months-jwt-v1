# ============================================================================
# HERRAMIENTA DE REFACTORIZACION AUTOMATIZADA PARA PROXIES APIGEE
# ============================================================================
# Autor: Asistente AI
# Fecha: $(Get-Date -Format 'yyyy-MM-dd')
# Descripcion: Refactoriza proxies Apigee aplicando estandares de nomenclatura
# ============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$ProxyPath = ".",
    [Parameter(Mandatory=$false)]
    [switch]$DryRun = $false,
    [Parameter(Mandatory=$false)]
    [switch]$VerboseOutput = $false,
    [Parameter(Mandatory=$false)]
    [string]$CustomMappingFile = "policy-mapping.csv"
)

# Configuracion global
$Global:LogFile = "refactor-log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$Global:BackupFolder = "backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$Global:ConflictsLog = "conflicts-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$Global:ChangesLog = "changes-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$Global:NewMappingsLog = "new-mappings-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$Global:UnmappedPoliciesLog = "unmapped-policies-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

# Tabla de prefijos para politicas (del JSON proporcionado)
$Global:PolicyPrefixes = @{
    'AccessControl' = 'AC'
    'AccessEntity' = 'AE'
    'AssignMessage' = 'AM'
    'BasicAuthentication' = 'BA'
    'ConcurrentRateLimit' = 'CCR'
    'ConnectorCallout' = 'CC'
    'DecodeJWS' = 'JWS'
    'DecodeJWT' = 'JWT'
    'ExtractVariables' = 'EV'
    'FlowCallout' = 'FC'
    'GenerateJWS' = 'JWS'
    'GenerateJWT' = 'JWT'
    'GenerateSAMLAssertion' = 'SAML'
    'HMAC' = 'HMAC'
    'InvalidateCache' = 'IC'
    'JavaCallout' = 'Java'
    'Javascript' = 'JS'
    'JSONThreatProtection' = 'JTP'
    'JSONToXML' = 'J2X'
    'KeyValueMapOperations' = 'KVM'
    'Ldap' = 'LDAP'
    'LookupCache' = 'LC'
    'MessageLogging' = 'ML'
    'MessageValidation' = 'MV'
    'MonetizationLimitsCheck' = 'MC'
    'OASValidation' = 'OAS'
    'OAuthV1' = 'OAuth'
    'OAuthV2' = 'OAuth'
    'PopulateCache' = 'PC'
    'Quota' = 'Q'
    'RaiseFault' = 'RF'
    'RegularExpressionProtection' = 'RE'
    'ResetQuota' = 'RQ'
    'ResponseCache' = 'RC'
    'RevokeOAuthV2' = 'OAuth'
    'Script' = 'Script'
    'ServiceCallout' = 'SC'
    'SpikeArrest' = 'SA'
    'StatisticsCollector' = 'Stats'
    'ValidateSAMLAssertion' = 'SAML'
    'VerifyAPIKey' = 'VA'
    'VerifyJWS' = 'JWS'
    'VerifyJWT' = 'JWT'
    'XMLThreatProtection' = 'XTP'
    'XMLToJSON' = 'X2J'
    'XSL' = 'XSL'
    'DeleteOAuthV1Info' = 'OAuth'
    'DeleteOAuthV2Info' = 'OAuth'
    'GetOAuthV1Info' = 'OAuth'
    'GetOAuthV2Info' = 'OAuth'
    'SetOAuthV2Info' = 'OAuth'
}

# Tabla de homologación específica COMPLETA (del JSON proporcionado)
$Global:HomologationTable = @{
    'AM-AddCORS' = 'AM-Add-CORS'
    'OPTIONS-CORS-Headers-Response' = 'RF-Stop-Options-Pre-Flight-Requests'
    'ACL' = 'FC-Validate-Origin-IP'
    'JS-Get-Data' = 'JS-Preserve-Original-Request-Data'
    'FC-HeadersMtls' = 'FC-Set-Backend-Authorization-Headers'
    'KVM-TERMINOS' = 'KVM-Terms'
    'AccessControlDeveloperProducts' = 'FC-Validate-API-Access'
    'Get-Developer-Data' = 'JS-Get-Developer-Data'
    'Developer-Quotas' = 'FC-Validate-Consumption'
    'SA-PeticionesSegundo' = 'SA-Limit-Requests-Per-Second'
    'JS-FormatError' = 'JS-Format-OAS-Validation-Error'
    'KVM-JWT-LOGINKVM-JWT-Login' = 'KVM-Get-JWT-Secret-Key'
    'Decode-JWT-1' = 'JWT-Decode-Authorization-Header'
    'JS-ValidateRequest' = 'JS-Validate-Request'
    'emitElapsed' = 'JS-Compute-Elapsed-Time-Values'
    'AM-signature' = 'AM-Set-Variables-To-Sign-Response'
    'Signaturing' = 'FC-Sign-Response'
    'AM-Singnature-response' = 'AM-Set-Response-Signature-Header'
    'EVS-stadistic-response' = 'EV-Response-Timing-Metric'
    'EVS-stadistic-request' = 'EV-Request-Timing-Metrics'
    'Statistics-Collector' = 'Stats-Collect-Timing-Metrics'
    'JS-Variables-Bitacora' = 'JS-Set-Data-For-Billing-Record'
    'RemoveHeaders' = 'FC-Remove-Headers'
    'JSON-validation' = 'MV-Validate-Json-Wellformed'
    'ValidateJsonRequest' = 'JTP-Validate-Json-Payload-Structure'
    'REP-HEADERS' = 'RE-Protect-From-Injections'
    'JS-REP-ERR' = 'JS-Report-Error'
    'KVM-Keycloak' = 'KVM-Get-Keycloak-Settings'
    'keycloak-cache' = 'FC-Process-OAuth-Token'
    'AM-elapse-kc' = 'AM-Set-Time-Keycloak-Elapsed-Header'
    'JS-ExtractOtorgante' = 'JS-Extract-Grantor'
    'AM-verifying' = 'AM-Set-Variables-To-Validate-Request-Signature'
    'Verifying-signature' = 'FC-Verify-Signature'
    'RemoveAcents' = 'JS-Remove-Accents'
    'AM-request-post' = 'AM-Set-Request'
    'Null-request-param' = 'JS-Set-Request-Param-To-Null'
    'AM-DefaultError' = 'AM-Default-Error'
    'AM-DELETE-PATHSUFGFIX' = 'AM-Remove-Path-Suffix'
    'ContentType' = 'JS-Validate-Content-Type'
    'HeadersMtls' = 'FC-Set-MTLS-Headers'
    'JS-REP-Error' = 'JS-Handle-Error-Response'
    'JS-ValidNewHeader' = 'JS-Valid-New-Header'
    'KVM-RCE-12-MESES' = 'KVM-Get-Quota-And-Billing-Data'
    'Null-response-params' = 'JS-Set-Response-Params-To-Null'
    'OAS-RCE-12-MESES-Validation' = 'OAS-Validate-Quota-Contract'
    'RefactorResponse' = 'JS-Format-Response'
    'Verify-JWT-1' = 'JWT-Verify-Authorization-Header'
    'BIC' = 'FC-BIC'
    'JSON-Threat-Protection' = 'JTP-JSON-Threat-Protection'
}

# Hashtable para mapeos personalizados
$Global:CustomPolicyMapping = @{}

# ============================================================================
# FUNCIONES DE UTILIDAD
# ============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $Global:LogFile -Value $logEntry
    if ($Global:VerboseOutput -or $Level -eq "ERROR" -or $Level -eq "WARNING") {
        Write-Host $logEntry -ForegroundColor $(if($Level -eq "ERROR"){"Red"} elseif($Level -eq "WARNING"){"Yellow"} else {"White"})
    }
}

function Write-ConflictLog {
    param([string]$Message)
    Add-Content -Path $Global:ConflictsLog -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
}

function Write-ChangeLog {
    param([string]$OldName, [string]$NewName, [string]$Type, [string]$File)
    $changeEntry = "$Type|$File|$OldName|$NewName"
    Add-Content -Path $Global:ChangesLog -Value $changeEntry
}

function Write-NewMappingLog {
    param([string]$OldName, [string]$NewName, [string]$PolicyType)
    $mappingEntry = "$OldName,$NewName,$PolicyType"
    Add-Content -Path $Global:NewMappingsLog -Value $mappingEntry
}

function Write-UnmappedPolicyLog {
    param([string]$PolicyName, [string]$PolicyType)
    
    # Registrar en el log de políticas no mapeadas
    $unmappedEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $PolicyName (Tipo: $PolicyType)"
    Add-Content -Path $Global:UnmappedPoliciesLog -Value $unmappedEntry
    
    # Generar un nombre sugerido automáticamente
    $suggestedName = Generate-SuggestedPolicyName -PolicyName $PolicyName -PolicyType $PolicyType
    
    # Agregar automáticamente al mapeo de nuevos nombres
    Write-NewMappingLog -OldName $PolicyName -NewName $suggestedName -PolicyType $PolicyType
    
    # Agregar al mapeo personalizado para uso inmediato en esta ejecución
    $Global:CustomPolicyMapping[$PolicyName] = @{
        NewName = $suggestedName
        PolicyType = $PolicyType
    }
    
    Write-Log "Política automáticamente mapeada: $PolicyName -> $suggestedName (Tipo: $PolicyType)" "INFO"
}

function Generate-SuggestedPolicyName {
    param([string]$PolicyName, [string]$PolicyType)
    
    # Intentar generar un prefijo basado en el tipo de política
    $prefix = "UNKNOWN"
    
    # Mapeo de tipos comunes a prefijos sugeridos
    $typeToPrefix = @{
        'XMLThreatProtection' = 'XTP'
        'RegularExpressionProtection' = 'REP'
        'MessageLogging' = 'ML'
        'ServiceCallout' = 'SC'
        'RaiseFault' = 'RF'
        'Script' = 'JS'
        'Policy' = 'POL'
        'Callout' = 'CO'
        'Transform' = 'TR'
        'Validation' = 'VAL'
        'Security' = 'SEC'
        'Cache' = 'CACHE'
        'Quota' = 'QUOTA'
        'Spike' = 'SA'
        'Statistics' = 'STATS'
        'OASValidation' = 'OAS'
        'FlowCallout' = 'FC'
        'ExtractVariables' = 'EV'
    }
    
    # Buscar un prefijo conocido
    foreach ($type in $typeToPrefix.Keys) {
        if ($PolicyType -like "*$type*") {
            $prefix = $typeToPrefix[$type]
            break
        }
    }
    
    # Si no se encuentra un prefijo conocido, usar las primeras letras del tipo
    if ($prefix -eq "UNKNOWN" -and $PolicyType.Length -gt 0) {
        # Tomar las primeras 2-3 letras mayúsculas del tipo
        $upperChars = $PolicyType -replace '[a-z]', ''
        if ($upperChars.Length -gt 0) {
            $prefix = $upperChars.Substring(0, [Math]::Min(3, $upperChars.Length))
        } else {
            $prefix = $PolicyType.Substring(0, [Math]::Min(3, $PolicyType.Length)).ToUpper()
        }
    }
    
    # Extraer la parte descriptiva del nombre actual
    $descriptivePart = $PolicyName
    
    # Si el nombre ya tiene un prefijo conocido, extraer solo la parte descriptiva
    foreach ($knownPrefix in $Global:PolicyPrefixes.Values) {
        if ($PolicyName.StartsWith($knownPrefix + "-")) {
            $descriptivePart = $PolicyName.Substring($knownPrefix.Length + 1)
            break
        } elseif ($PolicyName.StartsWith($knownPrefix)) {
            $descriptivePart = $PolicyName.Substring($knownPrefix.Length)
            break
        }
    }
    
    # Convertir la parte descriptiva a Upper-Kebab-Case
    $upperKebabDescriptive = Convert-ToUpperKebabCase -InputString $descriptivePart
    
    # Construir el nombre sugerido
    if ($upperKebabDescriptive -and $upperKebabDescriptive -ne "") {
        if ($upperKebabDescriptive.StartsWith("-")) {
            return "$prefix$upperKebabDescriptive"
        } else {
            return "$prefix-$upperKebabDescriptive"
        }
    } else {
        return "$prefix-Unknown"
    }
}

function Convert-ToUpperKebabCase {
    param([string]$InputString)
    
    if ([string]::IsNullOrEmpty($InputString)) {
        return $InputString
    }
    
    # Si ya está en formato correcto, devolverlo tal como está
    if ($InputString -match '^[A-Z][a-z0-9]*(-[A-Z][a-z0-9\.]*)*$') {
        return $InputString
    }
    
    # Limpiar y normalizar la cadena
    $cleaned = $InputString -replace '[^a-zA-Z0-9\s_.-]', ' '
    $cleaned = $cleaned -replace '[\s_-]+', ' '
    $cleaned = $cleaned.Trim()
    
    if ([string]::IsNullOrWhiteSpace($cleaned)) {
        return ""
    }
    
    # Dividir en palabras completas (NO caracteres individuales)
    $words = $cleaned -split '\s+' | Where-Object { $_.Length -gt 0 }
    
    # Formatear cada palabra completa
    $formattedWords = $words | ForEach-Object {
        if ($_.Length -gt 0) {
            $_.Substring(0,1).ToUpper() + $_.Substring(1).ToLower()
        }
    }
    
    return ($formattedWords -join '-')
}

function Convert-ToSnakeCase {
    param([string]$InputString)
    
    if ([string]::IsNullOrEmpty($InputString)) {
        return $InputString
    }
    
    # Si ya está en formato kebab-case (JS-Set-Data-For-Billing-Record), convertir directamente
    if ($InputString -match '^[A-Z]{2,}-[A-Z][a-zA-Z-]+') {
        # Convertir todo a minúsculas y reemplazar guiones por underscores
        return $InputString.ToLower() -replace '-', '_'
    }
    
    # Para otros casos, usar la lógica original
    $cleanString = $InputString -replace '[^a-zA-Z0-9\\-_]', ''
    
    # Convertir guiones a underscores primero
    $snakeCase = $cleanString -replace '-', '_'
    
    # Manejar transiciones de mayúscula SOLO entre letras minúsculas y mayúsculas
    $snakeCase = $snakeCase -replace '([a-z])([A-Z])', '$1_$2'
    $snakeCase = $snakeCase.ToLower()
    
    # Limpiar múltiples underscores
    $snakeCase = $snakeCase -replace '_+', '_'
    $snakeCase = $snakeCase.Trim('_')
    
    return $snakeCase
}

function Test-UpperKebabCase {
    param([string]$InputString)
    return $InputString -match '^[A-Z][a-z0-9]*(-[A-Z][a-z0-9]*)*$'
}

function Load-CustomPolicyMapping {
    param([string]$MappingFile)
    
    if (-not (Test-Path $MappingFile)) {
        Write-Log "Archivo de mapeo personalizado no encontrado: $MappingFile" "WARNING"
        Write-Log "Se usará solo el mapeo estándar basado en prefijos"
        return
    }
    
    try {
        $csvData = Import-Csv -Path $MappingFile -Header "OldName", "NewName", "PolicyType"
        
        foreach ($row in $csvData) {
            if (-not [string]::IsNullOrEmpty($row.OldName) -and -not [string]::IsNullOrEmpty($row.NewName)) {
                $Global:CustomPolicyMapping[$row.OldName] = @{
                    NewName = $row.NewName
                    PolicyType = $row.PolicyType
                }
            }
        }
        
        Write-Log "Mapeo personalizado cargado: $($Global:CustomPolicyMapping.Count) entradas desde $MappingFile"
        
    }
    catch {
        Write-Log "Error al cargar mapeo personalizado: $($_.Exception.Message)" "ERROR"
    }
}

function Update-PolicyInternalFields {
    param([string]$PolicyFile, [string]$NewName)
    
    try {
        [xml]$policyXml = Get-Content $PolicyFile -Raw
        $rootElement = $policyXml.DocumentElement
        
        $fieldsUpdated = $false
        
        # Actualizar atributo 'name'
        $oldName = $rootElement.GetAttribute("name")
        if ($oldName -ne $NewName) {
            $rootElement.SetAttribute("name", $NewName)
            Write-Log "Atributo 'name' actualizado: $oldName -> $NewName en $PolicyFile"
            $fieldsUpdated = $true
        }
        
        # Actualizar DisplayName si existe
        $displayNameNode = $policyXml.SelectSingleNode("//DisplayName")
        if ($displayNameNode -and $displayNameNode.InnerText -ne $NewName) {
            $oldDisplayName = $displayNameNode.InnerText
            $displayNameNode.InnerText = $NewName
            Write-Log "DisplayName actualizado: $oldDisplayName -> $NewName en $PolicyFile"
            $fieldsUpdated = $true
        }
        
        # Manejar ResourceURL para políticas JavaScript
        if ($rootElement.LocalName -eq "Javascript") {
            $resourceURLNode = $policyXml.SelectSingleNode("//ResourceURL")
            if ($resourceURLNode) {
                $oldResourceURL = $resourceURLNode.InnerText
                # Para archivos JS, usar el NUEVO nombre de la política (no el original)
                $jsFileName = Convert-ToSnakeCase -InputString $NewName
                $newResourceURL = "jsc://$jsFileName.js"
                
                if ($oldResourceURL -ne $newResourceURL) {
                    # Actualizar ResourceURL en el XML
                    $resourceURLNode.InnerText = $newResourceURL
                    Write-Log "ResourceURL actualizado: $oldResourceURL -> $newResourceURL en $PolicyFile"
                    $fieldsUpdated = $true
                    
                    # Renombrar el archivo JavaScript físico
                    $proxyPath = Split-Path (Split-Path (Split-Path $PolicyFile -Parent) -Parent) -Parent
                    Update-JavaScriptFile -OldResourceURL $oldResourceURL -NewResourceURL $newResourceURL -ProxyPath $proxyPath
                }
            }
        }
        
        if ($fieldsUpdated) {
            if ($Global:DryRun) {
                Write-Log "[DryRun] Campos internos se actualizarían en: $PolicyFile"
            } else {
                $policyXml.Save($PolicyFile)
                Write-Log "Campos internos actualizados en: $PolicyFile"
            }
        }
        
    }
    catch {
        Write-Log "Error al actualizar campos internos en $PolicyFile : $($_.Exception.Message)" "ERROR"
    }
}

function Update-JavaScriptFile {
    param([string]$OldResourceURL, [string]$NewResourceURL, [string]$ProxyPath)
    
    try {
        # Extraer nombre del archivo de la URL (jsc://filename.js)
        $oldFileName = $OldResourceURL -replace '^jsc://', ''
        $newFileName = $NewResourceURL -replace '^jsc://', ''
        
        $jscPath = Join-Path $ProxyPath "apiproxy\resources\jsc"
        $oldFilePath = Join-Path $jscPath $oldFileName
        $newFilePath = Join-Path $jscPath $newFileName
        
        if (Test-Path $oldFilePath) {
            if ($Global:DryRun) {
                Write-Log "[DryRun] Se renombraría archivo JavaScript: $oldFilePath -> $newFilePath"
            } else {
                if (Test-Path $newFilePath) {
                    Write-Log "Conflicto: El archivo JavaScript $newFilePath ya existe" "WARNING"
                    return $false
                }
                
                Rename-Item -Path $oldFilePath -NewName $newFileName
                Write-Log "Archivo JavaScript renombrado: $oldFileName -> $newFileName"
                Write-ChangeLog $oldFileName $newFileName "JS_FILE_RENAME" $oldFilePath
                return $true
            }
        } else {
            Write-Log "Archivo JavaScript no encontrado: $oldFilePath" "WARNING"
            return $false
        }
        
        return $true
    }
    catch {
        Write-Log "Error al renombrar archivo JavaScript: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-PolicyType {
    param([string]$PolicyFile)
    
    try {
        [xml]$policyXml = Get-Content $PolicyFile -Raw
        return $policyXml.DocumentElement.LocalName
    }
    catch {
        Write-Log "Error al obtener tipo de política de $PolicyFile : $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-PolicyEnabled {
    param([string]$PolicyFile)
    
    try {
        [xml]$policyXml = Get-Content $PolicyFile -Raw
        $enabledAttr = $policyXml.DocumentElement.GetAttribute("enabled")
        return [string]::IsNullOrEmpty($enabledAttr) -or $enabledAttr -eq "true"
    }
    catch {
        Write-Log "Error al verificar si la política está habilitada en $PolicyFile : $($_.Exception.Message)" "ERROR"
        return $true
    }
}

function Get-StandardizedPolicyName {
    param([string]$PolicyType, [string]$CurrentName)
    
    # 1. Verificar tabla de homologación específica primero (PRIORIDAD MÁXIMA)
    if ($Global:HomologationTable.ContainsKey($CurrentName)) {
        Write-Log "Usando mapeo de homologación: $CurrentName -> $($Global:HomologationTable[$CurrentName])"
        return $Global:HomologationTable[$CurrentName]
    }
    
    # 2. Verificar mapeo personalizado
    if ($Global:CustomPolicyMapping.ContainsKey($CurrentName)) {
        $mappedName = $Global:CustomPolicyMapping[$CurrentName].NewName
        Write-Log "Usando mapeo personalizado: $CurrentName -> $mappedName"
        return $mappedName
    }
    
    # 3. Aplicar reglas estándar
    $prefix = $Global:PolicyPrefixes[$PolicyType]
    if (-not $prefix) {
        Write-Log "Tipo de política no reconocido: $PolicyType para $CurrentName" "WARNING"
        Write-UnmappedPolicyLog -PolicyName $CurrentName -PolicyType $PolicyType
        
        # Ahora que la política se agregó automáticamente al mapeo, intentar usarla
        if ($Global:CustomPolicyMapping.ContainsKey($CurrentName)) {
            $mappedName = $Global:CustomPolicyMapping[$CurrentName].NewName
            Write-Log "Usando mapeo automático generado: $CurrentName -> $mappedName"
            return $mappedName
        }
        
        return $CurrentName
    }
    
    # Extraer la parte descriptiva (después del prefijo)
    $descriptivePart = $CurrentName
    if ($CurrentName.StartsWith($prefix + "-")) {
        $descriptivePart = $CurrentName.Substring($prefix.Length + 1)
    } elseif ($CurrentName.StartsWith($prefix)) {
        $descriptivePart = $CurrentName.Substring($prefix.Length)
    }
    
    # Convertir a Upper-Kebab-Case
    $upperKebabDescriptive = Convert-ToUpperKebabCase -InputString $descriptivePart
    
    # Corregir la construcción del nombre - evitar doble guión
    if ($upperKebabDescriptive.StartsWith('-')) {
        $standardName = "$prefix$upperKebabDescriptive"
    } else {
        $standardName = "$prefix-$upperKebabDescriptive"
    }
    
    if ($standardName -ne $CurrentName) {
        Write-NewMappingLog -OldName $CurrentName -NewName $standardName -PolicyType $PolicyType
    }
    
    return $standardName
}

function Get-PolicyReferences {
    param([string]$PolicyName, [string]$ProxyPath)
    
    $referenceFiles = @()
    
    # Determinar rutas base
    $proxiesPath = ""
    $targetsPath = ""
    
    if ($ProxyPath.EndsWith("apiproxy") -or $ProxyPath.EndsWith("apiproxy\\")) {
        # Si ProxyPath ya apunta a apiproxy
        $proxiesPath = Join-Path $ProxyPath "proxies"
        $targetsPath = Join-Path $ProxyPath "targets"
    } else {
        # Si ProxyPath apunta al directorio padre
        $proxiesPath = Join-Path $ProxyPath "apiproxy\proxies"
        $targetsPath = Join-Path $ProxyPath "apiproxy\targets"
    }
    
    $searchPaths = @(
        "$proxiesPath\*.xml",
        "$targetsPath\*.xml"
    )
    
    foreach ($searchPath in $searchPaths) {
        $files = Get-ChildItem -Path $searchPath -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            $content = Get-Content $file.FullName -Raw
            if ($content -match "<Name>$PolicyName</Name>") {
                $referenceFiles += $file.FullName
            }
        }
    }
    
    return $referenceFiles
}

function Rename-PolicyFile {
    param([string]$OldPath, [string]$NewName)
    
    $directory = Split-Path $OldPath -Parent
    $oldFileName = [System.IO.Path]::GetFileNameWithoutExtension($OldPath)
    $newPath = Join-Path $directory "$NewName.xml"
    
    # Actualizar campos internos primero
    Update-PolicyInternalFields -PolicyFile $OldPath -NewName $NewName
    
    if ($oldFileName -eq $NewName) {
        Write-Log "Archivo mantiene el mismo nombre, solo se actualizaron campos internos: $NewName"
        return $OldPath
    }
    
    if ($Global:DryRun) {
        Write-Log "[DryRun] Se renombraría: $OldPath -> $newPath"
        return $newPath
    }
    
    if (Test-Path $newPath) {
        Write-ConflictLog "Conflicto de nombres: $newPath ya existe"
        return $OldPath
    }
    
    try {
        Rename-Item -Path $OldPath -NewName "$NewName.xml"
        Write-Log "Archivo renombrado: $OldPath -> $newPath"
        Write-ChangeLog $oldFileName $NewName "POLICY_RENAME" $OldPath
        Write-Log "Politica renombrada: $oldFileName -> $NewName"
        return $newPath
    }
    catch {
        Write-Log "Error al renombrar $OldPath : $($_.Exception.Message)" "ERROR"
        return $OldPath
    }
}

function Update-PolicyReferences {
    param([string]$OldName, [string]$NewName, [array]$ReferenceFiles)
    
    foreach ($file in $ReferenceFiles) {
        try {
            $content = Get-Content $file -Raw
            $updatedContent = $content -replace "<Name>$OldName</Name>", "<Name>$NewName</Name>"
            
            if ($content -ne $updatedContent) {
                Write-Log "Referencia actualizada en: $file ($OldName -> $NewName)"
                
                if (-not $Global:DryRun) {
                    Set-Content -Path $file -Value $updatedContent -NoNewline
                }
            }
        }
        catch {
            Write-Log "Error al actualizar referencias en $file : $($_.Exception.Message)" "ERROR"
        }
    }
}

function Create-Backup {
    param([string]$SourcePath)
    
    if ($Global:DryRun) {
        Write-Log "[DryRun] Se crearía backup en: $Global:BackupFolder"
        return
    }
    
    try {
        # Corregir el problema cuando SourcePath es "."
        $parentPath = Split-Path $SourcePath -Parent
        if ([string]::IsNullOrEmpty($parentPath)) {
            $parentPath = Get-Location
        }
        $backupPath = Join-Path $parentPath $Global:BackupFolder
        Copy-Item -Path $SourcePath -Destination $backupPath -Recurse -Force
        Write-Log "Backup creado en: $backupPath"
    }
    catch {
        Write-Log "Error al crear backup: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Restore-Backup {
    param([string]$TargetPath)
    
    try {
        # Corregir el problema cuando TargetPath es "."
        $parentPath = Split-Path $TargetPath -Parent
        if ([string]::IsNullOrEmpty($parentPath)) {
            $parentPath = Get-Location
        }
        $backupPath = Join-Path $parentPath $Global:BackupFolder
        if (Test-Path $backupPath) {
            Remove-Item -Path $TargetPath -Recurse -Force
            Copy-Item -Path $backupPath -Destination $TargetPath -Recurse -Force
            Write-Log "Backup restaurado desde: $backupPath"
        }
    }
    catch {
        Write-Log "Error al restaurar backup: $($_.Exception.Message)" "ERROR"
    }
}

function Update-TargetInternalFields {
    param([string]$TargetFile, [string]$OldName, [string]$NewName)
    
    try {
        [xml]$targetXml = Get-Content $TargetFile -Encoding UTF8
        
        # Actualizar el atributo 'name' del TargetEndpoint
        if ($targetXml.TargetEndpoint -and $targetXml.TargetEndpoint.name) {
            if ($targetXml.TargetEndpoint.name -eq $OldName) {
                $targetXml.TargetEndpoint.name = $NewName
                Write-Log "Atributo 'name' actualizado: $OldName -> $NewName en $TargetFile"
            }
        }
        
        # Actualizar DisplayName si existe y coincide
        if ($targetXml.TargetEndpoint.DisplayName) {
            if ($targetXml.TargetEndpoint.DisplayName -eq $OldName) {
                $targetXml.TargetEndpoint.DisplayName = $NewName
                Write-Log "DisplayName actualizado: $OldName -> $NewName en $TargetFile"
            }
        }
        
        if (-not $Global:DryRun) {
            $targetXml.Save($TargetFile)
            Write-Log "Campos internos actualizados en: $TargetFile"
        }
    }
    catch {
        Write-Log "Error al actualizar campos internos en $TargetFile : $($_.Exception.Message)" "ERROR"
    }
}

function Get-TargetNameFromURL {
    param([string]$TargetFile)
    
    try {
        [xml]$targetXml = Get-Content $TargetFile -Encoding UTF8
        
        # Extraer información de la URL o Path para generar nombre descriptivo
        $url = $targetXml.TargetEndpoint.HTTPTargetConnection.URL
        $path = $targetXml.TargetEndpoint.HTTPTargetConnection.Path
        
        $targetPath = $null
        if ($url) {
            $targetPath = $url
        } elseif ($path) {
            $targetPath = $path
        }
        
        if ($targetPath) {
            # Extraer el path para generar un nombre descriptivo
            # Remover variables como {private.context.sf} y tomar la parte relevante
            $cleanPath = $targetPath -replace '\{[^}]+\}', '' -replace '^/', ''
            $pathParts = $cleanPath -split '/'
            
            # Tomar la última parte significativa del path
            $lastPart = $pathParts | Where-Object { $_ -and $_ -ne '' } | Select-Object -Last 1
            
            if ($lastPart -and $lastPart -ne '') {
                # Convertir a snake_case siguiendo las reglas
                $descriptiveName = $lastPart.ToLower() -replace '[^a-z0-9]', '_' -replace '_+', '_'
                $descriptiveName = $descriptiveName.Trim('_')
                return $descriptiveName
            }
        }
        
        # Si no se puede extraer del path, usar el nombre actual convertido
        $currentName = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path $TargetFile -Leaf))
        return $currentName.ToLower() -replace '[^a-z0-9]', '_' -replace '_+', '_' | ForEach-Object { $_.Trim('_') }
    }
    catch {
        Write-Log "Error al analizar target file $TargetFile : $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Standardize-TargetEndpoints {
    param([string]$ProxyPath)
    
    Write-Log "Estandarizando target endpoints..."
    
    # Determinar la ruta correcta de targets
    $targetsPath = ""
    if ($ProxyPath.EndsWith("apiproxy") -or $ProxyPath.EndsWith("apiproxy\\")) {
        # Si ProxyPath ya apunta a apiproxy, solo agregar targets
        $targetsPath = Join-Path $ProxyPath "targets"
    } else {
        # Si ProxyPath apunta al directorio padre, agregar apiproxy\targets
        $targetsPath = Join-Path $ProxyPath "apiproxy\\targets"
    }
    
    if (-not (Test-Path $targetsPath)) {
        Write-Log "No se encontró carpeta de targets: $targetsPath" "WARNING"
        return
    }
    
    $targetFiles = Get-ChildItem -Path $targetsPath -Filter "*.xml"
    
    if ($targetFiles.Count -eq 1) {
        # Un solo target -> debe llamarse "default"
        $targetFile = $targetFiles[0]
        $currentName = [System.IO.Path]::GetFileNameWithoutExtension($targetFile.Name)
        
        if ($currentName -ne "default") {
            if ($Global:DryRun) {
                Write-Log "[DryRun] Target se renombraría: $currentName -> default"
                Write-Log "[DryRun] Se actualizarían campos internos del target"
            } else {
                # Actualizar campos internos antes del renombrado
                Update-TargetInternalFields -TargetFile $targetFile.FullName -OldName $currentName -NewName "default"
                
                # Renombrar archivo
                $newPath = Join-Path $targetFile.Directory "default.xml"
                Rename-Item -Path $targetFile.FullName -NewName "default.xml"
                Write-ChangeLog $currentName "default" "TARGET_RENAME" $targetFile.FullName
                Write-Log "Target renombrado: $currentName -> default"
                
                # Actualizar referencias en proxy
                Update-TargetReferences -OldName $currentName -NewName "default" -ProxyPath $ProxyPath
            }
        }
    } elseif ($targetFiles.Count -gt 1) {
        # Múltiples targets -> nombres descriptivos y técnicos en snake_case (inglés)
        foreach ($targetFile in $targetFiles) {
            $currentName = [System.IO.Path]::GetFileNameWithoutExtension($targetFile.Name)
            
            # Generar nombre descriptivo basado en la función del target
            $newName = Get-TargetNameFromURL -TargetFile $targetFile.FullName
            
            if (-not $newName) {
                # Fallback: convertir nombre actual a snake_case
                $newName = $currentName.ToLower() -replace '[^a-z0-9]', '_' -replace '_+', '_'
                $newName = $newName.Trim('_')
            }
            
            # Aplicar reglas específicas para nombres más descriptivos y técnicos
            switch -Regex ($newName) {
                '^upsert$' { $newName = 'upsert' }  # Ya está correcto
                '^get.*value$' { $newName = 'get_value' }  # Normalizar get-value, getValue, etc.
                '^create' { $newName = $newName -replace '^create', 'create' }
                '^update' { $newName = $newName -replace '^update', 'update' }
                '^delete' { $newName = $newName -replace '^delete', 'delete' }
                '^fetch' { $newName = $newName -replace '^fetch', 'fetch' }
            }
            
            if ($currentName -ne $newName) {
                if ($Global:DryRun) {
                    Write-Log "[DryRun] Target se renombraría: $currentName -> $newName"
                    Write-Log "[DryRun] Se actualizarían campos internos del target"
                } else {
                    # Actualizar campos internos antes del renombrado
                    Update-TargetInternalFields -TargetFile $targetFile.FullName -OldName $currentName -NewName $newName
                    
                    # Renombrar archivo
                    $newPath = Join-Path $targetFile.Directory "$newName.xml"
                    Rename-Item -Path $targetFile.FullName -NewName "$newName.xml"
                    Write-ChangeLog $currentName $newName "TARGET_RENAME" $targetFile.FullName
                    Write-Log "Target renombrado: $currentName -> $newName"
                    
                    # Actualizar referencias en proxy
                    Update-TargetReferences -OldName $currentName -NewName $newName -ProxyPath $ProxyPath
                }
            }
        }
    }
}

function Update-TargetReferences {
    param([string]$OldName, [string]$NewName, [string]$ProxyPath)
    
    Write-Log "Actualizando referencias de target: $OldName -> $NewName"
    
    # Determinar rutas de búsqueda
    $proxiesPath = ""
    if ($ProxyPath.EndsWith("apiproxy") -or $ProxyPath.EndsWith("apiproxy\\")) {
        $proxiesPath = Join-Path $ProxyPath "proxies"
    } else {
        $proxiesPath = Join-Path $ProxyPath "apiproxy\\proxies"
    }
    
    if (Test-Path $proxiesPath) {
        $proxyFiles = Get-ChildItem -Path $proxiesPath -Filter "*.xml"
        
        foreach ($proxyFile in $proxyFiles) {
            try {
                [xml]$proxyXml = Get-Content $proxyFile.FullName -Encoding UTF8
                $updated = $false
                
                # Actualizar referencias en RouteRule TargetEndpoint
                $routeRules = $proxyXml.SelectNodes("//RouteRule/TargetEndpoint")
                foreach ($targetEndpoint in $routeRules) {
                    if ($targetEndpoint.InnerText -eq $OldName) {
                        $targetEndpoint.InnerText = $NewName
                        $updated = $true
                        Write-Log "Referencia de target actualizada en RouteRule: $OldName -> $NewName en $($proxyFile.Name)"
                    }
                }
                
                if ($updated -and -not $Global:DryRun) {
                    $proxyXml.Save($proxyFile.FullName)
                    Write-Log "Referencias actualizadas en: $($proxyFile.FullName)"
                }
            }
            catch {
                Write-Log "Error al actualizar referencias en $($proxyFile.FullName): $($_.Exception.Message)" "ERROR"
            }
        }
    }
}

# Agregar nueva función para eliminar políticas deshabilitadas
function Remove-DisabledPolicies {
    param(
        [string[]]$PolicyFiles,
        [string]$ProxyPath
    )
    
    foreach ($policyFile in $PolicyFiles) {
        try {
            # Obtener referencias antes de eliminar
            $policyName = [System.IO.Path]::GetFileNameWithoutExtension($policyFile)
            $references = Get-PolicyReferences -PolicyName $policyName -ProxyPath $ProxyPath
            
            # Eliminar referencias de la política en flows
            foreach ($refFile in $references) {
                [xml]$xml = Get-Content $refFile -Encoding UTF8
                $policyElements = $xml.SelectNodes("//Policy[@name='$policyName']")
                foreach ($element in $policyElements) {
                    $element.ParentNode.RemoveChild($element) | Out-Null
                }
                $xml.Save($refFile)
            }
            
            # Eliminar el archivo de política
            Remove-Item $policyFile -Force
            Write-Log "Política deshabilitada eliminada: $policyName"
        }
        catch {
            Write-Log "Error eliminando política $policyFile`: $($_.Exception.Message)" "ERROR"
        }
    }
}

# Agregar nueva función para remover AssignTo innecesarios
function Remove-UnnecessaryAssignTo {
    param(
        [string]$ProxyPath
    )
    
    $policyFiles = Get-ChildItem -Path "$ProxyPath\apiproxy\policies" -Filter "*.xml" -Recurse
    
    foreach ($policyFile in $policyFiles) {
        try {
            [xml]$xml = Get-Content $policyFile.FullName -Encoding UTF8
            $modified = $false
            
            # Buscar elementos AssignTo innecesarios
            $assignToElements = $xml.SelectNodes("//AssignTo[@createNew='false']")
            
            foreach ($assignTo in $assignToElements) {
                # Verificar si es un AssignTo por defecto innecesario
                $transport = $assignTo.GetAttribute("transport")
                $type = $assignTo.GetAttribute("type")
                
                # Remover AssignTo con valores por defecto
                if (($transport -eq "http") -and 
                    (($type -eq "request") -or ($type -eq "response")) -and 
                    ($assignTo.GetAttribute("createNew") -eq "false")) {
                    
                    $assignTo.ParentNode.RemoveChild($assignTo) | Out-Null
                    $modified = $true
                    Write-Log "AssignTo innecesario removido de: $($policyFile.Name)"
                }
            }
            
            if ($modified) {
                $xml.Save($policyFile.FullName)
            }
        }
        catch {
            Write-Log "Error procesando AssignTo en $($policyFile.Name)`: $($_.Exception.Message)" "ERROR"
        }
    }
}

# Agregar nueva función para corregir archivos JavaScript mal nombrados
function Fix-MalformedJavaScriptFiles {
    param([string]$ProxyPath)
    
    Write-Log "=== Corrigiendo archivos JavaScript mal formateados ==="
    
    # Mapeo de archivos problemáticos a nombres correctos
    $JSFileCorrections = @{
        "j_s_e_xt_ra_ct_g_ra_nt_or.js" = "extract_grantor.js"
        "j_s_f_or_ma_t_o_as_v_al_id_at_io_n_e_rr_or.js" = "format_oas_validation_error.js"
        "j_s_g_et_d_ev_el_op_er_d_at_a.js" = "get_developer_data.js"
        "j_s_h_an_dl_e_e_rr_or_r_es_po_ns_e.js" = "handle_error_response.js"
        "j_s_p_re_se_rv_e_o_ri_gi_na_l_r_eq_ue_st_d_at_a.js" = "preserve_original_request_data.js"
        "j_s_r_em_ov_e_a_cc_en_ts.js" = "remove_accents.js"
        "j_s_s_et_d_at_a_f_or_b_il_li_ng_r_ec_or_d.js" = "set_data_for_billing_record.js"
        "j_s_s_et_r_eq_ue_st_p_ar_am_t_o_n_ul_l.js" = "set_request_param_to_null.js"
        "j_s_v_al_id_n_ew_h_ea_de_r.js" = "valid_new_header.js"
        "j_s_v_al_id_at_e_r_eq_ue_st.js" = "validate_request.js"
    }
    
    # Determinar ruta de archivos JavaScript
    $jscPath = ""
    if ($ProxyPath.EndsWith("apiproxy") -or $ProxyPath.EndsWith("apiproxy\\")) {
        $jscPath = Join-Path $ProxyPath "resources\\jsc"
    } else {
        $jscPath = Join-Path $ProxyPath "apiproxy\\resources\\jsc"
    }
    
    if (-not (Test-Path $jscPath)) {
        Write-Log "No se encontró la carpeta jsc: $jscPath" "WARNING"
        return
    }
    
    $renamedFiles = @{}
    
    foreach ($oldFileName in $JSFileCorrections.Keys) {
        $newFileName = $JSFileCorrections[$oldFileName]
        $oldFilePath = Join-Path $jscPath $oldFileName
        $newFilePath = Join-Path $jscPath $newFileName
        
        if (Test-Path $oldFilePath) {
            if ($Global:DryRun) {
                Write-Log "[DryRun] Se renombraría archivo JS: $oldFileName -> $newFileName"
            } else {
                try {
                    if (Test-Path $newFilePath) {
                        Write-Log "Conflicto: El archivo $newFileName ya existe" "WARNING"
                        continue
                    }
                    
                    Rename-Item -Path $oldFilePath -NewName $newFileName -Force
                    Write-Log "Archivo JS renombrado: $oldFileName -> $newFileName"
                    Write-ChangeLog $oldFileName $newFileName "JS_FILE_FIX" $oldFilePath
                    $renamedFiles[$oldFileName] = $newFileName
                } catch {
                    Write-Log "Error al renombrar $oldFileName : $($_.Exception.Message)" "ERROR"
                }
            }
        } else {
            Write-Log "Archivo JS no encontrado: $oldFilePath" "WARNING"
        }
    }
    
    # Actualizar referencias en políticas XML
    if ($renamedFiles.Count -gt 0) {
        Write-Log "Actualizando referencias en políticas XML..."
        
        $policiesPath = ""
        if ($ProxyPath.EndsWith("apiproxy") -or $ProxyPath.EndsWith("apiproxy\\")) {
            $policiesPath = Join-Path $ProxyPath "policies"
        } else {
            $policiesPath = Join-Path $ProxyPath "apiproxy\\policies"
        }
        
        if (Test-Path $policiesPath) {
            $xmlFiles = Get-ChildItem -Path $policiesPath -Filter "*.xml" -File
            
            foreach ($xmlFile in $xmlFiles) {
                try {
                    $content = Get-Content -Path $xmlFile.FullName -Raw -Encoding UTF8
                    $modified = $false
                    
                    foreach ($oldFileName in $renamedFiles.Keys) {
                        $newFileName = $renamedFiles[$oldFileName]
                        $oldReference = "jsc://$oldFileName"
                        $newReference = "jsc://$newFileName"
                        
                        if ($content -match [regex]::Escape($oldReference)) {
                            if ($Global:DryRun) {
                                Write-Log "[DryRun] Se actualizaría referencia en $($xmlFile.Name): $oldReference -> $newReference"
                            } else {
                                $content = $content -replace [regex]::Escape($oldReference), $newReference
                                $modified = $true
                                Write-Log "Referencia actualizada en $($xmlFile.Name): $oldReference -> $newReference"
                            }
                        }
                    }
                    
                    if ($modified -and -not $Global:DryRun) {
                        Set-Content -Path $xmlFile.FullName -Value $content -Encoding UTF8
                        Write-Log "Referencias actualizadas en: $($xmlFile.Name)"
                    }
                } catch {
                    Write-Log "Error al actualizar referencias en $($xmlFile.Name): $($_.Exception.Message)" "ERROR"
                }
            }
        }
    }
    
    Write-Log "Corrección de archivos JavaScript completada. Archivos procesados: $($renamedFiles.Count)"
}

# ============================================================================
# FUNCION PRINCIPAL
# ============================================================================

function Start-ProxyRefactoring {
    param([string]$ProxyPath)
    
    Write-Log "=== INICIANDO REFACTORIZACION DE PROXY ==="
    Write-Log "Ruta del proxy: $ProxyPath"
    Write-Log "Modo DryRun: $Global:DryRun"
    Write-Log "Archivo de mapeo personalizado: $CustomMappingFile"
    Write-Log "Mapeos de homologación disponibles: $($Global:HomologationTable.Count)"
    
    # Cargar mapeo personalizado
    Load-CustomPolicyMapping -MappingFile $CustomMappingFile
    
    # Crear backup
    Create-Backup -SourcePath $ProxyPath
    
    # Inicializar archivos de log
    "OldName,NewName,PolicyType" | Out-File -FilePath $Global:NewMappingsLog -Encoding UTF8
    
    try {
        # 1. Corregir archivos JavaScript mal formateados
        Write-Log "Fase 1: Corrigiendo archivos JavaScript mal formateados..."
        # Fix-MalformedJavaScriptFiles -ProxyPath $ProxyPath  # COMENTADO: No es necesario
        
        # 2. Analizar y procesar politicas
        Write-Log "Fase 2: Procesando politicas..."
        
        # Determinar la ruta correcta de políticas
        $policiesPath = ""
        if ($ProxyPath.EndsWith("apiproxy") -or $ProxyPath.EndsWith("apiproxy\\")) {
            # Si ProxyPath ya apunta a apiproxy, solo agregar policies
            $policiesPath = Join-Path $ProxyPath "policies"
        } else {
            # Si ProxyPath apunta al directorio padre, agregar apiproxy\policies
            $policiesPath = Join-Path $ProxyPath "apiproxy\policies"
        }
        
        if (-not (Test-Path $policiesPath)) {
            Write-Log "No se encontro la carpeta de politicas: $policiesPath" "WARNING"
            return
        }
        
        $policyFiles = Get-ChildItem -Path $policiesPath -Filter "*.xml" | Where-Object { -not $_.Name.EndsWith(".backup") }
        
        $policiesToRename = @()
        $policiesToRemove = @()
        
        foreach ($policyFile in $policyFiles) {
            $policyType = Get-PolicyType -PolicyFile $policyFile.FullName
            $isEnabled = Get-PolicyEnabled -PolicyFile $policyFile.FullName
            $currentName = [System.IO.Path]::GetFileNameWithoutExtension($policyFile.Name)
            
            if (-not $isEnabled) {
                $policiesToRemove += $policyFile.FullName
            }
            elseif ($policyType) {
                $standardName = Get-StandardizedPolicyName -PolicyType $policyType -CurrentName $currentName
                if ($standardName -ne $currentName) {
                    $policiesToRename += @{
                        File = $policyFile.FullName
                        OldName = $currentName
                        NewName = $standardName
                    }
                } else {
                    # Aunque el nombre no cambie, verificar campos internos
                    Update-PolicyInternalFields -PolicyFile $policyFile.FullName -NewName $currentName
                }
            }
        }
        
        # 2.5. Eliminar políticas deshabilitadas
        if ($policiesToRemove.Count -gt 0) {
            Write-Log "Fase 2.5: Eliminando políticas deshabilitadas..."
            Remove-DisabledPolicies -PolicyFiles $policiesToRemove -ProxyPath $ProxyPath
        }
        
        # 3. Renombrar politicas
        Write-Log "Fase 3: Renombrando politicas..."
        foreach ($policy in $policiesToRename) {
            $references = Get-PolicyReferences -PolicyName $policy.OldName -ProxyPath $ProxyPath
            $newPath = Rename-PolicyFile -OldPath $policy.File -NewName $policy.NewName
            Update-PolicyReferences -OldName $policy.OldName -NewName $policy.NewName -ReferenceFiles $references
        }
        
        # 4. Estandarizar targets
        Write-Log "Fase 4: Estandarizando targets..."
        Standardize-TargetEndpoints -ProxyPath $ProxyPath
        
        # 5. Remover AssignTo innecesarios
        Write-Log "Fase 5: Removiendo AssignTo innecesarios..."
        Remove-UnnecessaryAssignTo -ProxyPath $ProxyPath
        
        Write-Log "=== REFACTORIZACION COMPLETADA ==="
        
        $removedCount = $policiesToRemove.Count
        $renamedCount = $policiesToRename.Count
        $homologationUsed = 0
        
        # Contar cuántos mapeos de homologación se usaron
        foreach ($policy in $policiesToRename) {
            if ($Global:HomologationTable.ContainsKey($policy.OldName)) {
                $homologationUsed++
            }
        }
        
        Write-Log "Estadísticas de refactorización:"
        Write-Log "- Políticas eliminadas: $removedCount"
        Write-Log "- Políticas renombradas: $renamedCount"
        Write-Log "- Mapeos de homologación usados: $homologationUsed de $($Global:HomologationTable.Count) disponibles"
        Write-Log "- Mapeos personalizados usados: $($Global:CustomPolicyMapping.Count)"
        
    }
    catch {
        Write-Log "Error durante la refactorizacion: $($_.Exception.Message)" "ERROR"
        Write-Log "Restaurando backup..."
        Restore-Backup -TargetPath $ProxyPath
        throw
    }
}

# ============================================================================
# EJECUCION PRINCIPAL
# ============================================================================

if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "=== HERRAMIENTA DE REFACTORIZACION APIGEE ===" -ForegroundColor Cyan
    Write-Host "Proxy: $ProxyPath" -ForegroundColor White
    Write-Host "DryRun: $DryRun" -ForegroundColor White
    Write-Host "Mapeo personalizado: $CustomMappingFile" -ForegroundColor White
    Write-Host "Mapeos de homologación: $($Global:HomologationTable.Count)" -ForegroundColor White
    Write-Host "" 
    
    $Global:DryRun = $DryRun
    $Global:VerboseOutput = $VerboseOutput
    
    Start-ProxyRefactoring -ProxyPath $ProxyPath
    
    Write-Host "" 
    Write-Host "Archivos generados:" -ForegroundColor Green
    Write-Host "- Log: $Global:LogFile" -ForegroundColor White
    Write-Host "- Cambios: $Global:ChangesLog" -ForegroundColor White
    Write-Host "- Conflictos: $Global:ConflictsLog" -ForegroundColor White
    Write-Host "- Nuevos mapeos: $Global:NewMappingsLog" -ForegroundColor White
    Write-Host "- Políticas sin mapear: $Global:UnmappedPoliciesLog" -ForegroundColor White
    Write-Host "- Backup: $Global:BackupFolder" -ForegroundColor White
}