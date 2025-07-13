# PowerBI Data Connector for Inactive Users Azure Storage Table

This script creates a PowerBI data connector for easy access to the inactive users data stored in Azure Storage Table.

## PowerBI Custom Data Connector

### M Query for Azure Storage Table

```powerquery
let
    // Parameters - Replace with your values
    StorageAccountName = "yourstorageaccount",
    StorageAccountKey = "your-storage-account-key",
    TableName = "InactiveUsers",
    
    // Function to generate SAS token
    GenerateSASToken = (accountName as text, accountKey as text, tableName as text) =>
        let
            // SAS token generation logic
            signedExpiry = DateTimeZone.ToText(DateTimeZone.UtcNow() + #duration(0, 1, 0, 0), "yyyy-MM-ddTHH:mm:ssZ"),
            signedResource = "t",
            signedPermission = "r",
            signedServices = "t",
            signedVersion = "2019-12-12",
            
            // Create string to sign
            stringToSign = accountName & Text.NewLine &
                          signedPermission & Text.NewLine &
                          signedServices & Text.NewLine &
                          signedResource & Text.NewLine &
                          "" & Text.NewLine &
                          signedExpiry & Text.NewLine &
                          "" & Text.NewLine &
                          "" & Text.NewLine &
                          signedVersion & Text.NewLine &
                          tableName & Text.NewLine &
                          "" & Text.NewLine &
                          "" & Text.NewLine &
                          "" & Text.NewLine &
                          "",
            
            // Generate HMAC-SHA256 signature
            signature = Binary.ToText(Crypto.CreateHmac(CryptoAlgorithm.SHA256, Binary.FromText(accountKey, BinaryEncoding.Base64), Text.ToBinary(stringToSign, TextEncoding.Utf8)), BinaryEncoding.Base64),
            
            // Create SAS token
            sasToken = "sv=" & signedVersion & 
                      "&ss=" & signedServices & 
                      "&srt=" & signedResource & 
                      "&sp=" & signedPermission & 
                      "&se=" & signedExpiry & 
                      "&sig=" & Uri.EscapeDataString(signature)
        in
            sasToken,
    
    // Generate SAS token
    SASToken = GenerateSASToken(StorageAccountName, StorageAccountKey, TableName),
    
    // Create the URL
    BaseUrl = "https://" & StorageAccountName & ".table.core.windows.net/" & TableName,
    FullUrl = BaseUrl & "?" & SASToken,
    
    // Get data from Azure Table Storage
    Source = Json.Document(Web.Contents(FullUrl, [Headers=[Accept="application/json;odata=nometadata"]])),
    
    // Convert to table
    value = Source[value],
    ConvertedToTable = Table.FromList(value, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    ExpandedColumns = Table.ExpandRecordColumn(ConvertedToTable, "Column1", {"PartitionKey", "RowKey", "Timestamp", "UserPrincipalName", "DisplayName", "SamAccountName", "AccountType", "LastLogon", "Action", "ProcessedDate", "DaysInactive"}, {"PartitionKey", "RowKey", "Timestamp", "UserPrincipalName", "DisplayName", "SamAccountName", "AccountType", "LastLogon", "Action", "ProcessedDate", "DaysInactive"}),
    
    // Data type transformations
    ChangedTypes = Table.TransformColumnTypes(ExpandedColumns, {
        {"Timestamp", type datetimezone},
        {"LastLogon", type datetime},
        {"ProcessedDate", type datetime},
        {"DaysInactive", Int64.Type},
        {"UserPrincipalName", type text},
        {"DisplayName", type text},
        {"SamAccountName", type text},
        {"AccountType", type text},
        {"Action", type text},
        {"PartitionKey", type text},
        {"RowKey", type text}
    }),
    
    // Add calculated columns
    AddedCustomColumns = Table.AddColumn(ChangedTypes, "MonthYear", each Date.ToText([ProcessedDate], "MMM yyyy"), type text),
    AddedRiskCategory = Table.AddColumn(AddedCustomColumns, "RiskCategory", each 
        if [DaysInactive] >= 180 then "High Risk"
        else if [DaysInactive] >= 90 then "Medium Risk"
        else "Low Risk", type text),
    AddedActionCategory = Table.AddColumn(AddedRiskCategory, "ActionCategory", each 
        if Text.StartsWith([Action], "Disabled") then "Disabled"
        else if Text.StartsWith([Action], "Notified") then "Notified"
        else if Text.StartsWith([Action], "TEST") then "Test"
        else "Other", type text),
    
    // Filter out test data (optional)
    FilteredRows = Table.SelectRows(AddedActionCategory, each not Text.StartsWith([Action], "TEST")),
    
    // Sort by ProcessedDate descending
    SortedRows = Table.Sort(FilteredRows, {{"ProcessedDate", Order.Descending}})
in
    SortedRows
```

### Parameterized Query for Template

```powerquery
let
    // Parameters that will be prompted when template is used
    StorageAccountName = Parameter_StorageAccountName,
    StorageAccountKey = Parameter_StorageAccountKey,
    TableName = Parameter_TableName,
    DaysToInclude = Parameter_DaysToInclude,
    
    // Rest of the query remains the same...
    // (Include the full query from above)
    
    // Additional filter for date range
    DateFilteredRows = Table.SelectRows(SortedRows, each [ProcessedDate] >= Date.AddDays(Date.From(DateTime.LocalNow()), -DaysToInclude))
in
    DateFilteredRows
```

## PowerBI Parameters

When creating the PowerBI template, define these parameters:

```powerquery
Parameter_StorageAccountName = "yourstorageaccount" meta [IsParameterQuery=true, Type="Text", IsParameterQueryRequired=true],
Parameter_StorageAccountKey = "your-storage-account-key" meta [IsParameterQuery=true, Type="Text", IsParameterQueryRequired=true],
Parameter_TableName = "InactiveUsers" meta [IsParameterQuery=true, Type="Text", IsParameterQueryRequired=false],
Parameter_DaysToInclude = 365 meta [IsParameterQuery=true, Type="Number", IsParameterQueryRequired=false]
```

## Alternative: Using Azure Storage REST API

For more robust connection, use the Azure Storage REST API:

```powerquery
let
    // Function to call Azure Storage REST API
    CallAzureStorageAPI = (accountName as text, accountKey as text, tableName as text, optional continuationToken as text) =>
        let
            // Create authentication headers
            utcNow = DateTimeZone.ToText(DateTimeZone.UtcNow(), "ddd, dd MMM yyyy HH:mm:ss") & " GMT",
            canonicalizedResource = "/" & accountName & "/" & tableName,
            stringToSign = "GET" & Text.NewLine &
                          "" & Text.NewLine &
                          "application/json" & Text.NewLine &
                          utcNow & Text.NewLine &
                          canonicalizedResource,
            
            signature = Binary.ToText(Crypto.CreateHmac(CryptoAlgorithm.SHA256, Binary.FromText(accountKey, BinaryEncoding.Base64), Text.ToBinary(stringToSign, TextEncoding.Utf8)), BinaryEncoding.Base64),
            
            authHeader = "SharedKey " & accountName & ":" & signature,
            
            // Build URL
            baseUrl = "https://" & accountName & ".table.core.windows.net/" & tableName,
            url = if continuationToken = null then baseUrl else baseUrl & "?" & continuationToken,
            
            // Make request
            response = Web.Contents(url, [
                Headers = [
                    #"Authorization" = authHeader,
                    #"x-ms-date" = utcNow,
                    #"x-ms-version" = "2019-12-12",
                    #"Accept" = "application/json;odata=nometadata"
                ]
            ])
        in
            response,
    
    // Get all data with pagination support
    GetAllData = (accountName as text, accountKey as text, tableName as text) =>
        let
            GetPage = (continuationToken as text) =>
                let
                    response = CallAzureStorageAPI(accountName, accountKey, tableName, continuationToken),
                    json = Json.Document(response),
                    data = json[value],
                    nextToken = try json[#"odata.nextLink"] otherwise null,
                    result = [Data = data, NextToken = nextToken]
                in
                    result,
            
            // Get first page
            firstPage = GetPage(null),
            
            // Function to get all pages
            GetAllPages = (token as text, accumulator as list) =>
                if token = null then
                    accumulator
                else
                    let
                        page = GetPage(token),
                        newAccumulator = accumulator & page[Data],
                        nextToken = page[NextToken]
                    in
                        @GetAllPages(nextToken, newAccumulator),
            
            allData = GetAllPages(firstPage[NextToken], firstPage[Data])
        in
            allData,
    
    // Main query
    Source = GetAllData(StorageAccountName, StorageAccountKey, TableName),
    ConvertedToTable = Table.FromList(Source, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    
    // Continue with column expansion and transformations...
    ExpandedColumns = Table.ExpandRecordColumn(ConvertedToTable, "Column1", {"PartitionKey", "RowKey", "Timestamp", "UserPrincipalName", "DisplayName", "SamAccountName", "AccountType", "LastLogon", "Action", "ProcessedDate", "DaysInactive"})
    
    // Rest of transformations...
in
    ExpandedColumns
```

## PowerBI Desktop Integration

### Using the Query
1. Open PowerBI Desktop
2. Get Data > Blank Query
3. Open Advanced Editor
4. Paste the M query code
5. Replace parameters with your values
6. Apply & Close

### Creating a Function
Create a reusable function:

```powerquery
let
    GetInactiveUsersData = (StorageAccountName as text, StorageAccountKey as text, TableName as text, optional DaysToInclude as number) =>
        let
            // Include the full query here
            // ...
        in
            SortedRows
in
    GetInactiveUsersData
```

## PowerBI Service Configuration

### Dataset Settings
```json
{
    "datasources": [
        {
            "datasourceType": "Web",
            "connectionDetails": {
                "server": "https://yourstorageaccount.table.core.windows.net/",
                "path": "/InactiveUsers"
            },
            "credentialDetails": {
                "credentialType": "Key",
                "credentials": {
                    "key": "your-storage-account-key"
                }
            }
        }
    ]
}
```

### Refresh Schedule
```powershell
# PowerShell to configure refresh schedule
$datasetId = "your-dataset-id"
$workspaceId = "your-workspace-id"

$refreshSchedule = @{
    value = @{
        days = @("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")
        times = @("06:00", "18:00")
        enabled = $true
        localTimeZoneId = "UTC"
    }
}

Invoke-PowerBIRestMethod -Url "groups/$workspaceId/datasets/$datasetId/refreshSchedule" -Method Patch -Body ($refreshSchedule | ConvertTo-Json -Depth 3)
```

## Error Handling

Add error handling to the M query:

```powerquery
let
    TryGetData = () =>
        try
            // Main query here
            FinalResult
        otherwise
            let
                ErrorTable = Table.FromRecords({[
                    Error = "Failed to retrieve data",
                    Timestamp = DateTime.LocalNow(),
                    Details = "Check storage account credentials and network connectivity"
                ]})
            in
                ErrorTable,
    
    Result = TryGetData()
in
    Result
```

## Performance Optimization

### Query Folding
Use query folding where possible:

```powerquery
let
    // Apply filters at source level
    FilteredSource = Table.SelectRows(Source, each [ProcessedDate] >= #date(2024, 1, 1)),
    
    // Use built-in functions for aggregations
    GroupedData = Table.Group(FilteredSource, {"AccountType"}, {{"Count", Table.RowCount, Int64.Type}})
in
    GroupedData
```

### Incremental Refresh
Configure incremental refresh for large datasets:

```powerquery
let
    // Use RangeStart and RangeEnd parameters
    FilteredData = Table.SelectRows(Source, each [ProcessedDate] >= RangeStart and [ProcessedDate] < RangeEnd)
in
    FilteredData
```

This data connector provides robust, parameterized access to your Azure Storage Table data, making it easy to create and maintain PowerBI dashboards for monitoring inactive user management.
