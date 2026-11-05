-- sqlcmd -S localhost -E -d HttpDb -b -r1 -v Top=100 -i .\tools\RequestInventory.sql -y0 -w65535 -o .\artifacts\request-inventory.json
SET NOCOUNT ON;
DECLARE @Top int = $(Top);
DECLARE @RecentStart datetime = DATEADD(day, -30, GETDATE());

SELECT
    Method,
    CONVERT(nvarchar(max), Target) COLLATE Latin1_General_100_BIN2 AS Target,
    COUNT_BIG(*) AS Requests,
    COUNT(DISTINCT COALESCE(CONVERT(varchar(20), SourceHostId), ''))
        - MAX(CASE WHEN SourceHostId IS NULL THEN 1 ELSE 0 END) AS Sources,
    SUM(CASE WHEN CreatedDate >= @RecentStart THEN CONVERT(bigint, 1) ELSE 0 END) AS RecentRequests,
    MIN(CreatedDate) AS FirstSeen,
    MAX(CreatedDate) AS LastSeen
INTO #Shapes
FROM dbo.Request
GROUP BY Method, CONVERT(nvarchar(max), Target) COLLATE Latin1_General_100_BIN2;

DECLARE @Report nvarchar(max) = (
    SELECT
        GETDATE() AS DatabaseTime,
        @RecentStart AS RecentStart,
        (SELECT SUM(Requests) FROM #Shapes) AS TotalRequests,
        (SELECT COUNT_BIG(*) FROM #Shapes) AS DistinctShapes,
        (SELECT MIN(FirstSeen) FROM #Shapes) AS FirstSeen,
        (SELECT MAX(LastSeen) FROM #Shapes) AS LastSeen,
        JSON_QUERY((SELECT Method, SUM(Requests) AS Requests FROM #Shapes
            GROUP BY Method ORDER BY SUM(Requests) DESC FOR JSON PATH)) AS Methods,
        JSON_QUERY((SELECT TOP (@Top) * FROM #Shapes
            ORDER BY Requests DESC, Method, Target FOR JSON PATH)) AS Common,
        JSON_QUERY((SELECT TOP (@Top) * FROM #Shapes
            ORDER BY Sources DESC, Requests DESC, Method, Target FOR JSON PATH)) AS Widespread,
        JSON_QUERY((SELECT TOP (@Top) * FROM #Shapes WHERE RecentRequests > 0
            ORDER BY RecentRequests DESC, Method, Target FOR JSON PATH)) AS Recent
    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER
);
SELECT @Report;
DROP TABLE #Shapes;
