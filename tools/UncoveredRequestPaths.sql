-- Run through tools\DecoyInventory, which fills #Covered using the real route matcher.
-- Only temporary tables are written; dbo.Request remains unchanged.
SET NOCOUNT ON;
SELECT TOP (@Top)
    CONVERT(nvarchar(max), r.Target) COLLATE Latin1_General_100_BIN2 AS Path,
    COUNT_BIG(*) AS Requests,
    COUNT(DISTINCT r.SourceHostId) AS Sources,
    SUM(CASE WHEN r.CreatedDate >= DATEADD(day, -30, GETDATE()) THEN CONVERT(bigint, 1) ELSE 0 END) AS RecentRequests,
    MIN(r.CreatedDate) AS FirstSeen,
    MAX(r.CreatedDate) AS LastSeen
INTO #UncoveredPaths
FROM dbo.Request AS r
WHERE NOT EXISTS (
    SELECT 1 FROM #Covered AS c
    WHERE c.Path = CONVERT(nvarchar(max), r.Target) COLLATE Latin1_General_100_BIN2
)
AND CONVERT(nvarchar(max), r.Target) COLLATE Latin1_General_100_CI_AS <> @ExcludePath
GROUP BY CONVERT(nvarchar(max), r.Target) COLLATE Latin1_General_100_BIN2
ORDER BY Requests DESC, Path;

SELECT p.*,
    JSON_QUERY((SELECT r.Method, COUNT_BIG(*) AS Requests
        FROM dbo.Request AS r
        WHERE CONVERT(nvarchar(max), r.Target) COLLATE Latin1_General_100_BIN2 = p.Path
        GROUP BY r.Method ORDER BY Requests DESC, r.Method FOR JSON PATH)) AS Methods
FROM #UncoveredPaths AS p
ORDER BY p.Requests DESC, p.Path
FOR JSON PATH;
