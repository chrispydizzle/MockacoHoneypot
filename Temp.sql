SELECT SourceHost, Target, Count(1), MAX(CreatedDATE) FROM Request 
GROUP BY SourceHost, Target
ORDER BY Count(1) DESC

SELECT * FROM Request ORder by requestid desc-- WHere target = '/cook' --order by RequestId Desc

ALTER VIEW dbo.HostStats AS
	WITH HostAgg AS
	(
	SELECT SourceHost, Target, COUNT(1) as Count, MIN(CreatedDate) as FirstContact, MAX(CreatedDate) as LastContact FROM dbo.Request
	Group By SourceHost, Target
	)
	SELECT SourceHost, STRING_AGG(Target, ',') as Targets, SUM(Count) as Count, MIN(FirstContact) as FirstContact, Max(LastContact) as LastContact
	From HostAgg
	Group By SourceHost