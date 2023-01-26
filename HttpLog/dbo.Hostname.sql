CREATE TABLE [dbo].[Hostname]
(
	[HostnameId] BIGINT NOT NULL PRIMARY KEY IDENTITY(1,1),
	[HostId] BIGINT NOT NULL,
	[Hostname] NVARCHAR(500) NOT NULL, 
    CONSTRAINT [FK_Hostname_ToHost] FOREIGN KEY ([HostId]) REFERENCES [Host]([HostId])
)
