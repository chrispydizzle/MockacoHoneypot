CREATE TABLE [dbo].[Discovery]
(
	[DiscoveryId] BIGINT NOT NULL PRIMARY KEY IDENTITY(1,1),
	[HostJobId] BIGINT NOT NULL,
	[HostId] BIGINT NOT NULL,
	[DiscoveryType] NVARCHAR(16) NOT NULL, 
	[DiscoveryDetail] TEXT NOT NULL, 
    [PortNumber] INT NULL, 
    CONSTRAINT [FK_Discovery_ToHostJob] FOREIGN KEY ([HostJobId]) REFERENCES [HostJob]([HostJobId]),
    CONSTRAINT [FK_Discovery_ToHost] FOREIGN KEY ([HostId]) REFERENCES [Host]([HostId])
)