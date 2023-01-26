CREATE TABLE [dbo].[Request]
(
	[RequestId] BIGINT NOT NULL PRIMARY KEY IDENTITY(1,1),
	[Target] TEXT NOT NULL,
	[Method] NVARCHAR(50) NOT NULL,
	[Body] BINARY NULL, 
	[QueryString] NVARCHAR(4000) NULL,
    [CreatedDate] DATETIME NOT NULL DEFAULT GETDATE(), 
    [TargetHost] NVARCHAR(500) NULL, 
    [SourceHostId] BIGINT NULL, 
    CONSTRAINT [FK_Request_Host] FOREIGN KEY ([SourceHostId]) REFERENCES [Host]([HostId])
	
)
