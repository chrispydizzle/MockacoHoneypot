CREATE TABLE [dbo].[ReconEvidence]
(
    [HostJobId] BIGINT NOT NULL PRIMARY KEY,
    [StatusCode] INT NOT NULL,
    [RetrievedAtUtc] DATETIME2 NOT NULL,
    [ResponseJson] NVARCHAR(MAX) NOT NULL,
    CONSTRAINT [FK_ReconEvidence_HostJob] FOREIGN KEY ([HostJobId]) REFERENCES [dbo].[HostJob]([HostJobId])
)
