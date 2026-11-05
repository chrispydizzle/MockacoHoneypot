SET XACT_ABORT ON;
BEGIN TRANSACTION;
IF COL_LENGTH('dbo.Job', 'Provider') IS NULL
    ALTER TABLE dbo.Job ADD Provider NVARCHAR(16) NOT NULL
        CONSTRAINT DF_Job_Provider DEFAULT N'Nmap' WITH VALUES;
IF COL_LENGTH('dbo.Discovery', 'ObservedAtUtc') IS NULL
    ALTER TABLE dbo.Discovery ADD ObservedAtUtc DATETIME2 NULL;
IF OBJECT_ID('dbo.ReconEvidence', 'U') IS NULL
    CREATE TABLE dbo.ReconEvidence
    (
        HostJobId BIGINT NOT NULL PRIMARY KEY,
        StatusCode INT NOT NULL,
        RetrievedAtUtc DATETIME2 NOT NULL,
        ResponseJson NVARCHAR(MAX) NOT NULL,
        CONSTRAINT FK_ReconEvidence_HostJob FOREIGN KEY (HostJobId) REFERENCES dbo.HostJob(HostJobId)
    );
COMMIT;
