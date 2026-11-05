SET XACT_ABORT ON;
BEGIN TRANSACTION;
IF COL_LENGTH('dbo.HostJob', 'LeaseToken') IS NULL
    ALTER TABLE dbo.HostJob ADD LeaseToken UNIQUEIDENTIFIER NULL;
IF COL_LENGTH('dbo.HostJob', 'LeaseUntil') IS NULL
    ALTER TABLE dbo.HostJob ADD LeaseUntil DATETIME2 NULL;
IF COL_LENGTH('dbo.HostJob', 'LastError') IS NULL
    ALTER TABLE dbo.HostJob ADD LastError NVARCHAR(MAX) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.HostJob') AND name = 'IX_HostJob_Host_Job')
    CREATE INDEX IX_HostJob_Host_Job ON dbo.HostJob (HostId, JobId);
COMMIT;
