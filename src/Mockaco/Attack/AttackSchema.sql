-- ============================================================
-- Attack Layer Schema Migration
-- Add these tables to the existing HttpDb database.
-- ============================================================

-- 1. Attack record: one row per attack launched against a host.
IF NOT EXISTS (SELECT 1 FROM sys.objects WHERE object_id = OBJECT_ID(N'dbo.Attack') AND type IN (N'U'))
BEGIN
    CREATE TABLE dbo.Attack
    (
        AttackId   bigint IDENTITY(1,1) PRIMARY KEY,
        HostId     bigint        NOT NULL,
        AttackName nvarchar(256) NOT NULL,
        AttackType int           NOT NULL DEFAULT 6,  -- 0=Exploit, 1=Service, 2=Port, 3=Credential, 4=Web, 5=LateralMovement, 6=Recon
        Status     int           NOT NULL DEFAULT 0,  -- 0=Queued, 1=Researching, 2=Running, 3=Success, 4=Failed
        Result     nvarchar(max) NULL,
        CreatedAt  datetime2     NOT NULL DEFAULT SYSUTCDATETIME(),
        UpdatedAt  datetime2     NOT NULL DEFAULT SYSUTCDATETIME()
    );

    CREATE NONCLUSTERED INDEX IX_Attack_HostId_Status
        ON dbo.Attack (HostId, Status) INCLUDE (AttackName, AttackType, CreatedAt);

    CREATE NONCLUSTERED INDEX IX_Attack_Status
        ON dbo.Attack (Status) INCLUDE (HostId, AttackName, AttackType);

    PRINT 'Created dbo.Attack table.';
END

-- 2. AttackFinding: one row per LLM-identified vulnerability / finding.
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'AttackFinding')
BEGIN
    CREATE TABLE dbo.AttackFinding
    (
        FindingId   bigint IDENTITY(1,1) PRIMARY KEY,
        AttackId    bigint        NOT NULL,
        FindingType nvarchar(128) NOT NULL,
        Severity    nvarchar(16)  NOT NULL DEFAULT 'medium',  -- critical/high/medium/low
        Title       nvarchar(512) NOT NULL,
        Description nvarchar(max) NULL,
        Evidence    nvarchar(max) NULL,
        Exploitable bit           NOT NULL DEFAULT 0
    );

    CREATE NONCLUSTERED INDEX IX_AttackFinding_AttackId
        ON dbo.AttackFinding (AttackId) INCLUDE (FindingType, Severity, Title);

    PRINT 'Created dbo.AttackFinding table.';
END

-- 3. AttackResult: one row per attack execution outcome.
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'AttackResult')
BEGIN
    CREATE TABLE dbo.AttackResult
    (
        ResultId     bigint IDENTITY(1,1) PRIMARY KEY,
        AttackId     bigint        NOT NULL,
        AttackName   nvarchar(256) NULL,
        Success      bit           NOT NULL DEFAULT 0,
        Response     nvarchar(max) NULL,
        ErrorMessage nvarchar(max) NULL
    );

    CREATE NONCLUSTERED INDEX IX_AttackResult_AttackId
        ON dbo.AttackResult (AttackId) INCLUDE (Success, Response, AttackName);

    PRINT 'Created dbo.AttackResult table.';
END

PRINT 'Attack layer schema migration complete.';
