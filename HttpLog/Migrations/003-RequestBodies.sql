SET XACT_ABORT ON;
BEGIN TRY
    BEGIN TRANSACTION;
    IF EXISTS (
        SELECT 1 FROM sys.columns
        WHERE object_id = OBJECT_ID('dbo.Request') AND name = 'Body'
            AND system_type_id IN (TYPE_ID('nvarchar'), TYPE_ID('nchar'))
    )
    BEGIN
        ALTER TABLE dbo.Request ADD Body_Migration003 VARBINARY(MAX) NULL;
        -- Compile the copy after adding its destination; preserve Unicode as UTF-16LE bytes.
        EXEC sys.sp_executesql N'
            UPDATE dbo.Request SET Body_Migration003 = CONVERT(VARBINARY(MAX), Body);';
        ALTER TABLE dbo.Request DROP COLUMN Body;
        EXEC sys.sp_rename N'dbo.Request.Body_Migration003', N'Body', N'COLUMN';
    END
    ELSE IF NOT EXISTS (
        SELECT 1 FROM sys.columns
        WHERE object_id = OBJECT_ID('dbo.Request') AND name = 'Body'
            AND system_type_id = TYPE_ID('varbinary') AND max_length = -1
    )
        EXEC sys.sp_executesql N'ALTER TABLE dbo.Request ALTER COLUMN Body VARBINARY(MAX) NULL;';

    IF COL_LENGTH('dbo.Request', 'ContentType') IS NULL
        ALTER TABLE dbo.Request ADD ContentType NVARCHAR(MAX) NULL;
    COMMIT;
END TRY
BEGIN CATCH
    IF XACT_STATE() <> 0 ROLLBACK;
    THROW;
END CATCH;
