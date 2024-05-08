BEGIN TRANSACTION;
GO

ALTER TABLE [AspNetUsers] ADD [DisplayName] nvarchar(100) NULL;
GO

ALTER TABLE [AspNetUsers] ADD [FirstName] nvarchar(100) NULL;
GO

ALTER TABLE [AspNetUsers] ADD [ImagePath] nvarchar(300) NULL;
GO

ALTER TABLE [AspNetUsers] ADD [LastName] nvarchar(100) NULL;
GO

ALTER TABLE [AspNetUsers] ADD [MiddleName] nvarchar(10) NULL;
GO

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20240207085346_ExtendUserProperties', N'8.0.1');
GO

COMMIT;
GO


