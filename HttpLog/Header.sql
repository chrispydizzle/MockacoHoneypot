CREATE TABLE [dbo].[Header]
(
	[RequestId] BIGINT NOT NULL,
	[RequestPosition] SMALLINT NOT NULL,
    [Name] TEXT NOT NULL,
	[Value] TEXT NOT NULL,
	PRIMARY KEY (RequestId, RequestPosition),
	FOREIGN KEY (RequestId) References Request(RequestId)
)
