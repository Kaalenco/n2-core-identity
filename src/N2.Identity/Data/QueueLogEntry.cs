using N2.Core.Entity;

namespace N2.Identity.Data;

public class QueueLogEntry : IChangeLog
{
    public DateTime Created { get; set; }
    public Guid CreatedBy { get; set; }
    public string CreatedByName { get; set; } = string.Empty;
    public int Id { get; set; }
    public Guid LogRecordId { get; set; }
    public string Message { get; set; } = string.Empty;
    public Guid ReferenceId { get; set; }
    public string TableName { get; set; } = string.Empty;
}