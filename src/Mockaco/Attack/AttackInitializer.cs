using Microsoft.Extensions.Logging;
using System.Data.SqlClient;
using System.IO;
using System.Runtime;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Attack
{
    /// <summary>
    /// Ensures the attack-layer tables exist on startup.
    /// </summary>
    public static class AttackInitializer
    {
        private static bool _initialized;
        private static readonly object _lock = new();

        /// <summary>
        /// Call once during application startup to ensure tables exist.
        /// </summary>
        public static async Task EnsureTablesAsync(string connectionString, ILogger logger, CancellationToken cancellationToken = default)
        {
            if (_initialized) return;

            lock (_lock)
            {
                if (_initialized) return;

                var script = LoadMigrationScript();
                using var connection = new SqlConnection(connectionString);
                connection.Open();

                using var command = new SqlCommand(script, connection);
                command.CommandTimeout = 30;
                command.ExecuteNonQuery();

                _initialized = true;
                logger.LogInformation("Attack layer tables verified in database.");
            }
        }

        private static string LoadMigrationScript()
        {
            var executingAssembly = System.Reflection.Assembly.GetExecutingAssembly();
            var assemblyName = executingAssembly.GetName().Name;
            var embeddedResourceName = $"{assemblyName}.Attack.AttackSchema.sql";

            using var stream = executingAssembly.GetManifestResourceStream(embeddedResourceName);
            if (stream != null)
            {
                using var reader = new StreamReader(stream);
                return reader.ReadToEnd();
            }

            // Fallback: read from disk path
            var scriptPath = System.AppContext.BaseDirectory.Length > 0
                ? Path.Combine(System.AppContext.BaseDirectory, "Attack", "AttackSchema.sql")
                : "Attack/AttackSchema.sql";
            if (File.Exists(scriptPath))
                return File.ReadAllText(scriptPath);

            return "-- empty";
        }
    }
}
