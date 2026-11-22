using System.Collections.Generic;

namespace Mockaco.Attack
{
    /// <summary>
    /// Configuration for the attack layer.
    /// </summary>
    public sealed class AttackOptions
    {
        /// <summary>
        /// Base URL of the local LLM server (e.g. http://192.168.1.3:8080).
        /// </summary>
        public string LlmBaseUrl { get; set; } = "http://192.168.1.3:8080";

        /// <summary>
        /// Model name to use for research and attack decisions.
        /// </summary>
        public string LlmModel { get; set; } = "uncensored";

        /// <summary>
        /// Temperature for LLM reasoning (lower = more deterministic).
        /// </summary>
        public double LlmTemperature { get; set; } = 0.3;

        /// <summary>
        /// Max number of hosts to process per worker cycle.
        /// </summary>
        public int BatchSize { get; set; } = 10;

        /// <summary>
        /// How often (seconds) the worker polls for new hosts to attack.
        /// </summary>
        public double PollIntervalSeconds { get; set; } = 5;

        /// <summary>
        /// Timeout (seconds) for a single LLM research call.
        /// </summary>
        public int ResearchTimeoutSeconds { get; set; } = 60;

        /// <summary>
        /// Connection string override (defaults to the honeypot DB string).
        /// </summary>
        public string ConnectionString { get; set; }

        /// <summary>
        /// Maximum number of concurrent research workers.
        /// </summary>
        public int Workers { get; set; } = 4;

        /// <summary>
        /// System prompt fragment appended to every research request.
        /// </summary>
        public string SystemPrompt { get; set; } =
            "You are an aggressive red-team analyst. Given network scan findings, identify vulnerabilities, " +
            "CVEs, misconfigurations, and recommend concrete exploitation steps. Respond in structured JSON.";
    }
}
