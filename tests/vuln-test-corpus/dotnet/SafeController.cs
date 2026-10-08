using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;
using System.IO;
using Microsoft.Extensions.Configuration;

namespace TestApp.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SafeController : ControllerBase
    {
        // Credentials from configuration / environment – no hard‑coded secret
        private readonly string _connStr;

        public SafeController(IConfiguration config)
        {
            _connStr = config.GetConnectionString("DefaultConnection"); // from appsettings.json / env vars
        }

        [HttpGet("profile")]
        public IActionResult Profile([FromQuery] string name)
        {
            // ----- Parameterised query (fixes CWE-89) -----
            using var conn = new SqlConnection(_connStr);
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @pName", conn);
            cmd.Parameters.AddWithValue("@pName", name);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                return Ok(reader["Name"]);
            }
            return NotFound();
        }

        [HttpGet("run")]
        public IActionResult Run([FromQuery] string cmd)
        {
            // ----- Whitelist (fixes CWE-78) -----
            var allowed = new[] { "ls", "pwd", "date" };
            var parts = cmd.Split(' ');
            if (parts.Length == 0 || !allowed.Contains(parts[0]))
                return BadRequest("Invalid command");

            var proc = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = parts[0],
                    Arguments = string.Join(" ", parts.Skip(1)),
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();
            return Ok(output);
        }

        [HttpGet("file")]
        public IActionResult File([FromQuery] string filename)
        {
            // ----- Path validation (fixes CWE-22) -----
            if (filename.Contains("..") || Path.IsPathRooted(filename))
                return BadRequest("Invalid file name");

            var path = Path.Combine(@"C:\Uploads", filename);
            if (System.IO.File.Exists(path))
            {
                var bytes = System.IO.File.ReadAllBytes(path);
                return File(bytes, "application/octet-stream");
            }
            return NotFound();
        }
    }
}
