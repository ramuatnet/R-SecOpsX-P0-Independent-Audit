using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;
using System.IO;

namespace TestApp.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class VulnerableController : ControllerBase
    {
        // ----- Hard‑coded connection string (CWE-798) -----
        private readonly string _connStr = "Server=localhost;Database=testdb;User Id=root;Password=hardcoded_password;";

        [HttpGet("profile")]
        public IActionResult Profile([FromQuery] string name)
        {
            // ----- SQL Injection (CWE-89) -----
            using var conn = new SqlConnection(_connStr);
            conn.Open();
            var cmd = new SqlCommand($"SELECT * FROM Users WHERE Name = '{name}'", conn);
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
            // ----- Command Injection (CWE-78) -----
            var proc = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c " + cmd,
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
            // ----- Path Traversal (CWE-22) -----
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
