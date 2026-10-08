package test;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.sql.*;

public class SafeServlet extends HttpServlet {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    private static final String USER = System.getenv("DB_USER"); // from env
    private static final String PASS=System...S"); // from env

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        String userInput = req.getParameter("input");

        // ---- Parameterised query (fixes CWE-89) ----
        String sql = "SELECT * FROM users WHERE name = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, userInput);
            try (ResultSet rs = ps.executeQuery()) {
                // process result …
            }
        } catch (SQLException e) {
            resp.getWriter().println("DB error");
        }

        // ---- Whitelist for command (fixes CWE-78) ----
        if (userInput.matches("[a-zA-Z0-9]+")) { // only alphanum allowed
            String cmd = "echo " + userInput;
            try {
                Process p = Runtime.getRuntime().exec(cmd);
                p.waitFor();
            } catch (Exception e) { /* ignore */ }
        } else {
            resp.getWriter().println("Invalid input");
            return;
        }

        // ---- Path validation (fixes CWE-22) ----
        String fileName = req.getParameter("file");
        if (fileName != null && !fileName.contains("..") && !fileName.startsWith("/")) {
            File f = new File("/var/www/uploads/" + fileName);
            try (FileInputStream fis = new FileInputStream(f)) {
                // read file …
            } catch (IOException e) {
                resp.getWriter().println("File error");
            }
        } else {
            resp.getWriter().println("Invalid file name");
            return;
        }

        // ---- Disallow deserialization from untrusted source (fixes CWE-502) ----
        String serialized = req.getHeader("X-Serialized-Data");
        // In a real app you would avoid deserializing user‑controlled data altogether.
        // Here we simply ignore the header.
        resp.setContentType("text/plain");
        resp.getWriter().println("Done");
    }
}
