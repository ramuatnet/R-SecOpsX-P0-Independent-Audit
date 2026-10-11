package test;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.sql.*;

public class VulnerableServlet extends HttpServlet {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    private static final String USER = "root";
    private static final String PASS="***"; // CWE-798: Hard‑coded Credentials

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        String userInput = req.getParameter("input"); // <-- source

        // ---- SQL Injection (CWE-89) ----
        String sql = "SELECT * FROM users WHERE name = '" + userInput + "'";
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            // process result …
        } catch (SQLException e) {
            resp.getWriter().println("DB error");
        }

        // ---- Command Injection (CWE-78) ----
        String cmd = "echo " + userInput; // concatenation without validation
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            p.waitFor();
        } catch (Exception e) { /* ignore */ }

        // ---- Path Traversal (CWE-22) ----
        String fileName = req.getParameter("file");
        File f = new File("/var/www/uploads/" + fileName); // no validation
        try (FileInputStream fis = new FileInputStream(f)) {
            // read file …
        } catch (IOException e) {
            resp.getWriter().println("File error");
        }

        // ---- Insecure Deserialization (CWE-502) ----
        String serialized = req.getHeader("X-Serialized-Data");
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(
                    serialized.getBytes()));
            Object obj = ois.readObject(); // <-- dangerous
        } catch (Exception e) { /* ignore */ }

        resp.setContentType("text/plain");
        resp.getWriter().println("Done");
    }
}
