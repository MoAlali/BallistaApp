import { exec } from "child_process";
import path from "path";
import fs from "fs";
import { tmpdir } from "os";

export default (app) => {
  app.log.info("App is Enabled!");

  app.on("push", async (context) => {
    const repoUrl = context.payload.repository.clone_url;
    const repoName = context.payload.repository.name;
    const tempDir = path.join(tmpdir(), `repo-${Date.now()}`);

    app.log.info(`Cloning repository: ${repoUrl}`);

    
    exec(`git clone --depth=1 ${repoUrl} ${tempDir}`, (cloneError) => {
      if (cloneError) {
        app.log.error(`Git clone error: ${cloneError.message}`);
        return;
      }

      app.log.info(`Repository cloned to ${tempDir}`);

      
      exec(`trivy fs ${tempDir} --format json`, (trivyError, stdout) => {
        if (trivyError) {
          app.log.error(`Trivy scan error: ${trivyError.message}`);
          return;
        }

        try {
          const scanResults = JSON.parse(stdout);
          let vulnerabilities = [];

          scanResults.Results?.forEach((result) => {
            if (result.Vulnerabilities) {
              vulnerabilities.push(...result.Vulnerabilities);
            }
          });

          if (vulnerabilities.length > 0) {
            let issueBody = `### Security vulnerabilities found:\n\n`;

            vulnerabilities.forEach((vuln) => {
              issueBody += `- **CVE:** ${vuln.VulnerabilityID}\n`;
              issueBody += `  - **Package:** ${vuln.PkgName}\n`;
              issueBody += `  - **Severity:** ${vuln.Severity}\n`;
              issueBody += `  - **Description:** ${vuln.Description || "N/A"}\n\n`;
            });

           
            context.octokit.issues.create(
              context.repo({
                title: "Security vulnerabilities found",
                body: issueBody,
              })
            );

            app.log.info("Issue created with security vulnerabilities.");
          } else {
            app.log.info("No vulnerabilities found.");
          }
        } catch (parseError) {
          app.log.error(`Error parsing Trivy output: ${parseError.message}`);
        } finally {
          
          fs.rm(tempDir, { recursive: true, force: true }, (err) => {
            if (err) app.log.error(`Error deleting temp repo: ${err.message}`);
            else app.log.info(`Deleted temp repo: ${tempDir}`);
          });
        }
      });
    });
  });
};
