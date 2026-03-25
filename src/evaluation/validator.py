"""
Fix Validator — automated correctness checking via CodeQL and Snyk.

Validation procedure (matches paper Section 3.5):
  1. Apply the LLM-generated fix to the vulnerable file.
  2. Rebuild the project (Maven/Gradle) and run test suite.
  3. Re-scan with CodeQL  → check that the original CWE is no longer flagged.
  4. Re-scan with Snyk    → check that the original CWE is no longer flagged.
  5. A fix is labelled CORRECT only when BOTH tools confirm removal
     AND tests still pass.

Prerequisites:
  - CodeQL CLI installed and on PATH  (https://github.com/github/codeql-cli-binaries)
  - Snyk CLI installed and authenticated (https://snyk.io/docs/snyk-cli/)
  - Maven or Gradle available for the project under test
"""

import os
import re
import shutil
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    vulnerability_id: str
    is_correct: bool
    codeql_clean: bool
    snyk_clean: bool
    tests_passed: bool
    codeql_output: str = ""
    snyk_output: str = ""
    build_output: str = ""
    error: Optional[str] = None


class FixValidator:
    """
    Applies a candidate fix to a project clone and validates it using
    CodeQL + Snyk, mirroring the two-step procedure in the paper.
    """

    def __init__(self,
                 projects_root: str,
                 codeql_db_root: str,
                 codeql_bin: str = "codeql",
                 snyk_bin: str = "snyk",
                 build_timeout: int = 300,
                 scan_timeout: int = 600):
        """
        projects_root : directory containing cloned project repos
        codeql_db_root: directory where CodeQL databases are stored per project
        """
        self.projects_root = Path(projects_root)
        self.codeql_db_root = Path(codeql_db_root)
        self.codeql_bin = codeql_bin
        self.snyk_bin = snyk_bin
        self.build_timeout = build_timeout
        self.scan_timeout = scan_timeout

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def validate(self,
                 vulnerability_id: str,
                 project_name: str,
                 vulnerable_file: str,
                 original_code: str,
                 generated_fix: str,
                 cwe_id: str) -> ValidationResult:
        """
        Apply generated_fix, rebuild, scan, and return a ValidationResult.
        Works on a TEMPORARY COPY of the project to avoid side effects.
        """
        project_dir = self.projects_root / project_name
        if not project_dir.exists():
            return ValidationResult(
                vulnerability_id=vulnerability_id,
                is_correct=False,
                codeql_clean=False,
                snyk_clean=False,
                tests_passed=False,
                error=f"Project directory not found: {project_dir}",
            )

        with tempfile.TemporaryDirectory(prefix="llm_svr_") as tmp:
            tmp_project = Path(tmp) / project_name
            shutil.copytree(project_dir, tmp_project)

            target_file = tmp_project / vulnerable_file
            if not target_file.exists():
                return ValidationResult(
                    vulnerability_id=vulnerability_id,
                    is_correct=False,
                    codeql_clean=False,
                    snyk_clean=False,
                    tests_passed=False,
                    error=f"Target file not found: {target_file}",
                )

            # Step 1 — apply the fix
            apply_error = self._apply_fix(target_file, original_code, generated_fix)
            if apply_error:
                return ValidationResult(
                    vulnerability_id=vulnerability_id,
                    is_correct=False,
                    codeql_clean=False,
                    snyk_clean=False,
                    tests_passed=False,
                    error=apply_error,
                )

            # Step 2 — rebuild + test
            build_ok, build_output = self._build_and_test(tmp_project)

            # Step 3 — CodeQL re-scan
            codeql_clean, codeql_output = self._run_codeql(
                tmp_project, cwe_id
            )

            # Step 4 — Snyk re-scan
            snyk_clean, snyk_output = self._run_snyk(tmp_project, cwe_id)

            is_correct = build_ok and codeql_clean and snyk_clean

            return ValidationResult(
                vulnerability_id=vulnerability_id,
                is_correct=is_correct,
                codeql_clean=codeql_clean,
                snyk_clean=snyk_clean,
                tests_passed=build_ok,
                codeql_output=codeql_output,
                snyk_output=snyk_output,
                build_output=build_output,
            )

    # ------------------------------------------------------------------
    # Step helpers
    # ------------------------------------------------------------------

    def _apply_fix(self, target_file: Path,
                   original_code: str, fixed_code: str) -> Optional[str]:
        """Replace the vulnerable snippet with the generated fix in the file."""
        try:
            content = target_file.read_text(encoding="utf-8")
            if original_code not in content:
                # Try a lenient match (strip leading/trailing whitespace per line)
                norm_original = _normalize_code(original_code)
                norm_content = _normalize_code(content)
                if norm_original not in norm_content:
                    return "Original snippet not found in file (exact or normalised match)."
                content = content.replace(
                    original_code.strip(), fixed_code.strip()
                )
            else:
                content = content.replace(original_code, fixed_code)
            target_file.write_text(content, encoding="utf-8")
            return None
        except Exception as exc:
            return str(exc)

    def _build_and_test(self, project_dir: Path) -> tuple[bool, str]:
        """Run Maven or Gradle build + test suite."""
        if (project_dir / "pom.xml").exists():
            cmd = ["mvn", "test", "-q", "--no-transfer-progress"]
        elif (project_dir / "build.gradle").exists():
            cmd = ["./gradlew", "test", "--quiet"]
        else:
            logger.warning("No build file found in %s; skipping build.", project_dir)
            return True, "No build file — skipped."

        result = subprocess.run(
            cmd,
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=self.build_timeout,
        )
        success = result.returncode == 0
        output = result.stdout + result.stderr
        return success, output[:5000]

    def _run_codeql(self, project_dir: Path,
                    cwe_id: str) -> tuple[bool, str]:
        """
        Create a fresh CodeQL database and run the Java security suite.
        Returns (True, output) if the original CWE is no longer reported.
        """
        db_path = project_dir / ".codeql_db"
        lang = "java"
        query_suite = f"{lang}-security-and-quality.qls"

        # Build CodeQL DB
        build_cmd = [
            self.codeql_bin, "database", "create", str(db_path),
            "--language", lang,
            "--source-root", str(project_dir),
            "--overwrite",
        ]
        # Add Maven/Gradle build command for compiled languages
        if (project_dir / "pom.xml").exists():
            build_cmd += ["--command", "mvn compile -q --no-transfer-progress"]
        elif (project_dir / "build.gradle").exists():
            build_cmd += ["--command", "./gradlew compileJava --quiet"]

        try:
            result = subprocess.run(
                build_cmd, capture_output=True, text=True,
                timeout=self.scan_timeout, cwd=project_dir,
            )
            if result.returncode != 0:
                return False, f"CodeQL DB creation failed:\n{result.stderr[:2000]}"
        except subprocess.TimeoutExpired:
            return False, "CodeQL DB creation timed out."
        except FileNotFoundError:
            return False, "CodeQL CLI not found. Install from: https://github.com/github/codeql-cli-binaries"

        # Run analysis
        sarif_out = project_dir / "codeql_results.sarif"
        analyze_cmd = [
            self.codeql_bin, "database", "analyze",
            str(db_path), query_suite,
            "--format", "sarifv2.1.0",
            "--output", str(sarif_out),
            "--sarif-add-snippets",
        ]
        try:
            result = subprocess.run(
                analyze_cmd, capture_output=True, text=True,
                timeout=self.scan_timeout, cwd=project_dir,
            )
        except subprocess.TimeoutExpired:
            return False, "CodeQL analysis timed out."

        if not sarif_out.exists():
            return False, "CodeQL produced no SARIF output."

        # Parse SARIF to check if the CWE is still flagged
        import json
        sarif = json.loads(sarif_out.read_text())
        cwe_still_present = _sarif_contains_cwe(sarif, cwe_id)
        return not cwe_still_present, result.stdout[:2000]

    def _run_snyk(self, project_dir: Path,
                  cwe_id: str) -> tuple[bool, str]:
        """
        Run Snyk Code test on the project. Returns (True, output) if the
        original CWE is no longer reported.
        """
        cmd = [self.snyk_bin, "code", "test", "--json", "."]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.scan_timeout, cwd=project_dir,
            )
        except FileNotFoundError:
            return False, "Snyk CLI not found. Install with: npm install -g snyk"
        except subprocess.TimeoutExpired:
            return False, "Snyk scan timed out."

        output = result.stdout + result.stderr
        # Snyk exit code 1 means issues found; 0 means clean
        if result.returncode == 0:
            return True, output[:2000]

        # Check if the CWE in question is still in the output
        import json
        try:
            data = json.loads(result.stdout)
            cwe_still_present = _snyk_contains_cwe(data, cwe_id)
            return not cwe_still_present, output[:2000]
        except json.JSONDecodeError:
            # If Snyk output is not parseable JSON, conservative: assume issue remains
            return False, output[:2000]


# ------------------------------------------------------------------
# SARIF / Snyk parsing helpers
# ------------------------------------------------------------------

def _sarif_contains_cwe(sarif: dict, cwe_id: str) -> bool:
    """Return True if any SARIF result references the given CWE."""
    cwe_num = cwe_id.upper().replace("CWE-", "")
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            for tag in result.get("taxa", []):
                if cwe_num in str(tag.get("id", "")):
                    return True
            # Also check rule ID / properties
            rule_id = str(result.get("ruleId", ""))
            if cwe_num in rule_id.upper():
                return True
    return False


def _snyk_contains_cwe(data: dict, cwe_id: str) -> bool:
    """Return True if any Snyk finding references the given CWE."""
    cwe_num = cwe_id.upper().replace("CWE-", "")
    for run in data.get("runs", []):
        for result in run.get("results", []):
            for prop_key, prop_val in result.get("properties", {}).items():
                if "cwe" in prop_key.lower() and cwe_num in str(prop_val):
                    return True
    return False


def _normalize_code(code: str) -> str:
    """Normalise whitespace for lenient snippet matching."""
    return re.sub(r"\s+", " ", code).strip()
