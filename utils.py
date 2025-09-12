"""
Utility functions for XSS Scanner API
"""
import re
import logging
from typing import Dict, List, Any, Tuple

logger = logging.getLogger(__name__)

class XSSScanner:
    """XSS vulnerability scanner class"""

    def __init__(self):
        self.vulnerability_patterns = self._get_vulnerability_patterns()
        self.compiled_patterns = self._compile_patterns()
        self.max_code_length = 50000  # Limit code size for performance
        self.max_vulnerabilities = 50  # Limit results to prevent excessive output

    def _get_vulnerability_patterns(self) -> Dict[str, str]:
        """
        Returns a dictionary of regex patterns for common XSS vulnerabilities.

        Returns:
            Dictionary mapping vulnerability names to regex patterns
        """
        return {
            "innerHTML_assignment": r"\.innerHTML\s*=\s*[^;]+",
            "document_write_call": r"document\.write\([^)]+\)",
            "eval_function_call": r"eval\([^)]+\)",
            "location_hash_usage": r"location\.hash",
            "script_tag_injection": r"<script[^>]*>.*?</script>",
            "on_event_handler": r"on\w+\s*=\s*[^>\s]+",
            "javascript_protocol": r"javascript:\s*[^\"\'\s]+",
            "unescaped_user_input": r"\.innerHTML\s*=\s*.*(\+.*userInput|\+.*req\.body|\+.*req\.query)",
            "dangerous_src_assignment": r"\.src\s*=\s*[^;]+",
            "dangerous_href_assignment": r"\.href\s*=\s*[^;]+",
        }

    def _compile_patterns(self) -> Dict[str, Any]:
        """
        Pre-compile regex patterns for better performance.

        Returns:
            Dictionary of compiled regex patterns
        """
        compiled = {}
        for name, pattern in self.vulnerability_patterns.items():
            compiled[name] = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        return compiled

    def _is_commented_line(self, line: str, match_position: int) -> bool:
        """
        Checks if a potential vulnerability match is inside a comment.

        Args:
            line: The line of code being analyzed
            match_position: The position where the match was found

        Returns:
            True if the match appears to be in a comment, False otherwise
        """
        # Check for common comment patterns before the match position
        comment_patterns = [
            r"^\s*//",      # Single line comment (//)
            r"^\s*#",       # Python-style comment (#)
            r"/\*.*\*/",    # Multi-line comment (/* */)
            r"<!--.*-->",   # HTML comment
        ]

        # Look at the text before the match
        text_before_match = line[:match_position]

        for pattern in comment_patterns:
            if re.search(pattern, text_before_match, re.DOTALL):
                return True

        return False

    def _scan_line_for_vulnerabilities(
        self,
        line: str,
        line_number: int
    ) -> List[Dict[str, Any]]:
        """
        Scans a single line of code for XSS vulnerabilities using compiled patterns.

        Args:
            line: The line of code to scan
            line_number: The line number in the original code

        Returns:
            List of found vulnerabilities in this line
        """
        found_vulnerabilities = []

        for vulnerability_name, compiled_pattern in self.compiled_patterns.items():
            # Find all matches of this pattern in the line
            matches = compiled_pattern.finditer(line)

            for match in matches:
                # Skip if this match appears to be in a comment
                if not self._is_commented_line(line, match.start()):
                    found_vulnerabilities.append({
                        "line": line_number,
                        "vulnerability_type": vulnerability_name,
                        "snippet": match.group().strip(),
                        "confidence": "medium",
                        "description": self._get_vulnerability_description(vulnerability_name)
                    })

        return found_vulnerabilities

    def _get_vulnerability_description(self, vulnerability_type: str) -> str:
        """Get human-readable description for vulnerability type"""
        descriptions = {
            "innerHTML_assignment": "Direct assignment to innerHTML can lead to XSS if user input is not sanitized",
            "document_write_call": "document.write() can execute malicious scripts",
            "eval_function_call": "eval() executes arbitrary code and is dangerous with user input",
            "location_hash_usage": "location.hash can be manipulated by attackers",
            "script_tag_injection": "Script tags can execute arbitrary JavaScript",
            "on_event_handler": "Inline event handlers can be exploited for XSS",
            "javascript_protocol": "javascript: URLs can execute malicious code",
            "unescaped_user_input": "User input assigned to innerHTML without proper escaping",
            "dangerous_src_assignment": "Dynamic src assignment can lead to script injection",
            "dangerous_href_assignment": "Dynamic href assignment can lead to script injection",
        }
        return descriptions.get(vulnerability_type, "Potential XSS vulnerability detected")

    def scan_code(self, code: str) -> Dict[str, Any]:
        """
        Scans provided code for XSS vulnerabilities with performance optimizations.

        Args:
            code: The HTML/JavaScript code to analyze

        Returns:
            Dictionary containing scan results
        """
        try:
            logger.info("Starting XSS scan")

            # Limit code size for performance
            if len(code) > self.max_code_length:
                code = code[:self.max_code_length]
                logger.warning(f"Code truncated to {self.max_code_length} characters for performance")

            # Split the code into individual lines for analysis
            code_lines = code.splitlines()

            # List to store all found vulnerabilities
            all_vulnerabilities = []

            # Scan each line of code with early exit for performance
            for line_number, line in enumerate(code_lines, start=1):
                if len(all_vulnerabilities) >= self.max_vulnerabilities:
                    logger.warning(f"Scan stopped early: reached maximum vulnerabilities limit ({self.max_vulnerabilities})")
                    break

                line_vulnerabilities = self._scan_line_for_vulnerabilities(line, line_number)
                all_vulnerabilities.extend(line_vulnerabilities)

            result = {
                "status": "success",
                "vulnerabilities_found": len(all_vulnerabilities),
                "vulnerabilities": all_vulnerabilities,
                "message": f"Scan completed. Found {len(all_vulnerabilities)} potential vulnerabilities."
            }

            logger.info(f"Scan completed: {len(all_vulnerabilities)} vulnerabilities found")
            return result

        except Exception as error:
            logger.error(f"Error during scanning: {str(error)}")
            raise Exception(f"An error occurred during scanning: {str(error)}")

# Global scanner instance
scanner = XSSScanner()
