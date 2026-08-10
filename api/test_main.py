import unittest

from fastapi import HTTPException

from main import (
    Finding,
    is_safe_relative_path,
    parse_json_response,
    synthetic_remediation,
    validate_result,
)


class RemediationTests(unittest.TestCase):
    def test_synthetic_finding_never_generates_a_patch(self) -> None:
        finding = Finding(
            id="CVE-TEST-001",
            severity="HIGH",
            tool="Trivy",
            category="CONTAINER",
            description="Hallazgo utilizado en una prueba.",
        )

        result = synthetic_remediation(finding)

        self.assertFalse(result["patchProposal"]["available"])
        self.assertTrue(result["patchProposal"]["requiresHumanReview"])

    def test_valid_patch_is_kept_for_human_review(self) -> None:
        result = validate_result(
            {
                "explanation": "Existe una dependencia vulnerable.",
                "recommendation": "Actualiza la dependencia.",
                "patchProposal": {
                    "available": True,
                    "file": "pom.xml",
                    "format": "unified-diff",
                    "content": "-<version>1.0</version>\n+<version>1.1</version>",
                    "confidence": "HIGH",
                    "requiresHumanReview": False,
                    "reason": None,
                },
                "validation": "Ejecuta las pruebas y Dependency-Check.",
                "learningNote": "Las dependencias deben mantenerse actualizadas.",
                "warnings": [],
            }
        )

        self.assertTrue(result["patchProposal"]["available"])
        self.assertTrue(result["patchProposal"]["requiresHumanReview"])

    def test_parent_directory_is_rejected(self) -> None:
        self.assertFalse(is_safe_relative_path("../pom.xml"))

    def test_json_inside_markdown_is_accepted(self) -> None:
        result = parse_json_response('```json\n{"available": true}\n```')

        self.assertTrue(result["available"])

    def test_invalid_patch_path_is_rejected(self) -> None:
        with self.assertRaises(HTTPException):
            validate_result(
                {
                    "explanation": "Explicación.",
                    "recommendation": "Recomendación.",
                    "patchProposal": {
                        "available": True,
                        "file": "../pom.xml",
                        "content": "-a\n+b",
                        "confidence": "HIGH",
                    },
                    "validation": "Validación.",
                    "learningNote": "Nota.",
                    "warnings": [],
                }
            )


if __name__ == "__main__":
    unittest.main()
