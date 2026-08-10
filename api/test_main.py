import unittest
from unittest.mock import patch

from fastapi import HTTPException

from main import (
    Finding,
    GEMINI_MODELS,
    ask_gemini_with_fallback,
    is_safe_relative_path,
    parse_json_response,
    synthetic_remediation,
    validate_result,
)


class RemediationTests(unittest.TestCase):
    def test_gemini_models_are_configured_in_order(self) -> None:
        self.assertGreaterEqual(len(GEMINI_MODELS), 1)
        self.assertEqual(GEMINI_MODELS[0], "gemini-3.5-flash-lite")

    def test_second_gemini_model_is_used_after_rate_limit(self) -> None:
        finding = Finding(
            id="CVE-2021-44228",
            severity="CRITICAL",
            tool="Dependency-Check",
            category="SCA",
            description="Dependencia vulnerable.",
        )
        expected = {"explanation": "Resultado del segundo modelo."}

        with (
            patch("main.GEMINI_MODELS", ("first", "second")),
            patch(
                "main.ask_gemini",
                side_effect=[HTTPException(status_code=429), (expected, 10)],
            ),
            patch("main.ask_ollama") as ask_ollama,
        ):
            result, _, provider, model = ask_gemini_with_fallback(finding)

        self.assertEqual(result, expected)
        self.assertEqual(provider, "gemini")
        self.assertEqual(model, "second")
        ask_ollama.assert_not_called()

    def test_ollama_is_used_after_all_gemini_models_fail(self) -> None:
        finding = Finding(
            id="CVE-2021-44228",
            severity="CRITICAL",
            tool="Dependency-Check",
            category="SCA",
            description="Dependencia vulnerable.",
        )
        expected = {"explanation": "Resultado local."}

        with (
            patch("main.GEMINI_MODELS", ("first", "second")),
            patch("main.ask_gemini", side_effect=HTTPException(status_code=429)),
            patch("main.ask_ollama", return_value=(expected, 10)),
        ):
            result, _, provider, model = ask_gemini_with_fallback(finding)

        self.assertEqual(result, expected)
        self.assertEqual(provider, "ollama")
        self.assertEqual(model, "qwen2.5-coder:3b")

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
